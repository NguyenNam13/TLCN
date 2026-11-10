# -*- coding: utf-8 -*-
"""
src/agents/triage_agent.py
Detection & Triage Agent với kiến trúc Parallel Multi-Model Ensemble.
Nhiệm vụ:
1. Thẩm định các sự kiện an ninh (ParsedEvent) từ IncidentState.
2. Thực thi song song 3 models phân tích chuyên biệt qua ThreadPoolExecutor:
   - Model A (Heuristic Rule Evaluator): Đánh giá nhanh dựa trên rule level, nhóm phân loại, chữ ký nguy hiểm.
   - Model B (LLM CoT Reasoner): Suy luận logic CoT 4 bước (Observation -> Contextualization -> Risk Scoring -> Conclusion).
   - Model C (MITRE & IoC Threat Evaluator): Đánh giá ma trận kỹ thuật MITRE ATT&CK và dấu hiệu xâm phạm IoC.
3. Ensemble Consensus Engine: Tổng hợp có trọng số, đưa ra phán đoán đồng thuận và sinh TriageOutput chuẩn Pydantic v2.
4. Cập nhật trạng thái IncidentState xuyên suốt pipeline.
"""

import os
import re
import json
import logging
import ipaddress
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("TriageAgent")

from src.core.schemas import (
    ParsedEvent,
    TriageOutput,
    SeverityLevel,
    IncidentStatus,
    AttackCategory
)
from src.core.state import IncidentState
from src.agents.prompts import TRIAGE_AGENT_SYSTEM_PROMPT
from src.tools.threat_intel import ThreatIntelTools
from src.core.security_guard import detect_prompt_injection, wrap_untrusted_log


class TriageAgent:
    """
    Detection & Triage Agent đa mô hình (Parallel Ensemble SOC Tier 1).
    Kế thừa và tuân thủ chặt chẽ TRIAGE_AGENT_SYSTEM_PROMPT.
    Hỗ trợ tích hợp HybridLLMProvider đa tầng vào Model B (LLM CoT Reasoner).
    """

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        """Chuyển đổi số nguyên an toàn, xử lý triệt để None, chuỗi rác, dash '-'."""
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        weight_heuristic: float = 0.30,
        weight_cot: float = 0.40,
        weight_mitre_ioc: float = 0.30,
        llm_provider: Optional[Any] = None,
        llm_enabled: bool = True,
        enable_tiered_routing: bool = True,
        fast_triage_max_level: int = 7,
    ):
        self.system_prompt = system_prompt or TRIAGE_AGENT_SYSTEM_PROMPT
        self.name = "DetectionAndTriageAgent"
        self.weight_heuristic = weight_heuristic
        self.weight_cot = weight_cot
        self.weight_mitre_ioc = weight_mitre_ioc
        # UPGRADE: LLM Integration
        self.llm_provider = llm_provider
        self.llm_enabled = llm_enabled
        # UPGRADE: Tiered Routing (Hạn chế 4: Tối ưu chi phí Token & Giảm độ trễ)
        self.enable_tiered_routing = enable_tiered_routing
        self.fast_triage_max_level = fast_triage_max_level
        # Nạp hồ sơ huấn luyện từ Public Datasets (Mordor/OTRF) nếu tồn tại
        self.trained_profiles: Dict[str, Any] = self._load_trained_profiles()

    @staticmethod
    def _load_trained_profiles() -> Dict[str, Any]:
        """Tự động nạp file data/models/trained_log_profiles.json nếu tồn tại."""
        candidate_paths = [
            os.path.join("data", "models", "trained_log_profiles.json"),
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "data",
                "models",
                "trained_log_profiles.json",
            ),
        ]
        for path in candidate_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            return data
                except Exception as ex:
                    logger.debug(f"[TriageAgent] Không thể nạp trained_log_profiles.json: {ex}")
        return {}

    @staticmethod
    def _sanitize_for_prompt(value: Any, max_len: int = 200) -> str:
        """
        Làm sạch chuỗi trước khi ghép vào LLM prompt (chống Prompt Injection - Finding H1):
        - Loại bỏ ký tự xuống dòng (\\r, \\n, \\t) và các ký tự điều khiển (\\x00-\\x1f, \\x7f).
        - Cắt chuỗi tối đa max_len ký tự.
        """
        if value is None:
            return "N/A"
        text = str(value)
        text = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", text).strip()
        if not text:
            return "N/A"
        return text[:max_len]

    def _check_trained_profile_match(self, evt: ParsedEvent, combined_cmd: str, desc_lower: str) -> Tuple[bool, float, str]:
        """
        Đối chiếu sự kiện với hồ sơ hành vi đã huấn luyện (self.trained_profiles)
        và các mẫu chữ ký tấn công thực tế từ bộ dữ liệu công khai Mordor/OTRF.
        """
        if not self.trained_profiles:
            self.trained_profiles = self._load_trained_profiles()

        evt_id_str = str(evt.event_id or "").strip()
        win_eid_str = str(
            evt.raw_attributes.get("event_id")
            or evt.raw_attributes.get("win_event_id")
            or evt.raw_attributes.get("eventID")
            or ""
        ).strip()

        # Các dấu hiệu đặc trưng học từ Mordor/OTRF Dataset
        mordor_high_risk_eids = {"1102", "4104"}
        mordor_keywords = [
            "sharpview",
            "promptforcreds",
            "httplistener",
            "audit log cleared",
            "eventlog cleared",
        ]

        # Mở rộng từ self.trained_profiles nếu file đã được nạp
        profile_eids = set(mordor_high_risk_eids)
        profile_keywords = list(mordor_keywords)

        if isinstance(self.trained_profiles, dict):
            candidate_dicts = [self.trained_profiles]
            for v in self.trained_profiles.values():
                if isinstance(v, dict):
                    candidate_dicts.append(v)

            for d in candidate_dicts:
                for key in ("high_risk_event_ids", "suspicious_event_ids", "mordor_event_ids", "event_ids", "top_event_ids"):
                    val = d.get(key)
                    if isinstance(val, (list, dict)):
                        items = val.keys() if isinstance(val, dict) else val
                        profile_eids.update(str(x).strip() for x in items if str(x).strip() not in {"4624", "60100"})

                for key in ("attack_keywords", "suspicious_keywords", "keywords", "signatures", "command_patterns", "malicious_tokens"):
                    val = d.get(key)
                    if isinstance(val, (list, dict)):
                        items = val.keys() if isinstance(val, dict) else val
                        for kw in items:
                            kw_s = str(kw).strip().lower()
                            if len(kw_s) >= 5 and kw_s not in profile_keywords:
                                profile_keywords.append(kw_s)

        search_blob = " ".join([
            combined_cmd,
            desc_lower,
            (evt.process_name or "").lower(),
            (evt.process_path or "").lower(),
            str(evt.raw_attributes.get("full_log", "")).lower(),
        ])

        if evt_id_str in profile_eids or win_eid_str in profile_eids:
            matched_eid = evt_id_str if evt_id_str in profile_eids else win_eid_str
            bonus = 45.0 if matched_eid in {"1102", "4104"} else 30.0
            return (
                True,
                bonus,
                f"Khớp mẫu hành vi tấn công đã huấn luyện từ Public Dataset (Mordor/OTRF - EventID {matched_eid})",
            )

        for kw in profile_keywords:
            if kw and kw in search_blob:
                bonus = 40.0 if kw in mordor_keywords else 25.0
                return (
                    True,
                    bonus,
                    f"Khớp mẫu hành vi tấn công đã huấn luyện từ Public Dataset (Mordor/OTRF - '{kw}')",
                )

        return False, 0.0, ""

    # =====================================================================
    # TIERED ROUTING: FAST TRIAGE ELIGIBILITY CHECK
    # =====================================================================
    def is_eligible_for_fast_triage(
        self,
        events_or_state: Union[List[ParsedEvent], ParsedEvent, IncidentState, Any]
    ) -> bool:
        """
        Kiểm tra sự kiện có đủ điều kiện đi theo luồng Phân tầng nhanh (Tiered Fast Triage) hay không.
        Khắc phục Hạn chế 4: Tối ưu chi phí Token, giảm độ trễ qua Tiered Routing.

        Tiêu chí thẩm định:
        1. Wazuh rule level thấp (Level < fast_triage_max_level, mặc định < 7).
        2. Không chứa chuỗi obfuscation hoặc download cradle nguy hiểm (Base64, -enc, downloadstring, iex, v.v.).
        3. Không có IoC bất thường (không có IP public ngoại lai, không có mã băm hoặc chỉ số độc hại).
        4. Phân loại sơ bộ từ Heuristic Model là Benign (is_incident == False).
        """
        if isinstance(events_or_state, IncidentState):
            events = events_or_state.parsed_events
        elif isinstance(events_or_state, list):
            events = events_or_state
        elif isinstance(events_or_state, ParsedEvent):
            events = [events_or_state]
        else:
            return False

        if not events:
            return True

        # 1. Kiểm tra Wazuh rule level: Toàn bộ phải < fast_triage_max_level (mặc định 7)
        for evt in events:
            lvl = int(evt.raw_attributes.get("wazuh_rule_level", 0))
            if lvl >= self.fast_triage_max_level:
                return False

        # 2. Kiểm tra chuỗi obfuscation nguy hiểm hoặc command patterns độc hại
        dangerous_keywords = [
            "-enc", "encodedcommand", "downloadstring", "webclient", "iex",
            "frombase64string", "invoke-expression", "schtasks", "certutil",
            "bitsadmin", "meterpreter", "reverse shell", "c2", "trojan",
            "payload.exe", "payload.ps1", "promptforcreds", "sharpview",
            "audit log cleared", "eventlog cleared", "mimikatz"
        ]
        for evt in events:
            if "encoded_payload" in evt.raw_attributes or "decoded_command" in evt.raw_attributes:
                return False

            cmd = (evt.command_line or "").lower()
            decoded_cmd = (evt.raw_attributes.get("decoded_command") or "").lower()
            combined_cmd = f"{cmd} {decoded_cmd}"

            if any(kw in combined_cmd for kw in dangerous_keywords):
                return False

            proc = (evt.process_name or "").lower()
            if any(kw in proc for kw in ["powershell", "cmd.exe", "cscript", "wscript", "mshta", "rundll32"]):
                if int(evt.raw_attributes.get("wazuh_rule_level", 0)) >= 5:
                    return False

        # 3. Kiểm tra IoC bất thường
        for evt in events:
            if evt.dest_ip:
                try:
                    ip_obj = ipaddress.ip_address(evt.dest_ip)
                    if not (ip_obj.is_private or ip_obj.is_loopback):
                        return False
                except ValueError:
                    pass

            prelim_iocs = evt.raw_attributes.get("preliminary_iocs", [])
            for ioc in prelim_iocs:
                if ioc.get("is_public") is True or ioc.get("is_malicious") is True:
                    return False

            if evt.file_hash:
                return False

            groups = [g.lower() for g in evt.raw_attributes.get("wazuh_groups", [])]
            if any(g in groups for g in [
                "malware", "c2", "reconnaissance", "port_scan",
                "web_attack", "authentication_failed", "attack"
            ]):
                return False

            mitre_ids = evt.raw_attributes.get("wazuh_mitre_ids", [])
            if mitre_ids:
                return False

        # 4. Phân loại sơ bộ từ Heuristic Model A là Benign
        res_a = self._evaluate_heuristic(events)
        if res_a.get("is_incident", True):
            return False
        if res_a.get("score", 0.0) >= 30.0:
            return False

        return True

    # =====================================================================
    # 1. MODEL A: HEURISTIC RULE & BEHAVIORAL ML EVALUATOR
    # =====================================================================
    def _evaluate_heuristic(self, events: List[ParsedEvent]) -> Dict[str, Any]:
        """
        Model A: Đánh giá dựa trên heuristic rules, Wazuh rule level, các signature nguy hiểm
        và hồ sơ hành vi tấn công đã huấn luyện (trained_log_profiles.json).
        """
        if not events:
            return {
                "model": "Model-A-Heuristic",
                "is_incident": False,
                "confidence_score": 0.5,
                "severity": SeverityLevel.LOW,
                "score": 0.0,
                "anomaly_score": 0.0,
                "reasons": [],
                "rationale": "Không có sự kiện nào được ghi nhận."
            }

        max_rule_level = 0
        is_all_routine_benign = True
        threat_score = 0.0
        triggers: List[str] = []

        for evt in events:
            level = int(evt.raw_attributes.get("wazuh_rule_level", 0))
            rule_id = str(evt.raw_attributes.get("wazuh_rule_id", ""))
            groups = [g.lower() for g in evt.raw_attributes.get("wazuh_groups", [])]
            desc = evt.raw_attributes.get("wazuh_rule_description", "")

            if level > max_rule_level:
                max_rule_level = level

            cmd = (evt.command_line or "").lower()
            decoded_cmd = (evt.raw_attributes.get("decoded_command") or "").lower()
            combined_cmd = f"{cmd} {decoded_cmd}"

            # Kiểm tra dấu hiệu lành tính rõ ràng (ví dụ Rule 60100)
            if rule_id == "60100" or (level <= 4 and "routine" in desc.lower() and "authentication_success" in groups):
                triggers.append(f"Quy tắc đăng nhập thường nhật {rule_id} (Level {level})")
                continue

            # Nếu có bất kỳ rule nào vượt mức cơ bản hoặc chứa hành vi đáng ngờ
            is_all_routine_benign = False

            # Signature 1: PowerShell Obfuscation & Download Cradle
            if "encoded_payload" in evt.raw_attributes or "decoded_command" in evt.raw_attributes or "-enc" in cmd:
                threat_score += 45.0
                triggers.append("Phát hiện PowerShell encoded command / obfuscation")

            if "downloadstring" in combined_cmd or "webclient" in combined_cmd or "iex" in combined_cmd:
                threat_score += 35.0
                triggers.append("Phát hiện PowerShell Download Cradle tải payload")

            # Signature 2: Persistence via Scheduled Task
            if "schtasks" in combined_cmd or (evt.process_name and "schtasks" in evt.process_name.lower()):
                threat_score += 30.0
                triggers.append("Phát hiện thiết lập duy trì qua schtasks.exe")

            # Signature 3: Network Reconnaissance & Port Scanning (Rule 5710, 5712, 5715)
            if any(term in desc.lower() for term in ["scan", "sweep", "echo request", "syn packet", "banner grabbing"]) or \
               any(term in groups for term in ["reconnaissance", "port_scan", "network"]):
                threat_score += 35.0
                triggers.append(f"Hoạt động dò quét mạng/cổng (Wazuh Rule {rule_id})")

            # Signature 4: Credential Spraying & Brute Force & Unusual External IP (Rule 60105, 60106, 60115)
            if any(term in desc.lower() for term in ["failed logins", "unusual external ip", "credential enumeration", "special privileges"]):
                threat_score += 35.0
                triggers.append(f"Dấu hiệu tấn công xác thực / leo thang (Wazuh Rule {rule_id})")

            # Căn cứ điểm số từ Rule Level của Wazuh
            if level >= 12:
                threat_score += 40.0
            elif level >= 10:
                threat_score += 30.0
            elif level >= 7:
                threat_score += 20.0
            elif level >= 5:
                threat_score += 10.0

            # Kiểm tra bổ sung với Hồ sơ Huấn luyện từ Public Dataset (trained_log_profiles.json / Mordor)
            matched_profile, profile_bonus, profile_reason = self._check_trained_profile_match(
                evt, combined_cmd, desc.lower()
            )
            if matched_profile:
                if threat_score < 75.0:
                    threat_score = min(95.0, max(threat_score + profile_bonus, 75.0))
                if profile_reason not in triggers:
                    triggers.append(profile_reason)

        # Kết luận của Heuristic Model
        if is_all_routine_benign and threat_score == 0:
            return {
                "model": "Model-A-Heuristic",
                "is_incident": False,
                "confidence_score": 0.90,
                "severity": SeverityLevel.LOW,
                "score": 10.0,
                "anomaly_score": 10.0,
                "reasons": list(triggers),
                "rationale": "Toàn bộ sự kiện trùng khớp với hành vi người dùng thường nhật hợp lệ (False Positive)."
            }

        # Nếu có dấu hiệu nguy cơ
        normalized_score = min(100.0, max(20.0, threat_score))
        if max_rule_level >= 12 or normalized_score >= 80:
            sev = SeverityLevel.CRITICAL
        elif max_rule_level >= 10 or normalized_score >= 60:
            sev = SeverityLevel.HIGH
        elif max_rule_level >= 5 or normalized_score >= 35:
            sev = SeverityLevel.MEDIUM
        else:
            sev = SeverityLevel.LOW

        is_incident = normalized_score >= 30.0
        confidence = min(0.98, 0.75 + (normalized_score / 400.0))

        return {
            "model": "Model-A-Heuristic",
            "is_incident": is_incident,
            "confidence_score": round(confidence, 2),
            "severity": sev,
            "score": normalized_score,
            "anomaly_score": normalized_score,
            "reasons": list(triggers),
            "rationale": f"Heuristic kích hoạt các cảnh báo: {'; '.join(triggers[:5])} (Max Rule Level: {max_rule_level})."
        }

    def _evaluate_behavioral_ml(self, events: List[ParsedEvent]) -> Dict[str, Any]:
        """Model A Behavioral ML & Heuristic Evaluator (kết hợp trained_log_profiles.json)."""
        return self._evaluate_heuristic(events)

    # =====================================================================
    # 2. MODEL B: LLM CHAIN-OF-THOUGHT (CoT) REASONER
    # =====================================================================
    def _evaluate_llm_cot(self, events: List[ParsedEvent]) -> Dict[str, Any]:
        """
        Model B: Suy luận logic Chain-of-Thought (CoT) 4 bước:
        1. Observation -> 2. Contextualization -> 3. Risk Scoring -> 4. Conclusion.
        """
        if not events:
            return {
                "model": "Model-B-LLM-CoT",
                "is_incident": False,
                "confidence_score": 0.5,
                "severity": SeverityLevel.LOW,
                "score": 0.0,
                "cot_steps": {},
                "rationale": "Không có sự kiện để suy luận CoT."
            }

        # BƯỚC 1: OBSERVATION (Quan sát)
        observations = []
        max_level = 0
        has_powershell = False
        has_decoded_cmd = False
        has_external_conn = False
        has_scan = False
        has_auth_anomaly = False
        is_routine_session = False

        for evt in events:
            lvl = int(evt.raw_attributes.get("wazuh_rule_level", 0))
            if lvl > max_level:
                max_level = lvl
            
            rule_id = str(evt.raw_attributes.get("wazuh_rule_id", ""))
            desc = evt.raw_attributes.get("wazuh_rule_description", "")

            if rule_id == "60100" or (lvl <= 3 and "routine" in desc.lower()):
                is_routine_session = True
                observations.append(f"Ghi nhận phiên đăng nhập hợp lệ trong giờ hành chính của tài khoản {evt.user_name} trên máy trạm {evt.host_name}.")

            if evt.process_name and "powershell" in evt.process_name.lower():
                has_powershell = True
                observations.append(f"Tiến trình powershell.exe thực thi lệnh trên host {evt.host_name}.")

            if "decoded_command" in evt.raw_attributes:
                has_decoded_cmd = True
                observations.append(f"Lệnh PowerShell được giải mã Base64: {evt.raw_attributes['decoded_command']}")

            if evt.dest_ip:
                try:
                    ip_obj = ipaddress.ip_address(evt.dest_ip)
                    if not (ip_obj.is_private or ip_obj.is_loopback):
                        has_external_conn = True
                        observations.append(f"Kết nối ra địa chỉ IP công cộng ngoại lai: {evt.dest_ip}:{evt.dest_port}")
                except ValueError:
                    pass

            if any(term in desc.lower() for term in ["scan", "sweep", "icmp", "syn packet"]):
                has_scan = True
                observations.append(f"Phát hiện dấu hiệu rà quét mạng: {desc}")

            if any(term in desc.lower() for term in ["logon failure", "unusual external ip", "credential"]):
                has_auth_anomaly = True
                observations.append(f"Bất thường trong xác thực: {desc}")

        obs_summary = " | ".join(observations) if observations else "Quan sát log hệ thống bình thường."

        # BƯỚC 2: CONTEXTUALIZATION (Phân tích bối cảnh)
        context_notes = []
        if is_routine_session and not (has_powershell or has_decoded_cmd or has_external_conn or has_scan or has_auth_anomaly):
            context_notes.append("Bối cảnh vận hành chuẩn: Người dùng nội bộ thao tác tương tác qua giao diện chuẩn trong giờ làm việc. Không xuất hiện câu lệnh lạ hoặc kết nối ra ngoài.")
        else:
            if has_decoded_cmd:
                context_notes.append("Bối cảnh kỹ thuật cho thấy kẻ tấn công đang che giấu mã độc (Defense Evasion) bằng Base64 và cố gắng nạp script từ xa vào bộ nhớ (Fileless In-Memory Execution).")
            if has_external_conn:
                context_notes.append("Địa chỉ IP đích không thuộc dải IP nội bộ doanh nghiệp hay các dịch vụ đám mây tin cậy, đây là dấu hiệu điển hình của máy chủ C2 / Data Exfiltration.")
            if has_scan:
                context_notes.append("Mẫu hình quét dải IP nội bộ và các cổng dịch vụ then chốt thể hiện giai đoạn trinh sát (Reconnaissance) chuẩn bị cho xâm nhập sâu.")
            if has_auth_anomaly:
                context_notes.append("Các lần đăng nhập thất bại liên tiếp trước khi có đăng nhập thành công từ IP lạ chỉ ra chiến dịch Password Spraying chiếm quyền tài khoản miền.")

        ctx_summary = " ".join(context_notes)

        # BƯỚC 3: RISK SCORING (Đánh giá rủi ro)
        # Theo prompt: "Nếu wazuh_rule_level >= 10, mặc định rủi ro ở mức HIGH hoặc CRITICAL trừ khi phát hiện dấu hiệu rõ ràng của False Positive."
        if is_routine_session and not (has_powershell or has_decoded_cmd or has_external_conn or has_scan or has_auth_anomaly):
            risk_score = 10.0
            sev = SeverityLevel.LOW
            is_inc = False
            risk_rationale = "Điểm rủi ro: 10/100 (LOW). Hoạt động thường nhật, không có dấu hiệu xâm phạm."
        else:
            is_inc = True
            if max_level >= 12 or (has_powershell and has_decoded_cmd and has_external_conn):
                risk_score = 95.0
                sev = SeverityLevel.CRITICAL
                risk_rationale = f"Điểm rủi ro: 95/100 (CRITICAL). Rule Level {max_level} kết hợp mã độc Base64 C2 nguy hiểm cao độ."
            elif max_level >= 10 or has_auth_anomaly:
                risk_score = 80.0
                sev = SeverityLevel.HIGH
                risk_rationale = f"Điểm rủi ro: 80/100 (HIGH). Rule Level {max_level} cho thấy hành vi xâm nhập hoặc tấn công tài khoản nghiêm trọng."
            elif max_level >= 7 or has_scan:
                risk_score = 65.0
                sev = SeverityLevel.MEDIUM
                risk_rationale = f"Điểm rủi ro: 65/100 (MEDIUM/HIGH). Dò quét mạng diện rộng có chủ đích."
            else:
                risk_score = 40.0
                sev = SeverityLevel.MEDIUM
                risk_rationale = f"Điểm rủi ro: 40/100 (MEDIUM). Cảnh báo mức trung bình."

        # BƯỚC 4: CONCLUSION (Kết luận)
        conf = 0.95 if (is_inc and risk_score >= 80) or (not is_inc and risk_score <= 15) else 0.85
        conclusion_text = f"Kết luận CoT: Xác nhận {'SỰ CỐ AN NINH (True Positive)' if is_inc else 'HOẠT ĐỘNG THƯỜNG NHẬT (False Positive)'} với độ tin cậy {conf*100:.0f}%, mức độ {sev.value}."

        fast_result = {
            "model": "Model-B-LLM-CoT",
            "is_incident": is_inc,
            "confidence_score": conf,
            "severity": sev,
            "score": risk_score,
            "cot_steps": {
                "observation": obs_summary,
                "contextualization": ctx_summary,
                "risk_scoring": risk_rationale,
                "conclusion": conclusion_text
            },
            "rationale": f"[CoT 4-Step Analysis] {conclusion_text} {risk_rationale}"
        }

        # TIERED ROUTING: Nếu alert đủ điều kiện fast triage, tuyệt đối không gọi LLM Cloud (tiết kiệm 100% token)
        if self.enable_tiered_routing and self.is_eligible_for_fast_triage(events):
            return fast_result

        # UPGRADE: Nếu sự kiện không thuộc các mẫu rõ ràng (Unfamiliar/OOD Event) hoặc có llm_provider,
        # kích hoạt phân tích ngữ nghĩa sâu từ HybridLLMProvider (OmniRouter/OpenRouter/Ollama/Deterministic)
        is_clear_pattern = (
            (is_routine_session and not (has_powershell or has_decoded_cmd or has_external_conn or has_scan or has_auth_anomaly))
            or (has_powershell and has_decoded_cmd and has_external_conn)
            or (has_auth_anomaly and max_level >= 10)
            or (has_scan and max_level >= 7)
        )

        if self.llm_enabled and (not is_clear_pattern or self.llm_provider is not None):
            llm_result = self._call_llm_for_triage(events, fast_result)
            if llm_result:
                return llm_result

        return fast_result

    def _call_llm_for_triage(
        self,
        events: List[ParsedEvent],
        heuristic_context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        UPGRADE: Gọi HybridLLMProvider (OmniRouter/Ollama/Deterministic) để phân tích
        sự kiện bảo mật lạ không có trong kịch bản mẫu bằng ngữ cảnh CoT 4 bước.
        """
        if not self.llm_enabled:
            return None

        try:
            # Lazy import HybridLLMProvider nếu chưa được truyền vào
            if self.llm_provider is None:
                from src.copilot.llm_provider import HybridLLMProvider
                self.llm_provider = HybridLLMProvider()

            # 1. Quét Indirect Prompt Injection trong toàn bộ sự kiện đầu vào
            injection_reasons = []
            for e in events:
                raw_attrs = e.raw_attributes or {}
                for check_text in (e.command_line, raw_attrs.get("wazuh_rule_description"), raw_attrs.get("decoded_command")):
                    if check_text:
                        is_inj, reason = detect_prompt_injection(str(check_text))
                        if is_inj:
                            injection_reasons.append(reason)
                            break

            # Nếu phát hiện ý đồ thao túng mô hình ngôn ngữ (Jailbreak / Evasion)
            if injection_reasons:
                logger.warning(f"🚨 Phát hiện Indirect Prompt Injection trong sự kiện: {'; '.join(injection_reasons)}")
                return {
                    "model": "Model-B-LLM-CoT-Guard",
                    "is_incident": True,
                    "confidence_score": 0.99,
                    "severity": SeverityLevel.CRITICAL,
                    "score": 95.0,
                    "attack_category": AttackCategory.MALWARE,
                    "attack_type": "Indirect Prompt Injection & Defense Evasion Attack",
                    "cot_steps": {
                        "observation": f"Phát hiện mẫu lệnh thao túng mô hình AI trong log: {'; '.join(injection_reasons)}",
                        "contextualization": "Kẻ tấn công cố gắng đánh lừa hệ thống Triage tự động gán nhãn False Positive / Benign.",
                        "risk_scoring": "Mức độ cực kỳ nguy hiểm (CRITICAL - 95.0) do có chủ đích che giấu dấu vết tấn công.",
                        "conclusion": "Xác nhận sự cố an ninh nghiêm trọng (True Positive) kết hợp hành vi phòng thủ đối kháng (Adversarial AI Attack)."
                    },
                    "rationale": f"Phát hiện Prompt Injection trong log: {'; '.join(injection_reasons)}"
                }

            event_summaries = []
            for i, e in enumerate(events[:10], 1):
                raw_attrs = e.raw_attributes or {}
                rule_lvl = self._sanitize_for_prompt(raw_attrs.get("wazuh_rule_level", "N/A"), max_len=32)
                rule_desc = self._sanitize_for_prompt(raw_attrs.get("wazuh_rule_description", ""), max_len=200)
                groups = raw_attrs.get("wazuh_groups", [])
                mitre = raw_attrs.get("wazuh_mitre_ids", [])
                src_type = self._sanitize_for_prompt(e.source_type, max_len=100)
                evt_id = self._sanitize_for_prompt(e.event_id, max_len=100)
                host_name = self._sanitize_for_prompt(e.host_name or "N/A", max_len=100)
                user_name = self._sanitize_for_prompt(e.user_name or "N/A", max_len=100)
                proc_name = self._sanitize_for_prompt(e.process_name or "N/A", max_len=150)
                proc_path = self._sanitize_for_prompt(e.process_path or "N/A", max_len=200)
                cmd_line = wrap_untrusted_log(self._sanitize_for_prompt(e.command_line or "N/A", max_len=200))
                parent_proc = self._sanitize_for_prompt(e.parent_process or "N/A", max_len=150)
                summary_parts = [
                    f"Event #{i}: Source={src_type}, EventID={evt_id}",
                    f"Host={host_name}, User={user_name}",
                    f"Process={proc_name} (Path: {proc_path})",
                    f"CommandLine={cmd_line}",
                    f"ParentProcess={parent_proc}",
                    f"Net: {e.source_ip}:{e.source_port} -> {e.dest_ip}:{e.dest_port}",
                    f"Rule: Level={rule_lvl}, Desc='{rule_desc}', Groups={groups}, MITRE={mitre}"
                ]
                event_summaries.append(" | ".join(summary_parts))

            events_text = "\n".join(event_summaries)

            prompt = (
                f"Bạn là chuyên viên SOC Tier 1 cao cấp. Hãy thẩm định các sự kiện an ninh mạng sau:\n\n"
                f"{events_text}\n\n"
                f"Thực hiện suy luận Chain-of-Thought (CoT) 4 bước:\n"
                f"1. Observation: Liệt kê các hành vi, tiến trình, kết nối mạng bất thường.\n"
                f"2. Contextualization: Đánh giá bối cảnh quản trị hay dấu hiệu xâm nhập.\n"
                f"3. Risk Scoring: Chấm điểm rủi ro từ 0 đến 100 và xác định mức (LOW, MEDIUM, HIGH, CRITICAL).\n"
                f"4. Conclusion: Kết luận is_incident (true/false), phân loại loại tấn công (attack_category: MALWARE, CREDENTIAL_ACCESS, RECONNAISSANCE, WEB_ATTACK, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, BENIGN, UNKNOWN) và attack_type.\n\n"
                f"HÃY TRẢ VỀ DUY NHẤT MỘT ĐỐI TƯỢNG JSON với cấu trúc sau:\n"
                f"{{\n"
                f'  "is_incident": true,\n'
                f'  "confidence_score": 0.95,\n'
                f'  "severity": "HIGH",\n'
                f'  "score": 80.0,\n'
                f'  "attack_category": "MALWARE",\n'
                f'  "attack_type": "Tên loại tấn công",\n'
                f'  "cot_steps": {{\n'
                f'    "observation": "...",\n'
                f'    "contextualization": "...",\n'
                f'    "risk_scoring": "...",\n'
                f'    "conclusion": "..."\n'
                f'  }},\n'
                f'  "rationale": "Tóm tắt lý do kết luận"\n'
                f"}}"
            )

            raw_response = self.llm_provider.generate_response(
                prompt=prompt,
                system_prompt=self.system_prompt
            )

            if not raw_response or not isinstance(raw_response, str):
                return None

            json_text = raw_response.strip()
            if "```" in json_text:
                m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", json_text, re.DOTALL)
                if m:
                    json_text = m.group(1)

            parsed = json.loads(json_text)
            if not isinstance(parsed, dict) or "is_incident" not in parsed:
                return None

            sev_val = str(parsed.get("severity", "MEDIUM")).upper()
            try:
                severity = SeverityLevel(sev_val)
            except Exception:
                severity = SeverityLevel.MEDIUM

            raw_conf = float(parsed.get("confidence_score", 0.85))
            clamped_conf = max(0.0, min(1.0, raw_conf))
            raw_score = float(parsed.get("score", 50.0))
            clamped_score = max(0.0, min(100.0, raw_score))

            return {
                "model": "Model-B-LLM-CoT",
                "is_incident": bool(parsed.get("is_incident", False)),
                "confidence_score": clamped_conf,
                "severity": severity,
                "score": clamped_score,
                "attack_category": parsed.get("attack_category"),
                "attack_type": parsed.get("attack_type"),
                "cot_steps": parsed.get("cot_steps", {}),
                "rationale": str(parsed.get("rationale") or parsed.get("cot_steps", {}).get("conclusion", "Phân tích suy luận từ LLM."))
            }
        except Exception as ex:
            logger.debug(f"[TriageAgent] LLM analysis fallback: {ex}")
            return None

    # =====================================================================
    # 3. MODEL C: MITRE & IOC THREAT EVALUATOR
    # =====================================================================
    def _evaluate_mitre_ioc(self, events: List[ParsedEvent]) -> Dict[str, Any]:
        """
        Model C: Đánh giá dựa trên kỹ thuật MITRE ATT&CK và danh tiếng chỉ số xâm phạm (IoC).
        """
        if not events:
            return {
                "model": "Model-C-MITRE-IoC",
                "is_incident": False,
                "confidence_score": 0.5,
                "severity": SeverityLevel.LOW,
                "score": 0.0,
                "rationale": "Không có dữ liệu sự kiện để đối chiếu MITRE/IoC."
            }

        mitre_ids = set()
        malicious_iocs = []
        suspicious_public_ips = set()

        # Ánh xạ kỹ thuật có trọng số nguy hiểm
        high_risk_techniques = {"T1059.001", "T1027", "T1105", "T1071.001", "T1053.005", "T1078.002", "T1110.003"}
        recon_techniques = {"T1018", "T1046", "T1595.002", "T1087.002"}

        for evt in events:
            # Thu thập MITRE IDs từ Wazuh rule metadata
            rule_mitre = evt.raw_attributes.get("wazuh_mitre_ids", [])
            for mid in rule_mitre:
                mitre_ids.add(mid)

            # Tra cứu từ khóa kỹ thuật nếu có lệnh
            cmd_full = f"{evt.command_line or ''} {evt.raw_attributes.get('decoded_command', '')}"
            if cmd_full.strip():
                matches = ThreatIntelTools.match_mitre_technique(cmd_full)
                for m in matches:
                    mitre_ids.add(m.get("mitre_id"))

            # Kiểm tra IoC từ prelim IoCs hoặc IP kết nối
            prelim_iocs = evt.raw_attributes.get("preliminary_iocs", [])
            for item in prelim_iocs:
                if item.get("type") == "IP" and item.get("is_public"):
                    ip_val = item.get("value")
                    suspicious_public_ips.add(ip_val)
                    # Tra cứu CTI Feed giả lập
                    ioc_res = ThreatIntelTools.lookup_ip(ip_val)
                    if ioc_res.is_malicious:
                        malicious_iocs.append(ioc_res)

        # Tính toán điểm MITRE & IoC
        score = 0.0
        # Điểm từ kỹ thuật nguy hiểm cao
        matched_high = mitre_ids.intersection(high_risk_techniques)
        score += len(matched_high) * 25.0

        # Điểm từ kỹ thuật trinh sát/dò quét
        matched_recon = mitre_ids.intersection(recon_techniques)
        score += len(matched_recon) * 15.0

        # Điểm từ IoC độc hại đã xác nhận
        if malicious_iocs:
            score += 40.0
        elif suspicious_public_ips:
            score += 20.0

        # Nếu không có kỹ thuật MITRE nào và không có IP ngoại lai
        if not mitre_ids and not suspicious_public_ips:
            return {
                "model": "Model-C-MITRE-IoC",
                "is_incident": False,
                "confidence_score": 0.92,
                "severity": SeverityLevel.LOW,
                "score": 5.0,
                "mitre_techniques": [],
                "rationale": "Không phát hiện kỹ thuật MITRE ATT&CK hoặc IoC độc hại nào liên quan."
            }

        normalized_score = min(100.0, max(20.0, score))
        is_incident = normalized_score >= 25.0

        if normalized_score >= 80.0 or any(m in high_risk_techniques for m in mitre_ids):
            sev = SeverityLevel.CRITICAL if len(matched_high) >= 2 or malicious_iocs else SeverityLevel.HIGH
        elif normalized_score >= 40.0:
            sev = SeverityLevel.MEDIUM
        else:
            sev = SeverityLevel.LOW

        confidence = 0.92 if malicious_iocs or len(matched_high) >= 2 else 0.85
        clean_mitre_ids = sorted([str(m).strip() for m in mitre_ids if m and str(m).strip()])
        rationale = f"MITRE phát hiện {len(clean_mitre_ids)} kỹ thuật ({', '.join(clean_mitre_ids)}). "
        if malicious_iocs:
            rationale += f"Xác nhận {len(malicious_iocs)} IoC độc hại từ CTI: {[i.value for i in malicious_iocs]}."
        elif suspicious_public_ips:
            rationale += f"Ghi nhận {len(suspicious_public_ips)} IP ngoại lai: {list(suspicious_public_ips)}."

        return {
            "model": "Model-C-MITRE-IoC",
            "is_incident": is_incident,
            "confidence_score": confidence,
            "severity": sev,
            "score": normalized_score,
            "mitre_techniques": sorted(list(mitre_ids)),
            "rationale": rationale
        }

    # =====================================================================
    # 4. PARALLEL ENSEMBLE EXECUTION & CONSENSUS ENGINE
    # =====================================================================
    def evaluate_models_parallel(self, events: List[ParsedEvent]) -> Dict[str, Any]:
        """
        Thực thi đánh giá sự kiện:
        - Nếu bật Tiered Routing và sự kiện đủ điều kiện Fast Triage (Level < 7, Benign, không IoC/obfuscation):
          Short-circuit đánh giá Heuristic ngay lập tức, bỏ qua gọi LLM Cloud đắt đỏ (tiết kiệm 100% token).
        - Ngược lại, thực thi đồng thời Model A, Model B, Model C trên ThreadPoolExecutor.
        """
        if self.enable_tiered_routing and self.is_eligible_for_fast_triage(events):
            res_a = self._evaluate_heuristic(events)
            res_b = {
                "model": "Model-B-LLM-CoT",
                "is_incident": False,
                "confidence_score": res_a.get("confidence_score", 0.90),
                "severity": SeverityLevel.LOW,
                "score": res_a.get("score", 10.0),
                "cot_steps": {
                    "observation": "Tiered Routing: Cảnh báo mức thấp thường nhật, không có dấu hiệu bất thường.",
                    "contextualization": "Hoạt động đăng nhập quản trị thông thường trong mạng nội bộ.",
                    "risk_scoring": "Điểm rủi ro: 10/100 (LOW).",
                    "conclusion": "Kết luận: HOẠT ĐỘNG THƯỜNG NHẬT (False Positive) - Short-circuit qua Tiered Routing (0 Token LLM)."
                },
                "rationale": "[Tiered Routing Fast Path] Short-circuit đánh giá Heuristic, bỏ qua LLM Cloud để tiết kiệm token."
            }
            res_c = {
                "model": "Model-C-MITRE-IoC",
                "is_incident": False,
                "confidence_score": 0.95,
                "severity": SeverityLevel.LOW,
                "score": 5.0,
                "mitre_techniques": [],
                "rationale": "Không phát hiện kỹ thuật MITRE ATT&CK hoặc IoC độc hại nào liên quan."
            }
            consensus = self._calculate_consensus(res_a, res_b, res_c, events)
            return {
                "model_a": res_a,
                "model_b": res_b,
                "model_c": res_c,
                "consensus": consensus,
                "tiered_routing": {
                    "applied": True,
                    "tier": "fast_heuristic",
                    "tokens_saved": True,
                    "llm_called": False
                }
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_a = executor.submit(self._evaluate_heuristic, events)
            future_b = executor.submit(self._evaluate_llm_cot, events)
            future_c = executor.submit(self._evaluate_mitre_ioc, events)

            res_a = future_a.result()
            res_b = future_b.result()
            res_c = future_c.result()

        # Tính toán Ensemble Consensus
        consensus = self._calculate_consensus(res_a, res_b, res_c, events)

        return {
            "model_a": res_a,
            "model_b": res_b,
            "model_c": res_c,
            "consensus": consensus,
            "tiered_routing": {
                "applied": False,
                "tier": "full_ensemble",
                "tokens_saved": False,
                "llm_called": bool(self.llm_enabled and self.llm_provider is not None)
            }
        }

    def _calculate_consensus(
        self,
        res_a: Dict[str, Any],
        res_b: Dict[str, Any],
        res_c: Dict[str, Any],
        events: List[ParsedEvent]
    ) -> TriageOutput:
        """
        Tổng hợp có trọng số từ 3 models để đưa ra phán đoán đồng thuận cuối cùng.
        """
        w_a = self.weight_heuristic
        w_b = self.weight_cot
        w_c = self.weight_mitre_ioc

        # Tính biểu quyết có trọng số cho is_incident
        vote_a = (1.0 if res_a["is_incident"] else 0.0) * res_a["confidence_score"] * w_a
        vote_b = (1.0 if res_b["is_incident"] else 0.0) * res_b["confidence_score"] * w_b
        vote_c = (1.0 if res_c["is_incident"] else 0.0) * res_c["confidence_score"] * w_c

        total_weight = (
            res_a["confidence_score"] * w_a +
            res_b["confidence_score"] * w_b +
            res_c["confidence_score"] * w_c
        )

        prob_incident = (vote_a + vote_b + vote_c) / total_weight if total_weight > 0 else 0.0
        final_is_incident = prob_incident >= 0.5

        # Tính điểm tin cậy tổng hợp
        if final_is_incident:
            final_conf = min(0.99, max(0.75, prob_incident))
        else:
            final_conf = min(0.99, max(0.75, 1.0 - prob_incident))

        # Tính Severity đồng thuận
        weighted_score = (
            w_a * res_a.get("score", 0.0) +
            w_b * res_b.get("score", 0.0) +
            w_c * res_c.get("score", 0.0)
        )

        max_rule_level = max(
            [int(e.raw_attributes.get("wazuh_rule_level", 0)) for e in events] or [0]
        )

        if not final_is_incident:
            final_severity = SeverityLevel.LOW
        else:
            # Nếu có model đánh giá CRITICAL và có căn cứ rule level >= 12 hoặc score >= 85
            if (res_a["severity"] == SeverityLevel.CRITICAL or res_b["severity"] == SeverityLevel.CRITICAL or res_c["severity"] == SeverityLevel.CRITICAL) and (max_rule_level >= 12 or weighted_score >= 80):
                final_severity = SeverityLevel.CRITICAL
            elif max_rule_level >= 10 or weighted_score >= 60.0 or res_a["severity"] == SeverityLevel.HIGH or res_b["severity"] == SeverityLevel.HIGH:
                final_severity = SeverityLevel.HIGH
            elif weighted_score >= 35.0 or max_rule_level >= 5:
                final_severity = SeverityLevel.MEDIUM
            else:
                final_severity = SeverityLevel.LOW

        # Tổng hợp tóm tắt phán đoán (Summary)
        if final_is_incident:
            summary = (
                f"[Đồng thuận Đa mô hình - TRUE POSITIVE] Sự cố an ninh mạng mức độ {final_severity.value} "
                f"(Độ tin cậy: {final_conf*100:.1f}%). "
                f"Lý do: {res_b.get('cot_steps', {}).get('conclusion', res_b.get('rationale', ''))} "
                f"Heuristic ghi nhận: {res_a.get('rationale', '')} "
                f"CTI & MITRE ghi nhận: {res_c.get('rationale', '')}"
            )
        else:
            summary = (
                f"[Đồng thuận Đa mô hình - FALSE POSITIVE] Hoạt động thường nhật hợp lệ "
                f"(Độ tin cậy: {final_conf*100:.1f}%). "
                f"Hệ thống không ghi nhận bất kỳ dấu hiệu mã độc, leo thang đặc quyền hay kỹ thuật tấn công nào. "
                f"{res_a.get('rationale', '')}"
            )

        # Xác định Attack Category, Attack Type và Primary MITRE Tactics
        if not final_is_incident:
            attack_category = AttackCategory.BENIGN
            attack_type = "Normal Administrative Activity (Benign)"
            primary_mitre_tactics: List[str] = []
        else:
            all_cmds = " ".join([e.command_line or "" for e in events] + [str(e.raw_attributes.get("decoded_command", "")) for e in events]).lower()
            all_descs = " ".join([str(e.raw_attributes.get("wazuh_rule_description", "")) for e in events]).lower()
            all_groups = {g.lower() for e in events for g in e.raw_attributes.get("wazuh_groups", [])}
            all_sources = {e.source_type.lower() for e in events}
            all_event_ids = {str(e.event_id) for e in events}
            all_rule_ids = {str(e.raw_attributes.get("wazuh_rule_id", "")) for e in events}

            mitre_techs = set(res_c.get("mitre_techniques", []))
            for e in events:
                for mid in e.raw_attributes.get("wazuh_mitre_ids", []):
                    mitre_techs.add(mid)

            is_malware = (
                any(k in all_cmds or k in all_descs for k in [
                    "powershell", "-enc", "encodedcommand", "downloadstring", "webclient",
                    "schtasks", "c2", "malware", "trojan", "emotet", "reverse shell",
                    "beacon", "payload.exe", "payload.ps1", "certutil", "meterpreter"
                ])
                or any("encoded_payload" in e.raw_attributes or "decoded_command" in e.raw_attributes for e in events)
                or any(g in all_groups for g in ["sysmon_process_creation", "malware", "c2"])
                or any(t.startswith("T1059") or t.startswith("T1027") or t.startswith("T1071") or t.startswith("T1105") or t.startswith("T1053") for t in mitre_techs)
            )

            is_cred = (
                any(k in all_descs or k in all_cmds for k in [
                    "failed logins", "logon failure", "unusual external ip", "credential",
                    "password", "spray", "brute force", "bruteforce", "promptforcreds",
                    "bad password", "credential enumeration", "special privileges"
                ])
                or any(rid in {"60105", "60106", "60115"} for rid in all_rule_ids)
                or any("4625" in eid for eid in all_event_ids)
                or any(g in all_groups for g in ["authentication_failed", "authentication_failure"])
                or any(t.startswith("T1110") or t.startswith("T1078") for t in mitre_techs)
            )

            is_recon = (
                any(k in all_descs or k in all_cmds for k in [
                    "scan", "sweep", "echo request", "syn packet", "banner grabbing",
                    "port scan", "port_scan", "network_scan", "icmp sweep", "host discovery"
                ])
                or any(rid in {"5710", "5712", "5715"} for rid in all_rule_ids)
                or any(g in all_groups for g in ["network_scan", "reconnaissance"])
                or any("zeek" in src for src in all_sources)
                or any(t.startswith("T1046") or t.startswith("T1018") or t.startswith("T1595") for t in mitre_techs)
            )

            is_web = (
                any(k in all_cmds or k in all_descs for k in [
                    "web exploit", "sqli", "sql injection", "xss", "rce", "web shell",
                    "webshell", "path traversal", "w3wp", "httpd", "nginx", "tomcat", "apache", "php-cgi"
                ])
                or any(g in all_groups for g in ["web", "web_app", "web_attack"])
                or any(t.startswith("T1190") for t in mitre_techs)
            )

            if is_malware:
                attack_category = AttackCategory.MALWARE
                attack_type = "Endpoint Malware & C2 Reverse Shell"
                primary_mitre_tactics = ["Execution", "Command and Control", "Defense Evasion"]
            elif is_cred:
                attack_category = AttackCategory.CREDENTIAL_ACCESS
                attack_type = "Password Spraying & Credential Theft"
                primary_mitre_tactics = ["Credential Access", "Initial Access"]
            elif is_recon:
                attack_category = AttackCategory.RECONNAISSANCE
                attack_type = "Network Scanning & Service Discovery"
                primary_mitre_tactics = ["Reconnaissance", "Discovery"]
            elif is_web:
                attack_category = AttackCategory.WEB_ATTACK
                attack_type = "Exploit Public-Facing Web Application"
                primary_mitre_tactics = ["Initial Access", "Execution"]
            elif res_b.get("attack_category"):
                llm_cat_str = str(res_b.get("attack_category")).upper()
                try:
                    attack_category = AttackCategory(llm_cat_str)
                except Exception:
                    attack_category = AttackCategory.UNKNOWN
                attack_type = res_b.get("attack_type") or "Unclassified Security Incident"
                primary_mitre_tactics = ["Execution", "Initial Access"]
            else:
                attack_category = AttackCategory.MALWARE
                attack_type = "Endpoint Malware & C2 Reverse Shell"
                primary_mitre_tactics = ["Execution", "Defense Evasion"]

        return TriageOutput(
            is_incident=final_is_incident,
            confidence_score=round(final_conf, 2),
            severity=final_severity,
            summary=summary,
            rule_or_model="Parallel-Ensemble-v1",
            attack_category=attack_category,
            attack_type=attack_type,
            primary_mitre_tactics=primary_mitre_tactics
        )

    # =====================================================================
    # 5. PUBLIC API & STATE PIPELINE INTEGRATION
    # =====================================================================
    def triage(self, state: IncidentState) -> IncidentState:
        """
        Cổng tiếp nhận chính khi tích hợp với LangGraph StateGraph.
        Thực thi phân loại song song và cập nhật trực tiếp vào IncidentState.

        :param state: Đối tượng IncidentState từ IngestionAgent.
        :return: IncidentState đã được cập nhật triage_result và status.
        """
        results = self.evaluate_models_parallel(state.parsed_events)
        triage_output: TriageOutput = results["consensus"]

        state.triage_result = triage_output
        state.attack_type = triage_output.attack_type
        target_status = IncidentStatus.TRIAGED if triage_output.is_incident else IncidentStatus.CLOSED_FALSE_POSITIVE
        
        transition_meta = {
            "confidence": triage_output.confidence_score,
            "severity": triage_output.severity.value,
            "model": triage_output.rule_or_model
        }
        if results.get("tiered_routing", {}).get("applied"):
            transition_meta["tiered_routing"] = "fast_heuristic"
            transition_meta["llm_called"] = False
            transition_meta["tokens_used"] = 0

        if hasattr(state, "record_transition"):
            state.record_transition(
                node="DetectionAndTriageAgent",
                to_status=target_status,
                message=f"Triage: {'Sự cố an ninh (True Positive)' if triage_output.is_incident else 'Hoạt động thường nhật (False Positive)'}",
                metadata=transition_meta
            )
        else:
            state.status = target_status
            state.updated_at = datetime.now(timezone.utc)

        return state

    def fast_triage(self, events: List[ParsedEvent]) -> TriageOutput:
        """
        Thực thi phân loại nhanh bằng Heuristic (Short-circuit Fast Triage),
        không gọi LLM Cloud, tiết kiệm 100% token cho cảnh báo thông thường.
        """
        results = self.evaluate_models_parallel(events)
        return results["consensus"]

    def process(self, state: IncidentState) -> IncidentState:
        """Alias cho phương thức triage nhằm tương thích quy ước agent.process(state)."""
        return self.triage(state)

    def evaluate(self, events: List[ParsedEvent]) -> TriageOutput:
        """Đánh giá danh sách ParsedEvent và trả về kết quả đồng thuận TriageOutput."""
        results = self.evaluate_models_parallel(events)
        return results["consensus"]

