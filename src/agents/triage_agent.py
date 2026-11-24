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
import contextvars
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union

logger = logging.getLogger("TriageAgent")

from src.core.schemas import (
    ParsedEvent,
    TriageOutput,
    TriageLLMResult,
    SeverityLevel,
    IncidentStatus,
    AttackCategory
)
from src.core.state import IncidentState
from src.agents.prompts import TRIAGE_AGENT_SYSTEM_PROMPT
from src.agents.llm_utils import invoke_structured_llm
from src.tools.threat_intel import ThreatIntelTools
from src.core.security_guard import (
    UNTRUSTED_LOG_SECURITY_HEADER,
    detect_prompt_injection,
    wrap_untrusted_log,
    inspect_and_wrap_untrusted,
    sanitize_prompt_text,
)


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
        enable_parallel_ensemble: bool = True,
        enable_security_guard: bool = True,
        skip_llm_on_clear_patterns: Optional[bool] = None,
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
        self.enable_parallel_ensemble = bool(enable_parallel_ensemble)
        self.enable_security_guard = bool(enable_security_guard)
        self._skip_llm_explicit: bool = (skip_llm_on_clear_patterns is not None)
        if skip_llm_on_clear_patterns is None:
            self.skip_llm_on_clear_patterns = (llm_provider is None)
        else:
            self.skip_llm_on_clear_patterns = bool(skip_llm_on_clear_patterns)
        # Nạp hồ sơ huấn luyện từ Public Datasets (Mordor/OTRF) nếu tồn tại
        self.trained_profiles: Dict[str, Any] = self._load_trained_profiles()

    def set_llm_provider(self, llm_provider: Any) -> None:
        """Cập nhật LLM provider sau khởi tạo và đồng bộ cờ skip_llm_on_clear_patterns nếu caller không ép cứng."""
        self.llm_provider = llm_provider
        if not getattr(self, "_skip_llm_explicit", False):
            self.skip_llm_on_clear_patterns = (llm_provider is None)

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
    @staticmethod
    def _build_event_search_blob(evt: ParsedEvent) -> str:
        """Tạo chuỗi hợp nhất phục vụ đối chiếu heuristic nội bộ (không gồm nhãn OOD ngoài phân phối)."""
        raw_attrs = evt.raw_attributes or {}
        parts = [
            evt.command_line or "",
            str(raw_attrs.get("decoded_command") or ""),
            str(raw_attrs.get("wazuh_rule_description") or ""),
            evt.process_name or "",
            evt.process_path or "",
            str(raw_attrs.get("target_object") or ""),
            str(raw_attrs.get("share_name") or ""),
            str(raw_attrs.get("relative_target_name") or ""),
            str(raw_attrs.get("full_log") or ""),
        ]
        return " ".join(p for p in parts if p).lower()

    @staticmethod
    def _is_suspicious_external_ip(ip_str: Optional[str]) -> bool:
        """
        Kiểm tra IP công cộng đáng ngờ bên ngoài.
        Loại trừ IP private RFC1918, loopback, link-local, multicast, unspecified,
        whitelist DNS/CDN sạch (KNOWN_CLEAN_IPS) và Azure WireServer (168.63.129.16).
        Luôn đánh dấu True đối với IP nằm trong KNOWN_MALICIOUS_IPS.
        """
        if not ip_str:
            return False
        ip_val = str(ip_str).strip()
        if not ip_val:
            return False
        if ip_val in ThreatIntelTools.KNOWN_MALICIOUS_IPS:
            return True
        if ip_val in ThreatIntelTools.KNOWN_CLEAN_IPS or ip_val == "168.63.129.16":
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_val)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
                or ip_obj.is_reserved
            ):
                return False
            return True
        except ValueError:
            return False

    def _has_suspicious_or_injection_signal(self, evt: ParsedEvent) -> bool:
        """Kiểm tra dấu hiệu obfuscation, lệnh nguy hiểm, IoC bất thường hoặc Prompt Injection trên 1 event."""
        raw_attrs = evt.raw_attributes or {}
        if "encoded_payload" in raw_attrs or "decoded_command" in raw_attrs:
            return True

        cmd = (evt.command_line or "").lower()
        decoded_cmd = str(raw_attrs.get("decoded_command") or "").lower()
        combined_cmd = f"{cmd} {decoded_cmd}"

        dangerous_keywords = (
            "-enc", "encodedcommand", "downloadstring", "webclient",
            "frombase64string", "invoke-expression", "schtasks", "certutil",
            "bitsadmin", "meterpreter", "reverse shell", "trojan",
            "payload.exe", "payload.ps1", "promptforcreds", "promptforcredential",
            "sharpview", "audit log cleared", "eventlog cleared", "mimikatz",
            "ntdsutil", "vssadmin", "dumpert", "creduiprompt", "httplistener",
            "userinitmprlogonscript",
        )
        if any(kw in combined_cmd for kw in dangerous_keywords):
            return True
        if re.search(r"\biex\b", combined_cmd) or re.search(r"(?<![a-z0-9])c2(?![a-z0-9])", combined_cmd):
            return True

        proc = (evt.process_name or "").lower()
        lvl = self._safe_int(raw_attrs.get("wazuh_rule_level"), 0)
        if any(kw in proc for kw in ("powershell", "cmd.exe", "cscript", "wscript", "mshta", "rundll32")):
            if lvl >= 5 or lvl == 0:
                return True

        if self._is_suspicious_external_ip(evt.dest_ip):
            return True

        if self._is_suspicious_external_ip(evt.source_ip):
            return True

        for ioc in raw_attrs.get("preliminary_iocs", []) or []:
            if not isinstance(ioc, dict):
                continue
            if ioc.get("is_malicious") is True:
                return True
            if ioc.get("is_public") is True:
                ioc_type = str(ioc.get("type") or "").upper()
                ioc_val = str(ioc.get("value") or "").strip()
                if ioc_type != "IP" or self._is_suspicious_external_ip(ioc_val):
                    return True

        if evt.file_hash:
            return True

        groups = [str(g).strip().lower() for g in (raw_attrs.get("wazuh_groups") or []) if g]
        if any(g in groups for g in (
            "malware", "c2", "reconnaissance", "port_scan", "network_scan",
            "vulnerability_scan", "web_attack", "authentication_failed",
            "authentication_failure", "attack", "privilege_escalation", "lateral_movement"
        )):
            return True

        if raw_attrs.get("wazuh_mitre_ids"):
            return True

        if self.enable_security_guard:
            for check_val in (
                evt.command_line,
                raw_attrs.get("decoded_command"),
                raw_attrs.get("wazuh_rule_description"),
                raw_attrs.get("full_log"),
                evt.user_name,
                evt.process_name,
                evt.parent_command_line,
                raw_attrs.get("parent_command_line"),
            ):
                if check_val:
                    is_inj, _ = detect_prompt_injection(str(check_val))
                    if is_inj:
                        return True

        return False

    def _is_routine_wazuh_benign_event(self, evt: ParsedEvent) -> bool:
        """
        Xác nhận sự kiện có bằng chứng quy tắc Wazuh lành tính rõ ràng:
        - Phải có `wazuh_rule_level` là số nguyên dương trong [1, fast_triage_max_level - 1].
        - Có dấu hiệu rule thường nhật/lành tính (`60100`, `5715` mức thấp không phải scan/attack,
          hoặc level 1..4 kèm mô tả/nhóm benign hợp lệ).
        - Không chứa bất kỳ dấu hiệu tấn công, IoC bất thường hay Prompt Injection nào.
        """
        raw_attrs = evt.raw_attributes or {}
        raw_level = raw_attrs.get("wazuh_rule_level")
        if raw_level is None or isinstance(raw_level, bool):
            return False
        try:
            lvl = int(raw_level)
        except (ValueError, TypeError):
            return False
        if not (1 <= lvl < self.fast_triage_max_level):
            return False

        rule_id = str(raw_attrs.get("wazuh_rule_id") or "").strip()
        desc_lower = str(raw_attrs.get("wazuh_rule_description") or "").lower()
        groups = [str(g).strip().lower() for g in (raw_attrs.get("wazuh_groups") or []) if g]

        has_benign_signal = (
            (rule_id == "60100")
            or (
                rule_id == "5715"
                and 1 <= lvl <= 4
                and not any(t in desc_lower for t in ("scan", "probe", "grabbing", "attack"))
            )
            or (
                1 <= lvl <= 4
                and ("authentication_success" in groups or "routine" in desc_lower)
                and any(g in groups for g in (
                    "authentication_success", "routine", "windows",
                    "system", "antivirus", "dns", "sysmon", "syslog", "sshd"
                ))
            )
        )
        if not has_benign_signal:
            return False

        return not self._has_suspicious_or_injection_signal(evt)

    @staticmethod
    def _is_safe_local_evtx_logon(evt: ParsedEvent) -> bool:
        """
        Xác nhận riêng mẫu đăng nhập cục bộ EVTX-4624 an toàn (LogonType 2/7/11, không command/process,
        không dest_ip, source_ip là loopback/private/None) nhằm giữ nguyên hợp đồng Tiered Routing EVTX nội bộ.
        """
        raw_attrs = evt.raw_attributes or {}
        if str(evt.event_id or "").strip() != "EVTX-4624":
            return False
        if str(evt.source_type or "").strip() != "WindowsSecurity":
            return False
        if str(raw_attrs.get("LogonType") or "").strip() not in {"2", "7", "11"}:
            return False
        if evt.command_line or evt.process_name or evt.dest_ip is not None:
            return False
        if evt.source_ip:
            try:
                sip = ipaddress.ip_address(str(evt.source_ip).strip())
                if not (sip.is_private or sip.is_loopback):
                    return False
            except ValueError:
                return False
        return True

    def is_eligible_for_fast_triage(
        self,
        events_or_state: Union[List[ParsedEvent], ParsedEvent, IncidentState, Any]
    ) -> bool:
        """
        Kiểm tra sự kiện có đủ điều kiện đi theo luồng Phân tầng nhanh (Tiered Fast Triage) hay không.
        Khắc phục Hạn chế 4 & P0-1: Chỉ fast-path khi TẤT CẢ sự kiện đều có bằng chứng lành tính tường minh
        (Wazuh benign rule level 1..fast_triage_max_level-1 hoặc EVTX-4624 local logon an toàn),
        không có IoC/obfuscation/injection và điểm heuristic < 30.0.
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

        for evt in events:
            if not (self._is_routine_wazuh_benign_event(evt) or self._is_safe_local_evtx_logon(evt)):
                return False
            if self._has_suspicious_or_injection_signal(evt):
                return False

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
                "abstain": True,
                "confidence_score": 0.30,
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

        def _add_trigger(msg: str) -> None:
            if msg not in triggers:
                triggers.append(msg)

        for evt in events:
            raw_attrs = evt.raw_attributes or {}
            level = self._safe_int(raw_attrs.get("wazuh_rule_level"), 0)
            rule_id = str(raw_attrs.get("wazuh_rule_id", "") or "").strip()
            groups = [str(g).strip().lower() for g in (raw_attrs.get("wazuh_groups") or []) if g]
            desc = str(raw_attrs.get("wazuh_rule_description") or "")
            desc_lower = desc.lower()

            if level > max_rule_level:
                max_rule_level = level

            cmd = (evt.command_line or "").lower()
            decoded_cmd = str(raw_attrs.get("decoded_command") or "").lower()
            combined_cmd = f"{cmd} {decoded_cmd}"
            search_blob = self._build_event_search_blob(evt)
            share_str = str(raw_attrs.get("share_name") or "").lower()

            # Kiểm tra dấu hiệu lành tính Wazuh rõ ràng (Rule 60100, 5715 thường nhật hoặc level 1..4 routine)
            if self._is_routine_wazuh_benign_event(evt):
                _add_trigger(f"Quy tắc đăng nhập/hoạt động thường nhật {rule_id} (Level {level})")
                continue

            # Nếu không khớp quy tắc thường nhật Wazuh
            is_all_routine_benign = False

            # Signature 1: PowerShell Obfuscation & Download Cradle
            if "encoded_payload" in raw_attrs or "decoded_command" in raw_attrs or "-enc" in cmd or "-encodedcommand" in combined_cmd:
                threat_score += 45.0
                _add_trigger("Phát hiện PowerShell encoded command / obfuscation")

            if "downloadstring" in combined_cmd or "webclient" in combined_cmd or re.search(r"\biex\b", combined_cmd):
                threat_score += 35.0
                _add_trigger("Phát hiện PowerShell Download Cradle tải payload")

            # Signature 2: Persistence via Scheduled Task
            if "schtasks" in combined_cmd or (evt.process_name and "schtasks" in evt.process_name.lower()):
                threat_score += 30.0
                _add_trigger("Phát hiện thiết lập duy trì qua schtasks.exe")

            # Signature 3: Network Reconnaissance & Port Scanning (Rule 5710, 5712, 5715)
            if any(term in desc_lower for term in ["scan", "sweep", "echo request", "syn packet", "banner grabbing"]) or \
               any(term in groups for term in ["reconnaissance", "port_scan", "network", "network_scan", "vulnerability_scan"]):
                threat_score += 35.0
                _add_trigger(f"Hoạt động dò quét mạng/cổng (Wazuh Rule {rule_id})")

            # Signature 4: Credential Spraying & Brute Force & Unusual External IP (Rule 60105, 60106, 60115)
            if any(term in desc_lower for term in ["failed logins", "unusual external ip", "credential enumeration", "special privileges"]):
                threat_score += 35.0
                _add_trigger(f"Dấu hiệu tấn công xác thực / leo thang (Wazuh Rule {rule_id})")

            # Signature 5 (ID Mordor): Credential Dumping & AD/LSASS/Shadow Copy Abuse
            if (
                "ntdsutil" in search_blob
                or "vssadmin" in search_blob
                or ("harddiskvolumeshadowcopy" in search_blob and "ntds.dit" in search_blob)
                or ("lsass" in search_blob and "shadow copy" in search_blob)
            ):
                threat_score += 45.0
                _add_trigger("Phát hiện dấu hiệu trích xuất NTDS.dit / Shadow Copy (Credential Access)")

            if (
                "dumpert" in search_blob
                or "mimikatz" in search_blob
                or "sekurlsa" in search_blob
                or ("lsass.exe" in search_blob and any(k in search_blob for k in ("minidump", "comsvcs.dll", "targetimage:")))
            ):
                threat_score += 45.0
                _add_trigger("Phát hiện dấu hiệu trích xuất bộ nhớ LSASS (Credential Dumping)")

            if any(k in search_blob for k in ("promptforcredential", "promptforcreds", "creduiprompt", "wincredui.dll", "credui.dll")):
                threat_score += 45.0
                _add_trigger("Phát hiện kỹ thuật đánh cắp thông tin xác thực qua GUI Prompt (CredUI)")

            # Signature 6 (ID Mordor): Persistence, Service Mod, Lateral Movement, Tool Transfer & Execution
            if "bitsadmin" in search_blob:
                threat_score += 40.0
                _add_trigger("Phát hiện lạm dụng bitsadmin.exe tải tệp từ xa")

            if re.search(r"\bsc(?:\.exe)?\s+config\b.*\bbinpath\s*=", search_blob):
                threat_score += 45.0
                _add_trigger("Phát hiện chỉnh sửa đường dẫn dịch vụ Windows (sc config binPath)")

            if any(k in search_blob for k in ("userinitmprlogonscript", "currentversion\\run", "currentversion\\runonce")):
                threat_score += 40.0
                _add_trigger("Phát hiện thiết lập persistence qua Registry Run / Logon Script")

            if (
                any(k in search_blob for k in ("wsman", "wsmprovhost", "ws-management listener", "seenabledelegationprivilege"))
                or re.search(r"pipename:\s*\\lsass", search_blob)
                or re.search(r"logon type:\s*3\b.*elevated token:\s*yes", search_blob, re.DOTALL)
            ):
                threat_score += 40.0
                _add_trigger("Phát hiện hoạt động di chuyển ngang / ủy quyền đặc quyền (WSMan/WinRM/LSASS)")

            if re.search(r"\\\\[^\\\s]+\\(?:admin|c)\$", share_str) or re.search(r"\\\\[^\\\s]+\\(?:admin|c)\$", search_blob):
                threat_score += 40.0
                _add_trigger("Phát hiện truy cập chia sẻ quản trị SMB (C$/ADMIN$)")

            if any(k in search_blob for k in ("httplistener", "system.net.httplistener")) or re.search(
                r"(?:targetimage:.*powershell\.exe|appswitched.*powershell\.exe|prefetch\\powershell\.exe)",
                search_blob,
            ):
                threat_score += 35.0
                _add_trigger("Phát hiện dấu hiệu thực thi PowerShell/HttpListener bất thường")

            if any(k in search_blob for k in ("sharpview", "get-objectacl")):
                threat_score += 40.0
                _add_trigger("Phát hiện công cụ trinh sát Active Directory (SharpView)")

            # Signature 7 (ID LogHub): OpenSSH / Linux PAM Auth Failures & Apache Error Anomalies
            is_benign_session_notice = (
                "session opened" in search_blob
                or "accepted publickey" in search_blob
                or "[notice]" in search_blob
            )
            if not is_benign_session_notice:
                if any(
                    k in search_blob
                    for k in (
                        "failed password",
                        "invalid user",
                        "authentication failure",
                        "authentication error",
                        "bad username",
                        "maximum authentication attempts",
                        "too many authentication failures",
                        "possible break-in attempt",
                        "user unknown",
                    )
                ):
                    threat_score += 35.0
                    _add_trigger("Phát hiện chuỗi thất bại xác thực / brute-force SSH/PAM")

                if re.search(r"\[error\].*(?:mod_jk|workerenv in error state|child init)", search_blob):
                    threat_score += 35.0
                    _add_trigger("Phát hiện lỗi bất thường trên máy chủ web Apache/mod_jk")

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
                evt, combined_cmd, desc_lower
            )
            if matched_profile:
                if threat_score < 75.0:
                    threat_score = min(95.0, max(threat_score + profile_bonus, 75.0))
                _add_trigger(profile_reason)

        # Kết luận của Heuristic Model
        if is_all_routine_benign and threat_score == 0:
            return {
                "model": "Model-A-Heuristic",
                "is_incident": False,
                "abstain": False,
                "confidence_score": 0.90,
                "severity": SeverityLevel.LOW,
                "score": 10.0,
                "anomaly_score": 10.0,
                "reasons": list(triggers),
                "rationale": "Toàn bộ sự kiện trùng khớp với hành vi người dùng thường nhật hợp lệ (False Positive)."
            }

        if not is_all_routine_benign and threat_score == 0:
            return {
                "model": "Model-A-Heuristic",
                "is_incident": False,
                "abstain": True,
                "confidence_score": 0.30,
                "severity": SeverityLevel.LOW,
                "score": 20.0,
                "anomaly_score": 20.0,
                "reasons": list(triggers),
                "rationale": "Không khớp chữ ký tấn công hay quy tắc thường nhật Wazuh (Model A bỏ phiếu trắng / abstain)."
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
            "abstain": False,
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
    def _infer_guard_severity(
        self,
        events: List[ParsedEvent],
        underlying_severity: Optional[SeverityLevel] = None,
    ) -> Tuple[SeverityLevel, float]:
        """
        Xác định mức độ nghiêm trọng cho SecurityGuard short-circuit:
        - Luôn tối thiểu HIGH (không bao giờ hạ xuống LOW hoặc MEDIUM).
        - Nâng lên CRITICAL khi có wazuh_rule_level >= 12, underlying_severity == CRITICAL,
          hoặc có chỉ dấu mã độc/credential/exfiltration/shadow-deletion nghiêm trọng.
        """
        max_rule_level = max(
            [self._safe_int((e.raw_attributes or {}).get("wazuh_rule_level"), 0) for e in events] or [0]
        )
        has_encoded_payload = any(
            "encoded_payload" in (e.raw_attributes or {})
            or "decoded_command" in (e.raw_attributes or {})
            for e in events
        )
        combined_blob = " ".join(self._build_event_search_blob(e) for e in events)
        severe_indicators = (
            "-enc",
            "encodedcommand",
            "downloadstring",
            "mimikatz",
            "sekurlsa",
            "comsvcs.dll",
            "minidump",
            "ntdsutil",
            "ntds.dit",
            "dumpert",
            "vssadmin",
            "delete shadows",
            "exfil",
        )
        has_severe_indicator = has_encoded_payload or any(ind in combined_blob for ind in severe_indicators)

        if max_rule_level >= 12 or underlying_severity == SeverityLevel.CRITICAL or has_severe_indicator:
            return SeverityLevel.CRITICAL, 95.0
        return SeverityLevel.HIGH, 80.0

    def _scan_events_for_prompt_injection(
        self,
        events: List[ParsedEvent],
        underlying_severity: Optional[SeverityLevel] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Quét Indirect Prompt Injection trên toàn bộ trường untrusted của các sự kiện.
        Trả về kết quả Model-B-LLM-CoT-Guard nếu phát hiện; trả về None nếu sạch hoặc guard tắt.
        """
        if not self.enable_security_guard or not events:
            return None

        injection_reasons: List[str] = []
        for e in events:
            raw_attrs = e.raw_attributes or {}
            candidates = [
                e.command_line,
                raw_attrs.get("decoded_command"),
                raw_attrs.get("wazuh_rule_description"),
                raw_attrs.get("full_log"),
                e.user_name,
                e.process_name,
                e.parent_command_line,
            ]
            alt_parent_cmd = raw_attrs.get("parent_command_line")
            if alt_parent_cmd and alt_parent_cmd != e.parent_command_line:
                candidates.append(alt_parent_cmd)

            for check_text in candidates:
                if check_text:
                    is_inj, reason = detect_prompt_injection(str(check_text))
                    if is_inj:
                        injection_reasons.append(reason or "Prompt injection pattern detected")
                        break

        if not injection_reasons:
            return None

        underlying_cat, _, underlying_tactics = self._classify_attack_category_and_type(events)
        if underlying_cat in (AttackCategory.UNKNOWN, AttackCategory.BENIGN):
            underlying_cat = AttackCategory.MALWARE

        guard_severity, guard_score = self._infer_guard_severity(
            events,
            underlying_severity=underlying_severity,
        )
        guard_tactics = ["Defense Evasion", "Execution"]
        for tactic in underlying_tactics:
            if tactic not in guard_tactics:
                guard_tactics.append(tactic)

        logger.warning(f"🚨 Phát hiện Indirect Prompt Injection trong sự kiện: {'; '.join(injection_reasons)}")
        return {
            "model": "Model-B-LLM-CoT-Guard",
            "is_incident": True,
            "confidence_score": 0.99,
            "severity": guard_severity,
            "score": guard_score,
            "attack_category": underlying_cat,
            "attack_type": "Indirect Prompt Injection & Defense Evasion Attack",
            "primary_mitre_tactics": guard_tactics,
            "cot_steps": {
                "observation": f"Phát hiện mẫu lệnh thao túng mô hình AI trong log: {'; '.join(injection_reasons)}",
                "contextualization": "Kẻ tấn công cố gắng đánh lừa hệ thống Triage tự động gán nhãn False Positive / Benign.",
                "risk_scoring": (
                    f"Mức độ nguy hiểm ({guard_severity.value} - {guard_score:.1f}) "
                    f"do có chủ đích che giấu dấu vết tấn công ({underlying_cat.value})."
                ),
                "conclusion": "Xác nhận sự cố an ninh nghiêm trọng (True Positive) kết hợp hành vi phòng thủ đối kháng (Adversarial AI Attack)."
            },
            "rationale": f"Phát hiện Prompt Injection trong log: {'; '.join(injection_reasons)}",
            "llm_called": False,
            "fallback_reason": "security_guard_short_circuit",
            "provider_used": "security_guard",
            "tokens_used": 0,
        }

    def _evaluate_llm_cot(
        self,
        events: List[ParsedEvent],
        incident_state: Optional[IncidentState] = None,
    ) -> Dict[str, Any]:
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
                "rationale": "Không có sự kiện để suy luận CoT.",
                "llm_called": False,
                "fallback_reason": "no_events",
                "provider_used": "deterministic",
                "tokens_used": 0,
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
            raw_attrs = evt.raw_attributes or {}
            lvl = self._safe_int(raw_attrs.get("wazuh_rule_level"), 0)
            if lvl > max_level:
                max_level = lvl

            rule_id = str(raw_attrs.get("wazuh_rule_id", "") or "").strip()
            desc = str(raw_attrs.get("wazuh_rule_description") or "")
            desc_lower = desc.lower()
            cmd_lower = (evt.command_line or "").lower()

            if self._is_routine_wazuh_benign_event(evt) or self._is_safe_local_evtx_logon(evt):
                is_routine_session = True
                observations.append(f"Ghi nhận phiên đăng nhập/hoạt động hợp lệ của tài khoản {evt.user_name} trên máy trạm {evt.host_name}.")

            if evt.process_name and "powershell" in evt.process_name.lower():
                has_powershell = True
                observations.append(f"Tiến trình powershell.exe thực thi lệnh trên host {evt.host_name}.")

            if "decoded_command" in raw_attrs or "encoded_payload" in raw_attrs or "-enc" in cmd_lower:
                has_decoded_cmd = True
                observations.append(f"Lệnh PowerShell mã hóa/obfuscation: {raw_attrs.get('decoded_command') or evt.command_line}")

            if self._is_suspicious_external_ip(evt.dest_ip):
                has_external_conn = True
                observations.append(f"Kết nối ra địa chỉ IP công cộng ngoại lai: {evt.dest_ip}:{evt.dest_port}")

            if any(term in desc_lower for term in ["scan", "sweep", "icmp", "syn packet", "banner grabbing"]):
                has_scan = True
                observations.append(f"Phát hiện dấu hiệu rà quét mạng: {desc}")

            if any(term in desc_lower for term in ["logon failure", "failed logins", "unusual external ip", "credential"]):
                has_auth_anomaly = True
                observations.append(f"Bất thường trong xác thực: {desc}")

        # Tham chiếu hồ sơ/heuristic nội bộ cho offline fallback (không chặn live LLM)
        has_anomaly_flag = (
            has_powershell
            or has_decoded_cmd
            or has_external_conn
            or has_scan
            or has_auth_anomaly
            or max_level >= 7
        )
        heuristic_probe: Optional[Dict[str, Any]] = None
        if not (is_routine_session and not has_anomaly_flag):
            heuristic_probe = self._evaluate_heuristic(events)
            if heuristic_probe.get("is_incident") and heuristic_probe.get("reasons"):
                observations.extend(heuristic_probe["reasons"][:3])

        obs_summary = " | ".join(observations) if observations else "Quan sát log hệ thống bình thường."

        # BƯỚC 2: CONTEXTUALIZATION (Phân tích bối cảnh)
        context_notes = []
        if is_routine_session and not has_anomaly_flag:
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
            if heuristic_probe and heuristic_probe.get("is_incident"):
                context_notes.append(heuristic_probe.get("rationale", ""))
            if not context_notes:
                context_notes.append("Không có chỉ báo chữ ký tấn công hoặc ngoại lệ rõ ràng trong chế độ fallback ngoại tuyến.")

        ctx_summary = " ".join(context_notes)

        # BƯỚC 3: RISK SCORING (Đánh giá rủi ro)
        # Theo prompt: "Nếu wazuh_rule_level >= 10, mặc định rủi ro ở mức HIGH hoặc CRITICAL trừ khi phát hiện dấu hiệu rõ ràng của False Positive."
        heuristic_is_threat = bool(heuristic_probe and heuristic_probe.get("is_incident"))
        if is_routine_session and not has_anomaly_flag and not heuristic_is_threat:
            risk_score = 10.0
            sev = SeverityLevel.LOW
            is_inc = False
            conf = 0.95
            risk_rationale = "Điểm rủi ro: 10/100 (LOW). Hoạt động thường nhật, không có dấu hiệu xâm phạm."
        elif max_level >= 12 or (has_powershell and has_decoded_cmd and has_external_conn):
            is_inc = True
            risk_score = 95.0
            sev = SeverityLevel.CRITICAL
            conf = 0.95
            risk_rationale = f"Điểm rủi ro: 95/100 (CRITICAL). Rule Level {max_level} kết hợp mã độc Base64 C2 nguy hiểm cao độ."
        elif max_level >= 10 or has_auth_anomaly:
            is_inc = True
            risk_score = 80.0
            sev = SeverityLevel.HIGH
            conf = 0.95
            risk_rationale = f"Điểm rủi ro: 80/100 (HIGH). Rule Level {max_level} cho thấy hành vi xâm nhập hoặc tấn công tài khoản nghiêm trọng."
        elif max_level >= 7 or has_scan:
            is_inc = True
            risk_score = 65.0
            sev = SeverityLevel.MEDIUM
            conf = 0.85
            risk_rationale = f"Điểm rủi ro: 65/100 (MEDIUM/HIGH). Dò quét mạng diện rộng có chủ đích."
        elif has_powershell or has_decoded_cmd or has_external_conn or heuristic_is_threat:
            is_inc = True
            h_score = float(heuristic_probe.get("score", 50.0) or 50.0) if heuristic_probe else 50.0
            risk_score = max(50.0, min(95.0, h_score))
            if risk_score >= 80.0:
                sev = SeverityLevel.CRITICAL
                conf = 0.95
            elif risk_score >= 60.0:
                sev = SeverityLevel.HIGH
                conf = 0.85
            else:
                sev = SeverityLevel.MEDIUM
                conf = 0.85
            risk_rationale = f"Điểm rủi ro: {risk_score:.0f}/100 ({sev.value}). Ghi nhận dấu hiệu bất thường hoặc khớp mẫu hành vi mối đe dọa."
        else:
            # P0-2: Neutral / unseen fallback khi offline không có bất kỳ cờ tấn công hay hồ sơ threat nào
            is_inc = False
            risk_score = 15.0
            sev = SeverityLevel.LOW
            conf = 0.60
            risk_rationale = "Điểm rủi ro: 15/100 (LOW). Không ghi nhận chỉ dấu tấn công hay bất thường rõ ràng (fallback độ tin cậy thấp)."

        # BƯỚC 4: CONCLUSION (Kết luận)
        conclusion_text = f"Kết luận CoT: Xác nhận {'SỰ CỐ AN NINH (True Positive)' if is_inc else 'HOẠT ĐỘNG THƯỜNG NHẬT (False Positive)'} với độ tin cậy {conf*100:.0f}%, mức độ {sev.value}."

        if is_inc:
            det_cat, det_type, det_tactics = self._classify_attack_category_and_type(events)
        else:
            det_cat = AttackCategory.BENIGN
            det_type = "Normal Administrative Activity (Benign)"
            det_tactics = []

        fast_result: Dict[str, Any] = {
            "model": "Model-B-LLM-CoT",
            "is_incident": is_inc,
            "confidence_score": conf,
            "severity": sev,
            "score": risk_score,
            "attack_category": det_cat,
            "attack_type": det_type,
            "primary_mitre_tactics": det_tactics,
            "cot_steps": {
                "observation": obs_summary,
                "contextualization": ctx_summary,
                "risk_scoring": risk_rationale,
                "conclusion": conclusion_text
            },
            "rationale": f"[CoT 4-Step Analysis] {conclusion_text} {risk_rationale}",
            "llm_called": False,
            "fallback_reason": None,
            "provider_used": "deterministic",
            "tokens_used": 0,
        }

        # TIERED ROUTING: Nếu alert đủ điều kiện fast triage, tuyệt đối không gọi LLM Cloud (tiết kiệm 100% token)
        if self.enable_tiered_routing and self.is_eligible_for_fast_triage(events):
            fast_result["fallback_reason"] = "tiered_fast_heuristic"
            return fast_result

        # SecurityGuard kiểm tra Indirect Prompt Injection trước khi quyết định skip/gọi LLM
        guard_result = self._scan_events_for_prompt_injection(events, underlying_severity=sev)
        if guard_result is not None:
            return guard_result

        # UPGRADE: Nếu sự kiện không thuộc các mẫu rõ ràng (Unfamiliar/OOD Event) hoặc caller bật LLM cho clear patterns,
        # kích hoạt phân tích ngữ nghĩa sâu từ HybridLLMProvider.
        is_clear_pattern = (
            (is_routine_session and not (has_powershell or has_decoded_cmd or has_external_conn or has_scan or has_auth_anomaly))
            or (has_powershell and has_decoded_cmd and has_external_conn)
            or (has_auth_anomaly and max_level >= 10)
            or (has_scan and max_level >= 7)
        )

        if not self.llm_enabled:
            fast_result["fallback_reason"] = "llm_disabled"
            return fast_result

        effective_skip_clear = (
            self.skip_llm_on_clear_patterns
            if (getattr(self, "_skip_llm_explicit", False) or self.llm_provider is None)
            else False
        )
        if is_clear_pattern and effective_skip_clear:
            fast_result["fallback_reason"] = "clear_pattern_skipped"
            return fast_result

        llm_result = self._call_llm_for_triage(events, fast_result, incident_state=incident_state)
        if llm_result is not None:
            return llm_result

        if not fast_result.get("fallback_reason"):
            fast_result["fallback_reason"] = "llm_fallback_deterministic"
        return fast_result

    def _call_llm_for_triage(
        self,
        events: List[ParsedEvent],
        heuristic_context: Dict[str, Any],
        incident_state: Optional[IncidentState] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        UPGRADE: Gọi LLM structured output (schema TriageLLMResult, fast tier) để phân tích
        sự kiện bảo mật bằng suy luận CoT 4 bước với SecurityGuardrails.
        """
        if not self.llm_enabled:
            heuristic_context["fallback_reason"] = "llm_disabled"
            return None

        try:
            # 1. Quét Indirect Prompt Injection trên toàn bộ sự kiện đầu vào (khi bật guard)
            guard_result = self._scan_events_for_prompt_injection(
                events,
                underlying_severity=heuristic_context.get("severity"),
            )
            if guard_result is not None:
                return guard_result

            # Lazy import HybridLLMProvider nếu chưa được truyền vào
            if self.llm_provider is None:
                from src.copilot.llm_provider import HybridLLMProvider
                self.llm_provider = HybridLLMProvider()

            def _clean_prompt_field(raw_val: Any, max_len: int) -> str:
                txt = self._sanitize_for_prompt(raw_val, max_len=max_len)
                if self.enable_security_guard and txt != "N/A":
                    txt = sanitize_prompt_text(txt, max_len=max_len + 40)
                    txt = re.sub(r"[\r\n\t]+", " ", txt).strip() or "N/A"
                return txt

            def _wrap_compact(raw_val: Any, max_len: int) -> str:
                if raw_val is None:
                    return "N/A"
                if self.enable_security_guard:
                    cleaned = self._sanitize_for_prompt(raw_val, max_len=max_len)
                    if not cleaned or cleaned == "N/A":
                        return "N/A"
                    return wrap_untrusted_log(cleaned, max_len=max_len + 50, include_notice=False)
                raw_s = str(raw_val)
                return raw_s[:max_len] if raw_s.strip() else "N/A"

            event_summaries = []
            for i, e in enumerate(events[:10], 1):
                raw_attrs = e.raw_attributes or {}
                rule_lvl = _clean_prompt_field(raw_attrs.get("wazuh_rule_level", "N/A"), max_len=32)
                raw_groups = raw_attrs.get("wazuh_groups", [])
                if isinstance(raw_groups, (list, tuple, set)):
                    groups = [
                        _clean_prompt_field(g, max_len=64)
                        for g in raw_groups
                        if g is not None and str(g).strip()
                    ]
                else:
                    groups = [_clean_prompt_field(raw_groups, max_len=120)] if raw_groups else []

                raw_mitre = raw_attrs.get("wazuh_mitre_ids", [])
                if isinstance(raw_mitre, (list, tuple, set)):
                    mitre = [
                        _clean_prompt_field(m, max_len=64)
                        for m in raw_mitre
                        if m is not None and str(m).strip()
                    ]
                else:
                    mitre = [_clean_prompt_field(raw_mitre, max_len=120)] if raw_mitre else []

                src_type = _clean_prompt_field(e.source_type, max_len=100)
                evt_id = _clean_prompt_field(e.event_id, max_len=100)
                host_name = _clean_prompt_field(e.host_name or "N/A", max_len=100)
                user_name = _clean_prompt_field(e.user_name or "N/A", max_len=100)
                proc_name = _clean_prompt_field(e.process_name or "N/A", max_len=150)
                proc_path = _clean_prompt_field(e.process_path or "N/A", max_len=200)
                parent_proc = _clean_prompt_field(e.parent_process or "N/A", max_len=150)
                src_ip = _clean_prompt_field(e.source_ip, max_len=64) if e.source_ip is not None else "None"
                dst_ip = _clean_prompt_field(e.dest_ip, max_len=64) if e.dest_ip is not None else "None"

                raw_cmd = e.command_line
                raw_decoded = raw_attrs.get("decoded_command")
                raw_rule_desc = raw_attrs.get("wazuh_rule_description")
                raw_parent_cmd = e.parent_command_line or raw_attrs.get("parent_command_line")
                raw_full_log = raw_attrs.get("full_log")

                cmd_line = _wrap_compact(raw_cmd, max_len=300)
                decoded_cmd_txt = _wrap_compact(raw_decoded, max_len=300)
                rule_desc = _wrap_compact(raw_rule_desc, max_len=250)
                parent_cmd_txt = _wrap_compact(raw_parent_cmd, max_len=250)
                full_log_txt = _wrap_compact(raw_full_log, max_len=250)

                summary_parts = [
                    f"Event #{i}: Source={src_type}, EventID={evt_id}",
                    f"Host={host_name}, User={user_name}",
                    f"Process={proc_name} (Path: {proc_path})",
                    f"CommandLine={cmd_line}",
                    f"DecodedCommand={decoded_cmd_txt}",
                    f"ParentProcess={parent_proc} (ParentCommandLine={parent_cmd_txt})",
                    f"Net: {src_ip}:{e.source_port} -> {dst_ip}:{e.dest_port}",
                    f"Rule: Level={rule_lvl}, Desc={rule_desc}, Groups={groups}, MITRE={mitre}",
                    f"FullLog={full_log_txt}",
                ]
                event_summaries.append(" | ".join(summary_parts))

            events_text = "\n".join(event_summaries)
            security_header = f"{UNTRUSTED_LOG_SECURITY_HEADER}\n\n" if self.enable_security_guard else ""

            prompt = (
                f"Bạn là chuyên viên SOC Tier 1 cao cấp. Hãy thẩm định các sự kiện an ninh mạng sau:\n\n"
                f"{security_header}"
                f"{events_text}\n\n"
                f"Thực hiện suy luận Chain-of-Thought (CoT) 4 bước:\n"
                f"1. Observation: Liệt kê các hành vi, tiến trình, câu lệnh giải mã (DecodedCommand), kết nối mạng bất thường.\n"
                f"2. Contextualization: Đánh giá bối cảnh quản trị hay dấu hiệu xâm nhập.\n"
                f"3. Risk Scoring: Chấm điểm rủi ro từ 0 đến 100 và xác định mức (LOW, MEDIUM, HIGH, CRITICAL).\n"
                f"4. Conclusion: Kết luận is_incident (true/false), phân loại loại tấn công (attack_category: MALWARE, CREDENTIAL_ACCESS, RECONNAISSANCE, WEB_ATTACK, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, BENIGN, UNKNOWN), attack_type và primary_mitre_tactics.\n\n"
                f"HÃY TRẢ VỀ DUY NHẤT MỘT ĐỐI TƯỢNG JSON theo schema TriageLLMResult:\n"
                f"{{\n"
                f'  "is_incident": true,\n'
                f'  "confidence_score": 0.95,\n'
                f'  "severity": "HIGH",\n'
                f'  "score": 80.0,\n'
                f'  "attack_category": "MALWARE",\n'
                f'  "attack_type": "Tên loại tấn công",\n'
                f'  "primary_mitre_tactics": ["Execution", "Defense Evasion"],\n'
                f'  "cot_steps": {{\n'
                f'    "observation": "...",\n'
                f'    "contextualization": "...",\n'
                f'    "risk_scoring": "...",\n'
                f'    "conclusion": "..."\n'
                f'  }},\n'
                f'  "rationale": "Tóm tắt lý do kết luận"\n'
                f"}}"
            )

            llm_obj, used_real_llm, info = invoke_structured_llm(
                self.llm_provider,
                prompt,
                TriageLLMResult,
                system_prompt=self.system_prompt,
                incident_state=incident_state,
                model_tier="fast",
                temperature=0.1,
                max_tokens=1500,
                agent_name="TriageAgent",
            )

            if not used_real_llm:
                last_tel = getattr(self.llm_provider, "last_telemetry", None)
                fb_reason = (
                    info
                    or (getattr(last_tel, "fallback_reason", None) if last_tel else None)
                    or f"provider_{getattr(self.llm_provider, 'last_used_provider', None) or 'deterministic'}"
                )
                heuristic_context["llm_called"] = False
                heuristic_context["fallback_reason"] = str(fb_reason)
                heuristic_context["provider_used"] = str(
                    getattr(self.llm_provider, "last_used_provider", None) or "deterministic"
                )
                heuristic_context["tokens_used"] = 0
                return None

            last_tel = getattr(self.llm_provider, "last_telemetry", None)
            provider_used = (
                getattr(self.llm_provider, "last_used_provider", None)
                or (getattr(last_tel, "provider_used", None) if last_tel else None)
                or "llm"
            )
            tokens_used = int(getattr(last_tel, "total_tokens", 0) or 0) if last_tel else 0

            if isinstance(llm_obj, TriageLLMResult):
                cot_dict = (
                    llm_obj.cot_steps.model_dump()
                    if hasattr(llm_obj.cot_steps, "model_dump")
                    else dict(llm_obj.cot_steps)
                )
                return {
                    "model": "Model-B-LLM-CoT",
                    "is_incident": bool(llm_obj.is_incident),
                    "confidence_score": max(0.0, min(1.0, float(llm_obj.confidence_score))),
                    "severity": llm_obj.severity,
                    "score": max(0.0, min(100.0, float(llm_obj.score))),
                    "attack_category": llm_obj.attack_category,
                    "attack_type": llm_obj.attack_type,
                    "primary_mitre_tactics": list(llm_obj.primary_mitre_tactics or []),
                    "cot_steps": cot_dict,
                    "rationale": str(llm_obj.rationale or cot_dict.get("conclusion", "Phân tích suy luận từ LLM.")),
                    "llm_called": True,
                    "fallback_reason": None,
                    "provider_used": str(provider_used),
                    "tokens_used": tokens_used,
                }

            if llm_obj is None and isinstance(info, str) and info.strip():
                json_text = info.strip()
                if "```" in json_text:
                    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", json_text, re.DOTALL)
                    if m:
                        json_text = m.group(1)

                parsed = json.loads(json_text)
                if not isinstance(parsed, dict) or "is_incident" not in parsed:
                    heuristic_context["llm_called"] = False
                    heuristic_context["fallback_reason"] = "invalid_llm_json"
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

                raw_cat = parsed.get("attack_category")
                parsed_cat: Optional[AttackCategory] = None
                if raw_cat:
                    try:
                        parsed_cat = AttackCategory(str(raw_cat).strip().upper())
                    except Exception:
                        parsed_cat = None

                tactics = parsed.get("primary_mitre_tactics") or []
                if not isinstance(tactics, list):
                    tactics = []

                return {
                    "model": "Model-B-LLM-CoT",
                    "is_incident": bool(parsed.get("is_incident", False)),
                    "confidence_score": clamped_conf,
                    "severity": severity,
                    "score": clamped_score,
                    "attack_category": parsed_cat,
                    "attack_type": parsed.get("attack_type"),
                    "primary_mitre_tactics": [str(t) for t in tactics if t],
                    "cot_steps": parsed.get("cot_steps", {}),
                    "rationale": str(
                        parsed.get("rationale")
                        or (parsed.get("cot_steps", {}) if isinstance(parsed.get("cot_steps"), dict) else {}).get("conclusion", "Phân tích suy luận từ LLM.")
                    ),
                    "llm_called": True,
                    "fallback_reason": None,
                    "provider_used": str(provider_used),
                    "tokens_used": tokens_used,
                }

            heuristic_context["llm_called"] = False
            heuristic_context["fallback_reason"] = "empty_llm_response"
            return None
        except Exception as ex:
            logger.debug(f"[TriageAgent] LLM analysis fallback: {ex}")
            heuristic_context["llm_called"] = False
            heuristic_context["fallback_reason"] = f"error:{type(ex).__name__}"
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
                "abstain": True,
                "confidence_score": 0.30,
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

            # Tra cứu từ khóa kỹ thuật nếu có lệnh (tránh false match substring 'c2' trong hex như 0xc28)
            cmd_full = f"{evt.command_line or ''} {evt.raw_attributes.get('decoded_command', '')}"
            if cmd_full.strip():
                cmd_full_lower = cmd_full.lower()
                matches = ThreatIntelTools.match_mitre_technique(cmd_full)
                for m in matches:
                    mid = m.get("mitre_id")
                    if (
                        mid == "T1071.001"
                        and "beacon" not in cmd_full_lower
                        and not re.search(r"(?<![a-z0-9])c2(?![a-z0-9])", cmd_full_lower)
                    ):
                        continue
                    mitre_ids.add(mid)

            # Kiểm tra IoC từ prelim IoCs hoặc IP kết nối
            prelim_iocs = evt.raw_attributes.get("preliminary_iocs", [])
            for item in prelim_iocs:
                if item.get("type") == "IP" and item.get("is_public"):
                    ip_val = str(item.get("value") or "").strip()
                    if not ip_val:
                        continue
                    ioc_res = ThreatIntelTools.lookup_ip(ip_val)
                    if ioc_res.is_malicious:
                        malicious_iocs.append(ioc_res)
                        suspicious_public_ips.add(ip_val)
                    elif ip_val not in ThreatIntelTools.KNOWN_CLEAN_IPS and ip_val != "168.63.129.16":
                        suspicious_public_ips.add(ip_val)

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

        # Nếu không có kỹ thuật MITRE nào và không có IP ngoại lai -> Abstain với độ tin cậy thấp
        if not mitre_ids and not suspicious_public_ips:
            return {
                "model": "Model-C-MITRE-IoC",
                "is_incident": False,
                "abstain": True,
                "confidence_score": 0.30,
                "severity": SeverityLevel.LOW,
                "score": 5.0,
                "mitre_techniques": [],
                "rationale": "Không phát hiện kỹ thuật MITRE ATT&CK hoặc IoC độc hại nào liên quan (Model C bỏ phiếu trắng / abstain)."
            }

        normalized_score = min(100.0, max(20.0, score))
        is_incident = normalized_score >= 25.0

        if normalized_score >= 80.0 or any(m in high_risk_techniques for m in mitre_ids):
            sev = SeverityLevel.CRITICAL if len(matched_high) >= 2 or malicious_iocs else SeverityLevel.HIGH
        elif normalized_score >= 40.0:
            sev = SeverityLevel.MEDIUM
        else:
            sev = SeverityLevel.LOW

        if is_incident:
            confidence = 0.92 if malicious_iocs or len(matched_high) >= 2 else 0.85
            abstain = False
        else:
            confidence = 0.35
            abstain = True

        clean_mitre_ids = sorted([str(m).strip() for m in mitre_ids if m and str(m).strip()])
        rationale = f"MITRE phát hiện {len(clean_mitre_ids)} kỹ thuật ({', '.join(clean_mitre_ids)}). "
        if malicious_iocs:
            rationale += f"Xác nhận {len(malicious_iocs)} IoC độc hại từ CTI: {[i.value for i in malicious_iocs]}."
        elif suspicious_public_ips:
            rationale += f"Ghi nhận {len(suspicious_public_ips)} IP ngoại lai: {list(suspicious_public_ips)}."

        return {
            "model": "Model-C-MITRE-IoC",
            "is_incident": is_incident,
            "abstain": abstain,
            "confidence_score": confidence,
            "severity": sev,
            "score": normalized_score,
            "mitre_techniques": sorted(list(mitre_ids)),
            "rationale": rationale
        }

    # =====================================================================
    # 4. PARALLEL ENSEMBLE EXECUTION & CONSENSUS ENGINE
    # =====================================================================
    @staticmethod
    def _parse_attack_category(value: Any) -> Optional[AttackCategory]:
        """Chuyển đổi giá trị bất kỳ sang AttackCategory hợp lệ nếu có."""
        if isinstance(value, AttackCategory):
            return value
        if not value:
            return None
        try:
            return AttackCategory(str(value).strip().upper())
        except Exception:
            return None

    @staticmethod
    def _infer_tactics_from_mitre(mitre_techs: set) -> List[str]:
        """Suy luận chiến thuật MITRE bổ sung từ tập mã kỹ thuật của Model C / Wazuh."""
        tactics: List[str] = []

        def _add(tactic: str) -> None:
            if tactic not in tactics:
                tactics.append(tactic)

        for tid in sorted(str(m).upper() for m in mitre_techs if m):
            if tid.startswith("T1190") or tid.startswith("T1566") or tid.startswith("T1078"):
                _add("Initial Access")
            if tid.startswith("T1059") or tid.startswith("T1204"):
                _add("Execution")
            if tid.startswith("T1053") or tid.startswith("T1547") or tid.startswith("T1505") or tid.startswith("T1197"):
                _add("Persistence")
            if tid.startswith("T1548") or tid.startswith("T1134") or tid.startswith("T1068"):
                _add("Privilege Escalation")
            if tid.startswith("T1027") or tid.startswith("T1218") or tid.startswith("T1112"):
                _add("Defense Evasion")
            if tid.startswith("T1110") or tid.startswith("T1003") or tid.startswith("T1555"):
                _add("Credential Access")
            if tid.startswith("T1046") or tid.startswith("T1018") or tid.startswith("T1087") or tid.startswith("T1033"):
                _add("Discovery")
            if tid.startswith("T1595"):
                _add("Reconnaissance")
            if tid.startswith("T1021") or tid.startswith("T1550") or tid.startswith("T1570"):
                _add("Lateral Movement")
            if tid.startswith("T1071") or tid.startswith("T1105"):
                _add("Command and Control")
            if tid.startswith("T1486") or tid.startswith("T1490"):
                _add("Impact")
        return tactics

    def _classify_attack_category_and_type(
        self,
        events: List[ParsedEvent],
        mitre_techs: Optional[set] = None,
    ) -> Tuple[AttackCategory, str, List[str]]:
        """
        Bộ phân loại xác định (deterministic) dùng chung để suy luận
        `(attack_category, attack_type, primary_mitre_tactics)` từ bằng chứng sự kiện & MITRE IDs.
        """
        resolved_mitre: set = set(mitre_techs or set())
        for e in events:
            for mid in (e.raw_attributes or {}).get("wazuh_mitre_ids", []) or []:
                if mid:
                    resolved_mitre.add(str(mid).strip())

        all_cmds = " ".join([self._build_event_search_blob(e) for e in events]).lower()
        all_descs = " ".join(
            [str((e.raw_attributes or {}).get("wazuh_rule_description", "")) for e in events]
        ).lower()
        all_groups = {
            str(g).lower()
            for e in events
            for g in ((e.raw_attributes or {}).get("wazuh_groups", []) or [])
            if g
        }
        all_sources = {(e.source_type or "").lower() for e in events}
        all_event_ids = {str(e.event_id) for e in events}
        all_rule_ids = {str((e.raw_attributes or {}).get("wazuh_rule_id", "")) for e in events}

        combined_cmd_desc = f"{all_cmds} {all_descs}"

        is_web = (
            any(k in combined_cmd_desc for k in [
                "web exploit", "sql injection", "web shell",
                "webshell", "path traversal", "w3wp", "httpd", "nginx",
                "tomcat", "apache", "php-cgi", "mod_jk", "workerenv in error state"
            ])
            or bool(re.search(r"\b(?:sqli|xss|rce)\b", combined_cmd_desc))
            or any(g in all_groups for g in ["web", "web_app", "web_attack"])
            or any(t.startswith("T1190") for t in resolved_mitre)
        )

        is_cred = (
            any(k in combined_cmd_desc for k in [
                "failed logins", "logon failure", "unusual external ip", "credential",
                "password", "spray", "brute force", "bruteforce", "promptforcreds",
                "promptforcredential", "creduiprompt", "wincredui.dll", "credui.dll",
                "bad password", "credential enumeration", "special privileges",
                "mimikatz", "dumpert", "sekurlsa", "sam dump", "ntds.dit",
                "ntdsutil", "harddiskvolumeshadowcopy", "kerberoast",
                "failed password", "invalid user", "authentication failure",
                "authentication error", "possible break-in attempt",
                "user unknown", "bad username", "comsvcs.dll", "minidump"
            ])
            or any(rid in {"60105", "60106", "60115"} for rid in all_rule_ids)
            or any("4625" in eid for eid in all_event_ids)
            or any(g in all_groups for g in ["authentication_failed", "authentication_failure"])
            or any(
                t.startswith("T1110") or t.startswith("T1078") or t.startswith("T1003") or t.startswith("T1056")
                for t in resolved_mitre
            )
        )

        is_privesc = (
            any(k in combined_cmd_desc for k in [
                "uac bypass", "fodhelper", "eventvwr", "sudo ", "suid", "setuid",
                "getsystem", "token impersonation", "juicypotato",
                "printspoofer", "privilege escalation", "elevate privileges",
                "userinitmprlogonscript", "currentversion\\run", "binpath=", "t1543.003",
                "__eventfilter", "root\\subscription", "commandlineeventconsumer",
            ])
            or bool(re.search(r"\bseimpersonate\b", combined_cmd_desc))
            or bool(re.search(r"\bsc(?:\.exe)?\s+config\b", combined_cmd_desc))
            or any(
                t.startswith("T1548") or t.startswith("T1134") or t.startswith("T1068")
                or t.startswith("T1543") or t.startswith("T1037") or t.startswith("T1547")
                or t.startswith("T1546")
                for t in resolved_mitre
            )
            or ("privilege_escalation" in all_groups and not is_cred)
        )

        is_lateral = (
            any(k in combined_cmd_desc for k in [
                "psexec", "wmiexec", "smbexec", "winrm", "wsmprovhost",
                "pass-the-hash", "pass the hash", "overpass", "lateral movement",
                "remote desktop", "rdp hijack", "dcom", "seenabledelegationprivilege"
            ])
            or ("wsman" in combined_cmd_desc and "bitsadmin" not in combined_cmd_desc)
            or bool(re.search(r"pipename:\s*\\lsass", combined_cmd_desc))
            or bool(re.search(r"\\\\[^\\\s]+\\(?:admin|c)\$", combined_cmd_desc))
            or any(
                t.startswith("T1021") or t.startswith("T1550") or t.startswith("T1570")
                for t in resolved_mitre
            )
            or any(g in all_groups for g in ["lateral_movement"])
        )

        is_recon = (
            any(k in combined_cmd_desc for k in [
                "sweep", "echo request", "syn packet", "banner grabbing",
                "port scan", "port_scan", "network_scan", "icmp sweep",
                "host discovery", "sharpview", "get-objectacl", "domain admins"
            ])
            or bool(re.search(r"\bscan(?:ning)?\b", combined_cmd_desc))
            or any(rid in {"5710", "5712", "5715"} for rid in all_rule_ids)
            or any(g in all_groups for g in ["network_scan", "reconnaissance"])
            or any("zeek" in src for src in all_sources)
            or any(
                t.startswith("T1046") or t.startswith("T1018") or t.startswith("T1595") or t.startswith("T1087")
                for t in resolved_mitre
            )
        )

        is_malware = (
            any(k in combined_cmd_desc for k in [
                "powershell", "-enc", "encodedcommand", "downloadstring", "webclient",
                "schtasks", "malware", "trojan", "emotet", "reverse shell",
                "beacon", "payload.exe", "payload.ps1", "certutil", "meterpreter",
                "bitsadmin", "httplistener", "regsvr32", "vssadmin", "mshta", "msbuild",
            ])
            or bool(re.search(r"(?<![a-z0-9])c2(?![a-z0-9])", combined_cmd_desc))
            or any(
                "encoded_payload" in (e.raw_attributes or {}) or "decoded_command" in (e.raw_attributes or {})
                for e in events
            )
            or any(g in all_groups for g in ["malware", "c2"])
            or any(
                t.startswith("T1059") or t.startswith("T1027") or t.startswith("T1071")
                or t.startswith("T1105") or t.startswith("T1053") or t.startswith("T1197")
                for t in resolved_mitre
            )
        )

        if is_web:
            return (
                AttackCategory.WEB_ATTACK,
                "Exploit Public-Facing Web Application",
                ["Initial Access", "Execution"],
            )
        if is_privesc:
            return (
                AttackCategory.PRIVILEGE_ESCALATION,
                "Privilege Escalation & Token Abuse",
                ["Privilege Escalation"],
            )
        if is_lateral:
            return (
                AttackCategory.LATERAL_MOVEMENT,
                "Lateral Movement & Remote Execution",
                ["Lateral Movement"],
            )
        if is_cred:
            return (
                AttackCategory.CREDENTIAL_ACCESS,
                "Password Spraying & Credential Theft",
                ["Credential Access", "Initial Access"],
            )
        if is_recon:
            return (
                AttackCategory.RECONNAISSANCE,
                "Network Scanning & Service Discovery",
                ["Reconnaissance", "Discovery"],
            )
        if is_malware:
            return (
                AttackCategory.MALWARE,
                "Endpoint Malware & C2 Reverse Shell",
                ["Execution", "Command and Control", "Defense Evasion"],
            )
        return (
            AttackCategory.UNKNOWN,
            "Unclassified Security Incident",
            self._infer_tactics_from_mitre(resolved_mitre),
        )

    def _build_single_model_consensus(self, res_b: Dict[str, Any], events: List[ParsedEvent]) -> TriageOutput:
        """Tạo TriageOutput trực tiếp từ Model B khi `enable_parallel_ensemble=False`."""
        is_guard = res_b.get("model") == "Model-B-LLM-CoT-Guard"
        is_incident = True if is_guard else bool(res_b.get("is_incident", False))
        conf = round(max(0.0, min(1.0, float(res_b.get("confidence_score", 0.5)))), 2)
        sev = res_b.get("severity")
        if not isinstance(sev, SeverityLevel):
            try:
                sev = SeverityLevel(str(sev or "MEDIUM").upper())
            except Exception:
                sev = SeverityLevel.MEDIUM if is_incident else SeverityLevel.LOW

        if is_guard:
            inferred_cat, _, inferred_tactics = self._classify_attack_category_and_type(events)
            guard_cat = self._parse_attack_category(res_b.get("attack_category"))
            if inferred_cat not in (AttackCategory.UNKNOWN, AttackCategory.BENIGN):
                attack_category = inferred_cat
            elif guard_cat not in (None, AttackCategory.UNKNOWN, AttackCategory.BENIGN):
                attack_category = guard_cat
            else:
                attack_category = AttackCategory.MALWARE

            guard_sev, _ = self._infer_guard_severity(events, underlying_severity=sev)
            sev = SeverityLevel.CRITICAL if (sev == SeverityLevel.CRITICAL or guard_sev == SeverityLevel.CRITICAL) else SeverityLevel.HIGH
            attack_type = "Indirect Prompt Injection & Defense Evasion Attack"
            primary_mitre_tactics = ["Defense Evasion", "Execution"]
            for t in inferred_tactics:
                if t not in primary_mitre_tactics:
                    primary_mitre_tactics.append(t)
        elif not is_incident:
            sev = SeverityLevel.LOW
            attack_category = AttackCategory.BENIGN
            attack_type = res_b.get("attack_type") or "Normal Administrative Activity (Benign)"
            primary_mitre_tactics = []
        else:
            parsed_cat = self._parse_attack_category(res_b.get("attack_category"))
            llm_called = bool(res_b.get("llm_called", False))
            mitre_techs = {
                str(mid)
                for e in events
                for mid in (e.raw_attributes or {}).get("wazuh_mitre_ids", [])
                if mid
            }
            if not llm_called and parsed_cat in (None, AttackCategory.BENIGN, AttackCategory.UNKNOWN):
                det_cat, det_type, det_tactics = self._classify_attack_category_and_type(events, mitre_techs)
                attack_category = det_cat
                attack_type = str(res_b.get("attack_type") or det_type)
                merged_tactics = list(res_b.get("primary_mitre_tactics") or [])
                for t in det_tactics:
                    if t not in merged_tactics:
                        merged_tactics.append(t)
            else:
                if parsed_cat in (None, AttackCategory.BENIGN):
                    parsed_cat = AttackCategory.UNKNOWN
                attack_category = parsed_cat
                attack_type = str(res_b.get("attack_type") or "LLM Classified Security Incident")
                merged_tactics = list(res_b.get("primary_mitre_tactics") or [])

            for t in self._infer_tactics_from_mitre(mitre_techs):
                if t not in merged_tactics:
                    merged_tactics.append(t)
            primary_mitre_tactics = merged_tactics

        summary = (
            f"[Model B Direct - {'TRUE POSITIVE' if is_incident else 'FALSE POSITIVE'}] "
            f"Mức độ {sev.value} (Độ tin cậy: {conf*100:.1f}%). "
            f"{res_b.get('rationale', '')}"
        )
        return TriageOutput(
            is_incident=is_incident,
            confidence_score=conf,
            severity=sev,
            summary=summary,
            rule_or_model=str(res_b.get("model") or "Model-B-LLM-CoT"),
            attack_category=attack_category,
            attack_type=attack_type,
            primary_mitre_tactics=primary_mitre_tactics,
        )

    def evaluate_models_parallel(
        self,
        events: List[ParsedEvent],
        incident_state: Optional[IncidentState] = None,
    ) -> Dict[str, Any]:
        """
        Thực thi đánh giá sự kiện:
        - Nếu bật Tiered Routing và sự kiện đủ điều kiện Fast Triage (Level < 7, Benign, không IoC/obfuscation):
          Short-circuit đánh giá Heuristic ngay lập tức, bỏ qua gọi LLM Cloud đắt đỏ (tiết kiệm 100% token).
        - Nếu `enable_parallel_ensemble=False`: dùng trực tiếp phán đoán Model B (không vote A/C).
        - Ngược lại, thực thi đồng thời Model A, Model B, Model C trên ThreadPoolExecutor (lan truyền ContextVar).
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
                "rationale": "[Tiered Routing Fast Path] Short-circuit đánh giá Heuristic, bỏ qua LLM Cloud để tiết kiệm token.",
                "llm_called": False,
                "fallback_reason": "tiered_fast_heuristic",
                "provider_used": "heuristic",
                "tokens_used": 0,
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
                    "llm_called": False,
                    "provider_used": "heuristic",
                    "tokens_used": 0,
                }
            }

        if not self.enable_parallel_ensemble:
            if not self.llm_enabled:
                # Config A (rule_only): Evaluate Model A + Model C via _calculate_consensus(), skip Model B
                res_a = self._evaluate_heuristic(events)
                res_c = self._evaluate_mitre_ioc(events)
                res_b = {
                    "model": "Model-B-LLM-CoT",
                    "skipped": True,
                    "is_incident": False,
                    "confidence_score": 0.0,
                    "severity": SeverityLevel.LOW,
                    "score": 0.0,
                    "cot_steps": {},
                    "rationale": "Skipped (llm_enabled=False, enable_parallel_ensemble=False)",
                    "llm_called": False,
                    "fallback_reason": "llm_disabled",
                    "provider_used": "deterministic",
                    "tokens_used": 0,
                }
                consensus = self._calculate_consensus(res_a, res_b, res_c, events)
                return {
                    "model_a": res_a,
                    "model_b": res_b,
                    "model_c": res_c,
                    "consensus": consensus,
                    "tiered_routing": {
                        "applied": False,
                        "tier": "full_ensemble_deterministic",
                        "tokens_saved": False,
                        "llm_called": False,
                        "provider_used": "deterministic",
                        "tokens_used": 0,
                        "fallback_reason": "llm_disabled",
                    },
                }

            res_b = self._evaluate_llm_cot(events, incident_state=incident_state)
            consensus = self._build_single_model_consensus(res_b, events)
            res_a = {
                "model": "Model-A-Heuristic",
                "skipped": True,
                "is_incident": consensus.is_incident,
                "confidence_score": 0.0,
                "severity": consensus.severity,
                "score": 0.0,
                "rationale": "Skipped (enable_parallel_ensemble=False)",
            }
            res_c = {
                "model": "Model-C-MITRE-IoC",
                "skipped": True,
                "is_incident": consensus.is_incident,
                "confidence_score": 0.0,
                "severity": consensus.severity,
                "score": 0.0,
                "mitre_techniques": [],
                "rationale": "Skipped (enable_parallel_ensemble=False)",
            }
            llm_called = bool(res_b.get("llm_called", False))
            provider_used = str(res_b.get("provider_used") or ("llm" if llm_called else "deterministic"))
            tokens_used = int(res_b.get("tokens_used") or 0)
            tier = "full_ensemble_llm" if llm_called else "full_ensemble_deterministic"
            return {
                "model_a": res_a,
                "model_b": res_b,
                "model_c": res_c,
                "consensus": consensus,
                "tiered_routing": {
                    "applied": False,
                    "tier": tier,
                    "tokens_saved": False,
                    "llm_called": llm_called,
                    "provider_used": provider_used,
                    "tokens_used": tokens_used,
                    "fallback_reason": res_b.get("fallback_reason"),
                },
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            ctx_a = contextvars.copy_context()
            ctx_b = contextvars.copy_context()
            ctx_c = contextvars.copy_context()
            future_a = executor.submit(ctx_a.run, self._evaluate_heuristic, events)
            future_b = executor.submit(ctx_b.run, self._evaluate_llm_cot, events, incident_state)
            future_c = executor.submit(ctx_c.run, self._evaluate_mitre_ioc, events)

            res_a = future_a.result()
            res_b = future_b.result()
            res_c = future_c.result()

        # Tính toán Ensemble Consensus
        consensus = self._calculate_consensus(res_a, res_b, res_c, events)

        llm_called = bool(res_b.get("llm_called", False))
        provider_used = str(res_b.get("provider_used") or ("llm" if llm_called else "deterministic"))
        tokens_used = int(res_b.get("tokens_used") or 0)
        tier = "full_ensemble_llm" if llm_called else "full_ensemble_deterministic"

        return {
            "model_a": res_a,
            "model_b": res_b,
            "model_c": res_c,
            "consensus": consensus,
            "tiered_routing": {
                "applied": False,
                "tier": tier,
                "tokens_saved": False,
                "llm_called": llm_called,
                "provider_used": provider_used,
                "tokens_used": tokens_used,
                "fallback_reason": res_b.get("fallback_reason"),
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
        is_guard_short_circuit = (res_b.get("model") == "Model-B-LLM-CoT-Guard")

        w_a = 0.0 if res_a.get("skipped") else self.weight_heuristic
        w_b = 0.0 if res_b.get("skipped") else self.weight_cot
        w_c = 0.0 if res_c.get("skipped") else self.weight_mitre_ioc

        models_with_weights = [
            (res_a, w_a),
            (res_b, w_b),
            (res_c, w_c),
        ]
        active_models = [(r, w) for r, w in models_with_weights if w > 0.0]
        non_abstaining_models = [(r, w) for r, w in active_models if not r.get("abstain")]

        # Khi có ít nhất 1 model đưa ra phán đoán có căn cứ (non-abstain), không để model abstain phủ quyết
        voting_models = non_abstaining_models if non_abstaining_models else active_models

        vote_sum = sum(
            (1.0 if r.get("is_incident") else 0.0) * float(r.get("confidence_score", 0.0) or 0.0) * w
            for r, w in voting_models
        )
        total_weight = sum(
            float(r.get("confidence_score", 0.0) or 0.0) * w
            for r, w in voting_models
        )

        prob_incident = vote_sum / total_weight if total_weight > 0 else 0.0

        llm_called = bool(res_b.get("llm_called", False))
        llm_conf = float(res_b.get("confidence_score", 0.0) or 0.0)
        llm_high_conf_tp = (
            not res_b.get("skipped")
            and llm_called
            and bool(res_b.get("is_incident"))
            and llm_conf >= 0.75
        )
        deterministic_silent_a = bool(
            res_a.get("skipped")
            or res_a.get("abstain")
            or (
                not res_a.get("is_incident")
                and not res_a.get("reasons")
                and float(res_a.get("score", 0.0) or 0.0) <= 20.0
            )
        )
        deterministic_silent_c = bool(
            res_c.get("skipped")
            or res_c.get("abstain")
            or (
                not res_c.get("is_incident")
                and not res_c.get("mitre_techniques")
                and float(res_c.get("score", 0.0) or 0.0) <= 20.0
            )
        )

        if is_guard_short_circuit:
            final_is_incident = True
        elif llm_high_conf_tp and deterministic_silent_a and deterministic_silent_c:
            final_is_incident = True
            prob_incident = max(prob_incident, llm_conf)
        else:
            final_is_incident = prob_incident >= 0.5

        # Tính điểm tin cậy tổng hợp
        if is_guard_short_circuit:
            final_conf = max(0.95, float(res_b.get("confidence_score", 0.99)))
        elif len(voting_models) == 1 and voting_models[0][0] is res_b and llm_called:
            final_conf = min(0.99, max(0.75, llm_conf))
        elif final_is_incident:
            final_conf = min(0.99, max(0.75, prob_incident))
        else:
            final_conf = min(0.99, max(0.75, 1.0 - prob_incident))

        # Tính Severity đồng thuận trên các model tham gia biểu quyết (tránh model skipped/abstain kéo tụt score OOD)
        score_weight_sum = sum(w for _, w in voting_models)
        weighted_score = (
            sum(w * float(r.get("score", 0.0) or 0.0) for r, w in voting_models) / score_weight_sum
            if score_weight_sum > 0
            else 0.0
        )

        max_rule_level = max(
            [self._safe_int((e.raw_attributes or {}).get("wazuh_rule_level"), 0) for e in events] or [0]
        )

        if is_guard_short_circuit:
            non_skipped_sevs = [
                r.get("severity")
                for r, _ in active_models
                if not r.get("abstain")
            ]
            guard_sev = res_b.get("severity")
            inferred_guard_sev, _ = self._infer_guard_severity(
                events,
                underlying_severity=SeverityLevel.CRITICAL if SeverityLevel.CRITICAL in non_skipped_sevs else guard_sev,
            )
            if (
                guard_sev == SeverityLevel.CRITICAL
                or inferred_guard_sev == SeverityLevel.CRITICAL
                or SeverityLevel.CRITICAL in non_skipped_sevs
                or max_rule_level >= 12
            ):
                final_severity = SeverityLevel.CRITICAL
            else:
                final_severity = SeverityLevel.HIGH
        elif not final_is_incident:
            final_severity = SeverityLevel.LOW
        else:
            active_sevs = [r.get("severity") for r, _ in voting_models]
            # Nếu có model đánh giá CRITICAL và có căn cứ rule level >= 12 hoặc score >= 80
            if SeverityLevel.CRITICAL in active_sevs and (max_rule_level >= 12 or weighted_score >= 80):
                final_severity = SeverityLevel.CRITICAL
            elif max_rule_level >= 10 or weighted_score >= 60.0 or SeverityLevel.HIGH in active_sevs:
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
        if is_guard_short_circuit:
            mitre_techs = set(res_c.get("mitre_techniques", []))
            for e in events:
                for mid in (e.raw_attributes or {}).get("wazuh_mitre_ids", []):
                    mitre_techs.add(mid)
            inferred_cat, _, inferred_tactics = self._classify_attack_category_and_type(events, mitre_techs)
            guard_cat = self._parse_attack_category(res_b.get("attack_category"))
            if inferred_cat not in (AttackCategory.UNKNOWN, AttackCategory.BENIGN):
                attack_category = inferred_cat
            elif guard_cat not in (None, AttackCategory.UNKNOWN, AttackCategory.BENIGN):
                attack_category = guard_cat
            else:
                attack_category = AttackCategory.MALWARE
            attack_type = "Indirect Prompt Injection & Defense Evasion Attack"
            primary_mitre_tactics = ["Defense Evasion", "Execution"]
            for t in inferred_tactics:
                if t not in primary_mitre_tactics:
                    primary_mitre_tactics.append(t)
        elif not final_is_incident:
            attack_category = AttackCategory.BENIGN
            attack_type = "Normal Administrative Activity (Benign)"
            primary_mitre_tactics = []
        else:
            mitre_techs = set(res_c.get("mitre_techniques", []))
            for e in events:
                for mid in (e.raw_attributes or {}).get("wazuh_mitre_ids", []):
                    mitre_techs.add(mid)

            # Ưu tiên bảo toàn phán đoán LLM khi Model B thực sự gọi LLM với confidence >= 0.70
            llm_cat = self._parse_attack_category(res_b.get("attack_category"))

            if (
                llm_called
                and llm_cat is not None
                and llm_cat not in (AttackCategory.BENIGN, AttackCategory.UNKNOWN)
                and llm_conf >= 0.70
            ):
                attack_category = llm_cat
                attack_type = str(res_b.get("attack_type") or f"{llm_cat.value} Security Incident")
                primary_mitre_tactics = list(res_b.get("primary_mitre_tactics") or [])
                for t in self._infer_tactics_from_mitre(mitre_techs):
                    if t not in primary_mitre_tactics:
                        primary_mitre_tactics.append(t)
                if not primary_mitre_tactics:
                    primary_mitre_tactics = ["Execution"]
            else:
                det_cat, det_type, det_tactics = self._classify_attack_category_and_type(events, mitre_techs)
                if det_cat != AttackCategory.UNKNOWN:
                    attack_category = det_cat
                    attack_type = det_type
                    primary_mitre_tactics = det_tactics
                elif llm_cat is not None and llm_cat not in (AttackCategory.BENIGN, AttackCategory.UNKNOWN):
                    attack_category = llm_cat
                    attack_type = str(res_b.get("attack_type") or "Unclassified Security Incident")
                    primary_mitre_tactics = list(res_b.get("primary_mitre_tactics") or ["Execution", "Initial Access"])
                else:
                    attack_category = AttackCategory.UNKNOWN
                    attack_type = "Unclassified Security Incident"
                    primary_mitre_tactics = det_tactics

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
        results = self.evaluate_models_parallel(state.parsed_events, incident_state=state)
        triage_output: TriageOutput = results["consensus"]

        state.triage_result = triage_output
        state.attack_type = triage_output.attack_type
        target_status = IncidentStatus.TRIAGED if triage_output.is_incident else IncidentStatus.CLOSED_FALSE_POSITIVE

        tr = results.get("tiered_routing", {})
        transition_meta = {
            "confidence": triage_output.confidence_score,
            "severity": triage_output.severity.value,
            "model": triage_output.rule_or_model,
            "tiered_routing": tr.get("tier", "full_ensemble_deterministic"),
            "llm_called": bool(tr.get("llm_called", False)),
            "provider_used": tr.get("provider_used", "deterministic"),
            "tokens_used": int(tr.get("tokens_used", 0) or 0),
        }

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

