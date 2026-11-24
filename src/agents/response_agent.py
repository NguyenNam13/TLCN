# -*- coding: utf-8 -*-
"""
src/agents/response_agent.py
Response Recommendation Agent chuyên trách đề xuất kế hoạch phản ứng sự cố an ninh mạng.
Tuân thủ tiêu chuẩn NIST SP 800-61 (Computer Security Incident Handling Guide):
1. Khẩn cấp / Ngăn chặn tức thì (Containment - Priority 1):
   - ISOLATE_HOST: Cô lập máy trạm bị nhiễm mã độc khỏi mạng nội bộ.
   - BLOCK_IP: Chặn IP máy chủ điều khiển C2 hoặc IP tấn công bên ngoài trên Firewall/Proxy.
   - KILL_PROCESS: Tiêu diệt tiến trình độc hại đang chạy trên endpoint.
2. Xử lý tài khoản / Danh tính (Eradication - Priority 2):
   - REVOKE_USER: Thu hồi toàn bộ phiên đăng nhập của người dùng bị lộ lọt.
   - RESET_PASSWORD: Buộc đổi mật khẩu và tái thiết lập xác thực đa yếu tố (MFA).
3. Triệt tiêu / Khôi phục hệ thống (Recovery - Priority 3-4):
   - PATCH_SYSTEM: Vá lỗ hổng, cập nhật bản vá bảo mật và quét toàn diện hệ thống.
4. Wazuh Active Response:
   - Tích hợp WazuhClientTool thực thi các script phản ứng tự động trên agent:
     `firewall-drop`, `host-isolate`, `kill-process`.
5. Quản lý cờ phê duyệt chuyên viên (Human-In-The-Loop - HITL):
   - Các hành động rủi ro cao (ISOLATE_HOST, BLOCK_IP, WAZUH_ACTIVE_RESPONSE, RESET_PASSWORD)
     bắt buộc yêu cầu phê duyệt (require_human_approval = True).
   - Các hành động rủi ro thấp (KILL_PROCESS, REVOKE_USER, PATCH_SYSTEM) có thể tự động phê duyệt
     nếu được cấu hình (auto_approve_low_risk = True).
"""

import ipaddress
import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple

from src.core.schemas import (
    ActionType,
    ActionAdjustment,
    RecommendedAction,
    ResponseLLMStrategy,
    IncidentStatus,
    IncidentPhase,
)
from src.core.state import IncidentState
from src.core.rbac import is_protected_process
from src.core.security_guard import (
    UNTRUSTED_LOG_SECURITY_HEADER,
    inspect_and_wrap_untrusted,
    sanitize_prompt_text,
)
from src.agents.prompts import RESPONSE_AGENT_SYSTEM_PROMPT
from src.agents.llm_utils import invoke_structured_llm
from src.tools.playbooks import ResponsePlaybooks
from src.tools.wazuh_client import WazuhClientTool

try:
    from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool
except Exception:
    RAGKnowledgeBaseTool = None

logger = logging.getLogger("ResponseAgent")


class ResponseAgent:
    """
    Response Recommendation Agent đóng vai trò Chỉ huy ứng phó sự cố (Incident Commander).
    Xây dựng kế hoạch ngăn chặn, triệt tiêu và khôi phục dựa trên dữ liệu điều tra
    từ Triage, Threat Intelligence và Root Cause Analysis (RCA).
    """

    # Danh mục hành động rủi ro cao (ảnh hưởng diện rộng hoặc gián đoạn dịch vụ)
    HIGH_RISK_ACTIONS: Set[ActionType] = {
        ActionType.ISOLATE_HOST,
        ActionType.BLOCK_IP,
        ActionType.WAZUH_ACTIVE_RESPONSE,
        ActionType.RESET_PASSWORD,
    }

    # Danh mục hành động rủi ro thấp / cục bộ
    LOW_RISK_ACTIONS: Set[ActionType] = {
        ActionType.KILL_PROCESS,
        ActionType.REVOKE_USER,
        ActionType.PATCH_SYSTEM,
    }

    # Tài khoản hệ thống mặc định (không áp dụng khóa tài khoản thông thường)
    SYSTEM_ACCOUNTS: Set[str] = {
        "system",
        "local service",
        "network service",
        "anonymous logon",
        "dwm-1",
        "umfd-1",
    }

    def __init__(
        self,
        require_approval_by_default: bool = True,
        auto_approve_low_risk: bool = False,
        enable_wazuh_active_response: bool = True,
        system_prompt: Optional[str] = None,
        playbooks: Optional[Any] = None,
        wazuh_client: Optional[Any] = None,
        rag_kb: Optional[Any] = None,
        llm_provider: Optional[Any] = None,
        llm_enabled: bool = True,
        enable_rag: bool = True,
        enable_security_guard: bool = True,
    ):
        """
        Khởi tạo ResponseAgent với cấu hình chính sách phê duyệt, công cụ và LLM.

        :param require_approval_by_default: Yêu cầu phê duyệt chuyên viên mặc định cho các hành động.
        :param auto_approve_low_risk: Tự động phê duyệt các hành động ít rủi ro (KILL_PROCESS, REVOKE_USER).
        :param enable_wazuh_active_response: Cho phép kích hoạt cơ chế Wazuh Active Response.
        :param system_prompt: System prompt định hướng vai trò Incident Commander.
        :param playbooks: Lớp chứa kịch bản mẫu (mặc định ResponsePlaybooks).
        :param wazuh_client: Client tích hợp Wazuh SIEM (mặc định WazuhClientTool).
        :param rag_kb: Công cụ truy vấn cơ sở tri thức RAG (mặc định RAGKnowledgeBaseTool).
        :param llm_provider: Provider kết nối LLM phục vụ tổng hợp chiến lược (mặc định lazy load HybridLLMProvider).
        :param llm_enabled: Bật/tắt cơ chế sinh chiến lược phản ứng tùy biến qua LLM.
        :param enable_rag: Bật/tắt truy xuất và khởi tạo tự động RAGKnowledgeBaseTool.
        :param enable_security_guard: Bật/tắt làm sạch và cô lập dữ liệu untrusted trước khi gửi LLM.
        """
        self.require_approval_by_default = require_approval_by_default
        self.auto_approve_low_risk = auto_approve_low_risk
        self.enable_wazuh_active_response = enable_wazuh_active_response
        self.system_prompt = system_prompt or RESPONSE_AGENT_SYSTEM_PROMPT
        self.playbooks = playbooks or ResponsePlaybooks
        self.wazuh_client = wazuh_client or WazuhClientTool
        self.enable_rag = bool(enable_rag)
        self.enable_security_guard = bool(enable_security_guard)
        self.rag_kb = rag_kb if self.enable_rag else None
        if self.enable_rag and self.rag_kb is None and RAGKnowledgeBaseTool is not None:
            try:
                self.rag_kb = RAGKnowledgeBaseTool()
            except Exception as exc:
                logger.warning(f"Không thể khởi tạo RAGKnowledgeBaseTool: {exc}")
                self.rag_kb = None
        self._last_rag_info: Dict[str, Any] = {}
        self.llm_provider = llm_provider
        self.llm_enabled = llm_enabled
        self._last_strategy_summary: str = ""
        self._last_llm_strategy: Optional[ResponseLLMStrategy] = None
        self._last_security_flags: List[Dict[str, str]] = []

    # =====================================================================
    # 1. HELPER POLICY VÀ APPROVAL FLAG DETERMINATION
    # =====================================================================
    def determine_approval_requirement(self, action_type: ActionType) -> bool:
        """
        Xác định xem hành động có bắt buộc chuyên viên SOC phê duyệt hay không.
        - Hành động rủi ro cao: LUÔN LUÔN yêu cầu phê duyệt (True).
        - Hành động rủi ro thấp:
          + Nếu auto_approve_low_risk=True -> False.
          + Ngược lại theo require_approval_by_default.
        """
        if action_type in self.HIGH_RISK_ACTIONS:
            return True

        if self.auto_approve_low_risk:
            return False

        return self.require_approval_by_default

    def apply_approval_policy(self, action: RecommendedAction) -> RecommendedAction:
        """Áp dụng chính sách phê duyệt lên một hành động RecommendedAction."""
        action.require_human_approval = self.determine_approval_requirement(action.action_type)
        return action

    _GROUNDING_IPV4_RE = re.compile(
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
    )
    _GROUNDING_PROC_EXT_RE = re.compile(
        r"\b([A-Za-z0-9_\-]+\.(?:exe|dll|ps1|bat|cmd|vbs))\b", re.IGNORECASE
    )
    _GROUNDING_LSASS_RE = re.compile(r"\blsass(?:\.exe)?\b", re.IGNORECASE)
    _GROUNDING_MITRE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
    _GROUNDING_PID_RE = re.compile(r"\bPID\s*[:=#]?\s*(\d{2,7})\b", re.IGNORECASE)
    _GROUNDING_HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
    _GROUNDING_MTTA_8_RE = re.compile(r"MTTA\*{0,2}\s*[:=]?\s*\*{0,2}\s*8\s*phút", re.IGNORECASE)

    _GENERIC_PROC_DESCRIPTIONS: Dict[str, str] = {
        "lsass.exe": "critical credential subsystem",
        "powershell.exe": "script interpreter",
        "pwsh.exe": "script interpreter",
        "cmd.exe": "command shell interpreter",
        "vssadmin.exe": "shadow copy utility",
        "wbadmin.exe": "backup utility",
        "bcdedit.exe": "boot configuration utility",
        "schtasks.exe": "scheduled task utility",
        "wevtutil.exe": "event log utility",
        "certutil.exe": "certificate transfer utility",
        "procdump.exe": "memory dump utility",
        "rundll32.exe": "DLL host utility",
        "comsvcs.dll": "COM services library",
        "w3wp.exe": "web worker process",
        "outlook.exe": "email client process",
    }

    @staticmethod
    def is_private_ip(ip_str: Optional[str]) -> bool:
        """Kiểm tra một địa chỉ IP có phải IP Private (RFC 1918) hoặc loopback hay không."""
        if not ip_str:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            if isinstance(ip_obj, ipaddress.IPv4Address):
                s = str(ip_obj)
                if s.startswith("192.0.2.") or s.startswith("198.51.100.") or s.startswith("203.0.113."):
                    return False
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    @staticmethod
    def _normalize_proc_basename(value: str) -> str:
        cleaned = str(value).strip().strip("\"'`").replace("\\", "/")
        if "/" in cleaned:
            cleaned = cleaned.split("/")[-1]
        return cleaned.lower()

    @staticmethod
    def _is_trivial_hex_or_non_hash(token: str) -> bool:
        low = token.lower()
        return len(set(low)) <= 2 or low.isdigit()

    @classmethod
    def _collect_text_blobs_from_value(cls, val: Any, out: List[str]) -> None:
        if val is None:
            return
        if isinstance(val, str):
            if val.strip():
                out.append(val)
        elif isinstance(val, dict):
            for v in val.values():
                cls._collect_text_blobs_from_value(v, out)
        elif isinstance(val, (list, tuple, set)):
            for item in val:
                cls._collect_text_blobs_from_value(item, out)
        elif hasattr(val, "model_dump"):
            cls._collect_text_blobs_from_value(val.model_dump(), out)

    def _collect_observed_grounding_entities(self, state: IncidentState) -> Dict[str, Any]:
        """
        Thu thập các thực thể (IPv4, tiến trình/tập thực thi, PID, MITRE ID, hash) thực sự quan sát
        được từ bằng chứng trong state để khử rò rỉ thực thể ngoài ngữ cảnh khi sinh chiến lược RAG.
        """
        source_texts: List[str] = []
        allowed_ips: Set[str] = set()
        allowed_procs: Set[str] = set()
        allowed_pids: Set[str] = set()
        allowed_mitre_ids: Set[str] = set()
        allowed_hashes: Set[str] = set()

        def _scan_text(txt: Optional[str], include_procs: bool = True) -> None:
            if not txt:
                return
            s = str(txt)
            source_texts.append(s)
            for ip in self._GROUNDING_IPV4_RE.findall(s):
                allowed_ips.add(ip)
            for mid in self._GROUNDING_MITRE_RE.findall(s):
                up = mid.upper()
                allowed_mitre_ids.add(up)
                if "." in up:
                    allowed_mitre_ids.add(up.split(".")[0])
            if include_procs:
                for proc in self._GROUNDING_PROC_EXT_RE.findall(s):
                    allowed_procs.add(proc.lower())
            for pid in self._GROUNDING_PID_RE.findall(s):
                allowed_pids.add(pid)
            for pid_m in re.findall(r"\[(\d{2,7})\]", s):
                allowed_pids.add(pid_m)
            for h in self._GROUNDING_HASH_RE.findall(s):
                if not self._is_trivial_hex_or_non_hash(h):
                    allowed_hashes.add(h.lower())

        for rlog in state.raw_logs:
            _scan_text(rlog.raw_payload)

        for ev in state.parsed_events:
            if ev.source_ip:
                _scan_text(ev.source_ip, include_procs=False)
            if ev.dest_ip:
                _scan_text(ev.dest_ip, include_procs=False)
            if ev.process_name:
                allowed_procs.add(self._normalize_proc_basename(ev.process_name))
                source_texts.append(ev.process_name)
            if ev.process_path:
                allowed_procs.add(self._normalize_proc_basename(ev.process_path))
                _scan_text(ev.process_path)
            if ev.parent_process:
                allowed_procs.add(self._normalize_proc_basename(ev.parent_process))
                source_texts.append(ev.parent_process)
            _scan_text(ev.command_line)
            _scan_text(ev.parent_command_line)
            if ev.file_hash:
                _scan_text(ev.file_hash, include_procs=False)

            raw_attrs = ev.raw_attributes or {}
            attr_blobs: List[str] = []
            self._collect_text_blobs_from_value(raw_attrs, attr_blobs)
            for blob in attr_blobs:
                _scan_text(blob)
            for pid_key in (
                "process_id",
                "pid",
                "parent_pid",
                "ppid",
                "mordorProcessId",
                "mordorClientProcessId",
            ):
                pval = raw_attrs.get(pid_key)
                if pval is not None and str(pval).strip():
                    allowed_pids.add(str(pval).strip())

        if state.threat_intel:
            for ioc in state.threat_intel.extracted_iocs or []:
                _scan_text(ioc.value, include_procs=False)
                det_blobs: List[str] = []
                self._collect_text_blobs_from_value(ioc.details, det_blobs)
                for b in det_blobs:
                    for ip in self._GROUNDING_IPV4_RE.findall(b):
                        allowed_ips.add(ip)
                    for h in self._GROUNDING_HASH_RE.findall(b):
                        if not self._is_trivial_hex_or_non_hash(h):
                            allowed_hashes.add(h.lower())
            for tid in state.threat_intel.mitre_techniques or []:
                up = str(tid).strip().upper()
                if up:
                    allowed_mitre_ids.add(up)
                    if "." in up:
                        allowed_mitre_ids.add(up.split(".")[0])
            for ctx in state.threat_intel.rag_mitre_context or []:
                if isinstance(ctx, dict) and ctx.get("technique_id"):
                    up = str(ctx["technique_id"]).strip().upper()
                    allowed_mitre_ids.add(up)
                    if "." in up:
                        allowed_mitre_ids.add(up.split(".")[0])

        if state.rca_result:
            for node in state.rca_result.process_tree or []:
                if node.process_name:
                    allowed_procs.add(self._normalize_proc_basename(node.process_name))
                if node.process_id:
                    allowed_pids.add(str(node.process_id).strip())
                if node.parent_id:
                    allowed_pids.add(str(node.parent_id).strip())
                _scan_text(node.command_line)
            for hnode in state.rca_result.high_fidelity_tree or []:
                if hnode.process_name:
                    allowed_procs.add(self._normalize_proc_basename(hnode.process_name))
                if hnode.process_id:
                    allowed_pids.add(str(hnode.process_id).strip())
                if hnode.parent_id:
                    allowed_pids.add(str(hnode.parent_id).strip())
                _scan_text(hnode.command_line)
                for tid in hnode.mitre_techniques or []:
                    up = str(tid).strip().upper()
                    if up:
                        allowed_mitre_ids.add(up)

        raw_evidence_lower = "\n".join(source_texts).lower()
        has_lsass_evidence = (
            "lsass" in raw_evidence_lower
            or "lsass.exe" in allowed_procs
            or any(m == "T1003" or m.startswith("T1003.") for m in allowed_mitre_ids)
        )
        return {
            "raw_evidence_lower": raw_evidence_lower,
            "allowed_ips": allowed_ips,
            "allowed_procs": allowed_procs,
            "allowed_pids": allowed_pids,
            "allowed_mitre_ids": allowed_mitre_ids,
            "allowed_hashes": allowed_hashes,
            "has_lsass_evidence": has_lsass_evidence,
        }

    def _sanitize_text_grounding(
        self,
        text: Optional[str],
        observed: Dict[str, Any],
    ) -> str:
        """
        Làm sạch các thực thể không có trong bằng chứng sự cố (đặc biệt lsass.exe, tiến trình .exe/.dll,
        IPv4, PID, MITRE ID hoặc số liệu bịa đặt) khỏi đoạn văn bản RAG/LLM mà giữ nguyên văn sạch.
        """
        if not text:
            return ""
        cleaned = str(text)
        allowed_ips: Set[str] = observed["allowed_ips"]
        allowed_procs: Set[str] = observed["allowed_procs"]
        allowed_pids: Set[str] = observed["allowed_pids"]
        allowed_mitre_ids: Set[str] = observed["allowed_mitre_ids"]
        allowed_hashes: Set[str] = observed["allowed_hashes"]
        has_lsass_evidence: bool = observed["has_lsass_evidence"]
        raw_lower: str = observed["raw_evidence_lower"]

        def _replace_proc(match: re.Match) -> str:
            token = match.group(1)
            low = token.lower()
            if low == "generic_process" or low in allowed_procs:
                return token
            if low in self._GENERIC_PROC_DESCRIPTIONS:
                return self._GENERIC_PROC_DESCRIPTIONS[low]
            if low.endswith(".dll"):
                return "system library"
            if low.endswith((".ps1", ".bat", ".cmd", ".vbs")):
                return "system script"
            return "critical system process"

        cleaned = self._GROUNDING_PROC_EXT_RE.sub(_replace_proc, cleaned)

        if not has_lsass_evidence:
            cleaned = self._GROUNDING_LSASS_RE.sub("critical credential subsystem", cleaned)

        def _replace_ip(match: re.Match) -> str:
            ip = match.group(0)
            return ip if ip in allowed_ips else "[external-ip]"

        cleaned = self._GROUNDING_IPV4_RE.sub(_replace_ip, cleaned)

        def _replace_pid(match: re.Match) -> str:
            pid = match.group(1)
            return match.group(0) if pid in allowed_pids else "target process ID"

        cleaned = self._GROUNDING_PID_RE.sub(_replace_pid, cleaned)

        def _replace_mitre(match: re.Match) -> str:
            mid = match.group(1)
            return mid if mid.upper() in allowed_mitre_ids else "related ATT&CK technique"

        cleaned = self._GROUNDING_MITRE_RE.sub(_replace_mitre, cleaned)

        def _replace_hash(match: re.Match) -> str:
            hval = match.group(1)
            if self._is_trivial_hex_or_non_hash(hval):
                return hval
            hlow = hval.lower()
            if hlow in allowed_hashes or any(hlow in ah for ah in allowed_hashes):
                return hval
            return "[observed-hash]"

        cleaned = self._GROUNDING_HASH_RE.sub(_replace_hash, cleaned)

        if "172.16.65.143" in cleaned and "172.16.65.143" not in raw_lower:
            cleaned = cleaned.replace("172.16.65.143", "[internal-host]")
        for phrase in ("450.000.000", "450 triệu", "3h45m"):
            if phrase in cleaned.lower() and phrase not in raw_lower:
                cleaned = re.sub(re.escape(phrase), "[unverified-metric]", cleaned, flags=re.IGNORECASE)
        if "8 phút" not in raw_lower and self._GROUNDING_MTTA_8_RE.search(cleaned):
            cleaned = self._GROUNDING_MTTA_8_RE.sub("MTTA: N/A", cleaned)

        return cleaned

    # =====================================================================
    # 1B. TRA CỨU TRI THỨC RAG (MITRE ATT&CK MITIGATIONS & WAZUH REMEDIATION)
    # =====================================================================
    def lookup_rag_remediation(self, state: IncidentState) -> Dict[str, Any]:
        """
        Truy vấn RAG Knowledge Base để thu thập TTPs, MITRE Mitigations và Wazuh Remediation
        phù hợp với ngữ cảnh sự cố hiện tại.
        Ưu tiên tra cứu chính xác theo mitre_ids/rule_ids; chỉ fallback ngữ nghĩa khi thiếu
        kết quả và áp ngưỡng điểm liên quan (>= 0.30) cùng bộ lọc thực thể ngoài ngữ cảnh.
        """
        mitre_ids: List[str] = []
        rule_ids: List[str] = []

        if state.threat_intel and state.threat_intel.mitre_techniques:
            for tid in state.threat_intel.mitre_techniques:
                tid_str = str(tid).strip()
                if tid_str and tid_str not in mitre_ids:
                    mitre_ids.append(tid_str)

        for event in state.parsed_events:
            raw_attrs = event.raw_attributes or {}
            for key in ("wazuh_mitre_ids", "mitre_ids"):
                raw_m = raw_attrs.get(key, [])
                if isinstance(raw_m, str):
                    raw_m = [x.strip() for x in raw_m.split(",") if x.strip()]
                elif isinstance(raw_m, list):
                    raw_m = [str(x).strip() for x in raw_m if str(x).strip()]
                else:
                    raw_m = []
                for m_id in raw_m:
                    if m_id not in mitre_ids:
                        mitre_ids.append(m_id)

            r_id = raw_attrs.get("wazuh_rule_id")
            if r_id is not None:
                r_id_str = str(r_id).strip()
                if r_id_str and r_id_str not in rule_ids:
                    rule_ids.append(r_id_str)

        query_parts: List[str] = []
        if state.triage_result:
            if state.triage_result.attack_type:
                query_parts.append(str(state.triage_result.attack_type))
            if state.triage_result.summary:
                query_parts.append(str(state.triage_result.summary))
        if state.rca_result:
            if state.rca_result.confirmed_attack_type:
                query_parts.append(str(state.rca_result.confirmed_attack_type))
            if state.rca_result.initial_access_vector:
                query_parts.append(str(state.rca_result.initial_access_vector))

        query_text = " ".join(p.strip() for p in query_parts if p and p.strip())

        ttp_matches: List[Dict[str, Any]] = []
        rule_matches: List[Dict[str, Any]] = []
        mitigations: List[str] = []
        remediations: List[str] = []

        if self.rag_kb is None:
            return {
                "mitre_ids": mitre_ids,
                "rule_ids": rule_ids,
                "query_text": query_text,
                "ttp_matches": ttp_matches,
                "rule_matches": rule_matches,
                "mitigations": mitigations,
                "remediations": remediations,
            }

        observed = self._collect_observed_grounding_entities(state)
        has_lsass_evidence: bool = observed["has_lsass_evidence"]
        mitre_id_set = {m.upper() for m in mitre_ids}
        rule_id_set = {r.strip() for r in rule_ids}
        score_threshold = 0.30

        seen_ttp_ids: Set[str] = set()
        seen_rule_ids: Set[str] = set()

        def _passes_semantic_threshold(rec: Any) -> bool:
            if not isinstance(rec, dict):
                return False
            if "score" not in rec or rec.get("score") is None:
                return True
            try:
                return float(rec.get("score", 0.0) or 0.0) >= score_threshold
            except (TypeError, ValueError):
                return True

        def _is_safe_semantic_ttp(rec: Dict[str, Any]) -> bool:
            tid = str(rec.get("technique_id") or rec.get("id") or "").strip().upper()
            if tid and tid in mitre_id_set:
                return True
            if not has_lsass_evidence:
                if tid == "T1003" or tid.startswith("T1003."):
                    return False
                blob = " ".join(
                    str(rec.get(k) or "")
                    for k in ("name", "description", "detection", "mitigations")
                ).lower()
                if "lsass" in blob:
                    return False
            return True

        def _is_safe_semantic_rule(rec: Dict[str, Any]) -> bool:
            rid = str(rec.get("rule_id") or rec.get("id") or "").strip()
            if rid and rid in rule_id_set:
                return True
            if not has_lsass_evidence:
                blob = " ".join(
                    str(rec.get(k) or "")
                    for k in ("description", "remediation")
                ).lower()
                if "lsass" in blob:
                    return False
            return True

        def _add_ttp_record(rec: Optional[Dict[str, Any]]) -> None:
            if not isinstance(rec, dict):
                return
            tid = str(rec.get("technique_id") or rec.get("id") or "").strip()
            if tid and tid in seen_ttp_ids:
                return
            if tid:
                seen_ttp_ids.add(tid)
            ttp_matches.append(rec)
            mit = str(rec.get("mitigations") or "").strip()
            if mit and mit not in mitigations:
                mitigations.append(mit)

        def _add_rule_record(rec: Optional[Dict[str, Any]]) -> None:
            if not isinstance(rec, dict):
                return
            rid = str(rec.get("rule_id") or rec.get("id") or "").strip()
            if rid and rid in seen_rule_ids:
                return
            if rid:
                seen_rule_ids.add(rid)
            rule_matches.append(rec)
            rem = str(rec.get("remediation") or "").strip()
            if rem and rem not in remediations:
                remediations.append(rem)

        # 1. Ưu tiên tra cứu chính xác theo MITRE ID và Wazuh Rule ID
        try:
            for tid in mitre_ids:
                if hasattr(self.rag_kb, "get_mitre_technique"):
                    exact_ttp = self.rag_kb.get_mitre_technique(tid)
                    if exact_ttp:
                        _add_ttp_record(exact_ttp)
                        continue
                if hasattr(self.rag_kb, "query_mitre_technique"):
                    for item in self.rag_kb.query_mitre_technique(tid, n_results=1):
                        if _passes_semantic_threshold(item):
                            _add_ttp_record(item)

            linked_rule_mitre_ids: List[str] = []
            for rid in rule_ids:
                if hasattr(self.rag_kb, "get_wazuh_rule"):
                    exact_rule = self.rag_kb.get_wazuh_rule(rid)
                    if exact_rule:
                        _add_rule_record(exact_rule)
                        for linked_tid in exact_rule.get("mitre_ids") or []:
                            lt = str(linked_tid).strip()
                            if lt and lt not in linked_rule_mitre_ids:
                                linked_rule_mitre_ids.append(lt)
                        continue
                if hasattr(self.rag_kb, "query_wazuh_rule"):
                    for item in self.rag_kb.query_wazuh_rule(rid, n_results=1):
                        if _passes_semantic_threshold(item):
                            _add_rule_record(item)

            if not mitigations and linked_rule_mitre_ids and hasattr(self.rag_kb, "get_mitre_technique"):
                for ltid in linked_rule_mitre_ids:
                    linked_ttp = self.rag_kb.get_mitre_technique(ltid)
                    if linked_ttp and _is_safe_semantic_ttp(linked_ttp):
                        _add_ttp_record(linked_ttp)
        except Exception as exc:
            logger.debug(f"Lỗi khi tra cứu exact ID từ RAG Knowledge Base: {exc}")

        # 2. Chỉ gọi retrieve_incident_knowledge khi exact ID chưa phủ đủ mitigations/remediations
        need_mitigations = not mitigations
        need_remediations = not remediations
        if need_mitigations or need_remediations:
            try:
                if hasattr(self.rag_kb, "retrieve_incident_knowledge"):
                    rag_res = self.rag_kb.retrieve_incident_knowledge(
                        query_text=query_text,
                        mitre_ids=mitre_ids,
                        rule_ids=rule_ids,
                    )
                    if isinstance(rag_res, dict):
                        tech_items = (
                            rag_res.get("matched_techniques")
                            or rag_res.get("mitre_techniques")
                            or rag_res.get("ttp_matches")
                            or []
                        )
                        if need_mitigations:
                            for item in tech_items:
                                if _passes_semantic_threshold(item) and _is_safe_semantic_ttp(item):
                                    _add_ttp_record(item)
                            if not mitigations:
                                mit_items = (
                                    rag_res.get("nist_mitigations")
                                    or rag_res.get("mitigations")
                                    or []
                                )
                                for m in mit_items:
                                    m_str = str(m).strip() if m else ""
                                    if not m_str:
                                        continue
                                    if not has_lsass_evidence and "lsass" in m_str.lower():
                                        continue
                                    if m_str not in mitigations:
                                        mitigations.append(m_str)

                        rule_items = (
                            rag_res.get("matched_rules")
                            or rag_res.get("wazuh_rules")
                            or rag_res.get("rule_matches")
                            or []
                        )
                        if need_remediations:
                            for item in rule_items:
                                if _passes_semantic_threshold(item) and _is_safe_semantic_rule(item):
                                    _add_rule_record(item)
                            if not remediations:
                                rem_items = (
                                    rag_res.get("nist_remediations")
                                    or rag_res.get("remediations")
                                    or []
                                )
                                for r in rem_items:
                                    r_str = str(r).strip() if r else ""
                                    if not r_str:
                                        continue
                                    if not has_lsass_evidence and "lsass" in r_str.lower():
                                        continue
                                    if r_str not in remediations:
                                        remediations.append(r_str)
            except Exception as exc:
                logger.debug(f"retrieve_incident_knowledge fallback: {exc}")

        # 3. Truy vấn ngữ nghĩa dự phòng chỉ khi vẫn còn trống sau exact ID + retrieve_incident_knowledge
        try:
            if query_text:
                if not mitigations and hasattr(self.rag_kb, "query_mitre_technique"):
                    for item in self.rag_kb.query_mitre_technique(query_text, n_results=2):
                        if _passes_semantic_threshold(item) and _is_safe_semantic_ttp(item):
                            _add_ttp_record(item)
                if not remediations and hasattr(self.rag_kb, "query_wazuh_rule"):
                    for item in self.rag_kb.query_wazuh_rule(query_text, n_results=2):
                        if _passes_semantic_threshold(item) and _is_safe_semantic_rule(item):
                            _add_rule_record(item)
        except Exception as exc:
            logger.debug(f"Lỗi khi truy vấn ngữ nghĩa RAG Knowledge Base: {exc}")

        return {
            "mitre_ids": mitre_ids,
            "rule_ids": rule_ids,
            "query_text": query_text,
            "ttp_matches": ttp_matches,
            "rule_matches": rule_matches,
            "mitigations": mitigations,
            "remediations": remediations,
        }

    def _wrap_untrusted(
        self,
        text: Optional[str],
        field_name: str,
        max_len: int = 800,
        *,
        include_notice: bool = False,
        security_flags: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        """Làm sạch và bọc dữ liệu untrusted bằng <raw_untrusted_log> khi SecurityGuard bật, đồng thời lưu cờ phát hiện."""
        raw = "" if text is None else str(text)
        if not raw.strip() or raw.strip() == "N/A":
            return "N/A"
        if not self.enable_security_guard:
            return raw[:max_len] if max_len > 0 and len(raw) > max_len else raw
        wrapped, is_inj, reason = inspect_and_wrap_untrusted(
            raw,
            field_name=field_name,
            max_len=max_len,
            include_notice=include_notice,
        )
        if is_inj:
            flag_entry = {
                "field": field_name,
                "reason": reason or "prompt_injection_detected",
            }
            if security_flags is not None:
                security_flags.append(flag_entry)
            else:
                self._last_security_flags.append(flag_entry)
        return wrapped

    def _collect_valid_targets(self, state: IncidentState) -> Set[str]:
        """Thu thập tập target hợp lệ từ _extract_context(state) để chặn target bịa đặt từ LLM."""
        ctx = self._extract_context(state)
        valid_targets: Set[str] = set()
        for key in ("hosts", "users", "processes", "external_ips", "source_ips"):
            for val in ctx.get(key, []):
                if val and str(val).strip():
                    valid_targets.add(str(val).strip().lower())
        for ag in ctx.get("wazuh_agents", []):
            if isinstance(ag, dict):
                if ag.get("id"):
                    valid_targets.add(f"agent-{str(ag['id']).strip().lower()}")
                if ag.get("name"):
                    valid_targets.add(str(ag["name"]).strip().lower())
                if ag.get("ip"):
                    valid_targets.add(str(ag["ip"]).strip().lower())
        return valid_targets

    def _apply_llm_action_adjustments(
        self,
        actions: List[RecommendedAction],
        strategy: Optional[ResponseLLMStrategy],
        state: IncidentState,
    ) -> List[RecommendedAction]:
        """
        Áp dụng tối đa 3 điều chỉnh an toàn từ ResponseLLMStrategy lên danh sách hành động hiện có.
        Bất biến an toàn tuyệt đối:
        - Chỉ điều chỉnh action hiện có có target tồn tại trong _extract_context(state).
        - Từ chối KILL_PROCESS nhắm vào tiến trình hệ thống trọng yếu (lsass.exe, svchost.exe...).
        - SUPPRESS_PER_FEEDBACK chỉ hợp lệ khi bool(state.analyst_feedback) là True.
        - Luôn tái áp dụng apply_approval_policy() và giữ is_approved=None trên mọi hành động.
        """
        working: List[RecommendedAction] = list(actions)
        if strategy is None or not getattr(strategy, "action_adjustments", None):
            for act in working:
                self.apply_approval_policy(act)
                act.is_approved = None
            return working

        valid_targets = self._collect_valid_targets(state)
        has_feedback = bool(state.analyst_feedback and str(state.analyst_feedback).strip())
        applied_count = 0

        for adj in strategy.action_adjustments:
            if adj.operation == "KEEP":
                continue
            if applied_count >= 3:
                break

            target_raw = (adj.target or "").strip()
            target_norm = target_raw.lower()
            if not target_norm or target_norm not in valid_targets:
                logger.warning(
                    f"[ResponseGuardrail] Từ chối điều chỉnh {adj.operation} cho target ngoài ngữ cảnh: '{adj.target}'"
                )
                continue

            if adj.action_type == ActionType.KILL_PROCESS and (
                self.playbooks.is_critical_system_process(target_raw)
                or is_protected_process(target_raw)
            ):
                logger.warning(
                    f"[ResponseGuardrail] Chặn điều chỉnh KILL_PROCESS nhắm tiến trình hệ thống trọng yếu: '{target_raw}'"
                )
                continue

            if adj.operation == "SUPPRESS_PER_FEEDBACK" and not has_feedback:
                logger.warning(
                    f"[ResponseGuardrail] Từ chối SUPPRESS_PER_FEEDBACK cho '{target_raw}' vì không có analyst_feedback."
                )
                continue

            matched_indices: List[int] = []
            if adj.action_id:
                matched_indices = [
                    idx
                    for idx, act in enumerate(working)
                    if act.action_id == adj.action_id
                    and act.action_type == adj.action_type
                    and act.target.strip().lower() == target_norm
                ]
            if not matched_indices:
                matched_indices = [
                    idx
                    for idx, act in enumerate(working)
                    if act.action_type == adj.action_type
                    and act.target.strip().lower() == target_norm
                ]

            if not matched_indices:
                logger.debug(
                    f"[ResponseGuardrail] Không tìm thấy hành động hiện có khớp ({adj.action_type.value}, '{target_raw}') để điều chỉnh."
                )
                continue

            if adj.operation == "CUSTOMIZE_RATIONALE":
                raw_custom = (adj.custom_description or adj.reason or "").strip()
                if not raw_custom:
                    continue
                safe_custom = (
                    sanitize_prompt_text(raw_custom, max_len=400).strip()
                    if self.enable_security_guard
                    else raw_custom[:400]
                )
                if not safe_custom:
                    continue
                for idx in matched_indices:
                    act = working[idx]
                    if safe_custom not in (act.description or ""):
                        act.description = f"{(act.description or '').rstrip()} | {safe_custom}".strip(" |")
                applied_count += 1

            elif adj.operation == "REPRIORITIZE":
                if adj.new_priority is None:
                    continue
                new_prio = int(adj.new_priority)
                if new_prio < 1 or new_prio > 5:
                    continue
                for idx in matched_indices:
                    working[idx].priority = new_prio
                applied_count += 1

            elif adj.operation == "SUPPRESS_PER_FEEDBACK":
                idx_set = set(matched_indices)
                working = [act for idx, act in enumerate(working) if idx not in idx_set]
                applied_count += 1

        # Cưỡng chế bất biến an toàn trên toàn bộ hành động sau điều chỉnh
        for act in working:
            self.apply_approval_policy(act)
            act.is_approved = None

        return working

    # =====================================================================
    # 1C. TỔNG HỢP CHIẾN LƯỢC RAG GENERATION (INCIDENT COMMANDER LLM STRATEGY)
    # =====================================================================
    def synthesize_rag_response_strategy(
        self,
        state: IncidentState,
        rag_info: Optional[Dict[str, Any]] = None,
        proposed_actions: Optional[List[RecommendedAction]] = None,
    ) -> str:
        """
        Tổng hợp chiến lược phản ứng sự cố hoàn chỉnh (RAG Generation Loop):
        1. Retrieval: Tiếp nhận tri thức RAG đã truy xuất từ rag_info (MITRE Mitigations, Wazuh Remediation, TTP matches).
        2. Augmentation: Kết hợp toàn diện bối cảnh sự cố, danh sách proposed_actions, rca_result,
           analyst_feedback (+ reanalysis_count) và tri thức RAG (bọc qua SecurityGuard).
        3. Generation: Gọi invoke_structured_llm(..., schema_class=ResponseLLMStrategy, model_tier="reasoning")
           để sinh chiến lược và điều chỉnh action_adjustments an toàn (tương thích MockLLMProvider).
        4. Tích hợp kết quả: Lưu vào state.response_strategy_summary và self._last_llm_strategy.
        5. Fallback Engine: Nếu LLM bị tắt hoặc gặp lỗi, tự động chuyển tầng an toàn về chuỗi [NIST/MITRE RAG Guidance].
        """
        self._last_llm_strategy = None
        self._last_security_flags = []
        security_flags: List[Dict[str, str]] = []
        rag_info = rag_info or self._last_rag_info or self.lookup_rag_remediation(state)
        observed = self._collect_observed_grounding_entities(state)

        raw_remediations = [str(r).strip() for r in (rag_info.get("remediations") or []) if r and str(r).strip()]
        raw_mitigations = [str(m).strip() for m in (rag_info.get("mitigations") or []) if m and str(m).strip()]
        remediations = [self._sanitize_text_grounding(r, observed) for r in raw_remediations]
        mitigations = [self._sanitize_text_grounding(m, observed) for m in raw_mitigations]

        guidance_snippets: List[str] = []
        if remediations:
            guidance_snippets.append(f"Wazuh Remediation: {remediations[0]}")
        if mitigations:
            guidance_snippets.append(f"MITRE Mitigation: {mitigations[0]}")

        fallback_guidance = (
            f"[NIST/MITRE RAG Guidance] {' | '.join(guidance_snippets)}"
            if guidance_snippets
            else "[NIST/MITRE RAG Guidance] Tuân thủ quy trình kiểm soát và xử lý sự cố theo NIST SP 800-61."
        )

        # 1. Nếu LLM bị vô hiệu hóa, kích hoạt fallback ngay
        if not self.llm_enabled:
            strategy_summary = fallback_guidance
            self._last_strategy_summary = strategy_summary
            if hasattr(state, "response_strategy_summary"):
                state.response_strategy_summary = strategy_summary
            else:
                try:
                    setattr(state, "response_strategy_summary", strategy_summary)
                except Exception:
                    pass
            return strategy_summary

        # 2. Lazy import HybridLLMProvider nếu chưa được cung cấp
        if self.llm_provider is None:
            try:
                from src.copilot.llm_provider import HybridLLMProvider
                self.llm_provider = HybridLLMProvider()
            except Exception as exc:
                logger.warning(f"Không thể lazy import HybridLLMProvider cho ResponseAgent: {exc}")
                self.llm_provider = None

        if self.llm_provider is None:
            strategy_summary = fallback_guidance
            self._last_strategy_summary = strategy_summary
            if hasattr(state, "response_strategy_summary"):
                state.response_strategy_summary = strategy_summary
            else:
                try:
                    setattr(state, "response_strategy_summary", strategy_summary)
                except Exception:
                    pass
            return strategy_summary

        # 3. Thu thập ngữ cảnh chi tiết từ IncidentState (và bọc gọn qua SecurityGuard khi bật)
        context = self._extract_context(state)
        hosts_raw = ", ".join(context.get("hosts", [])) or "N/A"
        ips_raw = ", ".join(context.get("external_ips", []) or context.get("source_ips", [])) or "N/A"
        ips_str = (
            sanitize_prompt_text(ips_raw, max_len=300)
            if self.enable_security_guard and ips_raw != "N/A"
            else ips_raw
        )
        procs_raw = ", ".join(context.get("processes", [])) or "N/A"
        users_raw = ", ".join(context.get("users", [])) or "N/A"

        hosts_str = self._wrap_untrusted(
            hosts_raw,
            "response.hosts",
            max_len=400,
            include_notice=False,
            security_flags=security_flags,
        )
        procs_str = self._wrap_untrusted(
            procs_raw,
            "response.processes",
            max_len=400,
            include_notice=False,
            security_flags=security_flags,
        )
        users_str = self._wrap_untrusted(
            users_raw,
            "response.users",
            max_len=400,
            include_notice=False,
            security_flags=security_flags,
        )

        triage_summary_raw = ""
        if state.triage_result and state.triage_result.summary:
            triage_summary_raw = str(state.triage_result.summary)
        triage_summary_str = (
            self._wrap_untrusted(
                triage_summary_raw,
                "response.triage_summary",
                max_len=500,
                include_notice=False,
                security_flags=security_flags,
            )
            if triage_summary_raw
            else "N/A"
        )

        attack_type = "UNKNOWN"
        if state.triage_result and state.triage_result.attack_type:
            attack_type = str(state.triage_result.attack_type)
        elif state.attack_type:
            attack_type = str(state.attack_type)
        elif state.rca_result and state.rca_result.confirmed_attack_type:
            attack_type = str(state.rca_result.confirmed_attack_type)
        if self.enable_security_guard and attack_type not in ("UNKNOWN", "N/A"):
            attack_type = sanitize_prompt_text(attack_type, max_len=200)

        rca_section = "Chưa có kết quả RCA chi tiết."
        if state.rca_result:
            pz_node = next((n for n in (state.rca_result.process_tree or []) if n.is_malicious_origin), None)
            pz_text = f"{pz_node.process_name} (PID {pz_node.process_id})" if pz_node else "N/A"
            rca_raw = state.rca_result.root_cause_summary or ""
            rca_wrapped = (
                self._wrap_untrusted(
                    rca_raw,
                    "response.rca_summary",
                    max_len=600,
                    include_notice=False,
                    security_flags=security_flags,
                )
                if rca_raw
                else "N/A"
            )
            rca_section = (
                f"- Initial Access Vector: {state.rca_result.initial_access_vector}\n"
                f"- Patient Zero: {pz_text}\n"
                f"- Tóm tắt RCA:\n{rca_wrapped}"
            )

        actions_for_prompt = (
            proposed_actions
            if proposed_actions is not None
            else (state.recommended_actions or [])
        )
        if actions_for_prompt:
            action_lines = []
            for act in actions_for_prompt:
                phase_val = act.phase.value if act.phase else "N/A"
                action_lines.append(
                    f"- [{act.action_id}] {act.action_type.value} | target={act.target} "
                    f"| priority={act.priority} | phase={phase_val} "
                    f"| require_human_approval={act.require_human_approval}"
                )
            proposed_actions_str = "\n".join(action_lines)
        else:
            proposed_actions_str = "Chưa có hành động đề xuất."

        feedback_section = ""
        if state.analyst_feedback and str(state.analyst_feedback).strip():
            wrapped_fb = self._wrap_untrusted(
                state.analyst_feedback,
                "response.analyst_feedback",
                max_len=600,
                include_notice=False,
                security_flags=security_flags,
            )
            feedback_section = (
                f"\n=== PHẢN HỒI CHUYÊN VIÊN SOC (Lần thứ {state.reanalysis_count}) ===\n"
                f"{wrapped_fb}\n"
                f"Lưu ý: Bắt buộc phản hồi trong `analyst_feedback_addressed` và cân nhắc "
                f"`SUPPRESS_PER_FEEDBACK` hoặc `REPRIORITIZE` trong `action_adjustments` nếu hợp lý.\n"
            )

        self._last_security_flags = list(security_flags)
        guard_header = f"{UNTRUSTED_LOG_SECURITY_HEADER}\n\n" if self.enable_security_guard else ""

        mitre_ids = ", ".join(rag_info.get("mitre_ids", [])) or "N/A"
        rule_ids = ", ".join(rag_info.get("rule_ids", [])) or "N/A"
        mitigations_str = "; ".join(mitigations[:3]) if mitigations else "N/A"
        remediations_str = "; ".join(remediations[:3]) if remediations else "N/A"

        # 4. Xây dựng prompt tích hợp Ngữ cảnh sự cố + Proposed Actions + RCA + Feedback + Tri thức RAG
        prompt = (
            f"Bạn là Incident Commander đang điều phối phản ứng sự cố an ninh mạng theo chuẩn NIST SP 800-61.\n"
            f"Dựa trên ngữ cảnh sự cố, danh sách hành động đề xuất hiện tại và tri thức an ninh mạng từ RAG Knowledge Base (MITRE ATT&CK & Wazuh Rules),\n"
            f"hãy xây dựng chiến lược phản ứng chuẩn JSON schema ResponseLLMStrategy (Custom Mitigation Rationale & Operational Guidance):\n\n"
            f"{guard_header}"
            f"=== NGỮ CẢNH SỰ CỐ ===\n"
            f"- Mã sự cố (Incident ID): {state.incident_id}\n"
            f"- Loại tấn công (Attack Type): {attack_type}\n"
            f"- Tóm tắt Triage:\n{triage_summary_str}\n"
            f"- Máy trạm/Máy chủ mục tiêu (Target Hosts):\n{hosts_str}\n"
            f"- Địa chỉ IP tấn công/C2 (Attacker/C2 IPs): {ips_str}\n"
            f"- Tiến trình liên quan (Processes):\n{procs_str}\n"
            f"- Tài khoản ảnh hưởng (Compromised Users):\n{users_str}\n\n"
            f"=== KẾT QUẢ ĐIỀU TRA RCA ===\n"
            f"{rca_section}\n\n"
            f"=== DANH SÁCH HÀNH ĐỘNG ĐỀ XUẤT HIỆN TẠI (PROPOSED ACTIONS) ===\n"
            f"{proposed_actions_str}\n"
            f"{feedback_section}\n"
            f"=== TRI THỨC RAG TRUY XUẤT (RETRIEVED KNOWLEDGE) ===\n"
            f"- Kỹ thuật MITRE ATT&CK: {mitre_ids}\n"
            f"- Biện pháp giảm thiểu MITRE (Mitigations): {mitigations_str}\n"
            f"- Quy tắc cảnh báo Wazuh: {rule_ids}\n"
            f"- Hướng dẫn khắc phục Wazuh (Remediation): {remediations_str}\n\n"
            f"=== YÊU CẦU ĐẦU RA ===\n"
            f"Hãy tổng hợp phản hồi theo schema ResponseLLMStrategy gồm:\n"
            f"1. `rationale`, `containment_guidance`, `eradication_recovery_guidance`, `operational_safety_notes`.\n"
            f"2. `action_adjustments` (tối đa 3 điều chỉnh hợp lệ lên các hành động hiện có, không hạ phê duyệt rủi ro cao, không diệt tiến trình hệ thống).\n"
            f"3. `strategy_summary`: Tóm tắt súc tích 2-4 câu chỉ đạo tác chiến."
        )

        # 5. Gọi LLM Provider qua invoke_structured_llm
        strategy_obj, used_real_llm, info = invoke_structured_llm(
            self.llm_provider,
            prompt=prompt,
            schema_class=ResponseLLMStrategy,
            system_prompt=self.system_prompt,
            incident_state=state,
            model_tier="reasoning",
            temperature=0.15,
            agent_name="ResponseAgent",
        )

        if isinstance(strategy_obj, ResponseLLMStrategy) and used_real_llm:
            self._last_llm_strategy = strategy_obj
            summary_candidate = (strategy_obj.strategy_summary or strategy_obj.rationale or "").strip()
            strategy_summary = (
                self._sanitize_text_grounding(summary_candidate, observed)
                if summary_candidate
                else fallback_guidance
            )
        elif used_real_llm and isinstance(info, str) and info.strip():
            # Tương thích ngược MockLLMProvider tối giản chỉ định nghĩa generate_response()
            strategy_summary = self._sanitize_text_grounding(info.strip(), observed)
        else:
            strategy_summary = fallback_guidance

        self._last_strategy_summary = strategy_summary
        if hasattr(state, "response_strategy_summary"):
            state.response_strategy_summary = strategy_summary
        else:
            try:
                setattr(state, "response_strategy_summary", strategy_summary)
            except Exception:
                pass

        return strategy_summary

    # =====================================================================
    # 2. SINH HÀNH ĐỘNG TỪ PLAYBOOK VÀ WAZUH ACTIVE RESPONSE
    # =====================================================================
    def generate_malware_response(
        self,
        host_name: str,
        malicious_ip: str,
        process_name: str,
    ) -> List[RecommendedAction]:
        """
        Sinh danh sách hành động ngăn chặn mã độc theo NIST SP 800-61.
        Bao gồm: Cô lập máy trạm, chặn IP C2, tiêu diệt tiến trình độc hại.
        """
        raw_actions = self.playbooks.malware_incident_playbook(
            host_name=host_name,
            malicious_ip=malicious_ip,
            process_name=process_name,
        )
        for act in raw_actions:
            self.apply_approval_policy(act)
        return raw_actions

    def generate_phishing_response(
        self,
        compromised_user: str,
        phishing_ip: str,
    ) -> List[RecommendedAction]:
        """
        Sinh danh sách hành động xử lý lừa đảo và đánh cắp danh tính.
        Bao gồm: Thu hồi phiên đăng nhập, đặt lại mật khẩu và chặn IP tấn công.
        """
        raw_actions = self.playbooks.phishing_credential_playbook(
            compromised_user=compromised_user,
            phishing_ip=phishing_ip,
        )
        for act in raw_actions:
            self.apply_approval_policy(act)
        return raw_actions

    def create_wazuh_active_response(
        self,
        agent_id: str,
        command: str,
        target_ip: Optional[str] = None,
        use_wazuh_action_type: bool = False,
    ) -> RecommendedAction:
        """
        Tạo hành động Wazuh Active Response tích hợp với WazuhClientTool.
        Hỗ trợ các lệnh chuẩn: 'firewall-drop', 'host-isolate', 'kill-process'.
        """
        target = target_ip if target_ip else f"Agent-{agent_id}"
        if use_wazuh_action_type:
            action = RecommendedAction(
                action_type=ActionType.WAZUH_ACTIVE_RESPONSE,
                target=target,
                description=f"Wazuh Active Response [{command}] trên Agent ID {agent_id} (Target: {target}).",
                priority=1,
                require_human_approval=True,
            )
        else:
            action = self.wazuh_client.execute_active_response(
                agent_id=agent_id,
                command=command,
                target_ip=target_ip,
            )

        if not action.script_bundle:
            action.phase = IncidentPhase.CONTAINMENT
            action.script_bundle = self.playbooks.create_bundle(
                action_id=action.action_id or f"ACT-WAZUH-{command}",
                action_type=action.action_type,
                target=target,
                phase=IncidentPhase.CONTAINMENT,
            )

        self.apply_approval_policy(action)
        return action

    # =====================================================================
    # 3. DEDUPLICATION VÀ PRIORITY SORTING
    # =====================================================================
    def deduplicate_and_sort_actions(
        self,
        actions: List[RecommendedAction],
    ) -> List[RecommendedAction]:
        """
        Loại bỏ các hành động trùng lặp (theo action_type và target đã chuẩn hóa).
        Khi trùng, giữ lại hành động có mức ưu tiên cao hơn (chỉ số priority nhỏ hơn).
        Sắp xếp danh sách hành động theo thứ tự ưu tiên tăng dần (Priority 1 -> 5).
        """
        dedup_map: Dict[Tuple[ActionType, str], RecommendedAction] = {}

        for act in actions:
            target_norm = act.target.strip().lower()
            key = (act.action_type, target_norm)

            if key not in dedup_map:
                dedup_map[key] = act
            else:
                existing = dedup_map[key]
                # Nếu hành động mới có độ ưu tiên cao hơn (priority nhỏ hơn) thì ghi đè
                if act.priority < existing.priority:
                    dedup_map[key] = act

        # Sắp xếp theo: 1. Priority tăng dần, 2. action_type, 3. target
        sorted_actions = sorted(
            dedup_map.values(),
            key=lambda a: (a.priority, a.action_type.value, a.target),
        )
        return sorted_actions

    # =====================================================================
    # 4. KHẢO SÁT VÀ BÓC TÁCH NGỮ CẢNH TỪ INCIDENT STATE
    # =====================================================================
    def _extract_context(self, state: IncidentState) -> Dict[str, Any]:
        """Trích xuất toàn bộ thông tin đối tượng mục tiêu từ IncidentState."""
        hosts: Set[str] = set()
        users: Set[str] = set()
        processes: Set[str] = set()
        external_ips: Set[str] = set()
        source_ips: Set[str] = set()
        wazuh_agents: List[Dict[str, str]] = []

        # 1. Trích xuất từ parsed_events
        for event in state.parsed_events:
            if event.host_name and event.host_name not in {"UNKNOWN-HOST", ""}:
                hosts.add(event.host_name)

            if event.user_name and event.user_name.lower() not in self.SYSTEM_ACCOUNTS:
                users.add(event.user_name)

            if event.process_name:
                processes.add(event.process_name)

            if event.dest_ip and not self.is_private_ip(event.dest_ip):
                external_ips.add(event.dest_ip)

            if event.source_ip:
                if not self.is_private_ip(event.source_ip):
                    external_ips.add(event.source_ip)
                elif event.source_ip.strip() not in {"127.0.0.1", "::1"}:
                    source_ips.add(event.source_ip.strip())

            # Wazuh Agent metadata
            agent_id = event.raw_attributes.get("wazuh_agent_id")
            if agent_id:
                wazuh_agents.append({
                    "id": str(agent_id),
                    "name": event.raw_attributes.get("wazuh_agent_name") or event.host_name or f"agent-{agent_id}",
                    "ip": event.source_ip or event.dest_ip,
                })

        # 2. Trích xuất từ threat_intel
        if state.threat_intel:
            for ioc in state.threat_intel.extracted_iocs:
                if ioc.ioc_type.upper() == "IP" and not self.is_private_ip(ioc.value):
                    external_ips.add(ioc.value)

        # 3. Trích xuất từ rca_result
        if state.rca_result and state.rca_result.process_tree:
            for node in state.rca_result.process_tree:
                if node.is_malicious_origin or node.process_name:
                    processes.add(node.process_name)

        return {
            "hosts": sorted(list(hosts)),
            "users": sorted(list(users)),
            "processes": sorted(list(processes)),
            "external_ips": sorted(list(external_ips)),
            "source_ips": sorted(list(source_ips)),
            "wazuh_agents": wazuh_agents,
        }

    # =====================================================================
    # 5. RECOMMENDACTION ENGINE (SUY LUẬN THEO NIST SP 800-61)
    # =====================================================================
    def _build_user_containment_actions(
        self,
        user: str,
        revoke_id: str,
        reset_id: str,
    ) -> List[RecommendedAction]:
        """Tạo cặp hành động REVOKE_USER và RESET_PASSWORD cho tài khoản bị lộ lọt."""
        return [
            self.apply_approval_policy(
                RecommendedAction(
                    action_id=revoke_id,
                    action_type=ActionType.REVOKE_USER,
                    target=user,
                    description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {user}.",
                    priority=1,
                    require_human_approval=False,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=self.playbooks.create_bundle(
                        revoke_id, ActionType.REVOKE_USER, user, IncidentPhase.CONTAINMENT
                    ),
                )
            ),
            self.apply_approval_policy(
                RecommendedAction(
                    action_id=reset_id,
                    action_type=ActionType.RESET_PASSWORD,
                    target=user,
                    description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {user}.",
                    priority=2,
                    require_human_approval=True,
                    phase=IncidentPhase.ERADICATION,
                    script_bundle=self.playbooks.create_bundle(
                        reset_id, ActionType.RESET_PASSWORD, user, IncidentPhase.ERADICATION
                    ),
                )
            ),
        ]

    @staticmethod
    def _is_host_isolate_action(action: RecommendedAction) -> bool:
        """Kiểm tra hành động có phải cô lập máy trạm (ISOLATE_HOST hoặc lệnh Wazuh host-isolate) không."""
        if action.action_type == ActionType.ISOLATE_HOST:
            return True
        if "host-isolate" in (action.description or "").lower():
            return True
        params = action.parameters or {}
        if isinstance(params, dict):
            for val in params.values():
                if val is not None and "host-isolate" in str(val).lower():
                    return True
        elif "host-isolate" in str(params).lower():
            return True
        if action.script_bundle is not None:
            war = action.script_bundle.wazuh_active_response or {}
            if isinstance(war, dict) and "host-isolate" in str(war.get("command", "") or "").lower():
                return True
        return False

    def recommend_actions(self, state: IncidentState) -> List[RecommendedAction]:
        """
        Đề xuất danh sách các hành động ứng phó phù hợp dựa trên tình trạng sự cố.
        Phân loại theo NIST SP 800-61:
        - Priority 1: Ngăn chặn khẩn cấp (ISOLATE_HOST, BLOCK_IP, KILL_PROCESS, REVOKE_USER).
        - Priority 2: Triệt tiêu / Danh tính (RESET_PASSWORD, KILL_PROCESS).
        - Priority 3: Khôi phục hệ thống (PATCH_SYSTEM, Quét EDR).
        """
        self._last_security_flags = []
        # Nếu Triage đã kết luận là False Positive thì không đề xuất hành động ngăn chặn
        if state.triage_result and not state.triage_result.is_incident:
            logger.info(f"[{state.incident_id}] Sự cố được phân loại False Positive, không đề xuất hành động.")
            self._last_rag_info = {}
            return []

        context = self._extract_context(state)
        hosts = context["hosts"]
        users = context["users"]
        processes = context["processes"]
        external_ips = context["external_ips"]
        source_ips = context["source_ips"]
        wazuh_agents = context["wazuh_agents"]

        actions: List[RecommendedAction] = []

        # Nhận diện đặc tính sự cố từ RCA, Triage và Threat Intel
        rca = state.rca_result
        triage = state.triage_result
        cti = state.threat_intel

        triage_cat_str = ""
        if triage and triage.attack_category:
            triage_cat_str = str(
                triage.attack_category.value
                if hasattr(triage.attack_category, "value")
                else triage.attack_category
            ).upper()

        triage_type = (triage.attack_type.lower() if triage and triage.attack_type else "")
        rca_type = (rca.confirmed_attack_type.lower() if rca and rca.confirmed_attack_type else "")
        rca_vector = (rca.initial_access_vector.lower() if rca and rca.initial_access_vector else "")
        summary_text = (triage.summary.lower() if triage and triage.summary else "")
        combined_text = f"{triage_type} {rca_type} {rca_vector} {summary_text}"
        cmd_lines_text = " ".join((e.command_line or "").lower() for e in state.parsed_events)

        mitre_techniques = {m.lower() for m in (cti.mitre_techniques if cti else [])}
        for event in state.parsed_events:
            raw_m = (event.raw_attributes or {}).get("wazuh_mitre_ids", [])
            if isinstance(raw_m, list):
                mitre_techniques.update(str(m).lower() for m in raw_m)
            elif isinstance(raw_m, str):
                mitre_techniques.update(m.strip().lower() for m in raw_m.split(",") if m.strip())

        web_Server_procs = ("nginx", "apache", "httpd", "iis", "w3wp", "tomcat", "php")
        has_web_service = any(
            w in combined_text or any(w in p.lower() for p in processes) or any(w in (e.parent_process or "").lower() for e in state.parsed_events)
            for w in web_Server_procs
        )

        is_web_attack = (
            triage_cat_str == "WEB_ATTACK"
            or any(
                kw in combined_text
                for kw in (
                    "web_attack",
                    "web attack",
                    "sql injection",
                    "sqli",
                    "xss",
                    "cross-site scripting",
                    "webshell",
                    "web shell",
                    "exploit public-facing",
                )
            )
            or ("rce" in combined_text and has_web_service)
            or "t1190" in mitre_techniques
            or "t1505.003" in mitre_techniques
        )

        is_reconnaissance = (
            triage_cat_str == "RECONNAISSANCE"
            or any(
                kw in combined_text
                for kw in (
                    "reconnaissance",
                    "network scanning",
                    "port scan",
                    "icmp sweep",
                    "service discovery",
                    "syn scan",
                )
            )
            or "t1046" in mitre_techniques
            or "t1595" in mitre_techniques
        )

        is_ransomware = (
            any(
                kw in combined_text or kw in cmd_lines_text
                for kw in (
                    "ransomware",
                    "vssadmin",
                    "shadow copy",
                    "shadowcopy",
                    "data encrypted",
                )
            )
            or "t1486" in mitre_techniques
            or "t1490" in mitre_techniques
        )

        is_privilege_escalation = (
            triage_cat_str == "PRIVILEGE_ESCALATION"
            or any(
                kw in combined_text
                for kw in (
                    "privilege_escalation",
                    "privilege escalation",
                    "leo thang đặc quyền",
                    "sudo",
                )
            )
            or "t1548" in mitre_techniques
            or "t1068" in mitre_techniques
            or any(m.startswith("t1548.") for m in mitre_techniques)
        )

        is_specialized_scenario = (
            is_web_attack
            or is_reconnaissance
            or is_ransomware
            or is_privilege_escalation
        )

        if is_specialized_scenario:
            is_phishing_or_credential = (
                "phish" in combined_text
                or "credential" in combined_text
                or "brute" in combined_text
                or "t1110" in mitre_techniques
                or "t1566" in mitre_techniques
            )
            is_malware_or_c2 = False
        else:
            is_phishing_or_credential = (
                "phish" in rca_vector
                or "credential" in rca_vector
                or "brute" in rca_vector
                or "account" in rca_vector
                or "logon" in rca_vector
                or "rdp" in rca_vector
                or "t1078" in mitre_techniques
                or "t1110" in mitre_techniques
                or "t1003" in mitre_techniques
                or "t1566" in mitre_techniques
                or bool(users)
            )

            is_malware_or_c2 = (
                "malware" in rca_vector
                or "macro" in rca_vector
                or "exploit" in rca_vector
                or "powershell" in summary_text
                or "trojan" in summary_text
                or bool(processes)
                or bool(hosts)
                or not is_phishing_or_credential
            )

        # -------------------------------------------------------------
        # 0. CÁC TÌNH HUỐNG MỚI THEO CHUẨN NIST SP 800-61
        # -------------------------------------------------------------
        if is_web_attack:
            target_host = hosts[0] if hosts else "WEB-SERVER-01"
            attacker_ip = external_ips[0] if external_ips else (source_ips[0] if source_ips else None)
            shell_names = {"cmd.exe", "powershell.exe", "bash", "sh", "nc", "php-cgi", "cmd", "powershell", "pwsh", "nc.exe", "netcat"}
            web_proc: Optional[str] = None
            for p in processes:
                p_base = p.strip().lower().split("/")[-1].split("\\")[-1]
                if p_base in shell_names:
                    web_proc = p
                    break
            if web_proc is None and processes:
                web_proc = processes[0]

            if attacker_ip:
                web_actions = self.playbooks.web_attack_playbook(
                    host_name=target_host,
                    attacker_ip=attacker_ip,
                    web_process=web_proc,
                )
            else:
                web_actions = []
                if web_proc:
                    proc_clean = web_proc.strip().lower().split("/")[-1].split("\\")[-1]
                    if proc_clean in shell_names:
                        web_actions.append(
                            RecommendedAction(
                                action_id="ACT-WEB-KILL",
                                action_type=ActionType.KILL_PROCESS,
                                target=web_proc,
                                description=f"Tiêu diệt tiến trình shell độc hại {web_proc} sinh ra từ dịch vụ Web trên {target_host}.",
                                priority=2,
                                require_human_approval=False,
                                phase=IncidentPhase.ERADICATION,
                                script_bundle=self.playbooks.create_bundle("ACT-WEB-KILL", ActionType.KILL_PROCESS, web_proc, IncidentPhase.ERADICATION),
                            )
                        )
                web_actions.append(
                    RecommendedAction(
                        action_id="ACT-WEB-PATCH",
                        action_type=ActionType.PATCH_SYSTEM,
                        target=target_host,
                        description=f"Vá lỗ hổng ứng dụng Web (SQLi/RCE/XSS) và rà soát Web Shell trên máy chủ {target_host}.",
                        priority=3,
                        require_human_approval=False,
                        phase=IncidentPhase.RECOVERY,
                        script_bundle=self.playbooks.create_bundle("ACT-WEB-PATCH", ActionType.PATCH_SYSTEM, target_host, IncidentPhase.RECOVERY),
                    )
                )
            for act in web_actions:
                self.apply_approval_policy(act)
            actions.extend(web_actions)

            for ip_val in external_ips[1:]:
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=f"ACT-WEB-BLOCK-{ip_val}",
                            action_type=ActionType.BLOCK_IP,
                            target=ip_val,
                            description=f"Chặn địa chỉ IP tấn công Web phụ trợ {ip_val} trên WAF/Firewall.",
                            priority=1,
                            require_human_approval=True,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(f"ACT-WEB-BLOCK-{ip_val}", ActionType.BLOCK_IP, ip_val, IncidentPhase.CONTAINMENT),
                        )
                    )
                )

        if is_reconnaissance:
            attacker_ip = external_ips[0] if external_ips else (source_ips[0] if source_ips else None)
            target_host = hosts[0] if hosts else None
            if attacker_ip:
                recon_actions = self.playbooks.reconnaissance_playbook(
                    attacker_ip=attacker_ip,
                    target_host=target_host,
                )
            else:
                recon_actions = []
                for proc in processes:
                    if not self.playbooks.is_critical_system_process(proc) and not is_protected_process(proc):
                        recon_actions.append(
                            RecommendedAction(
                                action_id=f"ACT-RECON-KILL-{proc}",
                                action_type=ActionType.KILL_PROCESS,
                                target=proc,
                                description=f"Tiêu diệt tiến trình dò quét nội bộ {proc} trên {target_host or 'WORKSTATION-01'}.",
                                priority=2,
                                require_human_approval=False,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle(f"ACT-RECON-KILL-{proc}", ActionType.KILL_PROCESS, proc, IncidentPhase.CONTAINMENT),
                            )
                        )
                        break
                if target_host or not recon_actions:
                    harden_target = target_host or "NETWORK-PERIMETER"
                    recon_actions.append(
                        RecommendedAction(
                            action_id="ACT-RECON-HARDEN",
                            action_type=ActionType.PATCH_SYSTEM,
                            target=harden_target,
                            description=f"Đóng các cổng dịch vụ không cần thiết và rà soát cấu hình Firewall trên {harden_target}.",
                            priority=3,
                            require_human_approval=False,
                            phase=IncidentPhase.RECOVERY,
                            script_bundle=self.playbooks.create_bundle("ACT-RECON-HARDEN", ActionType.PATCH_SYSTEM, harden_target, IncidentPhase.RECOVERY),
                        )
                    )
            for act in recon_actions:
                self.apply_approval_policy(act)
            actions.extend(recon_actions)

        if is_ransomware:
            target_host = hosts[0] if hosts else "WORKSTATION-01"
            target_proc = processes[0] if processes else None
            c2_ip = external_ips[0] if external_ips else None
            comp_user = users[0] if users else None
            ransom_actions = self.playbooks.ransomware_incident_playbook(
                host_name=target_host,
                process_name=target_proc,
                c2_ip=c2_ip,
                compromised_user=comp_user,
            )
            for act in ransom_actions:
                self.apply_approval_policy(act)
            actions.extend(ransom_actions)

        if is_privilege_escalation:
            target_host = hosts[0] if hosts else "WORKSTATION-01"
            comp_user = users[0] if users else None
            rogue_proc = processes[0] if processes else None
            privesc_actions = self.playbooks.privilege_escalation_playbook(
                host_name=target_host,
                compromised_user=comp_user,
                rogue_process=rogue_proc,
            )
            for act in privesc_actions:
                self.apply_approval_policy(act)
            actions.extend(privesc_actions)

        # -------------------------------------------------------------
        # 1. CONTAINMENT & ERADICATION: MALWARE / C2 INTRUSION
        # -------------------------------------------------------------
        if is_malware_or_c2:
            target_host = hosts[0] if hosts else "WORKSTATION-01"
            target_proc = processes[0] if processes else None

            if external_ips and target_proc:
                malware_actions = self.generate_malware_response(
                    host_name=target_host,
                    malicious_ip=external_ips[0],
                    process_name=target_proc,
                )
                actions.extend(malware_actions)
            else:
                # Không bịa IP C2 hay tiến trình giả khi thiếu dữ liệu quan sát
                if hosts or (not external_ips and not target_proc):
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_id="ACT-MALW-ISOLATE",
                                action_type=ActionType.ISOLATE_HOST,
                                target=target_host,
                                description=f"Cô lập máy trạm {target_host} khỏi mạng nội bộ để ngăn chặn lây lan.",
                                priority=1,
                                require_human_approval=True,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle("ACT-MALW-ISOLATE", ActionType.ISOLATE_HOST, target_host, IncidentPhase.CONTAINMENT),
                            )
                        )
                    )
                if target_proc:
                    is_crit = self.playbooks.is_critical_system_process(target_proc)
                    kill_desc = (
                        f"CẢNH BÁO: Tiến trình {target_proc} là tiến trình hệ thống trọng yếu. Đề xuất cô lập máy trạm thay vì tiêu diệt."
                        if is_crit
                        else f"Tiêu diệt tiến trình độc hại {target_proc} đang chạy trên máy trạm."
                    )
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_id="ACT-MALW-KILL",
                                action_type=ActionType.KILL_PROCESS,
                                target=target_proc,
                                description=kill_desc,
                                priority=1 if is_crit else 2,
                                require_human_approval=True if is_crit else False,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle("ACT-MALW-KILL", ActionType.KILL_PROCESS, target_proc, IncidentPhase.CONTAINMENT),
                            )
                        )
                    )
                if external_ips:
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_id="ACT-MALW-BLOCK",
                                action_type=ActionType.BLOCK_IP,
                                target=external_ips[0],
                                description=f"Chặn địa chỉ IP C2 {external_ips[0]} trên Firewall và Web Proxy.",
                                priority=1,
                                require_human_approval=True,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle("ACT-MALW-BLOCK", ActionType.BLOCK_IP, external_ips[0], IncidentPhase.CONTAINMENT),
                            )
                        )
                    )

            # Bổ sung các host khác nếu có nhiều host bị ảnh hưởng
            for h in hosts[1:]:
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=f"ACT-MALW-ISOLATE-{h}",
                            action_type=ActionType.ISOLATE_HOST,
                            target=h,
                            description=f"Cô lập máy trạm {h} khỏi mạng nội bộ để ngăn chặn lây lan ngang.",
                            priority=1,
                            require_human_approval=True,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(f"ACT-MALW-ISOLATE-{h}", ActionType.ISOLATE_HOST, h, IncidentPhase.CONTAINMENT),
                        )
                    )
                )

            # Bổ sung các tiến trình độc hại khác nếu phát hiện từ RCA tree
            if rca and rca.process_tree:
                for node in rca.process_tree:
                    if node.process_name and (not target_proc or node.process_name.lower() != target_proc.lower()):
                        actions.append(
                            self.apply_approval_policy(
                                RecommendedAction(
                                    action_id=f"ACT-KILL-{node.process_name}",
                                    action_type=ActionType.KILL_PROCESS,
                                    target=node.process_name,
                                    description=f"Tiêu diệt tiến trình độc hại liên quan {node.process_name} (PID: {node.process_id}).",
                                    priority=2,
                                    require_human_approval=False,
                                    phase=IncidentPhase.CONTAINMENT,
                                    script_bundle=self.playbooks.create_bundle(f"ACT-KILL-{node.process_name}", ActionType.KILL_PROCESS, node.process_name, IncidentPhase.CONTAINMENT),
                                )
                            )
                        )

            # Bổ sung các IP C2 khác nếu có
            for ip_val in external_ips[1:]:
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=f"ACT-BLOCK-{ip_val}",
                            action_type=ActionType.BLOCK_IP,
                            target=ip_val,
                            description=f"Chặn địa chỉ IP C2 phụ trợ {ip_val} trên Firewall và Web Proxy.",
                            priority=1,
                            require_human_approval=True,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(f"ACT-BLOCK-{ip_val}", ActionType.BLOCK_IP, ip_val, IncidentPhase.CONTAINMENT),
                        )
                    )
                )

        # -------------------------------------------------------------
        # 2. CONTAINMENT & ERADICATION: PHISHING & CREDENTIAL COMPROMISE
        # -------------------------------------------------------------
        if is_phishing_or_credential:
            target_user = users[0] if users else "compromised_user"
            if external_ips:
                phishing_actions = self.generate_phishing_response(
                    compromised_user=target_user,
                    phishing_ip=external_ips[0],
                )
                actions.extend(phishing_actions)
            else:
                # Sự cố lộ tài khoản nội bộ không có IP ngoài
                act_revoke_id = "ACT-PHISH-REVOKE"
                act_reset_id = "ACT-PHISH-RESET"
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_revoke_id,
                            action_type=ActionType.REVOKE_USER,
                            target=target_user,
                            description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {target_user}.",
                            priority=1,
                            require_human_approval=False,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(act_revoke_id, ActionType.REVOKE_USER, target_user, IncidentPhase.CONTAINMENT),
                        )
                    )
                )
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_reset_id,
                            action_type=ActionType.RESET_PASSWORD,
                            target=target_user,
                            description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {target_user}.",
                            priority=2,
                            require_human_approval=True,
                            phase=IncidentPhase.ERADICATION,
                            script_bundle=self.playbooks.create_bundle(act_reset_id, ActionType.RESET_PASSWORD, target_user, IncidentPhase.ERADICATION),
                        )
                    )
                )
                if source_ips:
                    act_block_id = "ACT-PHISH-BLOCK"
                    actions.append(
                        self.apply_approval_policy(
                            RecommendedAction(
                                action_id=act_block_id,
                                action_type=ActionType.BLOCK_IP,
                                target=source_ips[0],
                                description=f"Chặn IP {source_ips[0]} đã sử dụng tài khoản đăng nhập trái phép.",
                                priority=1,
                                require_human_approval=True,
                                phase=IncidentPhase.CONTAINMENT,
                                script_bundle=self.playbooks.create_bundle(act_block_id, ActionType.BLOCK_IP, source_ips[0], IncidentPhase.CONTAINMENT),
                            )
                        )
                    )

            # Bổ sung các tài khoản khác nếu có
            for u in users[1:]:
                act_revoke_u = f"ACT-PHISH-REVOKE-{u}"
                act_reset_u = f"ACT-PHISH-RESET-{u}"
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_revoke_u,
                            action_type=ActionType.REVOKE_USER,
                            target=u,
                            description=f"Thu hồi toàn bộ phiên đăng nhập đang hoạt động của người dùng {u}.",
                            priority=1,
                            require_human_approval=False,
                            phase=IncidentPhase.CONTAINMENT,
                            script_bundle=self.playbooks.create_bundle(act_revoke_u, ActionType.REVOKE_USER, u, IncidentPhase.CONTAINMENT),
                        )
                    )
                )
                actions.append(
                    self.apply_approval_policy(
                        RecommendedAction(
                            action_id=act_reset_u,
                            action_type=ActionType.RESET_PASSWORD,
                            target=u,
                            description=f"Buộc đặt lại mật khẩu và cấu hình lại xác thực đa yếu tố (MFA) cho {u}.",
                            priority=2,
                            require_human_approval=True,
                            phase=IncidentPhase.ERADICATION,
                            script_bundle=self.playbooks.create_bundle(act_reset_u, ActionType.RESET_PASSWORD, u, IncidentPhase.ERADICATION),
                        )
                    )
                )

        # -------------------------------------------------------------
        # 3. WAZUH ACTIVE RESPONSE (NẾU CÓ WAZUH AGENT LIÊN QUAN)
        # -------------------------------------------------------------
        if self.enable_wazuh_active_response and wazuh_agents:
            primary_agent = wazuh_agents[0]
            agent_id = primary_agent["id"]

            if external_ips:
                for ext_ip in external_ips[:2]:
                    actions.append(
                        self.create_wazuh_active_response(
                            agent_id=agent_id,
                            command="firewall-drop",
                            target_ip=ext_ip,
                        )
                    )

            if not (is_reconnaissance or is_web_attack or is_privilege_escalation):
                actions.append(
                    self.create_wazuh_active_response(
                        agent_id=agent_id,
                        command="host-isolate",
                        target_ip=None,
                    )
                )

        # Loại bỏ trùng lặp và sắp xếp ứng viên ban đầu trước khi gửi sang LLM Strategy
        candidate_actions = self.deduplicate_and_sort_actions(actions)

        # -------------------------------------------------------------
        # 5. ĐÍNH KÈM TRI THỨC RAG & GENERATION CHIẾN LƯỢC (NIST/MITRE/WAZUH)
        # -------------------------------------------------------------
        rag_info = self.lookup_rag_remediation(state)
        self._last_rag_info = rag_info

        # Hoàn thiện vòng lặp: Retrieval -> Augmentation (kèm proposed_actions + feedback) -> Generation
        strategy_summary = self.synthesize_rag_response_strategy(
            state,
            rag_info,
            proposed_actions=candidate_actions,
        )

        # Áp dụng điều chỉnh an toàn từ LLM Strategy (tối đa 3 điều chỉnh hợp lệ)
        if self._last_llm_strategy is not None:
            candidate_actions = self._apply_llm_action_adjustments(
                candidate_actions,
                self._last_llm_strategy,
                state,
            )

        # -------------------------------------------------------------
        # 6. ADAPTIVE FEEDBACK FALLBACK (QUY TẮC XÁC ĐỊNH DỰ PHÒNG KHI QUAY LUI)
        # -------------------------------------------------------------
        if state.analyst_feedback:
            feedback_lower = state.analyst_feedback.lower()
            # Nếu chuyên viên từ chối cô lập host (hoặc máy chủ quan trọng Domain Controller / Database)
            if any(term in feedback_lower for term in ["không cô lập", "từ chối cô lập", "không isolate", "không ngắt kết nối", "domain controller", "dc-server"]):
                logger.info("Phát hiện chỉ thị từ chối cô lập host từ phản hồi của chuyên viên. Tự động loại bỏ hành động ISOLATE_HOST.")
                candidate_actions = [
                    a for a in candidate_actions
                    if not self._is_host_isolate_action(a)
                ]
                # Đảm bảo bổ sung hành động tiêu diệt tiến trình độc hại thay thế nếu chưa có (tránh tiến trình hệ thống trọng yếu)
                if not any(a.action_type == ActionType.KILL_PROCESS for a in candidate_actions) and processes:
                    non_crit_procs = [
                        p for p in processes
                        if not self.playbooks.is_critical_system_process(p) and not is_protected_process(p)
                    ]
                    if non_crit_procs:
                        candidate_actions.append(
                            self.apply_approval_policy(
                                RecommendedAction(
                                    action_type=ActionType.KILL_PROCESS,
                                    target=non_crit_procs[0],
                                    description=f"Tiêu diệt tiến trình độc hại {non_crit_procs[0]} thay thế cho phương án cô lập host.",
                                    priority=1,
                                    require_human_approval=False,
                                )
                            )
                        )

        final_actions = self.deduplicate_and_sort_actions(candidate_actions)
        for act in final_actions:
            self.apply_approval_policy(act)
            act.is_approved = None

        if strategy_summary:
            guidance_tag = (
                strategy_summary
                if any(strategy_summary.startswith(p) for p in ("[NIST/MITRE RAG Guidance]", "[NIST/MITRE RAG Strategy]", "[RAG Strategy]"))
                else f"[NIST/MITRE RAG Guidance] {strategy_summary}"
            )
            for act in final_actions:
                if act.script_bundle:
                    current_inst = act.script_bundle.instructions or ""
                    if not any(tag in current_inst for tag in ("[NIST/MITRE RAG Guidance]", "[NIST/MITRE RAG Strategy]", "[RAG Strategy]")):
                        base_inst = current_inst.strip()
                        act.script_bundle.instructions = f"{base_inst} {guidance_tag}".strip()

        return final_actions

    # =====================================================================
    # 6. PIPELINE & STATEGRAPH INTERACTION
    # =====================================================================
    def process_state(self, state: IncidentState) -> IncidentState:
        """
        Thực thi đề xuất hành động và cập nhật trực tiếp vào IncidentState của StateGraph.

        :param state: IncidentState hiện tại.
        :return: IncidentState đã cập nhật recommended_actions và lịch sử chuyển dịch.
        """
        logger.info(f"[{state.incident_id}] Bắt đầu quy trình đề xuất phản ứng sự cố...")

        actions = self.recommend_actions(state)
        state.recommended_actions = actions

        action_summary = [f"{a.action_type.value}({a.target})" for a in actions]
        rag_info = self._last_rag_info or self.lookup_rag_remediation(state)
        rag_ttp_matches = [
            t.get("technique_id") or t.get("id")
            for t in rag_info.get("ttp_matches", [])
            if isinstance(t, dict) and (t.get("technique_id") or t.get("id"))
        ]
        rag_remediations = list(rag_info.get("remediations", [])) + list(rag_info.get("mitigations", []))

        strategy_summary = getattr(state, "response_strategy_summary", None) or self._last_strategy_summary
        if not strategy_summary and actions:
            strategy_summary = self.synthesize_rag_response_strategy(state, rag_info)
            if hasattr(state, "response_strategy_summary"):
                state.response_strategy_summary = strategy_summary

        transition_metadata: Dict[str, Any] = {
            "action_count": len(actions),
            "actions": [a.action_type.value for a in actions],
            "action_summary": action_summary,
            "high_priority_count": sum(1 for a in actions if a.priority == 1),
            "require_approval_count": sum(1 for a in actions if a.require_human_approval),
            "rag_ttp_matches": rag_ttp_matches,
            "rag_remediations": rag_remediations,
            "response_strategy_summary": strategy_summary,
        }
        if self._last_security_flags:
            transition_metadata["security_guard_flags"] = list(self._last_security_flags)

        state.record_transition(
            node="response",
            to_status=IncidentStatus.INVESTIGATING,
            message=f"Đã đề xuất {len(actions)} hành động ứng phó theo chuẩn NIST SP 800-61.",
            metadata=transition_metadata,
        )

        logger.info(f"[{state.incident_id}] Đã sinh {len(actions)} hành động (HITL required: {sum(1 for a in actions if a.require_human_approval)}).")
        return state

    def analyze_state(self, state: IncidentState) -> IncidentState:
        """Bí danh tương thích cho process_state."""
        return self.process_state(state)

    def evaluate(self, state: IncidentState) -> List[RecommendedAction]:
        """Bí danh tương thích cho recommend_actions."""
        return self.recommend_actions(state)


ResponseRecommendationAgent = ResponseAgent

__all__ = ["ResponseAgent", "ResponseRecommendationAgent"]

