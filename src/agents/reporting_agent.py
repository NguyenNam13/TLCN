# -*- coding: utf-8 -*-
"""
src/agents/reporting_agent.py
Reporting Agent phụ trách tổng hợp và xuất bản Báo cáo Điều tra Sự cố An ninh Mạng toàn diện.
Được thiết kế cho Hệ thống Multi-Agent SOC (Đề tài Khóa luận Tốt nghiệp TLCN-NAM).

Nhiệm vụ:
1. Tiếp nhận toàn bộ trạng thái IncidentState cuối cùng từ LangGraph pipeline.
2. Xây dựng các thành phần báo cáo gắn chặt với bằng chứng thực tế (Evidence-Grounded):
   - Executive Summary (cho CISO/CIO)
   - Technical Detailed Findings (cho SOC Tier 2/3 & DFIR)
   - IoC Table (chỉ số xâm phạm kèm danh tiếng, nhóm APT)
   - Action Plan (kế hoạch hành động kèm độ ưu tiên và trạng thái duyệt HITL)
   - Operational Metrics, Impact Assessment, Deep RCA Breakdown, Integrity Gate, CAPA Plan
3. Hỗ trợ cơ chế Fallback Graceful khi dữ liệu thiếu hụt hoặc chưa qua một số node (tuyệt đối không bịa dữ liệu).
4. Xuất bản báo cáo đa định dạng: Pydantic v2 Model, Markdown chuẩn hóa cho Streamlit UI, JSON và Word (.docx).
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union
from datetime import datetime, timezone
import io
import ipaddress
import json
import logging
import re

from src.core.schemas import (
    ActionType,
    AttackCategory,
    CAPAItem,
    CIADimension,
    DeepRCABreakdown,
    ImpactAssessment,
    IncidentPhase,
    IncidentReport,
    IncidentStatus,
    IoCItem,
    OperationalMetrics,
    RecommendedAction,
    ReportingLLMSynthesis,
    SeverityLevel,
    VerificationGateItem,
)
from src.core.security_guard import (
    UNTRUSTED_LOG_SECURITY_HEADER,
    inspect_and_wrap_untrusted,
    sanitize_prompt_text,
)
from src.core.state import IncidentState
from src.core.time_utils import format_vn_time
from src.agents.llm_utils import invoke_structured_llm
from src.agents.prompts import REPORTING_AGENT_SYSTEM_PROMPT

logger = logging.getLogger("ReportingAgent")

DEFAULT_ORGANIZATION_NAME = "Hệ thống Điều tra An ninh Mạng HCMUTE"
DEFAULT_DOCX_ORGANIZATION_NAME = "TRƯỜNG ĐẠI HỌC SƯ PHẠM KỸ THUẬT TP. HỒ CHÍ MINH (HCMUTE)"
UNMEASURED_METRIC_LABEL = "Chưa đo lường (thiếu dữ liệu mốc thời gian)"
_MITRE_CODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TITLE_SEVERITY_RE = re.compile(r"\[(CRITICAL|HIGH|MEDIUM|LOW|BENIGN)\]", re.IGNORECASE)
_NEGATION_PREFIX_RE = re.compile(
    r"(?:không(?:\s+(?:có|phát\s+hiện|ghi\s+nhận|qua|liên\s+quan|chứa|bị))?|"
    r"chưa(?:\s+(?:có|phát\s+hiện|ghi\s+nhận))?|"
    r"\bno\b|\bwithout\b|\bnot\b|\bnon-)\s*(?:\w+\s+){0,3}$",
    re.IGNORECASE,
)
_POWERSHELL_RE = re.compile(
    r"\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|t1059\.001|encodedcommand|executionpolicy\s+bypass)\b",
    re.IGNORECASE,
)
_MACRO_RE = re.compile(
    r"(?:\boffice\s+macro\b|\bmacro\b|\bwinword(?:\.exe)?\b|\bexcel\.exe\b|\bpowerpnt\.exe\b|"
    r"\.(?:docm|xlsm|pptm)\b|\bspearphishing\b|\bt1566(?:\.\d{3})?\b)",
    re.IGNORECASE,
)
_PII_EXFIL_RE = re.compile(
    r"\b(?:pii|dữ liệu cá nhân|personal data|cccd|cmnd|hồ sơ khách hàng|customer data|"
    r"medical record|lộ lọt dữ liệu|data breach|data exfiltration|exfiltrat\w*|"
    r"trích xuất dữ liệu|database dump|sql dump)\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_CURRENCY_RE = re.compile(
    r"(?:\d[\d\.,]*\s*(?:vnđ|vnd|triệu|tỷ|usd|\$)|(?:\$|usd)\s*\d[\d\.,]*)",
    re.IGNORECASE,
)
_LSASS_RE = re.compile(r"\blsass(?:\.exe)?\b", re.IGNORECASE)
_PRIVATE_NETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("255.255.255.255/32"),
)


class ReportingAgent:
    """
    Reporting Agent trong hệ thống Multi-Agent SOC.
    Tổng hợp toàn diện dữ liệu điều tra từ các Agent (Triage, CTI, RCA, Response, HITL)
    thành Báo cáo Điều tra Sự cố An ninh Mạng gắn chặt với bằng chứng thực tế.
    """

    def __init__(
        self,
        system_prompt: Optional[str] = None,
        organization_name: str = DEFAULT_ORGANIZATION_NAME,
        include_raw_logs: bool = False,
        llm_provider: Optional[Any] = None,
        llm_enabled: bool = True,
        enable_security_guard: bool = True,
        rag_kb: Optional[Any] = None,
    ):
        """
        Khởi tạo Reporting Agent.

        :param system_prompt: System prompt định hướng vai trò Agent.
        :param organization_name: Tên cơ quan/tổ chức điều tra an ninh mạng.
        :param include_raw_logs: Cờ bật/tắt chèn toàn bộ log thô vào báo cáo chi tiết.
        :param llm_provider: Provider kết nối LLM (tùy chọn).
        :param llm_enabled: Cờ bật/tắt khả năng suy luận LLM.
        :param enable_security_guard: Cờ bật/tắt bọc và phát hiện Prompt Injection cho dữ liệu đầu vào.
        :param rag_kb: Công cụ RAG tùy chọn cung cấp tri thức MITRE cho bước kiểm chứng grounding.
        """
        self.system_prompt = system_prompt or REPORTING_AGENT_SYSTEM_PROMPT
        self.organization_name = organization_name
        self.include_raw_logs = include_raw_logs
        self.llm_provider = llm_provider
        self.llm_enabled = llm_enabled
        self.enable_security_guard = enable_security_guard
        self.rag_kb = rag_kb
        self._last_grounding_violations: List[str] = []
        self._last_security_flags: List[Dict[str, str]] = []
        self._last_grounded_synthesis: Optional[ReportingLLMSynthesis] = None

    # =====================================================================
    # 0. HELPERS TRÍCH XUẤT NGỮ CẢNH THỰC TẾ (GROUNDING HELPERS)
    # =====================================================================
    @staticmethod
    def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
        """Chuẩn hóa đối tượng datetime về UTC để so sánh mốc thời gian an toàn."""
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _format_duration_vi(seconds: float) -> str:
        """Định dạng khoảng thời gian đo được thành chuỗi tiếng Việt tự nhiên."""
        secs = max(0.0, float(seconds))
        if secs < 1.0:
            return "0 giây" if secs == 0.0 else f"{secs:.2f} giây"
        if secs < 60.0:
            return f"{int(round(secs))} giây"
        if secs < 3600.0:
            mins = int(secs // 60)
            rem_secs = int(round(secs % 60))
            if rem_secs == 60:
                mins += 1
                rem_secs = 0
            return f"{mins} phút {rem_secs} giây" if rem_secs > 0 else f"{mins} phút"
        hours = int(secs // 3600)
        mins = int((secs % 3600) // 60)
        return f"{hours} giờ {mins} phút" if mins > 0 else f"{hours} giờ"

    @staticmethod
    def _get_triage(state: Optional[IncidentState]) -> Optional[Any]:
        """Lấy kết quả triage từ IncidentState (hỗ trợ cả alias triage_result/triage)."""
        if state is None:
            return None
        return getattr(state, "triage_result", None) or getattr(state, "triage", None)

    @staticmethod
    def _get_rca(state: Optional[IncidentState]) -> Optional[Any]:
        """Lấy kết quả RCA từ IncidentState (hỗ trợ cả alias rca_result/rca)."""
        if state is None:
            return None
        return getattr(state, "rca_result", None) or getattr(state, "rca", None)

    @staticmethod
    def _get_actions(
        report: Optional[IncidentReport],
        state: Optional[IncidentState] = None,
    ) -> List[RecommendedAction]:
        """Trích xuất danh sách hành động phản ứng ưu tiên từ state, fallback sang report."""
        if state is not None:
            state_actions = getattr(state, "recommended_actions", None)
            if state_actions:
                return list(state_actions)
            resp = getattr(state, "response", None)
            if isinstance(resp, list):
                return list(resp)
            if resp is not None and hasattr(resp, "recommended_actions"):
                return list(getattr(resp, "recommended_actions") or [])
        if report is not None and report.action_plan:
            return list(report.action_plan)
        return []

    @staticmethod
    def _is_action_rolled_back(action: RecommendedAction) -> bool:
        """Kiểm tra hành động đã bị hoàn tác (rollback) hay chưa."""
        return bool(action.parameters and action.parameters.get("rollback_executed"))

    @classmethod
    def _is_action_executed(
        cls,
        action: RecommendedAction,
        state: Optional[IncidentState] = None,
        report: Optional[IncidentReport] = None,
    ) -> bool:
        """
        Xác định hành động thực sự đã được thực thi (EXECUTED) hay chưa.
        Không bao giờ tính hành động đang chờ duyệt, bị từ chối hoặc đã hoàn tác.
        """
        if cls._is_action_rolled_back(action):
            return False
        if action.is_approved is False or action.is_approved is None:
            return False

        params = action.parameters or {}
        if "execution_status" in params and params["execution_status"] is not None:
            return str(params["execution_status"]).strip().upper() == "EXECUTED"
        if "executed" in params:
            return bool(params["executed"])
        if params.get("executed_at"):
            return True

        explicit_attr_status = getattr(action, "execution_status", None)
        if explicit_attr_status is not None:
            return str(explicit_attr_status).strip().upper() == "EXECUTED"

        # Tương thích pipeline chuẩn: hành động đã duyệt trong trạng thái CONTAINED/RESOLVED
        if state is not None:
            cur_status = state.status.value if hasattr(state.status, "value") else str(state.status)
            return cur_status in {IncidentStatus.CONTAINED.value, IncidentStatus.RESOLVED.value}
        if report is not None and report.incident_status:
            return str(report.incident_status).upper() in {
                IncidentStatus.CONTAINED.value,
                IncidentStatus.RESOLVED.value,
            }
        return False

    @classmethod
    def _is_benign_context(
        cls,
        report: Optional[IncidentReport],
        state: Optional[IncidentState] = None,
    ) -> bool:
        """Kiểm tra ngữ cảnh sự kiện là Benign / False Positive hay sự cố thực tế."""
        triage = cls._get_triage(state)
        if triage is not None:
            if getattr(triage, "is_incident", True) is False:
                return True
            t_cat = getattr(triage, "attack_category", None)
            t_cat_val = t_cat.value if hasattr(t_cat, "value") else (str(t_cat) if t_cat else "")
            if t_cat_val.upper() == AttackCategory.BENIGN.value:
                return True

        if state is not None:
            st_val = state.status.value if hasattr(state.status, "value") else str(state.status)
            if st_val == IncidentStatus.CLOSED_FALSE_POSITIVE.value:
                return True
            if state.attack_type and any(
                k in state.attack_type.lower() for k in ("benign", "normal administrative", "false positive")
            ):
                return True

        if report is not None:
            if report.is_incident is False:
                return True
            if report.incident_status and str(report.incident_status).upper() == IncidentStatus.CLOSED_FALSE_POSITIVE.value:
                return True
            if report.attack_category and str(report.attack_category).upper() == AttackCategory.BENIGN.value:
                return True
            if report.attack_type and any(
                k in report.attack_type.lower() for k in ("benign", "normal administrative", "false positive")
            ):
                return True

        return False

    @classmethod
    def _resolve_report_severity(
        cls,
        report: Optional[IncidentReport],
        state: Optional[IncidentState] = None,
    ) -> str:
        """
        Trích xuất mức độ nghiêm trọng thực tế từ Triage / Report / Attack Category.
        Tuyệt đối không trả về nhãn cứng 'CRITICAL / HIGH'.
        """
        triage = cls._get_triage(state)
        if triage is not None:
            if getattr(triage, "is_incident", True) is False:
                t_cat = getattr(triage, "attack_category", None)
                t_cat_val = t_cat.value if hasattr(t_cat, "value") else (str(t_cat) if t_cat else "")
                if t_cat_val.upper() == AttackCategory.BENIGN.value or (
                    state is not None and state.status == IncidentStatus.CLOSED_FALSE_POSITIVE
                ):
                    return "BENIGN"
            sev = getattr(triage, "severity", None)
            if sev is not None:
                return sev.value if hasattr(sev, "value") else str(sev).upper()

        if report is not None and report.severity:
            return str(report.severity).strip().upper()

        if cls._is_benign_context(report, state):
            return "BENIGN"

        if report is not None and report.incident_title:
            match = _TITLE_SEVERITY_RE.search(report.incident_title)
            if match:
                return match.group(1).upper()

        if report is not None and report.attack_category:
            cat_up = str(report.attack_category).upper()
            if cat_up == AttackCategory.BENIGN.value:
                return "BENIGN"
            if cat_up == AttackCategory.RECONNAISSANCE.value:
                return SeverityLevel.MEDIUM.value

        return "Chưa xác định"

    @classmethod
    def _collect_evidence_text(
        cls,
        report: Optional[IncidentReport],
        state: Optional[IncidentState] = None,
    ) -> str:
        """Gom chuỗi văn bản bằng chứng thực tế từ report và state (chữ thường)."""
        parts: List[str] = []
        if report is not None:
            if report.attack_type:
                parts.append(str(report.attack_type))
            if report.attack_category:
                parts.append(str(report.attack_category))
            if report.executive_summary:
                parts.append(report.executive_summary)
            if report.detailed_findings:
                parts.append(report.detailed_findings)
            if report.mitre_attack_matrix_mapping:
                parts.extend(str(m) for m in report.mitre_attack_matrix_mapping)
            if report.response_strategy_summary:
                parts.append(report.response_strategy_summary)

        if state is not None:
            triage = cls._get_triage(state)
            if triage is not None:
                if getattr(triage, "summary", None):
                    parts.append(str(triage.summary))
                if getattr(triage, "attack_type", None):
                    parts.append(str(triage.attack_type))
            rca = cls._get_rca(state)
            if rca is not None:
                if getattr(rca, "initial_access_vector", None):
                    parts.append(str(rca.initial_access_vector))
                if getattr(rca, "root_cause_summary", None):
                    parts.append(str(rca.root_cause_summary))
                if getattr(rca, "confirmed_attack_type", None):
                    parts.append(str(rca.confirmed_attack_type))
                for item in getattr(rca, "attack_timeline", None) or []:
                    parts.append(str(item))
                for node in getattr(rca, "process_tree", None) or []:
                    parts.append(f"{node.process_name} {node.command_line}")
            if state.threat_intel:
                if state.threat_intel.enrichment_summary:
                    parts.append(state.threat_intel.enrichment_summary)
                parts.extend(str(m) for m in (state.threat_intel.mitre_techniques or []))
            for ev in state.parsed_events:
                parts.append(
                    " ".join(
                        str(v)
                        for v in (
                            ev.event_id,
                            ev.source_type,
                            ev.process_name,
                            ev.process_path,
                            ev.command_line,
                            ev.parent_process,
                            ev.parent_command_line,
                        )
                        if v
                    )
                )
                if ev.raw_attributes:
                    parts.append(str(ev.raw_attributes))
            for rlog in state.raw_logs:
                if rlog.log_source:
                    parts.append(rlog.log_source)
                if rlog.raw_payload:
                    parts.append(rlog.raw_payload[:1000])

        return "\n".join(parts).lower()

    @staticmethod
    def _has_positive_match(text: str, pattern: re.Pattern[str]) -> bool:
        """Kiểm tra pattern xuất hiện ở ngữ cảnh khẳng định (không bị phủ định ngay trước đó)."""
        if not text:
            return False
        for match in pattern.finditer(text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            prefix = text[max(line_start, match.start() - 45) : match.start()]
            if not _NEGATION_PREFIX_RE.search(prefix):
                return True
        return False

    @classmethod
    def _has_powershell_evidence(
        cls,
        state: Optional[IncidentState] = None,
        report: Optional[IncidentReport] = None,
    ) -> bool:
        """Kiểm tra có bằng chứng PowerShell hoặc mã T1059.001 thực sự hay không."""
        text = cls._collect_evidence_text(report, state)
        return cls._has_positive_match(text, _POWERSHELL_RE)

    @classmethod
    def _has_macro_evidence(
        cls,
        state: Optional[IncidentState] = None,
        report: Optional[IncidentReport] = None,
    ) -> bool:
        """Kiểm tra có bằng chứng Office Macro / Spearphishing tài liệu thực sự hay không."""
        text = cls._collect_evidence_text(report, state)
        return cls._has_positive_match(text, _MACRO_RE)

    @classmethod
    def _has_pii_or_exfil_indicator(
        cls,
        report: Optional[IncidentReport],
        state: Optional[IncidentState] = None,
    ) -> bool:
        """Kiểm tra dấu hiệu lộ lọt dữ liệu cá nhân (PII) hoặc trích xuất dữ liệu thực tế."""
        text = cls._collect_evidence_text(report, state)
        mitre_codes = {
            m.upper()
            for m in ((report.mitre_attack_matrix_mapping if report else None) or [])
        }
        if state and state.threat_intel and state.threat_intel.mitre_techniques:
            mitre_codes.update(m.upper() for m in state.threat_intel.mitre_techniques)

        exfil_mitre = {"T1041", "T1048", "T1567", "T1020", "T1005", "T1530"}
        if any(any(code.startswith(prefix) for prefix in exfil_mitre) for code in mitre_codes):
            return True

        return cls._has_positive_match(text, _PII_EXFIL_RE)

    @staticmethod
    def _extract_finding_field(detailed_findings: str, prefix: str) -> Optional[str]:
        """Trích xuất giá trị một dòng trường từ detailed_findings khi thiếu state."""
        if not detailed_findings:
            return None
        for line in detailed_findings.splitlines():
            stripped = line.strip()
            if stripped.startswith(prefix):
                val = stripped[len(prefix) :].strip().strip("*").strip()
                if val:
                    return val
        return None

    # =====================================================================
    # 1. GROUNDED BUILDER CLASSMETHODS
    # =====================================================================
    @classmethod
    def build_operational_metrics(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> OperationalMetrics:
        """
        Tính toán các chỉ số vận hành IR (MTTA, MTTC, MTTR, SLA) từ mốc thời gian thực
        trong state.history / executed actions. Nếu thiếu dữ liệu mốc thời gian, trả về
        nhãn trung thực 'Chưa đo lường (thiếu dữ liệu mốc thời gian)'.
        """
        if state is None or not getattr(state, "history", None):
            return OperationalMetrics(
                mtta_display=UNMEASURED_METRIC_LABEL,
                mttc_display=UNMEASURED_METRIC_LABEL,
                mttr_display=UNMEASURED_METRIC_LABEL,
                mtta_seconds=None,
                mttc_seconds=None,
                mttr_seconds=None,
                sla_status="Chưa đánh giá (thiếu dữ liệu mốc thời gian)",
            )

        history_sorted = sorted(
            state.history,
            key=lambda h: cls._ensure_utc(h.timestamp) or datetime.min.replace(tzinfo=timezone.utc),
        )
        first_hist_ts = cls._ensure_utc(history_sorted[0].timestamp)
        created_ts = cls._ensure_utc(getattr(state, "created_at", None))
        if created_ts is not None and first_hist_ts is not None:
            t_start = created_ts if created_ts <= first_hist_ts else first_hist_ts
        else:
            t_start = created_ts or first_hist_ts

        # Nếu lịch sử chỉ có đúng 1 bản ghi reporting mà không có mốc điều tra trước đó -> không đủ dữ liệu đo
        workflow_nodes = {str(h.node).lower() for h in history_sorted}
        has_prior_milestone = bool(
            workflow_nodes
            & {
                "ingestion",
                "triage",
                "triage_agent",
                "enrichment",
                "threatintelagent",
                "rca",
                "parallel_investigation",
                "response",
                "hitl_approval",
                "closed_fp",
            }
        )
        if t_start is None or not has_prior_milestone:
            return OperationalMetrics(
                mtta_display=UNMEASURED_METRIC_LABEL,
                mttc_display=UNMEASURED_METRIC_LABEL,
                mttr_display=UNMEASURED_METRIC_LABEL,
                mtta_seconds=None,
                mttc_seconds=None,
                mttr_seconds=None,
                sla_status="Chưa đánh giá (thiếu mốc phân loại/phản ứng trong history)",
            )

        t_ack: Optional[datetime] = None
        t_contain: Optional[datetime] = None
        t_resolve: Optional[datetime] = None

        for h in history_sorted:
            node_l = str(h.node).lower()
            to_st = h.to_status.value if hasattr(h.to_status, "value") else str(h.to_status)
            ts = cls._ensure_utc(h.timestamp)
            if ts is None:
                continue

            if t_ack is None and (
                node_l in {"triage", "triage_agent", "closed_fp"}
                or to_st
                in {
                    IncidentStatus.TRIAGED.value,
                    IncidentStatus.INVESTIGATING.value,
                    IncidentStatus.AWAITING_APPROVAL.value,
                    IncidentStatus.CLOSED_FALSE_POSITIVE.value,
                }
            ):
                t_ack = ts

            if t_contain is None and (
                to_st == IncidentStatus.CONTAINED.value
                or (node_l == "hitl_approval" and (h.metadata or {}).get("approved") is True)
            ):
                t_contain = ts

            if to_st in {IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED_FALSE_POSITIVE.value}:
                t_resolve = ts

        if t_contain is None:
            exec_times: List[datetime] = []
            for act in cls._get_actions(report, state):
                if cls._is_action_executed(act, state, report):
                    raw_exec_at = (act.parameters or {}).get("executed_at")
                    if isinstance(raw_exec_at, datetime):
                        parsed_dt = cls._ensure_utc(raw_exec_at)
                        if parsed_dt is not None:
                            exec_times.append(parsed_dt)
                    elif isinstance(raw_exec_at, str) and raw_exec_at.strip():
                        try:
                            parsed_dt = cls._ensure_utc(
                                datetime.fromisoformat(raw_exec_at.strip().replace("Z", "+00:00"))
                            )
                            if parsed_dt is not None:
                                exec_times.append(parsed_dt)
                        except ValueError:
                            pass
            if exec_times:
                t_contain = min(exec_times)

        mtta_seconds: Optional[float] = None
        mtta_display = UNMEASURED_METRIC_LABEL
        if t_ack is not None:
            mtta_seconds = round(max(0.0, (t_ack - t_start).total_seconds()), 2)
            mtta_display = cls._format_duration_vi(mtta_seconds)

        is_benign = cls._is_benign_context(report, state)
        cur_status = state.status.value if hasattr(state.status, "value") else str(state.status)

        mttc_seconds: Optional[float] = None
        if t_contain is not None:
            mttc_seconds = round(max(0.0, (t_contain - t_start).total_seconds()), 2)
            mttc_display = cls._format_duration_vi(mttc_seconds)
        elif is_benign and cur_status == IncidentStatus.CLOSED_FALSE_POSITIVE.value:
            mttc_display = "N/A (Dương tính giả - không cần cô lập)"
        else:
            mttc_display = UNMEASURED_METRIC_LABEL

        mttr_seconds: Optional[float] = None
        if t_resolve is not None and cur_status in {
            IncidentStatus.RESOLVED.value,
            IncidentStatus.CLOSED_FALSE_POSITIVE.value,
        }:
            mttr_seconds = round(max(0.0, (t_resolve - t_start).total_seconds()), 2)
            mttr_display = cls._format_duration_vi(mttr_seconds)
        else:
            mttr_display = UNMEASURED_METRIC_LABEL

        if mttr_seconds is not None:
            # Tham chiếu ngưỡng nội bộ 4 giờ (14400s) chỉ đánh giá khi đã có MTTR thực đo
            sla_status = (
                f"Đạt ngưỡng tham chiếu 4 giờ (MTTR thực đo: {mttr_display})"
                if mttr_seconds <= 14400.0
                else f"Vượt ngưỡng tham chiếu 4 giờ (MTTR thực đo: {mttr_display})"
            )
        elif mttc_seconds is not None:
            sla_status = f"Đã ghi nhận MTTC thực đo ({mttc_display}); chờ đóng sự cố để chốt MTTR"
        elif mtta_seconds is not None:
            sla_status = f"Đã ghi nhận MTTA thực đo ({mtta_display}); chưa hoàn tất cô lập/khắc phục"
        else:
            sla_status = "Chưa đánh giá (thiếu dữ liệu mốc thời gian)"

        return OperationalMetrics(
            mtta_display=mtta_display,
            mttc_display=mttc_display,
            mttr_display=mttr_display,
            mtta_seconds=mtta_seconds,
            mttc_seconds=mttc_seconds,
            mttr_seconds=mttr_seconds,
            sla_status=sla_status,
        )

    @classmethod
    def build_impact_assessment(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> ImpactAssessment:
        """
        Đánh giá tác động CIA, vận hành, tài chính và tuân thủ NĐ 13/2023/NĐ-CP
        dựa hoàn toàn trên bằng chứng thực tế trong report và state (chỉ tính action EXECUTED).
        """
        is_benign = cls._is_benign_context(report, state)
        triage = cls._get_triage(state)
        rca = cls._get_rca(state)
        actions = cls._get_actions(report, state)
        executed_actions = [a for a in actions if cls._is_action_executed(a, state, report)]
        rolled_back_actions = [a for a in actions if cls._is_action_rolled_back(a)]

        iocs = list(report.ioc_table or [])
        if not iocs and state is not None and state.threat_intel and state.threat_intel.extracted_iocs:
            iocs = list(state.threat_intel.extracted_iocs)
        malicious_iocs = [i for i in iocs if i.is_malicious]

        mitre_codes = {m.upper() for m in (report.mitre_attack_matrix_mapping or [])}
        text = cls._collect_evidence_text(report, state)
        attack_cat = str(report.attack_category or "").upper()
        if not attack_cat and triage is not None and getattr(triage, "attack_category", None):
            cat_obj = triage.attack_category
            attack_cat = (cat_obj.value if hasattr(cat_obj, "value") else str(cat_obj)).upper()
        severity_label = cls._resolve_report_severity(report, state)

        # --- 1. Confidentiality ---
        if is_benign:
            conf_dim = CIADimension(
                level="Không (None)",
                assessment="Không phát hiện rò rỉ hay truy cập trái phép dữ liệu (sự kiện lành tính / dương tính giả).",
            )
        else:
            has_cred_dump = any(k in text for k in ("lsass", "mimikatz", "sam dump")) or any(
                m.startswith("T1003") for m in mitre_codes
            )
            has_exfil = cls._has_pii_or_exfil_indicator(report, state)
            has_cred_attack = (
                attack_cat == AttackCategory.CREDENTIAL_ACCESS.value
                or any(m.startswith("T1110") or m.startswith("T1078") for m in mitre_codes)
                or any(k in text for k in ("brute", "ssh", "failed password", "password spray"))
            )
            has_mal_c2 = bool(malicious_iocs) or any(m.startswith("T1071") for m in mitre_codes)

            if has_exfil or (has_cred_dump and has_mal_c2):
                evidence_bits = []
                if has_cred_dump:
                    evidence_bits.append("trích xuất thông tin xác thực")
                if malicious_iocs:
                    evidence_bits.append(f"IoC độc hại `{malicious_iocs[0].value}`")
                if has_exfil:
                    evidence_bits.append("dấu hiệu trích xuất/rò rỉ dữ liệu")
                conf_dim = CIADimension(
                    level="Cao (High)",
                    assessment=f"Ghi nhận rủi ro lộ lọt thông tin dựa trên bằng chứng: {', '.join(evidence_bits)}.",
                )
            elif has_cred_attack:
                conf_dim = CIADimension(
                    level="Trung bình (Medium)",
                    assessment="Ghi nhận nỗ lực xâm phạm thông tin xác thực/tài khoản; cần kiểm tra nhật ký đăng nhập thành công bất thường.",
                )
            elif has_mal_c2:
                ioc_sample = f"`{malicious_iocs[0].value}`" if malicious_iocs else "đích mạng đáng ngờ"
                conf_dim = CIADimension(
                    level="Cao (High)" if severity_label == "CRITICAL" else "Trung bình (Medium)",
                    assessment=f"Phát hiện liên lạc tới hạ tầng mạng đáng ngờ ({ioc_sample}); chưa ghi nhận bằng chứng rò rỉ dữ liệu cá nhân trực tiếp.",
                )
            elif attack_cat == AttackCategory.RECONNAISSANCE.value or any(
                m.startswith("T1046") or m.startswith("T1595") for m in mitre_codes
            ):
                conf_dim = CIADimension(
                    level="Thấp (Low)",
                    assessment="Chỉ ghi nhận hoạt động rà quét/thăm dò mạng; chưa có dấu hiệu đọc hoặc đánh cắp dữ liệu.",
                )
            else:
                conf_dim = CIADimension(
                    level="Thấp (Low)",
                    assessment="Chưa ghi nhận bằng chứng lộ lọt thông tin mật hoặc trích xuất dữ liệu trong phạm vi log hiện tại.",
                )

        # --- 2. Integrity ---
        if is_benign:
            int_dim = CIADimension(
                level="Không (None)",
                assessment="Không phát hiện thay đổi trái phép tệp tin, tiến trình hoặc cấu hình hệ thống.",
            )
        else:
            has_persistence = any(
                k in text for k in ("schtasks", "scheduled task", "registry", "run key", "autorun")
            ) or any(m.startswith("T1053") or m.startswith("T1547") for m in mitre_codes)
            has_destructive = any(m.startswith("T1486") or m.startswith("T1490") for m in mitre_codes)
            has_exec_or_drop = (
                bool(rca and getattr(rca, "process_tree", None))
                or any(m.startswith("T1059") or m.startswith("T1105") for m in mitre_codes)
                or any(k in text for k in ("filecreate", "powershell", "cmd.exe", "drop"))
            )

            if has_destructive:
                int_dim = CIADimension(
                    level="Cao (High)",
                    assessment="Phát hiện dấu hiệu mã hóa/phá hoại tệp tin hoặc ảnh hưởng nghiêm trọng tới tính toàn vẹn dữ liệu.",
                )
            elif has_persistence or has_exec_or_drop:
                observed = []
                if has_persistence:
                    observed.append("cơ chế duy trì truy cập (persistence)")
                if has_exec_or_drop:
                    observed.append("thực thi tiến trình/tệp tin đáng ngờ trên endpoint")
                int_dim = CIADimension(
                    level="Trung bình (Medium)",
                    assessment=f"Ghi nhận tác động lên tính toàn vẹn qua bằng chứng: {', '.join(observed)}.",
                )
            elif attack_cat in {AttackCategory.CREDENTIAL_ACCESS.value, AttackCategory.RECONNAISSANCE.value}:
                int_dim = CIADimension(
                    level="Không (None)",
                    assessment="Chưa ghi nhận dấu hiệu chỉnh sửa tệp hệ thống, cấu hình hoặc mã độc trên endpoint trong log hiện có.",
                )
            else:
                int_dim = CIADimension(
                    level="Chưa xác định (Pending)",
                    assessment="Chưa đủ dữ liệu telemetry endpoint để kết luận mức độ biến đổi toàn vẹn tệp/cấu hình.",
                )

        # --- 3. Availability (CHỈ dựa trên hành động EXECUTED hoặc gián đoạn thực tế) ---
        if is_benign:
            if rolled_back_actions and any(
                (a.parameters or {}).get("rollback_reason") == "SERVICE_DISRUPTION"
                for a in rolled_back_actions
            ):
                avail_dim = CIADimension(
                    level="Thấp (Low)",
                    assessment="Đã hoàn tác hành động can thiệp do nguy cơ gián đoạn dịch vụ; hệ thống đã khôi phục bình thường.",
                )
            else:
                avail_dim = CIADimension(
                    level="Không (None)",
                    assessment="Hệ thống vận hành bình thường, không có hành động cô lập hay gián đoạn dịch vụ.",
                )
        else:
            executed_isolations = [
                a for a in executed_actions if a.action_type == ActionType.ISOLATE_HOST
            ]
            if executed_isolations:
                targets = ", ".join(a.target for a in executed_isolations)
                avail_dim = CIADimension(
                    level="Trung bình (Medium)" if severity_label != "CRITICAL" else "Cao (High)",
                    assessment=f"Đã thực thi cô lập mạng đối với `{targets}`, gây gián đoạn kết nối cục bộ trên đối tượng bị cô lập trong thời gian xử lý.",
                )
            elif executed_actions:
                act_types = ", ".join(
                    sorted({a.action_type.value if hasattr(a.action_type, "value") else str(a.action_type) for a in executed_actions})
                )
                avail_dim = CIADimension(
                    level="Thấp (Low)",
                    assessment=f"Đã thực thi {len(executed_actions)} hành động ngăn chặn mục tiêu ({act_types}); các dịch vụ hệ thống cốt lõi không bị cô lập.",
                )
            else:
                avail_dim = CIADimension(
                    level="Không (None)",
                    assessment="Chưa thực thi hành động cô lập hoặc ngắt kết nối hệ thống (chưa phát sinh gián đoạn vận hành từ công tác ứng phó).",
                )

        # --- 4. Operational / SLA, Financial, Compliance ---
        op_metrics = (
            OperationalMetrics.model_validate(report.operational_metrics)
            if isinstance(report.operational_metrics, dict)
            else (report.operational_metrics or cls.build_operational_metrics(report, state))
        )
        if op_metrics.mttr_seconds is not None or op_metrics.mttc_seconds is not None:
            operational_sla_note = (
                f"MTTA: {op_metrics.mtta_display} | MTTC: {op_metrics.mttc_display} | "
                f"MTTR: {op_metrics.mttr_display} ({op_metrics.sla_status})."
            )
        else:
            operational_sla_note = (
                "Chưa đo lường được thời gian phản ứng/khôi phục thực tế do thiếu dữ liệu mốc thời gian hoàn chỉnh."
            )

        financial_impact_note = (
            "Không phát sinh thiệt hại tài chính (sự kiện lành tính / dương tính giả)."
            if is_benign
            else "Chưa ước tính thiệt hại tài chính trực tiếp (chưa có dữ liệu định lượng tổn thất kinh doanh)."
        )

        if is_benign:
            compliance_note = (
                "Không phát hiện dữ liệu cá nhân (PII) bị lộ lọt — chưa kích hoạt nghĩa vụ báo cáo A05 NĐ 13/2023."
            )
        elif cls._has_pii_or_exfil_indicator(report, state):
            compliance_note = (
                "Phát hiện dấu hiệu liên quan đến trích xuất/xâm phạm dữ liệu — cần đánh giá phạm vi dữ liệu cá nhân "
                "để thực hiện nghĩa vụ thông báo theo Nghị định 13/2023/NĐ-CP (Cục A05 trong 72 giờ nếu xác định lộ lọt PII)."
            )
        else:
            compliance_note = (
                "Không phát hiện dữ liệu cá nhân (PII) bị lộ lọt — chưa kích hoạt nghĩa vụ báo cáo A05 NĐ 13/2023."
            )

        return ImpactAssessment(
            confidentiality=conf_dim,
            integrity=int_dim,
            availability=avail_dim,
            operational_sla_note=operational_sla_note,
            financial_impact_note=financial_impact_note,
            compliance_note=compliance_note,
        )

    @classmethod
    def build_deep_rca_breakdown(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> DeepRCABreakdown:
        """
        Trích xuất phân tích nguyên nhân gốc rễ 3 tầng, chuỗi 5 Whys và Ishikawa
        gắn chặt với state.rca / report.detailed_findings / MITRE mapping.
        Tuyệt đối không bịa Office Macro khi sự cố không liên quan đến Macro.
        """
        is_benign = cls._is_benign_context(report, state)
        triage = cls._get_triage(state)
        rca = cls._get_rca(state)

        if is_benign:
            triage_note = getattr(triage, "summary", None) or report.executive_summary or "Hoạt động hợp lệ bình thường."
            return DeepRCABreakdown(
                applicable=False,
                proximate_cause="Không ghi nhận hành vi tấn công — sự kiện được xác minh là hoạt động hợp lệ (Benign / False Positive).",
                contributing_factors="Ngưỡng quy tắc phát hiện cần tinh chỉnh ngoại lệ (rule tuning) cho tác vụ hợp lệ.",
                root_cause=triage_note.strip().splitlines()[0],
                five_whys=[],
                ishikawa_factors=[],
            )

        initial_vector = (
            getattr(rca, "initial_access_vector", None)
            or cls._extract_finding_field(report.detailed_findings, "- Vector xâm nhập:")
            or "Chưa xác định"
        )
        rca_summary = (
            getattr(rca, "root_cause_summary", None)
            or cls._extract_finding_field(report.detailed_findings, "- Tóm tắt nguyên nhân gốc rễ:")
            or ""
        )

        text = cls._collect_evidence_text(report, state)
        mitre_codes = {m.upper() for m in (report.mitre_attack_matrix_mapping or [])}
        attack_cat = str(report.attack_category or "").upper()
        has_macro = cls._has_macro_evidence(state, report)
        has_powershell = cls._has_powershell_evidence(state, report)
        has_cred_brute = (
            attack_cat == AttackCategory.CREDENTIAL_ACCESS.value
            or any(m.startswith("T1110") for m in mitre_codes)
            or any(k in text for k in ("ssh", "brute", "password spray", "4625", "failed password"))
        )
        has_network_only = (
            not has_macro
            and not has_powershell
            and not has_cred_brute
            and (
                attack_cat == AttackCategory.RECONNAISSANCE.value
                or any(m.startswith("T1071") or m.startswith("T1046") or m.startswith("T1595") for m in mitre_codes)
                or any(k in text for k in ("zeek", "port scan", "network", "dest_ip"))
            )
        )

        # Case 1: Credential Brute-Force / SSH
        if has_cred_brute:
            proximate = (
                f"Chuỗi nỗ lực xác thực/đăng nhập bất thường ({initial_vector})."
                if initial_vector and "Chưa xác định" not in initial_vector
                else "Ghi nhận chuỗi thử đăng nhập/dò mật khẩu liên tiếp từ nguồn đáng ngờ."
            )
            contributing = (
                "Dịch vụ xác thực mở truy cập chưa giới hạn tốc độ thử sai (rate-limiting/fail2ban) "
                "hoặc chưa bắt buộc xác thực khóa công khai / MFA."
            )
            root_cause = (
                rca_summary
                if rca_summary and "Chưa có dữ liệu" not in rca_summary
                else "Thiếu chính sách kiểm soát nguồn truy cập xác thực, khóa tài khoản tự động và xác thực đa yếu tố."
            )
            five_whys = [
                f"Why 1: Hệ thống ghi nhận cảnh báo dò quét/xâm nhập xác thực ({initial_vector}).",
                "Why 2: Nguồn ngoài có thể gửi liên tiếp yêu cầu đăng nhập vào dịch vụ xác thực.",
                "Why 3: Cơ chế chặn IP tự động theo ngưỡng thất bại chưa chặn kịp thời từ vòng đầu.",
                "Why 4: Dịch vụ quản trị/xác thực chưa giới hạn theo danh sách IP tin cậy (allowlist) hoặc VPN.",
                f"Why 5 (Root Cause): {root_cause}",
            ]
            ishikawa = [
                {
                    "branch": "Con người (People)",
                    "finding": "Rủi ro sử dụng mật khẩu yếu hoặc tái sử dụng mật khẩu quản trị.",
                    "countermeasure": "Áp dụng chính sách mật khẩu mạnh và đào tạo quản lý thông tin xác thực.",
                },
                {
                    "branch": "Quy trình (Process)",
                    "finding": "Chưa chuẩn hóa quy trình rà soát định kỳ danh sách IP truy cập dịch vụ xác thực.",
                    "countermeasure": "Thiết lập quy trình cảnh báo và chặn tự động theo ngưỡng đăng nhập thất bại.",
                },
                {
                    "branch": "Công nghệ (Technology)",
                    "finding": "Thiếu cơ chế rate-limit / fail2ban hoặc MFA cho cổng xác thực.",
                    "countermeasure": "Bật SSH key-only / MFA và tích hợp chặn IP tự động qua tường lửa.",
                },
                {
                    "branch": "Môi trường (Environment)",
                    "finding": "Cổng dịch vụ xác thực tiếp xúc trực tiếp với vùng mạng không tin cậy.",
                    "countermeasure": "Đưa truy cập quản trị ra sau VPN hoặc giới hạn ACL theo IP nguồn.",
                },
            ]
        # Case 2: Network / Zeek C2 / Port Scan (không có Macro/PowerShell)
        elif has_network_only:
            ioc_vals = ", ".join(f"`{i.value}`" for i in (report.ioc_table or [])[:3]) or "địa chỉ IP/cổng bất thường"
            proximate = (
                f"Phát hiện lưu lượng hoặc kết nối mạng bất thường liên quan tới {ioc_vals} ({initial_vector})."
                if "Chưa xác định" not in initial_vector
                else f"Phát hiện lưu lượng hoặc kết nối mạng bất thường liên quan tới {ioc_vals}."
            )
            contributing = (
                "Chính sách tường lửa biên/phân đoạn mạng chưa lọc chặt kết nối bất thường theo danh sách uy tín CTI."
            )
            root_cause = (
                rca_summary
                if rca_summary and "Chưa có dữ liệu" not in rca_summary
                else "Thiếu kiểm soát lọc lưu lượng mạng ra/vào theo baseline và đối chiếu chặn tự động IoC."
            )
            five_whys = [
                f"Why 1: Cảm biến mạng/Zeek ghi nhận bất thường tới {ioc_vals}.",
                "Why 2: Lưu lượng tới đích/cổng này chưa bị từ chối ở tầng tường lửa biên.",
                "Why 3: Quy tắc kiểm soát egress/ingress chưa đồng bộ danh sách IoC tình báo mối đe dọa.",
                f"Why 4 (Root Cause): {root_cause}",
            ]
            ishikawa = [
                {
                    "branch": "Quy trình (Process)",
                    "finding": "Chưa có quy trình đối chiếu định kỳ lưu lượng mạng với CTI.",
                    "countermeasure": "Tự động hóa đối chiếu IoC mạng và kích hoạt playbook chặn IP khi vượt ngưỡng.",
                },
                {
                    "branch": "Công nghệ (Technology)",
                    "finding": "Chính sách firewall/IDS chưa chặn chủ động kết nối bất thường.",
                    "countermeasure": "Bổ sung rule chặn IP/cổng không cần thiết trên tường lửa và Zeek/Suricata.",
                },
                {
                    "branch": "Môi trường (Environment)",
                    "finding": "Phân tách vùng mạng giữa phân hệ nội bộ và biên ngoài chưa chặt chẽ.",
                    "countermeasure": "Áp dụng phân vùng VLAN và kiểm soát egress theo nguyên tắc tối thiểu.",
                },
            ]
        # Case 3: PowerShell / Script KHÔNG có Office Macro
        elif has_powershell and not has_macro:
            proximate = (
                f"Thực thi tiến trình PowerShell đáng ngờ ({initial_vector})."
                if "Chưa xác định" not in initial_vector
                else "Thực thi lệnh PowerShell đáng ngờ trên máy trạm/máy chủ."
            )
            contributing = (
                "Endpoint chưa áp dụng PowerShell Constrained Language Mode hoặc chưa chặn tham số bypass/encoded."
            )
            root_cause = (
                rca_summary
                if rca_summary and "Chưa có dữ liệu" not in rca_summary
                else "Thiếu chính sách kiểm soát thực thi script PowerShell và giám sát hành vi tiến trình."
            )
            five_whys = [
                f"Why 1: Phát hiện tiến trình PowerShell thực thi lệnh đáng ngờ ({proximate}).",
                "Why 2: Hệ thống cho phép thực thi script với tham số nới lỏng chính sách.",
                "Why 3: Chính sách kiểm soát ứng dụng/script (AppLocker/WDAC/CLM) chưa hạn chế nguồn chạy.",
                f"Why 4 (Root Cause): {root_cause}",
            ]
            ishikawa = [
                {
                    "branch": "Quy trình (Process)",
                    "finding": "Thiếu kiểm soát ngoại lệ khi vận hành script quản trị PowerShell.",
                    "countermeasure": "Áp dụng ký số script nội bộ và rà soát cảnh báo tham số `-enc`/`Bypass`.",
                },
                {
                    "branch": "Công nghệ (Technology)",
                    "finding": "PowerShell chưa chạy ở chế độ Constrained Language Mode và thiếu kiểm soát EDR.",
                    "countermeasure": "Bật Script Block Logging, AMSI và chính sách AppLocker/CLM trên endpoint.",
                },
                {
                    "branch": "Môi trường (Environment)",
                    "finding": "Quyền thực thi script và kết nối mạng từ tiến trình shell chưa bị giới hạn.",
                    "countermeasure": "Tách quyền quản trị và kiểm soát kết nối egress từ tiến trình thông dịch.",
                },
            ]
        # Case 4: Office Macro / Spearphishing (CHỈ khi có bằng chứng thật)
        elif has_macro:
            proximate = (
                f"Kích hoạt thực thi từ tài liệu/tệp đính kèm ({initial_vector})."
                if "Chưa xác định" not in initial_vector
                else "Kích hoạt macro/script từ tài liệu văn phòng đáng ngờ."
            )
            contributing = (
                "Cơ chế kiểm soát macro từ nguồn ngoài chưa bị vô hiệu hóa triệt để hoặc tệp đính kèm chưa qua sandbox."
            )
            root_cause = (
                rca_summary
                if rca_summary and "Chưa có dữ liệu" not in rca_summary
                else "Thiếu chính sách chặn macro tài liệu từ Internet và thiếu lớp kiểm tra tệp đính kèm email."
            )
            five_whys = [
                f"Why 1: Tiến trình ứng dụng văn phòng/tệp đính kèm khởi chạy chuỗi thực thi ({initial_vector}).",
                "Why 2: Tài liệu chứa macro hoặc kịch bản nhúng được phép kích hoạt trên máy trạm.",
                "Why 3: Chính sách Group Policy/ASR chặn tiến trình con từ ứng dụng Office chưa được bật cưỡng bức.",
                f"Why 4 (Root Cause): {root_cause}",
            ]
            ishikawa = [
                {
                    "branch": "Con người (People)",
                    "finding": "Người dùng mở tệp tài liệu/đính kèm nghi vấn từ nguồn ngoài.",
                    "countermeasure": "Đào tạo nhận diện phishing và quy trình báo cáo email nghi ngờ.",
                },
                {
                    "branch": "Quy trình (Process)",
                    "finding": "Quy trình xử lý tài liệu đính kèm từ bên ngoài chưa qua bước kiểm duyệt an toàn.",
                    "countermeasure": "Chuẩn hóa quy trình kiểm tra tệp đính kèm và phản ứng nhanh khi phát sinh cảnh báo.",
                },
                {
                    "branch": "Công nghệ (Technology)",
                    "finding": "Thiếu Attack Surface Reduction (ASR) chặn Office tạo tiến trình con / chặn macro.",
                    "countermeasure": "Bật chính sách chặn macro từ Internet và sandboxing cổng email.",
                },
            ]
        # Case 5: Dữ liệu RCA tối giản / chưa đủ chi tiết
        else:
            has_concrete_rca = bool(
                rca and initial_vector and "Chưa xác định" not in initial_vector
            )
            proximate = (
                initial_vector
                if has_concrete_rca
                else "Ghi nhận cảnh báo an ninh cần thu thập thêm dữ liệu điều tra trực tiếp."
            )
            contributing = (
                "Dữ liệu nhật ký hiện có chưa cung cấp đủ ngữ cảnh về lỗ hổng hoặc điểm yếu cấu hình cụ thể."
            )
            root_cause = (
                rca_summary
                if rca_summary and "Chưa có dữ liệu" not in rca_summary
                else "Chưa đủ bằng chứng để xác định nguyên nhân gốc rễ đầy đủ từ telemetry hiện tại."
            )
            five_whys = (
                [
                    f"Why 1: Sự kiện bất thường được ghi nhận qua vector '{proximate}'.",
                    f"Why 2 (Root Cause): {root_cause}",
                ]
                if has_concrete_rca
                else []
            )
            ishikawa = []

        return DeepRCABreakdown(
            applicable=True,
            proximate_cause=proximate,
            contributing_factors=contributing,
            root_cause=root_cause,
            five_whys=five_whys,
            ishikawa_factors=ishikawa,
        )

    @classmethod
    def build_verification_gate(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> List[VerificationGateItem]:
        """
        Xây dựng Cổng kiểm định an toàn (Integrity Verification Gate) trung thực:
        CHỈ đánh dấu checked=True ([x]) khi có bằng chứng xác thực trong state/report.
        Các bước chưa thực thi hoặc chưa kiểm chứng luôn để checked=False ([ ]).
        """
        is_benign = cls._is_benign_context(report, state)
        triage = cls._get_triage(state)
        actions = cls._get_actions(report, state)
        executed_actions = [a for a in actions if cls._is_action_executed(a, state, report)]
        pending_actions = [a for a in actions if a.is_approved is None]
        rejected_actions = [
            a for a in actions if a.is_approved is False and not cls._is_action_rolled_back(a)
        ]
        rolled_back_actions = [a for a in actions if cls._is_action_rolled_back(a)]
        mitre_list = list(report.mitre_attack_matrix_mapping or [])

        # Gate 1: Phân loại & ánh xạ kỹ thuật
        if is_benign:
            gate1_checked = bool(
                triage is not None
                or report.is_incident is False
                or (state is not None and state.status == IncidentStatus.CLOSED_FALSE_POSITIVE)
            )
            gate1_detail = (
                "Đã xác minh phân loại sự kiện lành tính / dương tính giả (không ghi nhận kỹ thuật tấn công)."
                if gate1_checked
                else "Chưa có xác nhận phân loại từ Triage."
            )
        else:
            gate1_checked = len(mitre_list) > 0
            gate1_detail = (
                f"Đã đối chiếu và ánh xạ {len(mitre_list)} kỹ thuật MITRE ATT&CK ({', '.join(mitre_list[:4])})."
                if gate1_checked
                else "Chưa có mã kỹ thuật MITRE ATT&CK được xác thực trong báo cáo."
            )

        # Gate 2: Phê duyệt của chuyên viên (HITL Approval)
        hitl_history_approved = bool(
            state is not None
            and any(
                str(h.node).lower() == "hitl_approval" and (h.metadata or {}).get("approved") is True
                for h in (state.history or [])
            )
        )
        if state is not None:
            if state.analyst_approved is False:
                gate2_checked = False
                gate2_detail = "Chuyên viên SOC đã từ chối hoặc yêu cầu điều chỉnh kế hoạch phản ứng."
            elif pending_actions:
                gate2_checked = False
                gate2_detail = f"Còn {len(pending_actions)} hành động đang chờ chuyên viên phê duyệt HITL."
            elif (state.analyst_approved is True or hitl_history_approved) and (
                not actions or any(a.is_approved is True for a in actions)
            ):
                gate2_checked = True
                approved_cnt = sum(1 for a in actions if a.is_approved is True)
                gate2_detail = (
                    f"Đã ghi nhận phê duyệt HITL cho {approved_cnt}/{len(actions)} hành động ứng phó."
                    if actions
                    else "Đã ghi nhận xác nhận HITL từ chuyên viên SOC."
                )
            else:
                gate2_checked = False
                gate2_detail = "Chưa ghi nhận xác nhận phê duyệt HITL từ chuyên viên SOC."
        else:
            if actions and all(a.is_approved is True for a in actions) and not rolled_back_actions:
                gate2_checked = True
                gate2_detail = f"Tất cả {len(actions)} hành động trong kế hoạch đều có trạng thái Đã duyệt."
            elif pending_actions:
                gate2_checked = False
                gate2_detail = f"Còn {len(pending_actions)} hành động chưa được phê duyệt (Chờ duyệt)."
            elif rolled_back_actions or rejected_actions:
                gate2_checked = False
                gate2_detail = "Kế hoạch có hành động bị từ chối hoặc đã hoàn tác."
            else:
                gate2_checked = False
                gate2_detail = "Chưa có bằng chứng phê duyệt HITL trong dữ liệu báo cáo."

        # Gate 3: Thực thi hành động ngăn chặn (Containment Execution / is_completed)
        if is_benign and not actions:
            gate3_checked = False
            gate3_detail = "Không áp dụng biện pháp cô lập (sự kiện được phân loại Benign / False Positive)."
        elif executed_actions and not pending_actions:
            gate3_checked = True
            gate3_detail = f"Đã hoàn tất thực thi {len(executed_actions)}/{len(actions)} hành động ứng phó."
        elif pending_actions:
            gate3_checked = False
            gate3_detail = f"Chưa hoàn tất thực thi: còn {len(pending_actions)} hành động đang chờ duyệt/chưa chạy."
        elif rolled_back_actions:
            gate3_checked = False
            gate3_detail = f"Đã hoàn tác {len(rolled_back_actions)} hành động; chưa duy trì trạng thái cô lập."
        elif actions:
            gate3_checked = False
            gate3_detail = "Các hành động đề xuất chưa có xác nhận đã thực thi (EXECUTED)."
        else:
            gate3_checked = False
            gate3_detail = "Chưa có hành động ngăn chặn nào được đề xuất hoặc thực thi."

        # Gate 4: Kiểm chứng hậu khắc phục / Toàn vẹn sau khôi phục
        has_explicit_post_verify = False
        if state is not None:
            checkpoints = state.checkpoints or {}
            if "post_incident_verified" in checkpoints or "verification" in checkpoints:
                has_explicit_post_verify = True
            elif any(
                (h.metadata or {}).get("rollback_reason") == "RECOVERY_COMPLETE"
                or (h.metadata or {}).get("post_incident_verified") is True
                for h in (state.history or [])
            ):
                has_explicit_post_verify = True
            elif any(
                a.parameters and a.parameters.get("verified") is True
                for a in actions
            ):
                has_explicit_post_verify = True

        if has_explicit_post_verify:
            gate4_checked = True
            gate4_detail = "Đã ghi nhận xác minh khôi phục/kiểm tra hậu xử lý trong IncidentState."
        else:
            gate4_checked = False
            gate4_detail = (
                "Chưa có bằng chứng quét lại endpoint, kiểm tra hash baseline và giám sát sau khôi phục."
            )

        return [
            VerificationGateItem(
                label="Phân loại & Ánh xạ kỹ thuật (Triage / MITRE ATT&CK)",
                checked=gate1_checked,
                detail=gate1_detail,
            ),
            VerificationGateItem(
                label="Phê duyệt kiểm soát con người (HITL Approval)",
                checked=gate2_checked,
                detail=gate2_detail,
            ),
            VerificationGateItem(
                label="Thực thi hành động ngăn chặn (Containment Execution)",
                checked=gate3_checked,
                detail=gate3_detail,
            ),
            VerificationGateItem(
                label="Kiểm chứng hậu khắc phục & Giám sát khôi phục",
                checked=gate4_checked,
                detail=gate4_detail,
            ),
        ]

    @classmethod
    def build_capa_plan(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> List[CAPAItem]:
        """
        Xây dựng kế hoạch hành động khắc phục & phòng ngừa (CAPA) gắn trực tiếp với
        action_plan, MITRE ATT&CK mapping, IoC và RCA thực tế của sự cố.
        """
        is_benign = cls._is_benign_context(report, state)
        if is_benign:
            return [
                CAPAItem(
                    code="CAPA-01",
                    item=f"Tinh chỉnh luật phát hiện và danh sách ngoại lệ cho sự kiện hợp lệ ({report.report_id})",
                    category="Quy trình / Detection",
                    priority="P3",
                    raci="R: SOC Tier 1/2 | A: SOC Manager | C: System Owner | I: IT Ops",
                    timeline="Trong chu kỳ tuning kế tiếp",
                    kpi="Giảm cảnh báo dương tính giả lặp lại cho cùng mẫu hành vi",
                )
            ]

        items: List[CAPAItem] = []
        idx = 1

        def add_item(
            item_desc: str,
            category: str,
            priority: str,
            raci: str,
            timeline: str,
            kpi: str,
        ) -> None:
            nonlocal idx
            items.append(
                CAPAItem(
                    code=f"CAPA-{idx:02d}",
                    item=item_desc,
                    category=category,
                    priority=priority,
                    raci=raci,
                    timeline=timeline,
                    kpi=kpi,
                )
            )
            idx += 1

        actions = cls._get_actions(report, state)
        for act in actions[:4]:
            act_type = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
            is_exec = cls._is_action_executed(act, state, report)
            if cls._is_action_rolled_back(act):
                status_note = "Đã hoàn tác — cần phương án thay thế phù hợp"
            elif is_exec:
                status_note = "Đã thực thi — cần duy trì kiểm tra hiệu lực"
            elif act.is_approved is False:
                status_note = "Đã bị từ chối — rà soát phương án thay thế"
            else:
                status_note = "Chờ phê duyệt / hoàn tất thực thi"
            add_item(
                item_desc=f"[{act_type}] Mục tiêu `{act.target}`: {act.description} ({status_note})",
                category="Khắc phục (Corrective)",
                priority=f"P{min(max(1, int(act.priority)), 3)}",
                raci="R: SecOps | A: SOC Manager | C: Infra/System Owner | I: CISO",
                timeline="Ngay lập tức / 24h" if act.priority == 1 else "Trong 72 giờ",
                kpi=f"Xác minh trạng thái hành động `{act_type}` trên `{act.target}`",
            )

        mitre_codes = {m.upper() for m in (report.mitre_attack_matrix_mapping or [])}
        text = cls._collect_evidence_text(report, state)
        mal_iocs = [i for i in (report.ioc_table or []) if i.is_malicious]

        if any(m.startswith("T1059.001") for m in mitre_codes) or cls._has_powershell_evidence(state, report):
            add_item(
                item_desc="Bật PowerShell Script Block Logging, AMSI và giới hạn PowerShell Constrained Language Mode",
                category="Công nghệ (Preventive)",
                priority="P1",
                raci="R: Endpoint Eng | A: CISO | C: SecOps | I: IT Ops",
                timeline="1-2 tuần",
                kpi="100% máy trạm bật log thực thi script và chặn lệnh không ký số",
            )

        if any(m.startswith("T1110") or m.startswith("T1078") for m in mitre_codes) or any(
            k in text for k in ("ssh", "brute", "password spray", "credential")
        ):
            add_item(
                item_desc="Áp dụng khóa xác thực SSH / MFA và cơ chế giới hạn thử đăng nhập sai (fail2ban / account lockout)",
                category="Xác thực & Truy cập",
                priority="P1",
                raci="R: SysAdmin | A: Head of Infra | C: SecOps | I: CISO",
                timeline="1 tuần",
                kpi="Chặn tự động nguồn brute-force và phủ MFA 100% tài khoản quản trị",
            )

        if mal_iocs or any(m.startswith("T1071") or m.startswith("T1046") or m.startswith("T1595") for m in mitre_codes):
            ioc_hint = ", ".join(f"`{i.value}`" for i in mal_iocs[:3]) if mal_iocs else "IoC mạng liên quan"
            add_item(
                item_desc=f"Đồng bộ chặn {ioc_hint} trên tường lửa biên/IDS và rà soát luật kiểm soát lưu lượng egress/ingress",
                category="Mạng (Preventive)",
                priority="P1" if mal_iocs else "P2",
                raci="R: NetOps | A: Head of Infra | C: SecOps | I: CISO",
                timeline="1 tuần",
                kpi="100% IoC mạng xác nhận độc hại được đồng bộ vào chính sách chặn",
            )

        if cls._has_macro_evidence(state, report):
            add_item(
                item_desc="Cấu hình chặn Office Macro từ Internet (GPO/ASR) và tăng cường lọc tệp đính kèm cổng Email",
                category="Email & Endpoint",
                priority="P1",
                raci="R: Messaging/Endpoint Admin | A: CISO | C: SecOps | I: Toàn thể CBNV",
                timeline="1-2 tuần",
                kpi="Chặn 100% macro chưa ký từ nguồn ngoài",
            )

        if cls._has_pii_or_exfil_indicator(report, state):
            add_item(
                item_desc="Đánh giá phạm vi dữ liệu cá nhân và lập hồ sơ tuân thủ theo Nghị định 13/2023/NĐ-CP (Cục A05)",
                category="Pháp lý & Tuân thủ",
                priority="P1",
                raci="R: Legal / DPO | A: CISO | C: IR Lead | I: Ban Giám đốc",
                timeline="Trong 72 giờ",
                kpi="Hoàn tất đánh giá và lưu hồ sơ báo cáo đúng hạn nếu xác định lộ lọt PII",
            )

        if not items:
            add_item(
                item_desc=f"Hoàn tất thu thập log bổ sung và xác định hành động khắc phục cho `{report.report_id}`",
                category="Điều tra (Investigation)",
                priority="P2",
                raci="R: SOC Analyst | A: SOC Manager | C: System Owner | I: IT Ops",
                timeline="Trong 48 giờ",
                kpi="Đóng đầy đủ nguyên nhân và biện pháp phòng ngừa cho sự cố",
            )

        return items

    @classmethod
    def _coerce_operational_metrics(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> OperationalMetrics:
        if report.operational_metrics is not None and state is None:
            if isinstance(report.operational_metrics, OperationalMetrics):
                return report.operational_metrics
            return OperationalMetrics.model_validate(report.operational_metrics)
        if state is None and report.operational_metrics is None:
            return cls.build_operational_metrics(report, None)
        if report.operational_metrics is not None and isinstance(report.operational_metrics, OperationalMetrics):
            return report.operational_metrics
        return cls.build_operational_metrics(report, state)

    @classmethod
    def _coerce_impact_assessment(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> ImpactAssessment:
        if report.impact_assessment is not None and state is None:
            if isinstance(report.impact_assessment, ImpactAssessment):
                return report.impact_assessment
            return ImpactAssessment.model_validate(report.impact_assessment)
        if report.impact_assessment is not None and isinstance(report.impact_assessment, ImpactAssessment):
            return report.impact_assessment
        return cls.build_impact_assessment(report, state)

    @classmethod
    def _coerce_deep_rca(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> DeepRCABreakdown:
        if report.deep_rca_breakdown is not None and state is None:
            if isinstance(report.deep_rca_breakdown, DeepRCABreakdown):
                return report.deep_rca_breakdown
            return DeepRCABreakdown.model_validate(report.deep_rca_breakdown)
        if report.deep_rca_breakdown is not None and isinstance(report.deep_rca_breakdown, DeepRCABreakdown):
            return report.deep_rca_breakdown
        return cls.build_deep_rca_breakdown(report, state)

    @classmethod
    def _coerce_verification_gate(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> List[VerificationGateItem]:
        raw_gate = report.verification_gate or report.verification_checklist
        if raw_gate and (state is None or all(isinstance(x, VerificationGateItem) for x in raw_gate)):
            return [
                x if isinstance(x, VerificationGateItem) else VerificationGateItem.model_validate(x)
                for x in raw_gate
            ]
        return cls.build_verification_gate(report, state)

    @classmethod
    def _coerce_capa_plan(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
    ) -> List[CAPAItem]:
        raw_capa = report.capa_plan
        if raw_capa is not None and state is None:
            if isinstance(raw_capa, list):
                return [
                    x if isinstance(x, CAPAItem) else CAPAItem.model_validate(x)
                    for x in raw_capa
                ]
            if isinstance(raw_capa, dict):
                raw_items = raw_capa.get("items") or []
                if isinstance(raw_items, list):
                    return [
                        x if isinstance(x, CAPAItem) else CAPAItem.model_validate(x)
                        for x in raw_items
                    ]
        if isinstance(raw_capa, list) and all(isinstance(x, CAPAItem) for x in raw_capa):
            return raw_capa
        return cls.build_capa_plan(report, state)

    # =====================================================================
    # 2. HÀM SINH BÁO CÁO CHÍNH (GENERATE REPORT)
    # =====================================================================
    def generate_report(self, state: IncidentState) -> IncidentReport:
        """
        Tổng hợp toàn bộ IncidentState thành đối tượng IncidentReport chuẩn Pydantic v2.
        Tự động fallback an toàn nếu state thiếu thông tin CTI, RCA hoặc Triage.

        :param state: IncidentState luân chuyển từ pipeline.
        :return: Đối tượng IncidentReport hoàn chỉnh.
        """
        if not state or not state.incident_id:
            raise ValueError("IncidentState không hợp lệ hoặc thiếu incident_id")

        logger.info(f"[{state.incident_id}] Bắt đầu khởi tạo IncidentReport...")

        triage = self._get_triage(state)
        rca = self._get_rca(state)

        # 1. Thu thập thông tin cơ bản và Severity thực tế
        severity_str = self._resolve_severity(state)
        status_display = self._resolve_status_display(state)
        hosts_list, users_list = self._extract_scope(state)

        # Xác định Attack Type, Attack Category và Confidence Level
        attack_type = (
            state.attack_type
            or (rca.confirmed_attack_type if rca else None)
            or (triage.attack_type if triage else None)
        )
        if not attack_type:
            if triage and not triage.is_incident:
                attack_type = "Normal Administrative Activity (Benign)"
            elif rca and rca.initial_access_vector and any(
                k in rca.initial_access_vector for k in ["Spearphishing", "Drive-by"]
            ):
                attack_type = "Endpoint Malware & C2 Reverse Shell"
            elif triage and triage.summary and "mã độc" in triage.summary.lower():
                attack_type = "Endpoint Malware & C2 Reverse Shell"
            elif rca and rca.initial_access_vector and any(
                k in rca.initial_access_vector.lower() for k in ["brute-force", "brute force", "ssh"]
            ):
                attack_type = "Password Spraying & Credential Theft"
            elif triage and triage.summary and any(
                k in triage.summary.lower() for k in ["brute", "ssh", "đăng nhập sai"]
            ):
                attack_type = "Password Spraying & Credential Theft"
            elif triage and triage.summary and any(
                k in triage.summary.lower() for k in ["scan", "quét cổng", "recon"]
            ):
                attack_type = "Network Scanning & Service Discovery"
            else:
                attack_type = "Security Incident Investigation"

        if not state.attack_type:
            state.attack_type = attack_type

        # Xác định Attack Category
        if triage and triage.attack_category:
            cat = triage.attack_category
            attack_category = cat.value if hasattr(cat, "value") else str(cat)
        elif "Malware" in attack_type or "Reverse Shell" in attack_type:
            attack_category = AttackCategory.MALWARE.value
        elif "Password" in attack_type or "Credential" in attack_type or "Brute" in attack_type:
            attack_category = AttackCategory.CREDENTIAL_ACCESS.value
        elif "Scanning" in attack_type or "Discovery" in attack_type:
            attack_category = AttackCategory.RECONNAISSANCE.value
        elif "Web" in attack_type:
            attack_category = AttackCategory.WEB_ATTACK.value
        elif "Benign" in attack_type or "Normal" in attack_type:
            attack_category = AttackCategory.BENIGN.value
        else:
            attack_category = AttackCategory.UNKNOWN.value

        # Xác định Confidence Level trung thực
        if triage and triage.confidence_score is not None:
            confidence_level: Optional[float] = float(triage.confidence_score)
        else:
            confidence_level = None

        # 2. Xây dựng các thành phần cốt lõi
        self._last_grounding_violations = []
        self._last_security_flags = []
        self._last_grounded_synthesis = None

        base_exec_summary = self._build_executive_summary(
            state=state,
            severity=severity_str,
            status_display=status_display,
            hosts=hosts_list,
            users=users_list,
            attack_type=attack_type,
        )

        exec_summary = base_exec_summary
        grounded_synthesis: Optional[ReportingLLMSynthesis] = None
        llm_grounded_flag = False
        if self.llm_enabled and self.llm_provider is not None:
            (
                exec_summary,
                grounded_synthesis,
                llm_grounded_flag,
                violations,
                sec_flags,
            ) = self._synthesize_with_llm(
                state=state,
                base_summary=base_exec_summary,
                attack_type=attack_type,
                severity=severity_str,
            )
            self._last_grounding_violations = violations
            self._last_security_flags = sec_flags
            if llm_grounded_flag and grounded_synthesis is not None:
                self._last_grounded_synthesis = grounded_synthesis

        detailed_findings = self._build_detailed_findings(state)
        mitre_mapping = self._extract_mitre_mapping(state)
        ioc_table = self._build_ioc_table(state)
        action_plan = self._build_action_plan(state)

        report_id = f"REP-{state.incident_id}" if not state.incident_id.startswith("REP-") else state.incident_id
        incident_title = f"Báo cáo Điều tra Sự cố [{severity_str}]: {attack_type} - {state.incident_id}"

        is_incident_flag = (
            bool(triage.is_incident)
            if triage is not None
            else (state.status != IncidentStatus.CLOSED_FALSE_POSITIVE)
        )
        cur_status_val = state.status.value if hasattr(state.status, "value") else str(state.status)

        report = IncidentReport(
            report_id=report_id,
            incident_title=incident_title,
            created_at=datetime.now(timezone.utc),
            executive_summary=exec_summary,
            detailed_findings=detailed_findings,
            mitre_attack_matrix_mapping=mitre_mapping,
            ioc_table=ioc_table,
            action_plan=action_plan,
            attack_type=attack_type,
            attack_category=attack_category,
            confidence_level=confidence_level,
            severity=severity_str,
            incident_status=cur_status_val,
            is_incident=is_incident_flag,
            organization_name=self.organization_name,
            response_strategy_summary=getattr(state, "response_strategy_summary", None),
            llm_grounded=llm_grounded_flag,
        )

        # 3. Bổ sung các cấu trúc đánh giá grounded từ state + report
        report.operational_metrics = self.build_operational_metrics(report, state)
        report.impact_assessment = self.build_impact_assessment(report, state)
        deep_rca = self.build_deep_rca_breakdown(report, state)
        capa_items = self.build_capa_plan(report, state)

        # Chỉ áp dụng các trường structured từ LLM sau khi đã kiểm chứng grounding thành công
        if llm_grounded_flag and grounded_synthesis is not None:
            if grounded_synthesis.cia_rationale:
                report.impact_assessment = self._apply_cia_rationale(
                    report.impact_assessment,
                    grounded_synthesis.cia_rationale,
                )
            if grounded_synthesis.evidence_citations:
                report.detailed_findings = self._append_evidence_citations(
                    report.detailed_findings,
                    grounded_synthesis.evidence_citations,
                )
            is_benign_ctx = self._is_benign_context(report, state)
            if deep_rca.applicable and not is_benign_ctx:
                if grounded_synthesis.five_whys:
                    cleaned_whys = [str(w).strip() for w in grounded_synthesis.five_whys if str(w).strip()]
                    if cleaned_whys:
                        deep_rca.five_whys = cleaned_whys
                if grounded_synthesis.ishikawa_factors:
                    normalized_ishikawa: List[Dict[str, str]] = []
                    for row in grounded_synthesis.ishikawa_factors:
                        if isinstance(row, dict):
                            branch = str(row.get("branch", "") or "").strip()
                            finding = str(row.get("finding") or row.get("weakness") or "").strip()
                            countermeasure = str(row.get("countermeasure", "") or "").strip()
                            if branch or finding or countermeasure:
                                normalized_ishikawa.append(
                                    {
                                        "branch": branch,
                                        "finding": finding,
                                        "countermeasure": countermeasure,
                                    }
                                )
                    if normalized_ishikawa:
                        deep_rca.ishikawa_factors = normalized_ishikawa

            if not is_benign_ctx and grounded_synthesis.capa_recommendations:
                validated_capas: List[CAPAItem] = []
                for idx, item in enumerate(grounded_synthesis.capa_recommendations, start=1):
                    if isinstance(item, CAPAItem):
                        validated_capas.append(item)
                    elif isinstance(item, dict):
                        payload = dict(item)
                        payload.setdefault("code", f"CAPA-{idx:02d}")
                        validated_capas.append(CAPAItem.model_validate(payload))
                if validated_capas:
                    capa_items = validated_capas

        report.deep_rca_breakdown = deep_rca
        gate_items = self.build_verification_gate(report, state)
        report.verification_gate = gate_items
        report.verification_checklist = list(gate_items)
        report.capa_plan = capa_items

        logger.info(
            f"[{state.incident_id}] Hoàn tất sinh báo cáo {report.report_id} "
            f"(IoCs: {len(report.ioc_table)}, Actions: {len(report.action_plan)})"
        )
        return report

    # =====================================================================
    # 3. XUẤT ĐỊNH DẠNG MARKDOWN, JSON & DOCX
    # =====================================================================
    @classmethod
    def export_markdown(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
        organization_name: Optional[str] = None,
    ) -> str:
        """
        Định dạng báo cáo thành tài liệu Markdown chuyên nghiệp gắn với bằng chứng thực tế.
        Hỗ trợ gọi cả dưới dạng classmethod (ReportingAgent.export_markdown(report, state=None))
        lẫn instance method (agent.export_markdown(report)) và hoạt động độc lập khi state=None.

        :param report: Đối tượng IncidentReport cần xuất bản.
        :param state: IncidentState tùy chọn để làm giàu thêm kiểm chứng thực tế.
        :param organization_name: Tên cơ quan/tổ chức điều tra.
        :return: Chuỗi Markdown đã được định dạng.
        """
        if isinstance(state, str) and organization_name is None:
            organization_name = state
            state = None

        org_name = (
            organization_name
            or getattr(report, "organization_name", None)
            or DEFAULT_ORGANIZATION_NAME
        )
        created_str = format_vn_time(report.created_at, "%Y-%m-%d %H:%M:%S (ICT / Giờ Việt Nam)")
        severity_label = cls._resolve_report_severity(report, state)
        op_metrics = cls._coerce_operational_metrics(report, state)
        impact = cls._coerce_impact_assessment(report, state)
        deep_rca = cls._coerce_deep_rca(report, state)
        gate_items = cls._coerce_verification_gate(report, state)
        capa_items = cls._coerce_capa_plan(report, state)
        is_benign = cls._is_benign_context(report, state)
        evidence_text = cls._collect_evidence_text(report, state)

        if report.confidence_level is not None:
            confidence_str = f"{int(round(float(report.confidence_level) * 100))}%"
        else:
            confidence_str = "Chưa đánh giá (thiếu Triage)"

        md_lines: List[str] = []

        # Header Báo cáo & Bảng chỉ số thực đo
        md_lines.append(f"# {report.incident_title}")
        md_lines.append("")
        md_lines.append(f"> **Cơ quan điều tra:** {org_name}  ")
        md_lines.append(f"> **Mã báo cáo:** `{report.report_id}`  ")
        md_lines.append(f"> **Thời gian xuất bản:** {created_str}  ")
        md_lines.append("### 📋 Thông tin Định danh & Chỉ số Ứng cứu Sự cố")
        md_lines.append("")
        md_lines.append("| Thuộc tính | Chi tiết ghi nhận | Tiêu chuẩn quy chiếu |")
        md_lines.append("| :--- | :--- | :--- |")
        md_lines.append(
            f"| **Mã Sự cố (Incident ID)** | `{report.report_id.replace('REP-', '')}` | ISO/IEC 27035 Incident ID |"
        )
        md_lines.append(
            f"| **Phân loại Tấn công** | **{report.attack_type or 'Chưa phân loại'}** | "
            f"NIST SP 800-61 Category: `{report.attack_category or 'UNKNOWN'}` |"
        )
        md_lines.append(
            f"| **Mức độ Nghiêm trọng** | `{severity_label}` | Đánh giá từ Triage / Ngữ cảnh sự cố |"
        )
        md_lines.append(
            f"| **Độ tin cậy Phân tích** | {confidence_str} | Triage & Threat Intel Correlation |"
        )
        md_lines.append(
            f"| **Chỉ số Vận hành IR** | **MTTA:** {op_metrics.mtta_display} \\| "
            f"**MTTC:** {op_metrics.mttc_display} \\| **MTTR:** {op_metrics.mttr_display} | "
            f"**SLA:** {op_metrics.sla_status} |"
        )
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 1. Executive Summary Callout Block
        md_lines.append("## 📌 1. Tóm lược điều hành (Executive Summary)")
        md_lines.append("")
        md_lines.append("> ### 🚨 TÓM TẮT DÀNH CHO BAN GIÁM ĐỐC (CISO/CIO)")
        for line in report.executive_summary.strip().split("\n"):
            md_lines.append(f"> {line}")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 2. Detailed Technical Findings
        md_lines.append("## 🔍 2. Chi tiết kỹ thuật & Phân tích nguyên nhân (Detailed Findings)")
        md_lines.append("")
        md_lines.append(report.detailed_findings.strip())
        md_lines.append("")

        # Ma trận Bằng chứng Điều tra 3 Lớp (Evidence Matrix - Grounded)
        md_lines.append("### 📊 Ma trận Bằng chứng Điều tra 3 Lớp (Evidence Matrix)")
        md_lines.append("")
        md_lines.append("| Lớp Bằng chứng | Nguồn / Đối tượng Xác thực | Bằng chứng Cốt lõi & Quan sát Thực nghiệm | Đánh giá & Ý nghĩa Điều tra |")
        md_lines.append("| :--- | :--- | :--- | :--- |")

        # Lớp 1: Bằng chứng Log SIEM
        if state is not None and (state.raw_logs or state.parsed_events):
            sources = sorted(
                {
                    *(r.log_source for r in state.raw_logs if r.log_source),
                    *(e.source_type for e in state.parsed_events if e.source_type),
                }
            )
            siem_source = ", ".join(sources) if sources else "SIEM / Nhật ký hệ thống"
        elif "zeek" in evidence_text:
            siem_source = "Zeek Network Telemetry / SIEM"
        elif "sysmon" in evidence_text:
            siem_source = "Wazuh SIEM / Sysmon Event Log"
        else:
            siem_source = "SIEM / Nhật ký sự kiện hệ thống"

        if report.attack_category:
            siem_eval = (
                f"Phân loại nhóm `{report.attack_category}` (Mức độ: `{severity_label}`, Độ tin cậy: {confidence_str})"
            )
        else:
            siem_eval = f"Ghi nhận dữ liệu cảnh báo an ninh (Mức độ: `{severity_label}`)"
        siem_evidence = (
            f"Định danh sự kiện: `{report.report_id.replace('REP-', '')}` | "
            f"Phân loại: **{report.attack_type or 'Chưa xác định'}**"
        )
        md_lines.append(f"| **1. Bằng chứng Log SIEM** | {siem_source} | {siem_evidence} | {siem_eval} |")

        # Lớp 2: Bằng chứng Endpoint / Host
        rca = cls._get_rca(state)
        has_process_tree = bool(rca and getattr(rca, "process_tree", None)) or (
            "PATIENT ZERO" in report.detailed_findings or "PID `" in report.detailed_findings
        )
        if is_benign:
            endpoint_source = "Endpoint / Host Telemetry"
            endpoint_evidence = "Không ghi nhận chuỗi tiến trình độc hại"
            endpoint_eval = "Hoạt động bình thường trên hệ thống (Benign / False Positive)"
        elif has_process_tree:
            endpoint_source = "Sysmon / Process Lineage"
            endpoint_evidence = "Tái hiện cây tiến trình thực thi liên quan từ nhật ký sự kiện"
            endpoint_eval = "Xác định quan hệ tiến trình cha-con và dòng lệnh thực thi thực tế"
        elif cls._has_macro_evidence(state, report):
            endpoint_source = "Endpoint / Office Application Telemetry"
            endpoint_evidence = "Ghi nhận dấu vết tài liệu hoặc kịch bản thực thi đáng ngờ"
            endpoint_eval = "Đánh giá nguy cơ xâm nhập ban đầu từ tệp tài liệu"
        elif any(k in evidence_text for k in ("ssh", "brute", "4625", "failed password")):
            endpoint_source = "Authentication / Security Event Log"
            endpoint_evidence = "Ghi nhận chuỗi sự kiện xác thực / đăng nhập bất thường"
            endpoint_eval = "Đánh giá nỗ lực truy cập trái phép vào tài khoản hệ thống"
        else:
            endpoint_source = "Endpoint / Host Telemetry"
            endpoint_evidence = "Chưa có dữ liệu cây tiến trình endpoint chi tiết"
            endpoint_eval = "Đánh giá dựa trên ngữ cảnh sự kiện mạng/SIEM hiện có"
        md_lines.append(
            f"| **2. Bằng chứng Trạm nạn nhân (Endpoint)** | {endpoint_source} | {endpoint_evidence} | {endpoint_eval} |"
        )

        # Lớp 3: Bằng chứng Mạng & CTI
        network_source = "Network Logs / Threat Intel Feeds"
        if report.ioc_table:
            mal_iocs = [i for i in report.ioc_table if i.is_malicious]
            sample_list = mal_iocs[:2] if mal_iocs else report.ioc_table[:2]
            ioc_summary = ", ".join(f"`{i.value}` ({i.ioc_type})" for i in sample_list)
            tech_str = (
                f"MITRE: {', '.join(report.mitre_attack_matrix_mapping[:3])}"
                if report.mitre_attack_matrix_mapping
                else ""
            )
            network_evidence = f"IoCs ghi nhận: {ioc_summary} {tech_str}".strip()
            if mal_iocs:
                network_eval = f"Xác nhận {len(mal_iocs)} IoC có dấu hiệu độc hại qua đối chiếu CTI"
            else:
                network_eval = "Các IoC đã kiểm tra chưa ghi nhận dấu hiệu độc hại (Clean / Benign)"
        else:
            tech_str = (
                f"MITRE: {', '.join(report.mitre_attack_matrix_mapping[:3])}"
                if report.mitre_attack_matrix_mapping
                else "Không ghi nhận mã kỹ thuật"
            )
            network_evidence = f"Không ghi nhận IoC ngoại lai | {tech_str}"
            network_eval = "Không phát hiện chỉ số xâm phạm mạng bên ngoài trong dữ liệu hiện có"
        md_lines.append(f"| **3. Bằng chứng Mạng & CTI** | {network_source} | {network_evidence} | {network_eval} |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 3. MITRE ATT&CK Matrix Mapping
        md_lines.append("## 🎯 3. Ma trận kỹ thuật MITRE ATT&CK")
        md_lines.append("")
        if report.mitre_attack_matrix_mapping:
            md_lines.append("| STT | Mã kỹ thuật MITRE ATT&CK |")
            md_lines.append("| :---: | :--- |")
            for idx, tech in enumerate(report.mitre_attack_matrix_mapping, start=1):
                md_lines.append(f"| {idx} | `{tech}` |")
        else:
            md_lines.append("*Không ghi nhận mã kỹ thuật MITRE ATT&CK.*")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 4. IoC Table
        md_lines.append("## 🛡️ 4. Danh sách chỉ số xâm phạm (IoC Table)")
        md_lines.append("")
        md_lines.append("| Loại | Giá trị | Điểm nguy cơ | Độc hại |")
        md_lines.append("| :--- | :--- | :---: | :---: |")
        if report.ioc_table:
            for ioc in report.ioc_table:
                score_str = str(ioc.reputation_score) if ioc.reputation_score is not None else "N/A"
                malicious_str = "Có" if ioc.is_malicious else "Không"
                md_lines.append(f"| {ioc.ioc_type} | `{ioc.value}` | {score_str} | {malicious_str} |")
        else:
            md_lines.append("| N/A | Không phát hiện IoC bên ngoài | 0 | Không |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 5. Action Plan Table
        md_lines.append("## 📋 5. Kế hoạch phản ứng & Hành động ứng phó (Action Plan)")
        md_lines.append("")
        md_lines.append("| Loại hành động | Mục tiêu | Độ ưu tiên | Cần duyệt | Trạng thái |")
        md_lines.append("| :--- | :--- | :---: | :---: | :---: |")
        if report.action_plan:
            for action in report.action_plan:
                act_type = action.action_type.value if hasattr(action.action_type, "value") else str(action.action_type)
                need_approval = "Có" if action.require_human_approval else "Không"
                is_rb = cls._is_action_rolled_back(action)
                if is_rb:
                    rb_reason = (action.parameters or {}).get("rollback_reason", "HOÀN TÁC")
                    approval_status = f"Đã hoàn tác ({rb_reason})"
                elif action.is_approved is True:
                    approval_status = (
                        "Đã duyệt & Thực thi"
                        if cls._is_action_executed(action, state, report) and (action.parameters or {}).get("execution_status") == "EXECUTED"
                        else "Đã duyệt"
                    )
                elif action.is_approved is False:
                    approval_status = "Bị từ chối"
                else:
                    approval_status = "Chờ duyệt"
                md_lines.append(
                    f"| {act_type} | `{action.target}` | Mức {action.priority} | {need_approval} | {approval_status} |"
                )
        else:
            md_lines.append("| N/A | Không có hành động nào được đề xuất | N/A | Không | N/A |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 6. Comprehensive Impact Assessment (Grounded)
        md_lines.append("## ⚖️ 6. Đánh giá mức độ ảnh hưởng toàn diện (Comprehensive Impact Assessment)")
        md_lines.append("")
        md_lines.append("### 6.1. Đánh giá theo bộ ba an toàn thông tin (CIA Triad)")
        md_lines.append("")
        md_lines.append("| Chiều tác động | Mức độ ảnh hưởng | Đánh giá hiện trạng vi phạm & Rủi ro |")
        md_lines.append("| :--- | :---: | :--- |")
        md_lines.append(
            f"| **Tính Bảo mật (Confidentiality)** | **{impact.confidentiality.level}** | {impact.confidentiality.assessment} |"
        )
        md_lines.append(
            f"| **Tính Toàn vẹn (Integrity)** | **{impact.integrity.level}** | {impact.integrity.assessment} |"
        )
        md_lines.append(
            f"| **Tính Sẵn sàng (Availability)** | **{impact.availability.level}** | {impact.availability.assessment} |"
        )
        md_lines.append("")
        md_lines.append("### 6.2. Đánh giá tác động vận hành, tài chính & Tuân thủ pháp lý (Nghị định 13/2023/NĐ-CP)")
        md_lines.append("")
        md_lines.append("| Hạng mục tác động | Chi tiết đánh giá dựa trên bằng chứng |")
        md_lines.append("| :--- | :--- |")
        md_lines.append(f"| **Tác động Vận hành & SLA** | {impact.operational_sla_note} |")
        md_lines.append(f"| **Tác động Tài chính** | {impact.financial_impact_note} |")
        md_lines.append(f"| **Nghị định 13/2023/NĐ-CP (Bảo vệ DLCN)** | {impact.compliance_note} |")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 7. Deep Root Cause Analysis (Grounded)
        md_lines.append("## 🔬 7. Phân tích nguyên nhân gốc rễ chuyên sâu (Root Cause Analysis - RCA)")
        md_lines.append("")
        if not deep_rca.applicable:
            md_lines.append(f"*{deep_rca.proximate_cause}*")
            md_lines.append(f"- **Nhận định:** {deep_rca.root_cause}")
            md_lines.append(f"- **Khuyến nghị tinh chỉnh:** {deep_rca.contributing_factors}")
        else:
            md_lines.append("### 7.1. Phân định các tầng nguyên nhân")
            md_lines.append(f"1. **Nguyên nhân trực tiếp (Proximate Cause):** {deep_rca.proximate_cause}")
            md_lines.append(f"2. **Yếu tố đóng góp (Contributing Factors):** {deep_rca.contributing_factors}")
            md_lines.append(f"3. **Nguyên nhân gốc rễ (Root Cause):** {deep_rca.root_cause}")

            if deep_rca.five_whys:
                md_lines.append("")
                md_lines.append("### 7.2. Chuỗi phân tích nguyên nhân (5 Whys)")
                md_lines.append("```text")
                for step in deep_rca.five_whys:
                    md_lines.append(step)
                md_lines.append("```")

            if deep_rca.ishikawa_factors:
                md_lines.append("")
                md_lines.append("### 7.3. Biểu đồ xương cá Ishikawa (Fishbone Analysis)")
                md_lines.append("| Nhánh xương cá | Điểm yếu cốt lõi phát hiện | Biện pháp ngăn chặn căn cơ |")
                md_lines.append("| :--- | :--- | :--- |")
                for row in deep_rca.ishikawa_factors:
                    md_lines.append(
                        f"| **{row.get('branch', '')}** | {row.get('finding', '')} | {row.get('countermeasure', '')} |"
                    )
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 8. Multi-tiered Containment & Integrity Verification Gate (Grounded)
        md_lines.append("## 🛡️ 8. Chiến lược ứng cứu đa tầng & Cổng kiểm định an toàn (Containment & Integrity Gate)")
        md_lines.append("")
        md_lines.append("### 8.1. Tóm tắt biện pháp xử lý theo dữ liệu thực tế")
        if report.response_strategy_summary:
            md_lines.append(f"- **Chiến lược chỉ huy phản ứng:** {report.response_strategy_summary}")
        if is_benign and not report.action_plan:
            md_lines.append("- Không kích hoạt biện pháp cô lập/triệt tiêu vì sự kiện được xác minh là Benign / False Positive.")
        elif report.action_plan:
            for act in report.action_plan:
                act_type = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
                phase_str = act.phase.value if hasattr(act.phase, "value") else (str(act.phase) if act.phase else "RESPONSE")
                if cls._is_action_rolled_back(act):
                    st_label = "Đã hoàn tác"
                elif cls._is_action_executed(act, state, report):
                    st_label = "Đã thực thi"
                elif act.is_approved is True:
                    st_label = "Đã duyệt"
                elif act.is_approved is False:
                    st_label = "Bị từ chối"
                else:
                    st_label = "Chờ duyệt"
                md_lines.append(
                    f"- **[{phase_str}] {act_type}** trên `{act.target}` — {act.description} *(Trạng thái: {st_label})*"
                )
        else:
            md_lines.append("- Chưa có hành động khoanh vùng hoặc triệt tiêu nào được đề xuất trong báo cáo này.")

        md_lines.append("")
        md_lines.append("### 8.2. Cổng kiểm định an toàn trước khi Go-Live (Integrity Verification Gate)")
        for item in gate_items:
            mark = "[x]" if item.checked else "[ ]"
            md_lines.append(f"- {mark} **{item.label}:** {item.detail}")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # 9. Long-term Action Plan (CAPA) with RACI (Grounded)
        md_lines.append("## 📈 9. Kế hoạch hành động dài hạn (CAPA) & Bài học kinh nghiệm (Lessons Learned)")
        md_lines.append("")
        md_lines.append("### 9.1. Bảng kế hoạch hành động khắc phục & phòng ngừa (CAPA) với Ma trận RACI")
        md_lines.append("*Quy ước RACI:* **R** = Thực hiện (Responsible), **A** = Chịu trách nhiệm chính (Accountable), **C** = Tham vấn (Consulted), **I** = Nhận thông tin (Informed).")
        md_lines.append("")
        md_lines.append("| Mã việc | Hạng mục hành động khắc phục | Phân loại | Độ ưu tiên | Ma trận RACI | Thời hạn | Tiêu chí nghiệm thu (KPI) |")
        md_lines.append("| :---: | :--- | :---: | :---: | :---: | :---: | :--- |")
        for capa in capa_items:
            md_lines.append(
                f"| **{capa.code}** | {capa.item} | {capa.category} | **{capa.priority}** | "
                f"{capa.raci or 'N/A'} | {capa.timeline or 'N/A'} | {capa.kpi or 'N/A'} |"
            )
        md_lines.append("")
        md_lines.append("### 9.2. Chỉ số đo lường & Theo dõi hậu sự cố (Post-Incident KPIs)")
        md_lines.append(
            f"1. **Chỉ số phản ứng thực đo:** MTTA = `{op_metrics.mtta_display}`, "
            f"MTTC = `{op_metrics.mttc_display}`, MTTR = `{op_metrics.mttr_display}`."
        )
        for kpi_idx, capa in enumerate(capa_items[:2], start=2):
            if capa.kpi:
                md_lines.append(f"{kpi_idx}. **Nghiệm thu {capa.code}:** {capa.kpi}.")
        md_lines.append("")
        md_lines.append("---")

        return "\n".join(md_lines)

    @classmethod
    def export_json(cls, report: IncidentReport) -> str:
        """
        Trích xuất báo cáo ra chuỗi JSON định dạng chuẩn hóa, thụt lề 2 spaces.

        :param report: Đối tượng IncidentReport cần xuất bản.
        :return: Chuỗi JSON chuẩn hóa.
        """
        return report.model_dump_json(indent=2)

    @classmethod
    def export_docx(
        cls,
        report: IncidentReport,
        state: Optional[IncidentState] = None,
        organization_name: Optional[str] = None,
    ) -> bytes:
        """
        Sinh tài liệu Word (.docx) chuyên nghiệp từ IncidentReport bằng python-docx.
        Hỗ trợ gọi cả dưới dạng instance method (agent.export_docx(report))
        lẫn class method (ReportingAgent.export_docx(report, state=None)).

        :param report: Đối tượng IncidentReport cần xuất bản.
        :param state: IncidentState tùy chọn để đối chiếu dữ liệu thực tế.
        :param organization_name: Tên cơ quan điều tra an ninh mạng.
        :return: Mảng bytes của tệp DOCX sẵn sàng để lưu đĩa hoặc gửi qua HTTP download.
        """
        try:
            import docx
            from docx.shared import Inches, Pt, RGBColor
            from docx.enum.text import WD_ALIGN_PARAGRAPH
            from docx.enum.table import WD_TABLE_ALIGNMENT
        except ImportError:
            raise ImportError(
                "Thư viện 'python-docx' chưa được cài đặt. Vui lòng cài đặt: pip install python-docx"
            )

        if isinstance(state, str) and organization_name is None:
            organization_name = state
            state = None

        org_name = (
            organization_name
            or getattr(report, "organization_name", None)
            or DEFAULT_DOCX_ORGANIZATION_NAME
        )
        severity_label = cls._resolve_report_severity(report, state)
        op_metrics = cls._coerce_operational_metrics(report, state)
        impact = cls._coerce_impact_assessment(report, state)
        deep_rca = cls._coerce_deep_rca(report, state)
        gate_items = cls._coerce_verification_gate(report, state)
        capa_items = cls._coerce_capa_plan(report, state)

        if report.confidence_level is not None:
            confidence_str = f"{int(round(float(report.confidence_level) * 100))}%"
        else:
            confidence_str = "Chưa đánh giá (thiếu Triage)"

        doc = docx.Document()

        # Cấu hình lề trang 1 inch
        for section in doc.sections:
            section.top_margin = Inches(1)
            section.bottom_margin = Inches(1)
            section.left_margin = Inches(1)
            section.right_margin = Inches(1)

        # 1. Header Khóa luận & Cơ quan điều tra
        p_header = doc.add_paragraph()
        p_header.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_uni = p_header.add_run(f"{org_name}\n")
        r_uni.bold = True
        r_uni.font.size = Pt(13)
        r_uni.font.color.rgb = RGBColor(0, 51, 102)

        r_dep = p_header.add_run("KHOA CÔNG NGHỆ THÔNG TIN - BỘ MÔN AN TOÀN THÔNG TIN\n")
        r_dep.bold = True
        r_dep.font.size = Pt(11)

        r_sub = p_header.add_run("BÁO CÁO ĐIỀU TRA SỰ CỐ AN NINH MẠNG (SOC MULTI-AGENT)\n")
        r_sub.font.size = Pt(10)
        r_sub.font.italic = True

        doc.add_paragraph("―" * 45).alignment = WD_ALIGN_PARAGRAPH.CENTER

        # 2. Tiêu đề Báo cáo
        p_title = doc.add_heading(level=0)
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_title = p_title.add_run(f"🛡️ {report.incident_title}")
        r_title.font.size = Pt(18)
        r_title.bold = True
        r_title.font.color.rgb = RGBColor(180, 0, 0)

        # Metadata thực tế
        p_meta = doc.add_paragraph()
        p_meta.add_run("• Mã Báo cáo: ").bold = True
        p_meta.add_run(f"{report.report_id}\n")
        p_meta.add_run("• Thời gian xuất bản: ").bold = True
        p_meta.add_run(f"{format_vn_time(report.created_at, '%Y-%m-%d %H:%M:%S (ICT / Giờ Việt Nam)')}\n")
        p_meta.add_run("• Phân loại & Mức độ nghiêm trọng: ").bold = True
        p_meta.add_run(
            f"{report.attack_type or 'Chưa phân loại'} ({report.attack_category or 'UNKNOWN'}) | Mức độ: {severity_label} | Độ tin cậy: {confidence_str}\n"
        )
        p_meta.add_run("• Chỉ số Vận hành IR: ").bold = True
        p_meta.add_run(
            f"MTTA: {op_metrics.mtta_display} | MTTC: {op_metrics.mttc_display} | MTTR: {op_metrics.mttr_display} | SLA: {op_metrics.sla_status}\n"
        )
        p_meta.add_run("• Tiêu chuẩn tham chiếu: ").bold = True
        p_meta.add_run("NIST SP 800-61 Rev.2 & MITRE ATT&CK Framework\n")

        # 3. Mục 1: Executive Summary
        h1 = doc.add_heading("1. Tóm lược điều hành (Executive Summary)", level=1)
        h1.style.font.color.rgb = RGBColor(0, 51, 102)
        p_exec = doc.add_paragraph()
        r_exec = p_exec.add_run(report.executive_summary)
        r_exec.font.size = Pt(11)

        # 4. Mục 2: Detailed Technical Findings
        h2 = doc.add_heading("2. Chi tiết kỹ thuật & Phân tích nguyên nhân (Technical Findings)", level=1)
        h2.style.font.color.rgb = RGBColor(0, 51, 102)
        p_tech = doc.add_paragraph()
        p_tech.add_run(report.detailed_findings)

        # 5. Mục 3: MITRE ATT&CK Matrix Mapping
        h3 = doc.add_heading("3. Ma trận Kỹ thuật MITRE ATT&CK", level=1)
        h3.style.font.color.rgb = RGBColor(0, 51, 102)
        if report.mitre_attack_matrix_mapping:
            for idx, tech in enumerate(report.mitre_attack_matrix_mapping, start=1):
                doc.add_paragraph(f"{idx}. Mã Kỹ thuật: {tech}", style="List Bullet")
        else:
            doc.add_paragraph("Không ghi nhận mã kỹ thuật MITRE ATT&CK.")

        # 6. Mục 4: Bảng IoC
        h4 = doc.add_heading("4. Danh sách Chỉ số Xâm phạm (IoC Table)", level=1)
        h4.style.font.color.rgb = RGBColor(0, 51, 102)

        if report.ioc_table:
            table_ioc = doc.add_table(rows=1, cols=5)
            table_ioc.alignment = WD_TABLE_ALIGNMENT.CENTER
            hdr_cells = table_ioc.rows[0].cells
            hdr_titles = ["STT", "Loại IoC", "Giá trị Chỉ số", "Điểm Độc hại", "Đánh giá"]
            for i, title in enumerate(hdr_titles):
                hdr_cells[i].text = title
                hdr_cells[i].paragraphs[0].runs[0].bold = True

            for idx, ioc in enumerate(report.ioc_table, start=1):
                row_cells = table_ioc.add_row().cells
                row_cells[0].text = str(idx)
                row_cells[1].text = ioc.ioc_type
                row_cells[2].text = ioc.value
                row_cells[3].text = str(ioc.reputation_score) if ioc.reputation_score is not None else "N/A"
                row_cells[4].text = "Độc hại" if ioc.is_malicious else "Đã kiểm tra"
        else:
            doc.add_paragraph("Không phát hiện chỉ số xâm phạm ngoài vùng tin cậy.")

        # 7. Mục 5: Action Plan
        h5 = doc.add_heading("5. Kế hoạch Phản ứng & Hành động Khắc phục (Action Plan)", level=1)
        h5.style.font.color.rgb = RGBColor(0, 51, 102)

        if report.action_plan:
            table_act = doc.add_table(rows=1, cols=5)
            table_act.alignment = WD_TABLE_ALIGNMENT.CENTER
            hdr_cells_act = table_act.rows[0].cells
            hdr_titles_act = ["Loại hành động", "Mục tiêu (Target)", "Ưu tiên", "Cần duyệt", "Trạng thái"]
            for i, title in enumerate(hdr_titles_act):
                hdr_cells_act[i].text = title
                hdr_cells_act[i].paragraphs[0].runs[0].bold = True

            for act in report.action_plan:
                row_cells = table_act.add_row().cells
                row_cells[0].text = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
                row_cells[1].text = act.target
                row_cells[2].text = f"Mức {act.priority}"
                row_cells[3].text = "Có" if act.require_human_approval else "Không"
                if cls._is_action_rolled_back(act):
                    rb_reason = (act.parameters or {}).get("rollback_reason", "HOÀN TÁC")
                    st_txt = f"Đã hoàn tác ({rb_reason})"
                elif act.is_approved is True:
                    st_txt = "Đã duyệt"
                elif act.is_approved is False:
                    st_txt = "Bị từ chối"
                else:
                    st_txt = "Chờ duyệt"
                row_cells[4].text = st_txt
        else:
            doc.add_paragraph("Không có hành động nào cần thực thi.")

        # 8. Mục 6: Đánh giá tác động toàn diện (Grounded)
        h6 = doc.add_heading("6. Đánh giá mức độ ảnh hưởng toàn diện (CIA & Tuân thủ)", level=1)
        h6.style.font.color.rgb = RGBColor(0, 51, 102)
        doc.add_paragraph(f"• Bảo mật (Confidentiality) [{impact.confidentiality.level}]: {impact.confidentiality.assessment}")
        doc.add_paragraph(f"• Toàn vẹn (Integrity) [{impact.integrity.level}]: {impact.integrity.assessment}")
        doc.add_paragraph(f"• Sẵn sàng (Availability) [{impact.availability.level}]: {impact.availability.assessment}")
        doc.add_paragraph(f"• Vận hành & SLA: {impact.operational_sla_note}")
        doc.add_paragraph(f"• Tài chính: {impact.financial_impact_note}")
        doc.add_paragraph(f"• Tuân thủ pháp lý: {impact.compliance_note}")

        # 9. Mục 7: Phân tích nguyên nhân gốc rễ chuyên sâu (Grounded)
        h7 = doc.add_heading("7. Phân tích nguyên nhân gốc rễ (Deep RCA)", level=1)
        h7.style.font.color.rgb = RGBColor(0, 51, 102)
        if not deep_rca.applicable:
            doc.add_paragraph(f"• {deep_rca.proximate_cause}")
            doc.add_paragraph(f"• Nhận định: {deep_rca.root_cause}")
        else:
            doc.add_paragraph(f"• Nguyên nhân trực tiếp: {deep_rca.proximate_cause}")
            doc.add_paragraph(f"• Yếu tố đóng góp: {deep_rca.contributing_factors}")
            doc.add_paragraph(f"• Nguyên nhân gốc rễ: {deep_rca.root_cause}")
            for step in deep_rca.five_whys:
                doc.add_paragraph(step)

        # 10. Mục 8 & 9: Cổng kiểm định & CAPA (Grounded)
        h8 = doc.add_heading("8. Cổng kiểm định an toàn (Integrity Verification Gate)", level=1)
        h8.style.font.color.rgb = RGBColor(0, 51, 102)
        for gate in gate_items:
            mark = "[x]" if gate.checked else "[ ]"
            doc.add_paragraph(f"{mark} {gate.label}: {gate.detail}")

        h9 = doc.add_heading("9. Kế hoạch khắc phục & phòng ngừa dài hạn (CAPA)", level=1)
        h9.style.font.color.rgb = RGBColor(0, 51, 102)
        for capa in capa_items:
            doc.add_paragraph(
                f"• [{capa.code}] ({capa.priority} - {capa.category}) {capa.item} | Thời hạn: {capa.timeline} | KPI: {capa.kpi}"
            )

        # Footer
        p_footer = doc.add_paragraph()
        p_footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p_footer.add_run(
            f"\nBáo cáo tạo bởi Hệ thống HCMUTE Multi-Agent SOC - {format_vn_time(report.created_at, '%Y-%m-%d %H:%M:%S (ICT / Giờ Việt Nam)')}"
        ).italic = True

        buf = io.BytesIO()
        doc.save(buf)
        buf.seek(0)
        return buf.getvalue()

    # Alias tương thích ngược
    generate_docx_report = export_docx

    # =====================================================================
    # 4. STATEGRAPH INTEGRATION (PROCESS_STATE)
    # =====================================================================
    def process_state(self, state: IncidentState) -> IncidentState:
        """
        Thực thi Reporting Node trong StateGraph:
        1. Sinh đối tượng IncidentReport từ IncidentState.
        2. Gán báo cáo vào state.final_report.
        3. Ghi nhận chuyển dịch trạng thái (StateTransition).
        4. Đồng bộ lại operational_metrics nếu timeline vừa đóng sự cố.

        :param state: IncidentState hiện tại.
        :return: IncidentState đã được cập nhật final_report.
        """
        report = self.generate_report(state)
        state.final_report = report

        target_status = (
            IncidentStatus.CLOSED_FALSE_POSITIVE
            if state.status == IncidentStatus.CLOSED_FALSE_POSITIVE
            else IncidentStatus.RESOLVED
        )

        transition_metadata: Dict[str, Any] = {
            "report_id": report.report_id,
            "organization": self.organization_name,
            "ioc_count": len(report.ioc_table),
            "action_count": len(report.action_plan),
            "mitre_count": len(report.mitre_attack_matrix_mapping),
            "llm_grounded": bool(report.llm_grounded),
            "grounding_violations": list(self._last_grounding_violations),
        }
        if self._last_security_flags:
            transition_metadata["security_guard_flags"] = list(self._last_security_flags)

        state.record_transition(
            node="reporting",
            to_status=target_status,
            message=f"Đã xuất bản Báo cáo Điều tra Sự cố [{report.report_id}]",
            metadata=transition_metadata,
        )

        report.incident_status = target_status.value
        report.operational_metrics = self.build_operational_metrics(report, state)
        rebuilt_impact = self.build_impact_assessment(report, state)
        if (
            report.llm_grounded
            and self._last_grounded_synthesis is not None
            and self._last_grounded_synthesis.cia_rationale
        ):
            rebuilt_impact = self._apply_cia_rationale(
                rebuilt_impact,
                self._last_grounded_synthesis.cia_rationale,
            )
        report.impact_assessment = rebuilt_impact
        gate_items = self.build_verification_gate(report, state)
        report.verification_gate = gate_items
        report.verification_checklist = list(gate_items)

        return state

    # =====================================================================
    # 5. CÁC HÀM TRỢ GIÚP NỘI BỘ (BUILDERS & FALLBACKS)
    # =====================================================================
    def _resolve_severity(self, state: IncidentState) -> str:
        """Xác định mức độ nghiêm trọng từ Triage hoặc fallback an toàn khi thiếu Triage."""
        triage = self._get_triage(state)
        if triage is not None:
            if getattr(triage, "is_incident", True) is False:
                t_cat = getattr(triage, "attack_category", None)
                t_cat_val = t_cat.value if hasattr(t_cat, "value") else (str(t_cat) if t_cat else "")
                if t_cat_val.upper() == AttackCategory.BENIGN.value or (
                    state.status == IncidentStatus.CLOSED_FALSE_POSITIVE
                ):
                    return "BENIGN"
            if getattr(triage, "severity", None) is not None:
                sev = triage.severity
                return sev.value if hasattr(sev, "value") else str(sev)
        if state.status == IncidentStatus.CLOSED_FALSE_POSITIVE:
            return "BENIGN"
        return SeverityLevel.HIGH.value

    def _resolve_status_display(self, state: IncidentState) -> str:
        """Chuyển đổi enum IncidentStatus thành văn bản hiển thị thân thiện."""
        status_map = {
            IncidentStatus.NEW: "Mới tiếp nhận (NEW)",
            IncidentStatus.TRIAGED: "Đã phân loại sơ bộ (TRIAGED)",
            IncidentStatus.INVESTIGATING: "Đang điều tra / Đang xử lý (INVESTIGATING)",
            IncidentStatus.AWAITING_APPROVAL: "Đang chờ phê duyệt (AWAITING_APPROVAL)",
            IncidentStatus.CONTAINED: "Đã ngăn chặn (CONTAINED)",
            IncidentStatus.CLOSED_FALSE_POSITIVE: "Đã đóng - Dương tính giả (CLOSED_FALSE_POSITIVE)",
            IncidentStatus.RESOLVED: "Đã giải quyết (RESOLVED)",
        }
        return status_map.get(
            state.status,
            str(state.status.value if hasattr(state.status, "value") else state.status),
        )

    def _extract_scope(self, state: IncidentState) -> Tuple[List[str], List[str]]:
        """Trích xuất danh sách máy trạm (hosts) và người dùng (users) bị ảnh hưởng."""
        hosts: Set[str] = set()
        users: Set[str] = set()

        for event in state.parsed_events:
            if event.host_name and event.host_name.upper() not in {"UNKNOWN", "UNKNOWN-HOST", ""}:
                hosts.add(event.host_name)
            if event.user_name and event.user_name.upper() not in {"UNKNOWN", "UNKNOWN-USER", ""}:
                users.add(event.user_name)

        hosts_list = sorted(list(hosts)) if hosts else ["Hệ thống giám sát nội bộ"]
        users_list = sorted(list(users)) if users else ["Chưa xác định tài khoản cụ thể"]
        return hosts_list, users_list

    def _build_executive_summary(
        self,
        state: IncidentState,
        severity: str,
        status_display: str,
        hosts: List[str],
        users: List[str],
        attack_type: Optional[str] = None,
    ) -> str:
        """Xây dựng phần tóm tắt dành cho C-Level (CISO/CIO)."""
        triage = self._get_triage(state)
        rca = self._get_rca(state)

        if rca and getattr(rca, "initial_access_vector", None):
            attack_nature = rca.initial_access_vector
        elif triage and getattr(triage, "summary", None):
            attack_nature = triage.summary
        else:
            attack_nature = "Hành vi bất thường phát hiện trên nhật ký an ninh hệ thống."

        hosts_str = ", ".join(hosts)
        users_str = ", ".join(users)

        rolled_back_count = sum(
            1 for a in state.recommended_actions if self._is_action_rolled_back(a)
        )

        if state.status == IncidentStatus.CLOSED_FALSE_POSITIVE:
            action_status_text = (
                f"ĐÃ HOÀN TÁC TOÀN BỘ ({rolled_back_count} hành động) & ĐÓNG SỰ CỐ DƯƠNG TÍNH GIẢ (False Positive). "
                "Hệ thống đã phục hồi hiện trạng vận hành bình thường."
            )
        elif rolled_back_count > 0:
            action_status_text = (
                f"Ghi nhận {rolled_back_count} hành động đã được HOÀN TÁC (Rollback) bởi Chuyên viên SOC "
                "để phòng ngừa gián đoạn dịch vụ hoặc tái cấu hình phản ứng."
            )
        elif state.analyst_approved is True:
            action_status_text = "Đã được Chuyên viên An ninh phê duyệt thực thi toàn bộ."
        elif state.analyst_approved is False:
            action_status_text = "Chuyên viên An ninh đã từ chối hoặc yêu cầu điều chỉnh kế hoạch."
        elif state.recommended_actions:
            action_status_text = f"Đang chờ phê duyệt {len(state.recommended_actions)} hành động ứng phó khẩn cấp."
        else:
            action_status_text = "Chưa có hành động phản ứng nào được kích hoạt."

        summary = (
            f"Báo cáo điều tra sự cố do {self.organization_name} tiếp nhận và xử lý.\n"
            f"- Mã định danh sự cố: {state.incident_id}\n"
            f"- Mức độ nghiêm trọng: {severity}\n"
            f"- Định danh loại tấn công: {attack_type or 'Chưa xác định'}\n"
            f"- Bản chất cuộc tấn công: {attack_nature}\n"
            f"- Phạm vi ảnh hưởng:\n"
            f"  + Máy chủ / Máy trạm bị nhắm tới: {hosts_str}\n"
            f"  + Tài khoản người dùng liên quan: {users_str}\n"
            f"- Trạng thái ứng phó hiện tại: {status_display}\n"
            f"- Tình trạng hành động khắc phục: {action_status_text}"
        )
        return summary

    @staticmethod
    def _is_public_ipv4(ip_str: str) -> bool:
        """Kiểm tra một chuỗi IPv4 có phải địa chỉ công cộng (không thuộc dải private/loopback/reserved)."""
        try:
            addr = ipaddress.IPv4Address(ip_str.strip())
        except ValueError:
            return False
        return not any(addr in net for net in _PRIVATE_NETS)

    @classmethod
    def _extract_synthesis_texts(cls, synthesis: Any) -> List[str]:
        """Trích xuất toàn bộ đoạn văn bản từ ReportingLLMSynthesis / dict / chuỗi thô."""
        parts: List[str] = []

        def _walk(val: Any) -> None:
            if val is None:
                return
            if isinstance(val, str):
                stripped = val.strip()
                if stripped:
                    parts.append(stripped)
            elif isinstance(val, dict):
                for v in val.values():
                    _walk(v)
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    _walk(item)
            elif hasattr(val, "model_dump"):
                _walk(val.model_dump())

        _walk(synthesis)
        return parts

    @classmethod
    def _collect_allowed_entities(
        cls,
        state: Optional[IncidentState],
        rag_kb: Optional[Any] = None,
    ) -> Dict[str, Set[str]]:
        """
        Thu thập tập thực thể được phép (IPs, MITRE IDs, Hosts, PIDs) trực tiếp từ IncidentState
        và tri thức RAG gắn với sự cố nếu có.
        """
        allowed_ips: Set[str] = set()
        allowed_mitre_ids: Set[str] = set()
        allowed_hosts: Set[str] = set()
        allowed_pids: Set[str] = set()

        def _scan_ips_and_mitre(text: Optional[str]) -> None:
            if not text:
                return
            s = str(text)
            for ip in _IPV4_RE.findall(s):
                allowed_ips.add(ip)
            for mid in _MITRE_CODE_RE.findall(s):
                upper_mid = mid.upper()
                allowed_mitre_ids.add(upper_mid)
                if "." in upper_mid:
                    allowed_mitre_ids.add(upper_mid.split(".")[0])

        def _walk_any(val: Any) -> None:
            if val is None:
                return
            if isinstance(val, str):
                _scan_ips_and_mitre(val)
            elif isinstance(val, dict):
                for v in val.values():
                    _walk_any(v)
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    _walk_any(item)
            elif hasattr(val, "model_dump"):
                _walk_any(val.model_dump())

        if state is not None:
            for ev in state.parsed_events:
                if ev.host_name and ev.host_name.upper() not in {"UNKNOWN", "UNKNOWN-HOST", ""}:
                    allowed_hosts.add(ev.host_name.strip())
                if ev.source_ip:
                    _scan_ips_and_mitre(ev.source_ip)
                if ev.dest_ip:
                    _scan_ips_and_mitre(ev.dest_ip)
                _scan_ips_and_mitre(ev.command_line)
                _scan_ips_and_mitre(ev.parent_command_line)
                raw_attrs = ev.raw_attributes or {}
                _walk_any(raw_attrs)
                for pid_key in ("process_id", "pid", "parent_pid", "ppid"):
                    pid_val = raw_attrs.get(pid_key)
                    if pid_val is not None and str(pid_val).strip():
                        allowed_pids.add(str(pid_val).strip())

            for rlog in state.raw_logs:
                _scan_ips_and_mitre(rlog.raw_payload)

            triage = cls._get_triage(state)
            if triage is not None:
                _scan_ips_and_mitre(getattr(triage, "summary", None))
                _scan_ips_and_mitre(getattr(triage, "attack_type", None))
                _walk_any(getattr(triage, "primary_mitre_tactics", None))

            if state.threat_intel:
                for ioc in state.threat_intel.extracted_iocs or []:
                    _scan_ips_and_mitre(ioc.value)
                    _walk_any(ioc.details)
                for tid in state.threat_intel.mitre_techniques or []:
                    _scan_ips_and_mitre(tid)
                _scan_ips_and_mitre(state.threat_intel.enrichment_summary)

            rca = cls._get_rca(state)
            if rca is not None:
                _scan_ips_and_mitre(getattr(rca, "initial_access_vector", None))
                _scan_ips_and_mitre(getattr(rca, "root_cause_summary", None))
                _scan_ips_and_mitre(getattr(rca, "confirmed_attack_type", None))
                _walk_any(getattr(rca, "attack_timeline", None))
                _walk_any(getattr(rca, "mitre_tactics", None))
                for node in getattr(rca, "process_tree", None) or []:
                    if getattr(node, "process_id", None):
                        allowed_pids.add(str(node.process_id).strip())
                    if getattr(node, "parent_id", None):
                        allowed_pids.add(str(node.parent_id).strip())
                    if getattr(node, "host_name", None):
                        allowed_hosts.add(str(node.host_name).strip())
                    _scan_ips_and_mitre(getattr(node, "command_line", None))
                for hnode in getattr(rca, "high_fidelity_tree", None) or []:
                    if getattr(hnode, "process_id", None):
                        allowed_pids.add(str(hnode.process_id).strip())
                    if getattr(hnode, "parent_id", None):
                        allowed_pids.add(str(hnode.parent_id).strip())
                    if getattr(hnode, "host_name", None):
                        allowed_hosts.add(str(hnode.host_name).strip())
                    _scan_ips_and_mitre(getattr(hnode, "command_line", None))
                    _walk_any(getattr(hnode, "mitre_techniques", None))

            for act in state.recommended_actions:
                _scan_ips_and_mitre(act.target)
                _scan_ips_and_mitre(act.description)
                _walk_any(act.parameters)
                act_type = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
                if act_type == ActionType.ISOLATE_HOST.value and act.target:
                    allowed_hosts.add(str(act.target).strip())
                elif act_type == ActionType.KILL_PROCESS.value and act.target:
                    allowed_pids.add(str(act.target).strip())

            _scan_ips_and_mitre(getattr(state, "response_strategy_summary", None))
            _scan_ips_and_mitre(getattr(state, "analyst_feedback", None))
            _walk_any(getattr(state, "checkpoints", None))

            for inferred_tid in cls._extract_mitre_mapping(state):
                _scan_ips_and_mitre(inferred_tid)

        if rag_kb is not None:
            extra_rag_ids = getattr(rag_kb, "known_mitre_ids", None)
            if extra_rag_ids:
                _walk_any(extra_rag_ids)

        return {
            "ips": allowed_ips,
            "mitre_ids": allowed_mitre_ids,
            "hosts": allowed_hosts,
            "pids": allowed_pids,
        }

    _EMPTY_UNTRUSTED_VALUES = frozenset({"", "n/a", "na", "none", "null", "unknown", "-"})

    @staticmethod
    def _is_zero_currency_token(text: str, token: str, start_idx: int) -> bool:
        """
        Kiểm tra cụm tiền tệ khớp có biểu diễn giá trị bằng 0 rõ ràng hay không
        (vd: '0 USD', '0 VNĐ', '0 VND', '$0', '0.00 USD', '0,00 VNĐ', '0 đồng').
        """
        num_match = re.search(r"\d[\d\.,]*", token)
        if not num_match:
            return False
        digits_only = re.sub(r"[.,]", "", num_match.group(0))
        if not digits_only or any(ch != "0" for ch in digits_only):
            return False
        # Tránh lọt số lớn phân cách hàng nghìn bằng khoảng trắng (vd: "10 000 USD" khớp "000 USD")
        prefix = text[:start_idx]
        if re.search(r"[1-9]\d*\s+$", prefix):
            return False
        return True

    @staticmethod
    def _apply_cia_rationale(
        impact: ImpactAssessment,
        cia_rationale: Optional[Dict[str, str]],
    ) -> ImpactAssessment:
        """Làm giàu đánh giá CIA trong ImpactAssessment từ cia_rationale đã qua grounding."""
        if not isinstance(cia_rationale, dict) or not cia_rationale:
            return impact

        normalized: Dict[str, str] = {}
        for k, v in cia_rationale.items():
            key = str(k or "").strip().lower()
            val = re.sub(r"\s+", " ", str(v or "")).replace("|", "/").strip()
            if not val or val.lower() in {"n/a", "na", "none", "null", "-"}:
                continue
            if key in {"confidentiality", "c", "bao_mat", "bảo mật"}:
                normalized["confidentiality"] = val
            elif key in {"integrity", "i", "toan_ven", "toàn vẹn"}:
                normalized["integrity"] = val
            elif key in {"availability", "a", "san_sang", "sẵn sàng"}:
                normalized["availability"] = val

        for dim_name in ("confidentiality", "integrity", "availability"):
            rationale = normalized.get(dim_name)
            if not rationale:
                continue
            dim = getattr(impact, dim_name, None)
            if dim is None:
                continue
            base_text = (dim.assessment or "").strip()
            if not base_text:
                dim.assessment = rationale
            elif rationale.lower() not in base_text.lower():
                dim.assessment = f"{base_text} (Phân tích LLM: {rationale})"

        return impact

    @staticmethod
    def _append_evidence_citations(
        detailed_findings: str,
        citations: List[str],
    ) -> str:
        """Gắn danh sách trích dẫn bằng chứng (evidence_citations) đã qua grounding vào detailed_findings."""
        cleaned: List[str] = []
        seen: Set[str] = set()
        for raw_item in citations:
            item = re.sub(r"\s+", " ", str(raw_item or "")).strip()
            if item and item.lower() not in {"n/a", "na", "none", "null", "-"} and item.lower() not in seen:
                seen.add(item.lower())
                cleaned.append(item)
        if not cleaned:
            return detailed_findings
        citation_lines = "\n".join(f"- `{item}`" for item in cleaned[:12])
        return (
            f"{detailed_findings}\n\n"
            f"### 2.7. Trích dẫn Bằng chứng đối chiếu (Evidence Citations)\n"
            f"{citation_lines}"
        )

    @classmethod
    def _validate_llm_grounding(
        cls,
        synthesis: Any,
        state: Optional[IncidentState],
        rag_kb: Optional[Any] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Kiểm chứng chống bịa đặt (Grounding Validator) cho đầu ra LLM của Reporting Agent.
        Từ chối:
        (a) Con số tiền tệ khác 0 (VNĐ/VND/triệu/tỷ/USD/$) không có trong bằng chứng state
            (cho phép các phát biểu tổn thất bằng 0 rõ ràng như '0 USD', '0 VNĐ', '0 VND', '$0', '0 đồng').
        (b) IPv4 công cộng không nằm trong tập IP cho phép của state.
        (c) Mã kỹ thuật MITRE Txxxx(.xxx) không nằm trong tập MITRE cho phép.
        (d) Nhắc tới lsass khi state không có bằng chứng lsass hoặc T1003.
        """
        if synthesis is None:
            return False, ["empty_synthesis"]

        texts = cls._extract_synthesis_texts(synthesis)
        if not texts:
            return False, ["empty_synthesis"]

        synthesis_text = "\n".join(texts)
        entities = cls._collect_allowed_entities(state, rag_kb=rag_kb)
        allowed_ips = entities["ips"]
        allowed_mitre_ids = entities["mitre_ids"]

        state_evidence_text = cls._collect_evidence_text(None, state)
        norm_state_evidence = re.sub(r"\s+", " ", state_evidence_text).strip().lower()

        violations: List[str] = []

        # (a) Non-zero currency amounts not present in state evidence
        for match in _CURRENCY_RE.finditer(synthesis_text):
            token = match.group(0).strip()
            if cls._is_zero_currency_token(synthesis_text, token, match.start()):
                continue
            norm_token = re.sub(r"\s+", " ", token).lower()
            if norm_token and norm_token not in norm_state_evidence:
                violations.append(f"hallucinated_currency:{token}")

        # (b) Public IPv4 not in allowed IPs
        for ip in _IPV4_RE.findall(synthesis_text):
            if cls._is_public_ipv4(ip) and ip not in allowed_ips:
                violations.append(f"hallucinated_ip:{ip}")

        # (c) MITRE IDs not in allowed MITRE IDs
        for tid in _MITRE_CODE_RE.findall(synthesis_text):
            norm_tid = tid.upper()
            if norm_tid not in allowed_mitre_ids:
                violations.append(f"hallucinated_mitre:{norm_tid}")

        # (d) lsass mention when state has no lsass/T1003
        has_lsass_evidence = (
            "lsass" in state_evidence_text
            or any(m == "T1003" or m.startswith("T1003.") for m in allowed_mitre_ids)
        )
        if not has_lsass_evidence and _LSASS_RE.search(synthesis_text):
            violations.append("hallucinated_lsass:lsass")

        return len(violations) == 0, violations

    def _wrap_untrusted_field(
        self,
        text: Optional[str],
        field_name: str,
        max_len: int = 1000,
        security_flags: Optional[List[Dict[str, str]]] = None,
        include_notice: bool = False,
    ) -> str:
        """Kiểm tra và bọc dữ liệu chưa tin cậy qua SecurityGuard nếu enable_security_guard=True."""
        raw = "" if text is None else str(text)
        stripped = raw.strip()
        if not stripped or stripped.lower() in self._EMPTY_UNTRUSTED_VALUES:
            return ""
        if not self.enable_security_guard:
            return raw[:max_len] if max_len > 0 else raw
        wrapped, is_inj, reason = inspect_and_wrap_untrusted(
            raw,
            field_name=field_name,
            max_len=max_len,
            include_notice=include_notice,
        )
        if is_inj and security_flags is not None:
            security_flags.append(
                {
                    "field": field_name,
                    "reason": reason or "prompt_injection_detected",
                }
            )
        return wrapped

    def _build_llm_reporting_prompt(
        self,
        state: IncidentState,
        base_summary: str,
        attack_type: str,
        severity: str,
    ) -> Tuple[str, List[Dict[str, str]]]:
        """Xây dựng prompt Reporting có cô lập SecurityGuard gọn nhẹ (1 header chung + thẻ cô lập compact)."""
        security_flags: List[Dict[str, str]] = []
        hosts, users = self._extract_scope(state)

        raw_hosts = sorted(
            {
                ev.host_name.strip()
                for ev in state.parsed_events
                if ev.host_name
                and ev.host_name.strip().lower()
                not in {"unknown", "unknown-host", "n/a", "na", "none", "null", ""}
            }
        )
        raw_users = sorted(
            {
                ev.user_name.strip()
                for ev in state.parsed_events
                if ev.user_name
                and ev.user_name.strip().lower()
                not in {"unknown", "unknown-user", "n/a", "na", "none", "null", ""}
            }
        )

        if raw_hosts:
            raw_hosts_str = ", ".join(raw_hosts)
            hosts_display = (
                self._wrap_untrusted_field(
                    raw_hosts_str,
                    field_name="parsed_events.host_name",
                    max_len=300,
                    security_flags=security_flags,
                    include_notice=False,
                )
                if self.enable_security_guard
                else raw_hosts_str
            )
        else:
            hosts_display = ", ".join(hosts) if hosts else "Chưa xác định"

        if raw_users:
            raw_users_str = ", ".join(raw_users)
            users_display = (
                self._wrap_untrusted_field(
                    raw_users_str,
                    field_name="parsed_events.user_name",
                    max_len=300,
                    security_flags=security_flags,
                    include_notice=False,
                )
                if self.enable_security_guard
                else raw_users_str
            )
        else:
            users_display = ", ".join(users) if users else "Chưa xác định"

        triage = self._get_triage(state)
        rca = self._get_rca(state)

        triage_summary_block = (
            self._wrap_untrusted_field(
                getattr(triage, "summary", None),
                field_name="triage_result.summary",
                max_len=800,
                security_flags=security_flags,
                include_notice=False,
            )
            if triage is not None
            else ""
        )

        rca_vector_block = (
            self._wrap_untrusted_field(
                getattr(rca, "initial_access_vector", None),
                field_name="rca_result.initial_access_vector",
                max_len=500,
                security_flags=security_flags,
                include_notice=False,
            )
            if rca is not None
            else ""
        )
        rca_summary_block = (
            self._wrap_untrusted_field(
                getattr(rca, "root_cause_summary", None),
                field_name="rca_result.root_cause_summary",
                max_len=800,
                security_flags=security_flags,
                include_notice=False,
            )
            if rca is not None
            else ""
        )

        cmd_blocks: List[str] = []
        for idx, ev in enumerate(state.parsed_events[:10]):
            wrapped_cmd = self._wrap_untrusted_field(
                ev.command_line,
                field_name=f"parsed_events[{idx}].command_line",
                max_len=800,
                security_flags=security_flags,
                include_notice=False,
            )
            if wrapped_cmd:
                cmd_blocks.append(wrapped_cmd)

            raw_attrs = ev.raw_attributes if isinstance(ev.raw_attributes, dict) else {}
            decoded_cmd = raw_attrs.get("decoded_command") or getattr(ev, "decoded_command", None)
            if decoded_cmd:
                wrapped_decoded = self._wrap_untrusted_field(
                    str(decoded_cmd),
                    field_name=f"parsed_events[{idx}].decoded_command",
                    max_len=800,
                    security_flags=security_flags,
                    include_notice=False,
                )
                if wrapped_decoded:
                    cmd_blocks.append(f"[Decoded Command]\n{wrapped_decoded}")

            wrapped_parent = self._wrap_untrusted_field(
                ev.parent_command_line,
                field_name=f"parsed_events[{idx}].parent_command_line",
                max_len=800,
                security_flags=security_flags,
                include_notice=False,
            )
            if wrapped_parent:
                cmd_blocks.append(wrapped_parent)

        if rca is not None:
            for idx, node in enumerate((getattr(rca, "process_tree", None) or [])[:10]):
                wrapped_node_cmd = self._wrap_untrusted_field(
                    getattr(node, "command_line", None),
                    field_name=f"rca_result.process_tree[{idx}].command_line",
                    max_len=800,
                    security_flags=security_flags,
                    include_notice=False,
                )
                if wrapped_node_cmd:
                    cmd_blocks.append(wrapped_node_cmd)
                deobf_cmd = getattr(node, "deobfuscated_command", None)
                if deobf_cmd:
                    wrapped_deobf = self._wrap_untrusted_field(
                        str(deobf_cmd),
                        field_name=f"rca_result.process_tree[{idx}].deobfuscated_command",
                        max_len=800,
                        security_flags=security_flags,
                        include_notice=False,
                    )
                    if wrapped_deobf:
                        cmd_blocks.append(f"[Decoded Command]\n{wrapped_deobf}")

        raw_log_blocks: List[str] = []
        for idx, rlog in enumerate(state.raw_logs[:5]):
            wrapped_raw = self._wrap_untrusted_field(
                rlog.raw_payload,
                field_name=f"raw_logs[{idx}].raw_payload",
                max_len=800,
                security_flags=security_flags,
                include_notice=False,
            )
            if wrapped_raw:
                raw_log_blocks.append(wrapped_raw)

        feedback_block = self._wrap_untrusted_field(
            getattr(state, "analyst_feedback", None),
            field_name="analyst_feedback",
            max_len=600,
            security_flags=security_flags,
            include_notice=False,
        )

        safe_base_block = (
            self._wrap_untrusted_field(
                base_summary,
                field_name="base_summary",
                max_len=1500,
                security_flags=None,
                include_notice=False,
            )
            if self.enable_security_guard
            else base_summary
        )

        entities = self._collect_allowed_entities(state, rag_kb=self.rag_kb)
        allowed_ips_str = ", ".join(sorted(entities["ips"])) or "Không có"
        allowed_mitre_str = ", ".join(sorted(entities["mitre_ids"])) or "Không có"

        safe_incident_id = (
            sanitize_prompt_text(state.incident_id, max_len=128)
            if self.enable_security_guard
            else state.incident_id
        )
        safe_attack_type = (
            sanitize_prompt_text(attack_type, max_len=200)
            if self.enable_security_guard
            else attack_type
        )

        sections: List[str] = [
            "Bạn là Reporting Agent chuyên trách lập báo cáo C-Level cho Ban Giám đốc (CISO/CIO/Board of Directors).",
            "Dựa trên dữ liệu điều tra kỹ thuật đã xác thực dưới đây, hãy tổng hợp báo cáo theo schema ReportingLLMSynthesis.",
            "TUYỆT ĐỐI chỉ sử dụng thực thể, IP, MITRE ID có trong bằng chứng; KHÔNG bịa số tiền (VNĐ/USD), IP ngoài hoặc LSASS nếu không có trong dữ liệu.",
            "",
            "### THÔNG TIN SỰ CỐ ĐÃ CHUẨN HÓA:",
            f"- Mã sự cố: {safe_incident_id}",
            f"- Mức độ nghiêm trọng: {severity}",
            f"- Loại tấn công: {safe_attack_type}",
            f"- Tập IP được phép trích dẫn: {allowed_ips_str}",
            f"- Tập MITRE ATT&CK được phép trích dẫn: {allowed_mitre_str}",
        ]

        untrusted_sections: List[str] = [
            f"- Máy trạm/Máy chủ bị ảnh hưởng: {hosts_display}",
            f"- Tài khoản người dùng liên quan: {users_display}",
        ]
        if safe_base_block:
            untrusted_sections.append(f"- Tóm tắt hiện trạng kỹ thuật:\n{safe_base_block}")
        if triage_summary_block:
            untrusted_sections.append(f"- Tóm tắt Triage (Untrusted Data):\n{triage_summary_block}")
        if rca_vector_block:
            untrusted_sections.append(f"- Vector xâm nhập RCA (Untrusted Data):\n{rca_vector_block}")
        if rca_summary_block:
            untrusted_sections.append(f"- Tóm tắt RCA (Untrusted Data):\n{rca_summary_block}")
        if cmd_blocks:
            untrusted_sections.append(
                "- Chuỗi dòng lệnh quan sát được (Untrusted Data):\n" + "\n".join(cmd_blocks)
            )
        if raw_log_blocks:
            untrusted_sections.append(
                "- Nhật ký thô trích lục (Untrusted Data):\n" + "\n".join(raw_log_blocks)
            )
        if feedback_block:
            untrusted_sections.append(f"- Phản hồi Chuyên viên SOC (Untrusted Data):\n{feedback_block}")

        if untrusted_sections:
            sections.append("")
            sections.append("### DỮ LIỆU CHỨNG CỨ CHƯA TIN CẬY (UNTRUSTED EVIDENCE):")
            if self.enable_security_guard:
                sections.append(UNTRUSTED_LOG_SECURITY_HEADER)
            sections.extend(untrusted_sections)

        sections.extend(
            [
                "",
                "### YÊU CẦU BIÊN SOẠN CHO CISO/CIO:",
                "1. Executive Summary (`executive_advisory`): Tóm lược sự cố súc tích, tác động vận hành/kinh doanh (Business Impact), tình trạng khoanh vùng và kiểm soát hiện tại.",
                "2. Strategic Lessons Learned (`strategic_lessons_learned`): Đề xuất 3-4 bài học chiến lược theo mô hình Con người (People) - Quy trình (Process) - Công nghệ (Technology) nhằm nâng cao năng lực quản trị rủi ro an ninh mạng lâu dài.",
                "3. Deep RCA & CAPA (`five_whys`, `ishikawa_factors`, `capa_recommendations`): Bám sát bằng chứng thực tế; để trống `five_whys`/`ishikawa_factors` nếu là Benign/False Positive.",
            ]
        )
        return "\n".join(sections), security_flags

    @staticmethod
    def _format_synthesis_advisory(
        base_summary: str,
        synthesis: ReportingLLMSynthesis,
    ) -> str:
        """Định dạng phần LLM Executive Advisory từ ReportingLLMSynthesis đã qua grounding."""
        advisory_parts: List[str] = []
        if synthesis.executive_advisory and synthesis.executive_advisory.strip():
            advisory_parts.append(synthesis.executive_advisory.strip())
        if synthesis.business_impact_assessment and synthesis.business_impact_assessment.strip():
            advisory_parts.append(
                f"Đánh giá tác động nghiệp vụ: {synthesis.business_impact_assessment.strip()}"
            )
        if synthesis.strategic_lessons_learned:
            lessons_lines = [
                f"- {str(item).strip()}"
                for item in synthesis.strategic_lessons_learned
                if str(item).strip()
            ]
            if lessons_lines:
                advisory_parts.append("Strategic Lessons Learned:\n" + "\n".join(lessons_lines))

        advisory_body = "\n".join(advisory_parts).strip()
        if not advisory_body:
            return base_summary
        return (
            f"{base_summary}\n\n"
            f"### 🎯 Đánh giá Chiến lược & Bài học Quản trị (LLM Executive Advisory):\n"
            f"{advisory_body}"
        )

    def _synthesize_with_llm(
        self,
        state: IncidentState,
        base_summary: str,
        attack_type: str,
        severity: str,
    ) -> Tuple[str, Optional[ReportingLLMSynthesis], bool, List[str], List[Dict[str, str]]]:
        """
        Gọi LLM theo contract `invoke_structured_llm(..., schema_class=ReportingLLMSynthesis)`
        kèm SecurityGuard và Grounding Validator.
        Trả về `(exec_summary, synthesis_or_none, llm_grounded, violations, security_flags)`.
        """
        if not self.llm_enabled or self.llm_provider is None:
            return base_summary, None, False, [], []

        prompt, security_flags = self._build_llm_reporting_prompt(
            state=state,
            base_summary=base_summary,
            attack_type=attack_type,
            severity=severity,
        )

        synthesis_obj, used_real_llm, info = invoke_structured_llm(
            self.llm_provider,
            prompt,
            ReportingLLMSynthesis,
            system_prompt=self.system_prompt,
            incident_state=state,
            model_tier="reasoning",
            temperature=0.15,
            agent_name="ReportingAgent",
        )

        # Trường hợp HybridLLMProvider ở chế độ deterministic: dùng Phase 0 deterministic builders
        provider_last = getattr(self.llm_provider, "last_used_provider", None)
        if not used_real_llm and provider_last in ("deterministic", "none"):
            return base_summary, None, False, [], security_flags

        # Trường hợp structured output (HybridLLMProvider hoặc MockStructuredLLM)
        if synthesis_obj is not None:
            candidate: Optional[ReportingLLMSynthesis] = None
            if isinstance(synthesis_obj, ReportingLLMSynthesis):
                candidate = synthesis_obj
            elif isinstance(synthesis_obj, dict):
                try:
                    candidate = ReportingLLMSynthesis.model_validate(synthesis_obj)
                except Exception as exc:
                    logger.warning(f"Không thể validate ReportingLLMSynthesis: {exc}")
                    return base_summary, None, False, ["invalid_synthesis_schema"], security_flags

            if candidate is not None:
                is_grounded, violations = self._validate_llm_grounding(
                    candidate, state, rag_kb=self.rag_kb
                )
                if not is_grounded:
                    logger.warning(
                        f"[{state.incident_id}] Reporting LLM output rejected by Grounding Validator: {violations}"
                    )
                    return base_summary, None, False, violations, security_flags

                formatted_exec = self._format_synthesis_advisory(base_summary, candidate)
                return formatted_exec, candidate, True, [], security_flags

        # Trường hợp MockLLMProvider tối giản chỉ có generate_response() -> raw_text trong info
        if used_real_llm and isinstance(info, str) and info.strip():
            raw_text = info.strip()
            # Thử parse JSON nếu mock trả về JSON string của ReportingLLMSynthesis
            if raw_text.startswith("{"):
                try:
                    parsed_dict = json.loads(raw_text)
                    candidate = ReportingLLMSynthesis.model_validate(parsed_dict)
                    is_grounded, violations = self._validate_llm_grounding(
                        candidate, state, rag_kb=self.rag_kb
                    )
                    if not is_grounded:
                        logger.warning(
                            f"[{state.incident_id}] Reporting JSON output rejected by Grounding Validator: {violations}"
                        )
                        return base_summary, None, False, violations, security_flags
                    return (
                        self._format_synthesis_advisory(base_summary, candidate),
                        candidate,
                        True,
                        [],
                        security_flags,
                    )
                except Exception:
                    pass

            is_grounded, violations = self._validate_llm_grounding(
                raw_text, state, rag_kb=self.rag_kb
            )
            if not is_grounded:
                logger.warning(
                    f"[{state.incident_id}] Reporting raw LLM output rejected by Grounding Validator: {violations}"
                )
                return base_summary, None, False, violations, security_flags

            combined_summary = (
                f"{base_summary}\n\n"
                f"### 🎯 Đánh giá Chiến lược & Bài học Quản trị (LLM Executive Advisory):\n"
                f"{raw_text}"
            )
            return combined_summary, None, True, [], security_flags

        return base_summary, None, False, [], security_flags

    def _generate_llm_executive_summary(
        self,
        state: IncidentState,
        base_summary: str,
        attack_type: str,
        severity: str,
    ) -> str:
        """
        Cho phép LLM biên soạn bản Executive Summary và Strategic Lessons Learned cho CISO/CIO.
        Nếu LLM không khả dụng, gặp lỗi hoặc vi phạm grounding, trả về base_summary từ thuật toán template.
        """
        exec_summary, _, _, _, _ = self._synthesize_with_llm(
            state=state,
            base_summary=base_summary,
            attack_type=attack_type,
            severity=severity,
        )
        return exec_summary

    def _build_detailed_findings(self, state: IncidentState) -> str:
        """Xây dựng phần phân tích kỹ thuật chi tiết dành cho SOC Tier 2/3 và DFIR."""
        findings_parts: List[str] = []
        rca = self._get_rca(state)

        # 1. Thống kê sự kiện
        findings_parts.append(
            f"### 2.1. Thống kê dữ liệu sự kiện\n"
            f"- Tổng số bản ghi log thô tiếp nhận: {len(state.raw_logs)}\n"
            f"- Tổng số sự kiện an ninh đã bóc tách và chuẩn hóa: {len(state.parsed_events)}"
        )

        # 2. Phân tích phương thức xâm nhập ban đầu
        if rca:
            initial_vector = rca.initial_access_vector
            rca_summary = rca.root_cause_summary
        else:
            initial_vector = "Chưa xác định (Cần phân tích bổ sung từ RCA)"
            rca_summary = "Chưa có dữ liệu phân tích nguyên nhân gốc rễ chi tiết từ RCA Agent."

        findings_parts.append(
            f"### 2.2. Phương thức xâm nhập ban đầu (Initial Access Vector)\n"
            f"- Vector xâm nhập: **{initial_vector}**\n"
            f"- Tóm tắt nguyên nhân gốc rễ: {rca_summary}"
        )

        # 3. Cây tiến trình (Process Lineage)
        findings_parts.append("### 2.3. Tái hiện cây tiến trình độc hại (Process Lineage)")
        if rca and rca.process_tree:
            proc_lines = []
            for node in rca.process_tree:
                mal_badge = " **[GỐC ĐỘC HẠI - PATIENT ZERO]**" if node.is_malicious_origin else ""
                parent_info = f" (Cha PID: {node.parent_id})" if node.parent_id else ""
                proc_lines.append(
                    f"- PID `{node.process_id}`: `{node.process_name}`{parent_info}{mal_badge}\n"
                    f"  + Dòng lệnh: `{node.command_line}`"
                )
            findings_parts.append("\n".join(proc_lines))
        else:
            findings_parts.append("*Không có dữ liệu cây tiến trình tái hiện từ sự kiện.*")

        # 4. Dòng thời gian tấn công (Attack Timeline)
        findings_parts.append("### 2.4. Dòng thời gian sự kiện (Attack Timeline)")
        if rca and rca.attack_timeline:
            timeline_lines = [f"{idx}. {item}" for idx, item in enumerate(rca.attack_timeline, start=1)]
            findings_parts.append("\n".join(timeline_lines))
        else:
            findings_parts.append("*Chưa ghi nhận dòng thời gian chuỗi sự kiện chi tiết.*")

        # 5. Log thô mở rộng nếu được cấu hình
        if self.include_raw_logs and state.raw_logs:
            findings_parts.append("### 2.5. Trích lục nhật ký thô (Raw Logs Excerpt)")
            raw_samples = []
            for idx, rlog in enumerate(state.raw_logs[:5], start=1):
                payload_snip = rlog.raw_payload[:200] + ("..." if len(rlog.raw_payload) > 200 else "")
                raw_samples.append(f"- [Log {idx}] Nguồn: `{rlog.log_source}` | Payload: `{payload_snip}`")
            findings_parts.append("\n".join(raw_samples))

        # 6. Nhật ký Hoàn tác & Khôi phục Hiện trạng Hệ thống (Rollback & Restoration Audit Log)
        findings_parts.append("### 2.6. Nhật ký Hoàn tác & Khôi phục Hiện trạng (Remediation Rollback & Restoration Log)")
        rollback_actions = [
            a for a in state.recommended_actions if self._is_action_rolled_back(a)
        ]
        if rollback_actions:
            rb_lines = [
                "| Mã hành động | Loại hành động | Mục tiêu | Lý do hoàn tác | Người thực hiện | Lệnh hoàn tác khôi phục |",
                "| :---: | :--- | :--- | :---: | :---: | :--- |",
            ]
            for act in rollback_actions:
                act_type = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
                rb_reason = (act.parameters or {}).get("rollback_reason", "Chưa rõ")
                rb_by = (act.parameters or {}).get("rollback_by", "SOC Analyst")
                rb_cmd = (
                    act.script_bundle.rollback_script
                    if act.script_bundle and act.script_bundle.rollback_script
                    else "Khôi phục trạng thái ban đầu"
                )
                rb_lines.append(
                    f"| `{act.action_id}` | {act_type} | `{act.target}` | **{rb_reason}** | `{rb_by}` | `{rb_cmd}` |"
                )
            rb_lines.append("")
            rb_lines.append(
                "> ℹ️ **Đánh giá hiện trạng:** Tất cả các hành động trên đã được thu hồi và khôi phục cấu hình an toàn, "
                "loại bỏ gián đoạn vận hành hoặc gỡ bỏ chặn nhầm do dương tính giả."
            )
            findings_parts.append("\n".join(rb_lines))
        else:
            findings_parts.append(
                "*Không ghi nhận hành động hoàn tác nào (Các biện pháp can thiệp đang duy trì hiệu lực hoặc sự cố kết thúc bình thường).*"
            )

        return "\n\n".join(findings_parts)

    @classmethod
    def _extract_mitre_mapping(cls, state: IncidentState) -> List[str]:
        """
        Trích xuất và tổng hợp danh sách kỹ thuật MITRE ATT&CK thực tế.
        - Không bao giờ tự bịa 'T1059.001' khi không có bằng chứng PowerShell.
        - Trả về [] cho sự kiện lành tính / dương tính giả khi không có kỹ thuật thực sự.
        - Suy luận ['T1071'] cho sự kiện mạng/Zeek có kết nối ngoại lai không kèm PowerShell.
        """
        techniques: List[str] = []
        seen: Set[str] = set()

        def add_tech(t: str) -> None:
            clean_t = str(t).strip()
            if clean_t and clean_t not in seen:
                seen.add(clean_t)
                techniques.append(clean_t)

        triage = cls._get_triage(state)
        rca = cls._get_rca(state)
        is_benign = cls._is_benign_context(None, state)

        if state.threat_intel and state.threat_intel.mitre_techniques:
            for t in state.threat_intel.mitre_techniques:
                add_tech(t)

        # Thu thập mã MITRE trực tiếp từ parsed_events / high_fidelity_tree nếu có
        for ev in state.parsed_events:
            raw_attrs = ev.raw_attributes or {}
            for key in ("wazuh_mitre_ids", "mitre_techniques", "mitre_ids"):
                val = raw_attrs.get(key)
                if isinstance(val, list):
                    for item in val:
                        add_tech(item)
                elif isinstance(val, str):
                    for match in _MITRE_CODE_RE.findall(val):
                        add_tech(match.upper())

        if rca:
            for hnode in getattr(rca, "high_fidelity_tree", None) or []:
                for t in getattr(hnode, "mitre_techniques", None) or []:
                    add_tech(t)
            for t in getattr(rca, "mitre_tactics", None) or []:
                add_tech(t)

        if is_benign:
            # Nếu là Benign/False Positive và chưa có bằng chứng kỹ thuật thực sự từ CTI/RCA -> trả về []
            if not (state.threat_intel and state.threat_intel.mitre_techniques):
                return []
            return techniques

        if techniques:
            return techniques

        # Suy luận có căn cứ khi thiếu CTI/RCA nhưng có bằng chứng sự kiện thực sự
        evidence_text = cls._collect_evidence_text(None, state)

        if cls._has_powershell_evidence(state, None):
            add_tech("T1059.001")
        if any(k in evidence_text for k in ("cmd.exe", "t1059.003")):
            add_tech("T1059.003")
        if any(k in evidence_text for k in ("/bin/bash", "/bin/sh", "t1059.004")):
            add_tech("T1059.004")
        if any(k in evidence_text for k in ("schtasks", "scheduled task", "t1053.005")):
            add_tech("T1053.005")
        if any(k in evidence_text for k in ("lsass", "mimikatz", "t1003")):
            add_tech("T1003")

        triage_cat = ""
        if triage and getattr(triage, "attack_category", None):
            c = triage.attack_category
            triage_cat = (c.value if hasattr(c, "value") else str(c)).upper()

        if triage_cat == AttackCategory.CREDENTIAL_ACCESS.value or any(
            k in evidence_text for k in ("ssh", "brute", "password spray", "failed password", "4625", "t1110")
        ):
            add_tech("T1110")

        if triage_cat == AttackCategory.RECONNAISSANCE.value or any(
            k in evidence_text for k in ("port scan", "nmap", "network scan", "scanning", "t1046")
        ):
            add_tech("T1046")

        explicit_c2_network = any(
            k in evidence_text for k in ("dns", "http c2", "c2", "t1071", "zeek-conn", "zeek_conn")
        )
        has_network_source = any(
            (ev.dest_ip or ev.dest_port or (ev.source_type and "zeek" in ev.source_type.lower()))
            for ev in state.parsed_events
        )
        if explicit_c2_network or (not techniques and has_network_source):
            add_tech("T1071")

        return techniques

    @staticmethod
    def _is_external_ip(ip_str: Optional[str]) -> bool:
        """
        Kiểm tra địa chỉ IP (IPv4/IPv6) có hợp lệ và KHÔNG thuộc dải nội bộ,
        loopback, link-local, multicast hoặc unspecified.
        """
        if not ip_str:
            return False
        cleaned = str(ip_str).strip()
        if not cleaned:
            return False
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            return False
        if isinstance(addr, ipaddress.IPv4Address):
            return not any(addr in net for net in _PRIVATE_NETS)
        return not (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr in ipaddress.IPv6Network("fc00::/7")
        )

    @staticmethod
    def _parse_file_hashes(raw_hash: Optional[str]) -> List[Tuple[str, str]]:
        """
        Bóc tách danh sách mã băm hợp lệ (SHA256/SHA1/MD5) từ chuỗi đơn
        hoặc chuỗi danh sách Sysmon dạng 'SHA256=...,SHA1=...,MD5=...,IMPHASH=...'.
        """
        if not raw_hash:
            return []
        text = str(raw_hash).strip()
        if not text:
            return []

        expected_len = {"SHA256": 64, "SHA1": 40, "MD5": 32}
        results: List[Tuple[str, str]] = []
        seen_local: Set[str] = set()

        for part in re.split(r"[,;\s]+", text):
            token = part.strip()
            if not token:
                continue

            algo_hint: Optional[str] = None
            candidate = token
            if "=" in token:
                prefix, candidate = token.split("=", 1)
                algo_hint = prefix.strip().upper().replace("-", "")
                candidate = candidate.strip()
            elif ":" in token:
                prefix, candidate = token.split(":", 1)
                algo_hint = prefix.strip().upper().replace("-", "")
                candidate = candidate.strip()

            if not candidate or not re.fullmatch(r"[0-9a-fA-F]+", candidate):
                continue

            if algo_hint is not None:
                if algo_hint not in expected_len or len(candidate) != expected_len[algo_hint]:
                    continue
                ioc_type = algo_hint
            else:
                if len(candidate) == 64:
                    ioc_type = "SHA256"
                elif len(candidate) == 40:
                    ioc_type = "SHA1"
                elif len(candidate) == 32:
                    ioc_type = "MD5"
                else:
                    continue

            dedup_key = f"{ioc_type}:{candidate.lower()}"
            if dedup_key not in seen_local:
                seen_local.add(dedup_key)
                results.append((ioc_type, candidate))

        return results

    def _build_ioc_table(self, state: IncidentState) -> List[IoCItem]:
        """Trích xuất bảng IoC từ Threat Intel hoặc dữ liệu sự kiện (lọc bỏ IP nội bộ/loopback/link-local)."""
        if state.threat_intel and state.threat_intel.extracted_iocs:
            return state.threat_intel.extracted_iocs

        is_benign = self._is_benign_context(None, state)
        fallback_iocs: List[IoCItem] = []
        seen_values: Set[str] = set()

        for event in state.parsed_events:
            for ip_val in (event.dest_ip, event.source_ip):
                cleaned_ip = str(ip_val).strip() if ip_val else ""
                if (
                    cleaned_ip
                    and cleaned_ip.lower() not in seen_values
                    and self._is_external_ip(cleaned_ip)
                ):
                    seen_values.add(cleaned_ip.lower())
                    fallback_iocs.append(
                        IoCItem(
                            ioc_type="IP",
                            value=cleaned_ip,
                            reputation_score=0 if is_benign else 75,
                            is_malicious=not is_benign,
                            threat_actor="N/A" if is_benign else "Chưa định danh",
                            details={"source": "Fallback from ParsedEvent"},
                        )
                    )
            if event.file_hash:
                for hash_type, hash_val in self._parse_file_hashes(event.file_hash):
                    if hash_val.lower() not in seen_values:
                        seen_values.add(hash_val.lower())
                        fallback_iocs.append(
                            IoCItem(
                                ioc_type=hash_type,
                                value=hash_val,
                                reputation_score=0 if is_benign else 85,
                                is_malicious=not is_benign,
                                threat_actor="N/A" if is_benign else "Chưa định danh",
                                details={"source": "Fallback from ParsedEvent"},
                            )
                        )

        return fallback_iocs

    def _build_action_plan(self, state: IncidentState) -> List[RecommendedAction]:
        """Lấy danh sách hành động ứng phó từ state."""
        return list(state.recommended_actions)
