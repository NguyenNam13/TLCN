# -*- coding: utf-8 -*-
"""
src/ui/components.py
Các hàm trực quan hóa và helper components cho Streamlit Dashboard.
Đề tài Khóa luận Tốt nghiệp TLCN-NAM: Hệ thống Multi-Agent Điều tra và Phản ứng Sự cố An ninh Mạng.

Cung cấp:
- render_kpi_cards & get_kpi_metrics: Render các chỉ số KPI bằng st.metric và thẻ HTML.
- render_agent_graph_status & generate_mermaid_graph: Trực quan hóa StateGraph DAG và trạng thái các node.
- render_ioc_table & format_ioc_table_data: Bảng hiển thị IoC, danh tiếng, Threat Actor.
- render_mitre_matrix & extract_mitre_data: Ma trận và thẻ MITRE ATT&CK.
- render_process_tree & format_process_tree_data: Cây tiến trình Sysmon và Timeline sự kiện.
- render_hitl_action_cards & apply_hitl_action_decision: Bảng điều khiển can thiệp chuyên viên HITL.
"""

from typing import List, Dict, Any, Optional
import html
import streamlit as st

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    ThreatIntelEnrichment,
    RootCauseAnalysis,
    RecommendedAction,
    IoCItem,
    ProcessNode,
)
from src.core.state import IncidentState
from src.core.hitl_manager import HITLManager, RollbackReason


# =====================================================================
# 1. KPI CARDS COMPONENT
# =====================================================================
def get_kpi_metrics(state: Optional[IncidentState]) -> Dict[str, Any]:
    """
    Trích xuất các chỉ số KPI cốt lõi từ IncidentState phục vụ hiển thị và kiểm thử logic.

    :param state: IncidentState hiện tại.
    :return: Dictionary chứa các chỉ số KPI.
    """
    if state is None:
        return {
            "incident_id": "N/A",
            "status": "N/A",
            "severity": "UNKNOWN",
            "confidence_score": 0.0,
            "raw_logs_count": 0,
            "parsed_events_count": 0,
            "ioc_count": 0,
            "malicious_ioc_count": 0,
            "total_actions": 0,
            "pending_actions": 0,
            "approved_actions": 0,
            "rejected_actions": 0,
            "attack_type": "Chưa xác định",
            "attack_category": "UNKNOWN",
        }

    status_str = state.status.value if hasattr(state.status, "value") else str(state.status)
    severity_str = "UNKNOWN"
    confidence = 0.0

    if state.triage_result:
        if hasattr(state.triage_result.severity, "value"):
            severity_str = state.triage_result.severity.value
        else:
            severity_str = str(state.triage_result.severity)
        confidence = float(state.triage_result.confidence_score)

    ioc_items = state.threat_intel.extracted_iocs if state.threat_intel else []
    ioc_count = len(ioc_items)
    malicious_ioc_count = sum(1 for ioc in ioc_items if ioc.is_malicious)

    actions = state.recommended_actions or []
    total_actions = len(actions)
    pending_actions = sum(1 for a in actions if a.require_human_approval and a.is_approved is None)
    approved_actions = sum(1 for a in actions if a.is_approved is True)
    rejected_actions = sum(1 for a in actions if a.is_approved is False)

    attack_type = "Chưa xác định"
    attack_category = "UNKNOWN"
    if getattr(state, "attack_type", None):
        attack_type = state.attack_type
    elif state.triage_result and getattr(state.triage_result, "attack_type", None):
        attack_type = state.triage_result.attack_type
    elif state.rca_result and getattr(state.rca_result, "confirmed_attack_type", None):
        attack_type = state.rca_result.confirmed_attack_type

    if state.triage_result and getattr(state.triage_result, "attack_category", None):
        cat_val = state.triage_result.attack_category
        attack_category = cat_val.value if hasattr(cat_val, "value") else str(cat_val)

    return {
        "incident_id": state.incident_id,
        "status": status_str,
        "severity": severity_str,
        "confidence_score": confidence,
        "raw_logs_count": len(state.raw_logs),
        "parsed_events_count": len(state.parsed_events),
        "ioc_count": ioc_count,
        "malicious_ioc_count": malicious_ioc_count,
        "total_actions": total_actions,
        "pending_actions": pending_actions,
        "approved_actions": approved_actions,
        "rejected_actions": rejected_actions,
        "attack_type": attack_type,
        "attack_category": attack_category,
    }


def render_attack_detection_banner(state: Optional[IncidentState]):
    """
    Render Hero Banner hiển thị kết quả Định danh Loại Tấn Công theo chuẩn Trung tâm Điều hành SOC Thông minh.
    """
    if not state:
        return

    # Trạng thái Standby / Chờ nhận cảnh báo từ Wazuh OVA
    if not state.raw_logs and state.status == IncidentStatus.NEW:
        banner_html = f"""
        <div style="
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border: 1px solid #38bdf8;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 24px;
            color: #f8fafc;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        ">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <span style="
                    background: #0284c7;
                    color: #ffffff;
                    font-weight: 800;
                    font-size: 12px;
                    letter-spacing: 0.08em;
                    text-transform: uppercase;
                    padding: 4px 12px;
                    border-radius: 9999px;
                ">📡 WAZUH SIEM LIVE MODE: ĐANG LẮNG NGHE (STANDBY)</span>
                <span style="color: #cbd5e1; font-size: 13px;">Phiên làm việc: <strong style="color: #38bdf8;">{html.escape(state.incident_id)}</strong></span>
            </div>
            <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-end; gap: 16px;">
                <div>
                    <div style="color: #94a3b8; font-size: 13px; margin-bottom: 4px;">Trạng thái Cổng Webhook:</div>
                    <div style="font-size: 19px; font-weight: 700; color: #34d399; line-height: 1.2;">
                        🟢 Sẵn sàng nhận cảnh báo từ Wazuh OVA (:8000/api/v1/wazuh-alert)
                    </div>
                    <div style="color: #94a3b8; font-size: 13px; margin-top: 6px;">
                        Chưa ghi nhận cảnh báo mới. Vui lòng bật máy chủ Wazuh OVA (172.16.65.150) hoặc chọn kịch bản mẫu từ menu bên trái để điều tra.
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="color: #94a3b8; font-size: 12px;">Mức Rủi ro</div>
                    <div style="font-size: 14px; font-weight: 700; color: #38bdf8;">CHỜ CẢNH BÁO</div>
                </div>
            </div>
        </div>
        """
        st.markdown(banner_html, unsafe_allow_html=True)
        return

    metrics = get_kpi_metrics(state)
    attack_type = metrics.get("attack_type", "Chưa xác định")
    attack_cat = metrics.get("attack_category", "UNKNOWN")
    severity = metrics.get("severity", "UNKNOWN")
    confidence = int(metrics.get("confidence_score", 0.0) * 100)

    is_benign = (
        attack_cat == "BENIGN"
        or severity == "LOW"
        or (state.triage_result and not state.triage_result.is_incident)
    )

    badge_bg = "#10b981" if is_benign else "#ef4444"
    badge_text = "✅ HOẠT ĐỘNG THƯỜNG NHẬT / BENIGN" if is_benign else "🚨 PHÁT HIỆN TẤN CÔNG (ATTACK DETECTED)"
    border_color = "#10b981" if is_benign else "#dc2626"
    banner_bg = (
        "linear-gradient(135deg, #064e3b 0%, #0f172a 100%)"
        if is_benign
        else "linear-gradient(135deg, #2d0607 0%, #0f172a 100%)"
    )

    initial_vector = "Chưa xác định"
    if state.rca_result and state.rca_result.initial_access_vector:
        initial_vector = state.rca_result.initial_access_vector
    elif state.triage_result and state.triage_result.summary:
        initial_vector = state.triage_result.summary[:60] + "..."

    banner_html = f"""
    <div style="
        background: {banner_bg};
        border: 1px solid {border_color};
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 24px;
        color: #f8fafc;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="
                background: {badge_bg};
                color: #ffffff;
                font-weight: 700;
                font-size: 12px;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                padding: 4px 12px;
                border-radius: 9999px;
            ">{badge_text}</span>
            <span style="color: #cbd5e1; font-size: 13px;">Mã sự cố: <strong style="color: #38bdf8;">{html.escape(state.incident_id)}</strong></span>
        </div>
        <div style="display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-end; gap: 16px;">
            <div>
                <div style="color: #94a3b8; font-size: 13px; margin-bottom: 4px;">Định danh Loại Tấn công:</div>
                <div style="font-size: 24px; font-weight: 800; color: #ffffff; line-height: 1.2;">
                    {html.escape(attack_type)}
                </div>
            </div>
            <div style="display: flex; gap: 20px; align-items: center;">
                <div style="text-align: right;">
                    <div style="color: #94a3b8; font-size: 12px;">Vector Xâm nhập</div>
                    <div style="font-size: 14px; font-weight: 600; color: #f1f5f9;">{html.escape(initial_vector)}</div>
                </div>
                <div style="background: rgba(255,255,255,0.15); width: 1px; height: 32px;"></div>
                <div style="text-align: right;">
                    <div style="color: #94a3b8; font-size: 12px;">Mức Rủi ro</div>
                    <div style="font-size: 14px; font-weight: 700; color: {'#34d399' if is_benign else '#f87171'};">{html.escape(severity)}</div>
                </div>
                <div style="background: rgba(255,255,255,0.15); width: 1px; height: 32px;"></div>
                <div style="text-align: right;">
                    <div style="color: #94a3b8; font-size: 12px;">Độ tin cậy AI</div>
                    <div style="font-size: 14px; font-weight: 700; color: #38bdf8;">{confidence}%</div>
                </div>
            </div>
        </div>
    </div>
    """
    st.markdown(banner_html, unsafe_allow_html=True)


def render_kpi_cards(state: Optional[IncidentState]):
    """
    Render các chỉ số KPI bằng st.metric và thẻ hiển thị thông số tổng quan.
    """
    metrics = get_kpi_metrics(state)

    col1, col2, col3, col4, col5, col6 = st.columns(6)

    severity_colors = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW",
        "UNKNOWN": "⚪ UNKNOWN",
    }
    sev_display = severity_colors.get(metrics["severity"], metrics["severity"])

    with col1:
        st.metric(
            label="Loại Tấn Công",
            value=metrics["attack_type"][:20] + ("..." if len(metrics["attack_type"]) > 20 else ""),
            help=f"Định danh: {metrics['attack_type']} ({metrics['attack_category']})",
        )

    with col2:
        st.metric(
            label="Trạng thái sự cố",
            value=metrics["status"],
            help="Trạng thái hiện tại trong vòng đời LangGraph StateGraph",
        )

    with col3:
        conf_pct = f"{int(metrics['confidence_score'] * 100)}%"
        st.metric(
            label="Mức độ nghiêm trọng",
            value=sev_display,
            delta=f"Tin cậy: {conf_pct}" if metrics["confidence_score"] > 0 else None,
            help="Đánh giá từ Triage Agent dựa trên Rule và Mô hình AI",
        )

    with col4:
        st.metric(
            label="Nhật ký & Sự kiện",
            value=f"{metrics['parsed_events_count']} sự kiện",
            delta=f"Từ {metrics['raw_logs_count']} logs thô",
            delta_color="off",
            help="Số lượng log đã được Ingestion Agent phân tích bóc tách",
        )

    with col5:
        st.metric(
            label="Chỉ số xâm phạm (IoC)",
            value=f"{metrics['ioc_count']} IoCs",
            delta=f"{metrics['malicious_ioc_count']} độc hại" if metrics["malicious_ioc_count"] > 0 else "0 độc hại",
            delta_color="inverse" if metrics["malicious_ioc_count"] > 0 else "normal",
            help="Chỉ số IoC được Threat Intel Agent trích xuất và làm giàu",
        )

    with col6:
        pending = metrics["pending_actions"]
        st.metric(
            label="Hành động HITL",
            value=f"{pending} Chờ duyệt",
            delta=f"Đã duyệt: {metrics['approved_actions']}/{metrics['total_actions']}",
            delta_color="inverse" if pending > 0 else "normal",
            help="Các hành động ngăn chặn theo NIST SP 800-61 đang đợi chuyên viên SOC xử lý",
        )


# =====================================================================
# 2. STATEGRAPH AGENT STATUS & MERMAID DAG
# =====================================================================
DEFAULT_WORKFLOW_NODES = [
    ("ingestion", "Ingestion Agent", "Tiếp nhận log thô & chuẩn hóa ParsedEvent"),
    ("triage", "Triage Agent", "Phân loại True/False Positive & Severity"),
    ("enrichment", "Threat Intel Agent", "Trích xuất IoC & làm giàu dữ liệu CTI"),
    ("rca", "RCA Agent", "Tái hiện cây tiến trình Sysmon & nguyên nhân gốc"),
    ("response", "Response Agent", "Đề xuất kế hoạch phản ứng NIST SP 800-61"),
    ("hitl_approval", "HITL Approval", "Can thiệp phê duyệt của Chuyên viên SOC"),
    ("reporting", "Reporting Agent", "Xuất bản báo cáo điều tra sự cố toàn diện"),
]


def get_graph_node_statuses(state: Optional[IncidentState]) -> List[Dict[str, Any]]:
    """
    Xác định trạng thái hoạt động của từng Node trong đồ thị dựa trên IncidentState.

    :param state: IncidentState hiện tại.
    :return: Danh sách trạng thái chi tiết của từng Node.
    """
    if state is None:
        return [
            {
                "id": node_id,
                "name": name,
                "description": desc,
                "status": "PENDING",
                "badge": "⏳ Chờ thực thi",
                "color": "#6c757d",
            }
            for node_id, name, desc in DEFAULT_WORKFLOW_NODES
        ]

    executed_nodes = {t.node: t for t in state.history}
    checkpoints = state.checkpoints or {}

    results = []
    # Xác định node đang active gần nhất
    last_executed = state.history[-1].node if state.history else None

    for node_id, name, desc in DEFAULT_WORKFLOW_NODES:
        is_executed = node_id in executed_nodes or node_id in checkpoints

        # Kiểm tra điều kiện dữ liệu thực tế
        if node_id == "ingestion" and len(state.parsed_events) > 0:
            is_executed = True
        elif node_id == "triage" and state.triage_result is not None:
            is_executed = True
        elif node_id == "enrichment" and state.threat_intel is not None:
            is_executed = True
        elif node_id == "rca" and state.rca_result is not None:
            is_executed = True
        elif node_id == "response" and len(state.recommended_actions) > 0:
            is_executed = True
        elif node_id == "hitl_approval" and (state.analyst_approved is not None or any(a.is_approved is not None for a in state.recommended_actions)):
            is_executed = True
        elif node_id == "reporting" and state.final_report is not None:
            is_executed = True

        # Kiểm tra xem có bị rẽ nhánh FP bỏ qua không
        is_fp_skip = False
        if state.status == IncidentStatus.CLOSED_FALSE_POSITIVE and node_id in {"enrichment", "rca", "response", "hitl_approval"}:
            is_fp_skip = True

        if is_fp_skip:
            status = "SKIPPED"
            badge = "⏭️ Bỏ qua (FP)"
            color = "#17a2b8"
        elif is_executed:
            status = "COMPLETED"
            badge = "✅ Hoàn thành"
            color = "#28a745"
        elif node_id == last_executed:
            status = "ACTIVE"
            badge = "🔄 Đang xử lý"
            color = "#ffc107"
        else:
            status = "PENDING"
            badge = "⏳ Chờ thực thi"
            color = "#6c757d"

        results.append({
            "id": node_id,
            "name": name,
            "description": desc,
            "status": status,
            "badge": badge,
            "color": color,
            "timestamp": executed_nodes[node_id].timestamp.isoformat() if node_id in executed_nodes else None,
            "message": executed_nodes[node_id].message if node_id in executed_nodes else None,
        })

    return results


def generate_mermaid_graph(state: Optional[IncidentState]) -> str:
    """
    Sinh mã biểu đồ Mermaid DAG biểu diễn luồng điều phối StateGraph theo trục ngang (flowchart LR).
    Tối ưu hóa 100% dạng khối 2D đồng nhất (không dùng hình thoi gây lệch trục), chuẩn hóa hiển thị trên background tối.
    """
    node_statuses = {n["id"]: n["status"] for n in get_graph_node_statuses(state)}

    lines = [
        "%%{init: {",
        "  'theme': 'base',",
        "  'themeVariables': {",
        "    'darkMode': true,",
        "    'background': '#0b0f19',",
        "    'primaryColor': '#1e293b',",
        "    'primaryTextColor': '#f8fafc',",
        "    'primaryBorderColor': '#38bdf8',",
        "    'lineColor': '#64748b',",
        "    'textColor': '#f8fafc',",
        "    'mainBkg': '#1e293b',",
        "    'nodeBorder': '#334155',",
        "    'edgeLabelBackground': '#0f172a',",
        "    'tertiaryColor': '#0f172a'",
        "  }",
        "}}%%",
        "flowchart LR",
        '    Start["🚀 Bắt đầu: Raw Logs / Wazuh Alert"]',
        '    Ingestion["1. Ingestion Agent"]',
        '    Triage["2. Triage Agent"]',
        '    Enrichment["3. Threat Intel CTI"]',
        '    RCA["4. Root Cause Analysis"]',
        '    Response["5. Response Agent"]',
        '    HITL["6. HITL Approval"]',
        '    Reporting["7. Reporting Agent"]',
        '    ClosedFP["Đóng: False Positive"]',
        '    End["Hoàn tất Sự cố: RESOLVED"]',
        "",
        "    Start --> Ingestion",
        "    Ingestion --> Triage",
        "    Triage -->|True Positive| Enrichment",
        "    Triage -->|True Positive| RCA",
        "    Triage -.->|False Positive| ClosedFP",
        "    Enrichment --> Response",
        "    RCA --> Response",
        "    Response --> HITL",
        "    HITL -->|Duyệt / Điều chỉnh| Reporting",
        "    Reporting --> End",
        "    ClosedFP -.-> End",
        "",
        "    classDef completed fill:#064e3b,stroke:#10b981,color:#ecfdf5,stroke-width:2px;",
        "    classDef active fill:#78350f,stroke:#fbbf24,color:#fffbeb,stroke-width:2.5px;",
        "    classDef skipped fill:#0f172a,stroke:#334155,color:#64748b,stroke-width:1.5px,stroke-dasharray: 4 4;",
        "    classDef pending fill:#1e293b,stroke:#334155,color:#94a3b8,stroke-width:1.5px;",
        "    classDef terminal fill:#0f172a,stroke:#38bdf8,color:#f8fafc,stroke-width:2px;",
        "    classDef hitlGate fill:#451a03,stroke:#f97316,color:#ffedd5,stroke-width:2.5px,font-weight:bold;",
        "",
        "    class Start,End terminal;",
        "    class ClosedFP skipped;",
    ]

    mapping = {
        "ingestion": "Ingestion",
        "triage": "Triage",
        "enrichment": "Enrichment",
        "rca": "RCA",
        "response": "Response",
        "hitl_approval": "HITL",
        "reporting": "Reporting",
    }

    for nid, code_name in mapping.items():
        st_val = node_statuses.get(nid, "PENDING").lower()
        if nid == "hitl_approval" and st_val == "active":
            lines.append("    class HITL hitlGate;")
        else:
            lines.append(f"    class {code_name} {st_val};")

    if state and state.status == IncidentStatus.CLOSED_FALSE_POSITIVE:
        lines.append("    class ClosedFP completed;")

    return "\n".join(lines)


def render_agent_graph_status(state: Optional[IncidentState]):
    """
    Hiển thị biểu đồ Tiến trình Thực thi Thời gian thực với các ô được thiết kế theo mẫu Card Hitech (glowing neon, icon bo tròn, chữ to rõ nét, chạy song song Threat Intel & RCA).
    """
    st.subheader("🌐 Tiến trình Thực thi Thời gian thực (Multi-Agent StateGraph DAG)")

    # 1. Trực quan hóa sơ đồ tiến trình với ngoại hình ô mẫu Hitech Card & Chạy song song Agent
    render_parallel_agent_workflow(state, height=580)


# =====================================================================
# 3. IOC TABLE COMPONENT & MITRE METADATA
# =====================================================================
MITRE_TECHNIQUE_METADATA: Dict[str, Dict[str, str]] = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": "Lạm dụng PowerShell để thực thi các script độc hại, tải payload và tránh né giải pháp bảo mật.",
    },
    "T1059.003": {
        "name": "Command and Scripting Interpreter: Windows Command Shell",
        "tactic": "Execution",
        "description": "Thực thi câu lệnh hệ thống qua cmd.exe và batch script tự động.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Sử dụng trình thông dịch dòng lệnh để thực thi mã tùy ý trên hệ thống nạn nhân.",
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence / Privilege Escalation",
        "description": "Tạo tác vụ Windows Scheduled Task bằng schtasks.exe nhằm duy trì quyền truy cập lâu dài.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Dò quét cổng (SYN/TCP Connect) để nhận diện các dịch vụ mạng đang mở trong hạ tầng.",
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Gửi email lừa đảo chứa tệp đính kèm độc hại (Macro Office, ISO, ZIP) để xâm nhập ban đầu.",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Dẫn dụ nạn nhân nhấp vào liên kết độc hại nhằm đánh cắp thông tin xác thực hoặc tải malware.",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "description": "Trích xuất vé Kerberos, NTLM hash và mật khẩu dạng rõ từ không gian bộ nhớ tiến trình lsass.exe.",
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "description": "Thử một số ít mật khẩu phổ biến trên danh sách lớn tài khoản người dùng để tránh bị khóa tài khoản.",
    },
    "T1078.002": {
        "name": "Valid Accounts: Domain Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Lạm dụng tài khoản hợp lệ trong Active Directory để vượt qua các cơ chế kiểm soát truy cập.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Tải các công cụ tấn công hoặc mã độc bổ sung từ máy chủ chỉ huy (C2) về máy nạn nhân.",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Giao tiếp giữa máy nạn nhân và máy chủ C2 qua giao thức HTTP/HTTPS nhằm che giấu trong lưu lượng web.",
    },
    "T1218.011": {
        "name": "System Binary Proxy Execution: Rundll32",
        "tactic": "Defense Evasion",
        "description": "Lạm dụng tệp nhị phân hợp lệ của hệ điều hành rundll32.exe để thực thi thư viện DLL độc hại.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Làm rối mã lệnh, mã hóa chuỗi Base64 hoặc nén payload để tránh né chữ ký tĩnh của AV/EDR.",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Xóa bản sao lưu Volume Shadow Copies và tệp khôi phục hệ thống để ngăn chặn nạn nhân phục hồi.",
    },
}


def format_ioc_table_data(threat_intel: Optional[ThreatIntelEnrichment]) -> List[Dict[str, Any]]:
    """
    Định dạng danh sách IoC từ ThreatIntelEnrichment thành cấu trúc bảng hiển thị,
    loại bỏ trùng lặp và làm sạch tiền tố mã băm.
    """
    if not threat_intel or not threat_intel.extracted_iocs:
        return []

    rows = []
    seen = set()
    for ioc in threat_intel.extracted_iocs:
        val = str(ioc.value or "").strip()
        ioc_type = str(ioc.ioc_type or "UNKNOWN").upper().strip()

        # Chuẩn hóa loại băm và bóc tách giá trị sạch
        if val.upper().startswith("SHA256="):
            ioc_type = "SHA-256"
            val = val[7:].strip()
        elif val.upper().startswith("MD5="):
            ioc_type = "MD5"
            val = val[4:].strip()
        elif len(val) == 64 and all(c in "0123456789abcdefABCDEF" for c in val):
            ioc_type = "SHA-256"
        elif len(val) == 32 and all(c in "0123456789abcdefABCDEF" for c in val):
            ioc_type = "MD5"

        key = (ioc_type, val)
        if key in seen:
            continue
        seen.add(key)

        score = ioc.reputation_score if ioc.reputation_score is not None else 0
        if score >= 80 or ioc.is_malicious:
            assessment = "🚨 Độc hại nguy cấp (Critical)"
        elif score >= 50:
            assessment = "🟠 Độc hại (Suspicious)"
        elif score > 0:
            assessment = "🟡 Cảnh báo (Low)"
        else:
            assessment = "🟢 Đã thẩm định (Benign)"

        display_type = "IPv4" if ioc_type == "IPV4" else ("IPv6" if ioc_type == "IPV6" else ioc_type)

        rows.append({
            "Loại IoC": display_type,
            "Giá trị Chỉ số": val,
            "Điểm Độc hại": score,
            "Điểm Nguy cơ": score,
            "Đánh giá": assessment,
            "Đánh giá CTI": assessment,
            "Nhóm Tấn công": ioc.threat_actor or "Chưa định danh",
            "Nguồn Thẩm định": str(ioc.details.get("source", ioc.details.get("verdict", "VirusTotal & OTX"))),
        })
    return rows


def render_ioc_table(threat_intel: Optional[ThreatIntelEnrichment]):
    """
    Hiển thị bảng IoC danh sách IoC, loại, điểm danh tiếng, đánh giá độc hại, Threat Actor
    với giao diện Dark Theme chuẩn SOC độ tương phản cao.
    """
    st.markdown("#### 🛡️ Danh sách Chỉ số Xâm phạm (IoC Table)")

    if not threat_intel or not threat_intel.extracted_iocs:
        st.info("Chưa có chỉ số IoC nào được trích xuất hoặc sự cố chưa chuyển qua Threat Intel Agent.")
        return

    data = format_ioc_table_data(threat_intel)
    st.dataframe(
        data,
        use_container_width=True,
        column_config={
            "Loại IoC": st.column_config.TextColumn(
                "Loại IoC",
                width="small",
                help="Phân loại: IP, Domain, SHA-256, MD5, URL",
            ),
            "Giá trị Chỉ số": st.column_config.TextColumn(
                "Giá trị Chỉ số Xâm phạm (IoC Value)",
                help="Địa chỉ IP, Tên miền hoặc Mã băm tệp tin bóc tách từ log",
            ),
            "Điểm Nguy cơ": st.column_config.ProgressColumn(
                "Điểm Nguy cơ (0-100)",
                help="Điểm rủi ro tổng hợp từ VirusTotal, AbuseIPDB và AlienVault OTX",
                format="%d",
                min_value=0,
                max_value=100,
            ),
            "Đánh giá CTI": st.column_config.TextColumn(
                "Đánh giá Tình báo",
                width="medium",
            ),
            "Nhóm Tấn công": st.column_config.TextColumn(
                "Threat Actor liên kết",
                width="medium",
            ),
            "Nguồn Thẩm định": st.column_config.TextColumn(
                "Nguồn CTI Feeds",
                width="small",
            ),
        },
    )

    # Box tóm tắt Threat Actors & CTI Context (chuẩn SOC dark high-contrast)
    actors = threat_intel.related_threat_actors or []
    actors_badges_html = "".join(
        f'<span style="background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); font-weight: 700; font-size: 0.8rem; padding: 4px 10px; border-radius: 6px; margin-right: 6px; display: inline-block;">🏴‍☠️ {html.escape(a)}</span>'
        for a in actors
    ) if actors else '<span style="color: #94a3b8; font-size: 0.82rem;">Chưa phát hiện dấu vết liên kết với nhóm APT cụ thể</span>'

    summary_text = threat_intel.enrichment_summary or "Đã hoàn tất phân tích bóc tách và đối soát với các cơ sở dữ liệu tình báo an ninh mạng."

    st.markdown(
        f"""
        <div style="background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 16px 18px; margin-top: 14px;">
            <div style="margin-bottom: 10px;">
                <span style="color: #94a3b8; font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">Nhóm Tin tặc / Threat Actors Liên Quan:</span>
                <div style="margin-top: 6px;">{actors_badges_html}</div>
            </div>
            <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #1e293b;">
                <span style="color: #94a3b8; font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">Tóm Tắt Đánh Giá CTI:</span>
                <div style="color: #cbd5e1; font-size: 0.88rem; margin-top: 4px; line-height: 1.5;">{html.escape(summary_text)}</div>
            </div>
            <div style="display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap;">
                <span style="background: rgba(16, 185, 129, 0.12); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3); font-size: 0.72rem; font-weight: 600; padding: 2px 8px; border-radius: 4px;">🟢 VirusTotal v3 API</span>
                <span style="background: rgba(16, 185, 129, 0.12); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3); font-size: 0.72rem; font-weight: 600; padding: 2px 8px; border-radius: 4px;">🟢 AlienVault OTX Direct</span>
                <span style="background: rgba(16, 185, 129, 0.12); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3); font-size: 0.72rem; font-weight: 600; padding: 2px 8px; border-radius: 4px;">🟢 AbuseIPDB Intelligence</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =====================================================================
# 4. MITRE ATT&CK MATRIX COMPONENT
# =====================================================================
def extract_mitre_data(
    threat_intel: Optional[ThreatIntelEnrichment],
    rca: Optional[RootCauseAnalysis],
) -> Dict[str, Any]:
    """
    Trích xuất và tổng hợp các Chiến thuật (Tactics) và Kỹ thuật (Techniques) MITRE ATT&CK.
    """
    tactics: List[str] = []
    techniques: List[str] = []

    if rca and rca.mitre_tactics:
        tactics = list(dict.fromkeys(rca.mitre_tactics))

    if threat_intel and threat_intel.mitre_techniques:
        techniques = list(dict.fromkeys(threat_intel.mitre_techniques))

    return {
        "tactics": tactics,
        "techniques": techniques,
        "total_tactics": len(tactics),
        "total_techniques": len(techniques),
    }


def render_mitre_matrix(
    threat_intel: Optional[ThreatIntelEnrichment],
    rca: Optional[RootCauseAnalysis],
):
    """
    Hiển thị kỹ thuật và chiến thuật MITRE ATT&CK với thiết kế chuẩn SOC tối ưu tương phản cao.
    """
    st.markdown("#### 🎯 Ma trận Chiến thuật & Kỹ thuật MITRE ATT&CK")

    mitre_data = extract_mitre_data(threat_intel, rca)
    tactics = mitre_data["tactics"]
    techniques = mitre_data["techniques"]

    if not tactics and not techniques:
        st.info("Chưa có thông tin định danh MITRE ATT&CK trong sự cố hiện tại.")
        return

    col1, col2 = st.columns([1, 1.2])

    with col1:
        st.markdown("##### 🏹 Chiến thuật (Tactics)")
        if tactics:
            for t in tactics:
                st.markdown(
                    f"""
                    <div style="background: rgba(220, 38, 38, 0.12); border: 1px solid rgba(239, 68, 68, 0.35); border-left: 4px solid #ef4444; padding: 10px 14px; margin-bottom: 8px; border-radius: 6px;">
                        <strong style="color: #fca5a5; font-size: 0.92rem;">⚔️ {html.escape(t)}</strong>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.caption("Chưa xác định Chiến thuật cụ thể.")

    with col2:
        st.markdown("##### 🛠️ Kỹ thuật (Techniques)")
        if techniques:
            for tech in techniques:
                meta = MITRE_TECHNIQUE_METADATA.get(tech, {
                    "name": tech,
                    "tactic": "Chiến thuật liên kết",
                    "description": "Kỹ thuật được bóc tách từ dấu vết cảnh báo SIEM.",
                })
                tech_name = meta["name"]
                tech_desc = meta.get("description", "")
                st.markdown(
                    f"""
                    <div style="background: #0f172a; border: 1px solid #334155; border-left: 4px solid #38bdf8; padding: 10px 14px; margin-bottom: 8px; border-radius: 6px;">
                        <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap;">
                            <span style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); font-weight: 800; font-size: 0.78rem; padding: 2px 8px; border-radius: 4px; font-family: monospace;">{html.escape(tech)}</span>
                            <span style="color: #f1f5f9; font-weight: 700; font-size: 0.88rem;">{html.escape(tech_name)}</span>
                        </div>
                        <div style="color: #94a3b8; font-size: 0.78rem; margin-top: 4px; line-height: 1.4;">{html.escape(tech_desc)}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.caption("Chưa xác định Kỹ thuật cụ thể.")


# =====================================================================
# 5. PROCESS TREE & ATTACK TIMELINE COMPONENT
# =====================================================================
def format_process_tree_data(rca: Optional[RootCauseAnalysis]) -> List[Dict[str, Any]]:
    """
    Định dạng danh sách tiến trình từ RootCauseAnalysis.
    """
    if not rca or not rca.process_tree:
        return []

    tree = []
    for p in rca.process_tree:
        tree.append({
            "pid": p.process_id,
            "name": p.process_name,
            "cmd": p.command_line,
            "parent_id": p.parent_id,
            "is_origin": p.is_malicious_origin,
        })
    return tree


def format_timeline_data(rca: Optional[RootCauseAnalysis]) -> List[str]:
    """
    Lấy danh sách các mốc thời gian tấn công từ RCA.
    """
    if not rca or not rca.attack_timeline:
        return []
    return list(rca.attack_timeline)


def render_process_tree(rca: Optional[RootCauseAnalysis]):
    """
    Hiển thị cây tiến trình Sysmon và Timeline sự kiện.
    """
    st.subheader("🌲 Cây Tiến trình Sysmon & Dòng Thời gian Tấn công (Process Lineage & Timeline)")

    if not rca:
        st.info("Chưa có kết quả phân tích nguyên nhân gốc rễ (RCA Agent chưa chạy).")
        return

    st.markdown(f"**Cửa ngõ Xâm nhập Ban đầu (Initial Access Vector):** `{rca.initial_access_vector}`")
    st.markdown(f"**Tóm lược Nguyên nhân Gốc rễ:** {rca.root_cause_summary}")

    tab_tree, tab_timeline = st.tabs(["🌳 Cây Tiến trình (Process Lineage)", "⏱️ Dòng Thời gian (Attack Timeline)"])

    with tab_tree:
        tree_data = format_process_tree_data(rca)
        if tree_data:
            for item in tree_data:
                origin_badge = "🚨 **[ĐIỂM GỐC ĐỘC HẠI - PATIENT ZERO]**" if item["is_origin"] else "⚙️ [Tiến trình con]"
                border_color = "#dc3545" if item["is_origin"] else "#0d6efd"
                st.markdown(
                    f"""
                    <div style="border-left: 4px solid {border_color}; padding: 8px 12px; margin-bottom: 10px; background-color: rgba(255,255,255,0.02); border-radius: 4px;">
                        <div>{origin_badge} <strong>{html.escape(item['name'])}</strong> (PID: <code>{html.escape(item['pid'])}</code>)</div>
                        <div style="font-size: 0.85em; color: #aaa; margin-top: 4px;">Tiến trình cha (Parent): <code>{html.escape(str(item['parent_id'] or 'None'))}</code></div>
                        <div style="font-size: 0.85em; margin-top: 4px; background: rgba(0,0,0,0.2); padding: 4px 8px; border-radius: 4px;">
                            <code>{html.escape(item['cmd'])}</code>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.caption("Không ghi nhận cây tiến trình Sysmon chi tiết.")

    with tab_timeline:
        timeline = format_timeline_data(rca)
        if timeline:
            for idx, entry in enumerate(timeline, start=1):
                st.markdown(f"**{idx}.** {entry}")
        else:
            st.caption("Không có dữ liệu timeline sự kiện.")


# =====================================================================
# 6. HITL ACTION CARDS COMPONENT
# =====================================================================
def apply_hitl_action_decision(
    state: IncidentState,
    action_idx: int,
    decision: str,
    edited_target: Optional[str] = None,
    edited_priority: Optional[int] = None,
    edited_description: Optional[str] = None,
) -> IncidentState:
    """
    Xử lý cập nhật quyết định của chuyên viên SOC cho từng hành động hoặc chỉnh sửa tham số.

    :param state: IncidentState.
    :param action_idx: Chỉ số hành động trong state.recommended_actions.
    :param decision: "APPROVE", "REJECT", "EDIT".
    :param edited_target: Tham số mục tiêu mới (nếu có).
    :param edited_priority: Độ ưu tiên mới (nếu có).
    :param edited_description: Mô tả mới (nếu có).
    :return: IncidentState đã cập nhật.
    """
    if not state.recommended_actions or action_idx < 0 or action_idx >= len(state.recommended_actions):
        return state

    action = state.recommended_actions[action_idx]

    if edited_target:
        action.target = edited_target.strip()
    if edited_priority is not None and 1 <= edited_priority <= 5:
        action.priority = edited_priority
    if edited_description:
        action.description = edited_description.strip()

    decision_norm = decision.upper()
    if decision_norm == "APPROVE":
        action.is_approved = True
    elif decision_norm == "REJECT":
        action.is_approved = False
    elif decision_norm == "RESET":
        action.is_approved = None

    return state


def render_hitl_action_cards(state: Optional[IncidentState], manager=None):
    """
    Hiển thị từng hành động phản ứng (Wazuh Active Response, Isolate Host, Block IP, Kill Process),
    form chỉnh sửa tham số, nút Duyệt / Từ chối / Chỉnh sửa trực tiếp trên giao diện web.
    """
    st.subheader("🛡️ Trung tâm Phê duyệt Chuyên viên (Interactive HITL Console)")

    if not state or not state.recommended_actions:
        st.info("Chưa có hành động phản ứng nào được đề xuất (Response Agent chưa chạy).")
        return

    st.markdown(
        """
        > 💡 **Quy trình HITL (NIST SP 800-61 Rev.2):**
        > Chuyên viên phân tích SOC có quyền kiểm soát toàn diện: Duyệt các biện pháp khẩn cấp,
        > từ chối hành động gây gián đoạn dịch vụ, hoặc tùy biến địa chỉ IP/PID trước khi kích hoạt phản ứng tự động.
        """
    )

    # Đảm bảo tất cả action đều có ID duy nhất
    for idx, act in enumerate(state.recommended_actions):
        if act.action_id is None:
            act.action_id = f"ACT-{idx+1:03d}"

    hitl_mgr = manager or HITLManager()

    # Nút Duyệt tất cả / Từ chối tất cả / Hoàn tác tất cả nhanh
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1.5])
    with col_btn1:
        if st.button("✅ Phê duyệt Tất cả", use_container_width=True):
            for act in state.recommended_actions:
                act.is_approved = True
            state.analyst_approved = True
            state.analyst_feedback = "Phê duyệt đồng loạt tất cả các hành động bởi Chuyên viên SOC"
            st.success("Đã phê duyệt tất cả các hành động phản ứng!")
            st.rerun()

    with col_btn2:
        if st.button("❌ Từ chối Tất cả", use_container_width=True):
            for act in state.recommended_actions:
                act.is_approved = False
            state.analyst_approved = False
            state.analyst_feedback = "Từ chối toàn bộ kế hoạch hành động bởi Chuyên viên SOC"
            st.warning("Đã từ chối tất cả các hành động phản ứng!")
            st.rerun()

    with col_btn3:
        has_approved_reversible = any(
            a.is_approved is True
            and a.action_type != ActionType.KILL_PROCESS
            and a.script_bundle is not None
            and a.script_bundle.rollback_script is not None
            for a in state.recommended_actions
        )
        if has_approved_reversible:
            with st.popover("🔄 Hoàn tác Tất cả (Rollback All)", use_container_width=True):
                st.markdown("**Chọn lý do hoàn tác toàn bộ:**")
                reason_all_str = st.selectbox(
                    "Lý do",
                    options=[
                        "FALSE_POSITIVE - Dương tính giả (Đóng sự cố)",
                        "SERVICE_DISRUPTION - Gián đoạn dịch vụ (Điều tra lại)",
                        "RECOVERY_COMPLETE - Khôi phục hoàn tất (Resolved)",
                    ],
                    key="rb_reason_all_select",
                )
                rb_all_notes = st.text_input("Ghi chú hoàn tác toàn bộ", key="rb_all_notes")
                if st.button("Xác nhận Hoàn tác Toàn bộ", key="btn_confirm_rb_all", type="primary", use_container_width=True):
                    parsed_reason = RollbackReason.FALSE_POSITIVE
                    if "SERVICE_DISRUPTION" in reason_all_str:
                        parsed_reason = RollbackReason.SERVICE_DISRUPTION
                    elif "RECOVERY_COMPLETE" in reason_all_str:
                        parsed_reason = RollbackReason.RECOVERY_COMPLETE
                    try:
                        hitl_mgr.rollback_all(state, reason=parsed_reason, notes=rb_all_notes)
                        st.success("Đã hoàn tác toàn bộ các hành động phản ứng!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Lỗi hoàn tác: {e}")

    st.divider()

    action_type_icons = {
        ActionType.ISOLATE_HOST: "🔌",
        ActionType.BLOCK_IP: "🚫",
        ActionType.KILL_PROCESS: "🛑",
        ActionType.REVOKE_USER: "👤",
        ActionType.RESET_PASSWORD: "🔑",
        ActionType.PATCH_SYSTEM: "🩹",
        ActionType.WAZUH_ACTIVE_RESPONSE: "⚡",
    }

    for idx, act in enumerate(state.recommended_actions):
        icon = action_type_icons.get(act.action_type, "🛡️")
        act_name = act.action_type.value if hasattr(act.action_type, "value") else str(act.action_type)
        is_rolled_back = bool(act.parameters and act.parameters.get("rollback_executed"))

        if is_rolled_back:
            status_badge = "🔄 ĐÃ HOÀN TÁC (ROLLED BACK)"
            card_border = "#6f42c1"
        elif act.is_approved is True:
            status_badge = "🟢 ĐÃ PHÊ DUYỆT (APPROVED)"
            card_border = "#28a745"
        elif act.is_approved is False:
            status_badge = "🔴 ĐÃ TỪ CHỐI (REJECTED)"
            card_border = "#dc3545"
        else:
            status_badge = "🟡 CHỜ DUYỆT (PENDING)"
            card_border = "#ffc107"

        with st.expander(
            f"{icon} Hành động #{idx+1}: {act_name} | Target: {act.target} - [{status_badge}]",
            expanded=(act.is_approved is None)
        ):
            st.markdown(f"**Mã hành động (ID):** `{act.action_id}` | **Mô tả:** {act.description}")

            if is_rolled_back:
                rb_reason = act.parameters.get("rollback_reason", "Chưa rõ")
                rb_by = act.parameters.get("rollback_by", "SOC Analyst")
                rb_at = act.parameters.get("rollback_at", "")
                st.info(f"ℹ️ **Trạng thái Hoàn tác:** Đã hoàn tác bởi `{rb_by}`. Lý do: `{rb_reason}` ({rb_at})")

            col_edit1, col_edit2 = st.columns([2, 1])
            with col_edit1:
                new_target = st.text_input(
                    f"Mục tiêu (Target IP / Host / PID)",
                    value=act.target,
                    key=f"hitl_target_{idx}",
                )
            with col_edit2:
                new_prio = st.number_input(
                    f"Mức ưu tiên (Priority 1-5)",
                    min_value=1,
                    max_value=5,
                    value=int(act.priority),
                    key=f"hitl_prio_{idx}",
                )

            new_desc = st.text_input(
                f"Ghi chú / Mô tả cập nhật",
                value=act.description,
                key=f"hitl_desc_{idx}",
            )

            col_a, col_b, col_c = st.columns([1, 1, 1])
            with col_a:
                if st.button(f"✅ Duyệt #{idx+1}", key=f"btn_approve_{idx}", use_container_width=True):
                    apply_hitl_action_decision(
                        state=state,
                        action_idx=idx,
                        decision="APPROVE",
                        edited_target=new_target,
                        edited_priority=int(new_prio),
                        edited_description=new_desc,
                    )
                    st.success(f"Đã duyệt hành động #{idx+1}")
                    st.rerun()

            with col_b:
                if st.button(f"❌ Từ chối #{idx+1}", key=f"btn_reject_{idx}", use_container_width=True):
                    apply_hitl_action_decision(
                        state=state,
                        action_idx=idx,
                        decision="REJECT",
                        edited_target=new_target,
                        edited_priority=int(new_prio),
                        edited_description=new_desc,
                    )
                    st.warning(f"Đã từ chối hành động #{idx+1}")
                    st.rerun()

            with col_c:
                if st.button(f"💾 Cập nhật Tham số #{idx+1}", key=f"btn_save_{idx}", use_container_width=True):
                    apply_hitl_action_decision(
                        state=state,
                        action_idx=idx,
                        decision="EDIT",
                        edited_target=new_target,
                        edited_priority=int(new_prio),
                        edited_description=new_desc,
                    )
                    st.info(f"Đã lưu tham số điều chỉnh cho hành động #{idx+1}")
                    st.rerun()

            # Vùng Hoàn tác (Rollback) cho hành động đã duyệt
            if act.is_approved is True and not is_rolled_back:
                st.markdown("---")
                if act.action_type == ActionType.KILL_PROCESS or not act.script_bundle or not act.script_bundle.rollback_script:
                    st.warning("⚠️ **Không thể hoàn tác:** Hành động này mang tính phá hủy/không khả nghịch (KILL_PROCESS) hoặc không có kịch bản đảo ngược.")
                else:
                    with st.expander(f"🔄 Hoàn tác (Rollback) Hành động #{idx+1}"):
                        rollback_cmd = act.script_bundle.rollback_script if act.script_bundle and act.script_bundle.rollback_script else "N/A"
                        st.caption(f"**Lệnh khôi phục dự kiến:** `{rollback_cmd}`")
                        col_rb1, col_rb2 = st.columns([1, 2])
                        with col_rb1:
                            reason_choice = st.selectbox(
                                "Lý do hoàn tác",
                                options=[
                                    "FALSE_POSITIVE",
                                    "SERVICE_DISRUPTION",
                                    "RECOVERY_COMPLETE",
                                ],
                                key=f"rb_reason_choice_{idx}",
                            )
                        with col_rb2:
                            rb_note = st.text_input(
                                "Ghi chú hoàn tác",
                                placeholder="Nhập lý do chi tiết hoặc mã phiếu yêu cầu...",
                                key=f"rb_note_{idx}",
                            )

                        if st.button(f"🚨 Xác nhận Hoàn tác #{idx+1}", key=f"btn_do_rb_{idx}", type="primary"):
                            try:
                                hitl_mgr.rollback_action(
                                    state=state,
                                    action_id=act.action_id,
                                    reason=RollbackReason(reason_choice),
                                    notes=rb_note,
                                )
                                st.success(f"Đã hoàn tác thành công hành động #{idx+1}!")
                                st.rerun()
                            except Exception as ex:
                                st.error(f"Lỗi khi hoàn tác: {ex}")


# =====================================================================
# 7. HITECH 4-LANES ARCHITECTURE WORKFLOW DIAGRAM
# =====================================================================
from src.ui.workflow_diagram import (
    get_hitech_workflow_html,
    render_hitech_agent_workflow,
    get_parallel_agent_workflow_html,
    render_parallel_agent_workflow,
)

