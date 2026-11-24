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

import os
import html
from typing import List, Dict, Any, Optional
import streamlit as st

from src.core.schemas import (
    IncidentStatus,
    ActionType,
    ThreatIntelEnrichment,
    RootCauseAnalysis,
)
from src.core.state import IncidentState
from src.core.hitl_manager import HITLManager, RollbackReason


# =====================================================================
# 1. KPI CARDS COMPONENT
# =====================================================================
def _telemetry_attr(item: Any, attr: str, default: Any = None) -> Any:
    """Truy xuất an toàn thuộc tính trên LLMCallTelemetry hoặc dict."""
    if isinstance(item, dict):
        return item.get(attr, default)
    return getattr(item, attr, default)


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
            "total_llm_tokens": 0,
            "llm_calls_count": 0,
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

    telemetry_items = getattr(state, "llm_telemetry", None) or []
    exec_metrics = getattr(state, "execution_metrics", None) or {}
    llm_metrics = getattr(state, "llm_metrics", None) or {}

    if telemetry_items:
        total_llm_tokens = 0
        llm_calls_count = 0
        for item in telemetry_items:
            p_tok = int(_telemetry_attr(item, "prompt_tokens", 0) or 0)
            c_tok = int(_telemetry_attr(item, "completion_tokens", 0) or 0)
            tot_tok = int(_telemetry_attr(item, "total_tokens", 0) or 0)
            if tot_tok == 0 and (p_tok > 0 or c_tok > 0):
                tot_tok = p_tok + c_tok
            total_llm_tokens += tot_tok
            prov = str(_telemetry_attr(item, "provider_used", None) or _telemetry_attr(item, "provider", "") or "")
            if prov != "skipped_tiered":
                llm_calls_count += 1
    else:
        total_llm_tokens = int(exec_metrics.get("total_tokens", llm_metrics.get("total_tokens", 0)) or 0)
        llm_calls_count = int(exec_metrics.get("llm_calls_count", llm_metrics.get("llm_calls_count", 0)) or 0)

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
        "total_llm_tokens": total_llm_tokens,
        "llm_calls_count": llm_calls_count,
    }


def render_attack_detection_banner(state: Optional[IncidentState]):
    """
    Render Hero Banner hiển thị kết quả Định danh Loại Tấn Công theo chuẩn Trung tâm Điều hành SOC Thông minh.
    """
    if not state:
        return

    # Trạng thái Standby / Chờ nhận cảnh báo từ Wazuh OVA
    if not state.raw_logs and state.status == IncidentStatus.NEW:
        from src.core.config import get_wazuh_ova_ip, get_webhook_port

        wazuh_ova_ip = get_wazuh_ova_ip()
        webhook_port = get_webhook_port()
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
                        🟢 Sẵn sàng nhận cảnh báo từ Wazuh OVA (:{webhook_port}/api/v1/wazuh-alert)
                    </div>
                    <div style="color: #94a3b8; font-size: 13px; margin-top: 6px;">
                        Chưa ghi nhận cảnh báo mới. Vui lòng bật máy chủ Wazuh OVA ({html.escape(wazuh_ova_ip)}) hoặc chọn kịch bản mẫu từ menu bên trái để điều tra.
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
        '    HITL{{"🛑 Cổng Phê duyệt HITL"}}',
        '    Reporting["6. Reporting Agent"]',
        '    ClosedFP["📁 Đóng: False Positive"]',
        '    End["🏁 Hoàn tất Sự cố: RESOLVED"]',
        "",
        "    Start --> Ingestion",
        "    Ingestion --> Triage",
        "    Triage -->|⚡ True Positive (Song song)| Enrichment",
        "    Triage -->|⚡ True Positive (Song song)| RCA",
        "    Triage -.->|False Positive| ClosedFP",
        "    Enrichment -.->|CTI Context Feed| RCA",
        "    Enrichment --> Response",
        "    RCA --> Response",
        "    Response --> HITL",
        "    HITL -->|Duyệt ✓| Reporting",
        "    HITL -.->|Từ chối / Hiệu chỉnh ↺| Response",
        "    Reporting --> End",
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
# 6. SIMPLE RBAC CONSTANTS & PROCESS WHITELIST GUARD HELPERS (DELEGATED TO CORE RBAC)
# =====================================================================
from src.core.rbac import (
    ROLE_SOC_ANALYST,
    ROLE_TIER1,
    ROLE_SOC_MANAGER,
    USER_ROLES,
    HIGH_RISK_ACTION_TYPES,
    LOW_MEDIUM_ACTION_TYPES,
    DANGEROUS_ACTIONS,
    PROTECTED_PROCESSES,
    SYSTEM_CRITICAL_PROCESSES,
    PERMISSION_MATRIX,
    normalize_role,
    extract_action_type_str,
    is_dangerous_action,
    is_protected_process,
    is_critical_system_process,
    has_permission,
    can_user_approve_action,
    check_action_permission,
    get_action_rbac_warning,
    get_whitelist_guard_warning,
    build_rbac_denied_payload,
    enforce_hitl_rbac,
)


# =====================================================================
# 7. HITL ACTION CARDS COMPONENT
# =====================================================================
def apply_hitl_action_decision(
    state: IncidentState,
    action_idx: int,
    decision: str,
    edited_target: Optional[str] = None,
    edited_priority: Optional[int] = None,
    edited_description: Optional[str] = None,
    user_role: Optional[str] = None,
) -> IncidentState:
    """
    Xử lý cập nhật quyết định của chuyên viên SOC cho từng hành động hoặc chỉnh sửa tham số.
    Tích hợp Simple RBAC & Process Whitelist Guard: kiểm tra vai trò người dùng và bảo vệ tiến trình trọng yếu.

    :param state: IncidentState.
    :param action_idx: Chỉ số hành động trong state.recommended_actions.
    :param decision: "APPROVE", "REJECT", "EDIT".
    :param edited_target: Tham số mục tiêu mới (nếu có).
    :param edited_priority: Độ ưu tiên mới (nếu có).
    :param edited_description: Mô tả mới (nếu có).
    :param user_role: Vai trò người dùng ("SOC Analyst (Tier 1/2)" hoặc "SOC Manager (Incident Commander)").
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
        is_protected_kill = (
            extract_action_type_str(action) == "KILL_PROCESS"
            and is_protected_process(action.target)
        )
        if is_protected_kill:
            action.is_approved = None
        elif user_role is not None and not can_user_approve_action(user_role, action):
            # Không đủ thẩm quyền phê duyệt hành động rủi ro cao
            action.is_approved = None
        else:
            action.is_approved = True
    elif decision_norm == "REJECT":
        action.is_approved = False
    elif decision_norm == "RESET":
        action.is_approved = None

    return state


def render_response_strategy_callout(state: Optional[IncidentState]) -> Optional[str]:
    """
    Hiển thị hộp callout Chiến lược Phản ứng Tổng hợp (RAG + LLM Incident Commander Rationale)
    nếu state.response_strategy_summary có dữ liệu, đảm bảo HTML-escape chống XSS.
    """
    summary = getattr(state, "response_strategy_summary", None) if state is not None else None
    if not summary or not str(summary).strip():
        return None

    safe_summary = html.escape(str(summary).strip()).replace("\n", "<br/>")
    callout_html = (
        f'<div data-testid="response_strategy_callout" '
        f'style="background: linear-gradient(135deg, rgba(14, 165, 233, 0.12) 0%, #0f172a 100%); '
        f'border: 1px solid rgba(56, 189, 248, 0.45); border-left: 5px solid #38bdf8; '
        f'border-radius: 10px; padding: 14px 18px; margin-bottom: 16px;">'
        f'<div style="color: #38bdf8; font-weight: 800; font-size: 0.88rem; margin-bottom: 6px;">'
        f'🧠 Chiến lược Phản ứng Tổng hợp (RAG + LLM Incident Commander Rationale)'
        f'</div>'
        f'<div style="color: #e2e8f0; font-size: 0.86rem; line-height: 1.55;">{safe_summary}</div>'
        f'</div>'
    )
    try:
        st.markdown(callout_html, unsafe_allow_html=True)
    except Exception:
        pass
    return callout_html


def render_hitl_action_cards(
    state: Optional[IncidentState],
    manager=None,
    user_role: Optional[str] = None,
):
    """
    Hiển thị từng hành động phản ứng (Wazuh Active Response, Isolate Host, Block IP, Kill Process),
    form chỉnh sửa tham số, nút Duyệt / Từ chối / Chỉnh sửa trực tiếp trên giao diện web.
    Tích hợp Simple RBAC (SOC Analyst vs SOC Manager) và cảnh báo trực quan Process Whitelist Guard.
    """
    st.subheader("🛡️ Trung tâm Phê duyệt Chuyên viên (Interactive HITL Console)")

    render_response_strategy_callout(state)

    if not state or not state.recommended_actions:
        st.info("Chưa có hành động phản ứng nào được đề xuất (Response Agent chưa chạy).")
        return

    # Lấy vai trò người dùng từ session state nếu không truyền trực tiếp
    if user_role is None:
        try:
            user_role = st.session_state.get("user_role", ROLE_SOC_ANALYST)
        except Exception:
            user_role = ROLE_SOC_ANALYST

    is_manager = normalize_role(user_role) == ROLE_SOC_MANAGER
    role_border = "#38bdf8" if is_manager else "#f59e0b"
    role_color = "#38bdf8" if is_manager else "#fbbf24"
    role_desc = (
        "🔑 Toàn quyền Incident Commander: Được duyệt ISOLATE_HOST & KILL_PROCESS"
        if is_manager
        else "🔒 Phân tích viên Tier 1/2: Bị giới hạn các hành động rủi ro cao (Cần Manager duyệt)"
    )

    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; background: #0f172a; border: 1px solid {role_border}; border-left: 5px solid {role_border}; border-radius: 8px; padding: 10px 16px; margin-bottom: 14px;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 1.2rem;">👤</span>
                <div>
                    <span style="color: #94a3b8; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">Phiên Làm Việc Hiện Tại:</span>
                    <div style="color: {role_color}; font-weight: 800; font-size: 0.95rem;">{html.escape(user_role)}</div>
                </div>
            </div>
            <div style="text-align: right; color: #cbd5e1; font-size: 0.78rem;">
                {html.escape(role_desc)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        > 💡 **Quy trình HITL & Phân quyền RBAC (NIST SP 800-61 Rev.2):**
        > Chuyên viên phân tích SOC có quyền kiểm soát toàn diện: Duyệt các biện pháp khẩn cấp,
        > từ chối hành động gây gián đoạn dịch vụ, hoặc tùy biến địa chỉ IP/PID trước khi kích hoạt phản ứng tự động.
        > Các hành động rủi ro cao (Cô lập máy / Diệt tiến trình) bắt buộc vai trò **SOC Manager (Incident Commander)** phê duyệt.
        """
    )

    # Đảm bảo tất cả action đều có ID duy nhất
    for idx, act in enumerate(state.recommended_actions):
        if act.action_id is None:
            act.action_id = f"ACT-{idx+1:03d}"

    hitl_mgr = manager or HITLManager()

    rbac_batch = enforce_hitl_rbac(
        user_role,
        action_type="APPROVE_ALL",
        actions=state.recommended_actions,
    )
    has_protected_kill = any(
        extract_action_type_str(a) == "KILL_PROCESS" and is_protected_process(a.target)
        for a in state.recommended_actions
    )
    can_approve_all = bool(rbac_batch.get("allowed", False)) and not has_protected_kill

    # Nút Duyệt tất cả / Từ chối tất cả / Hoàn tác tất cả nhanh
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1.5])
    with col_btn1:
        if has_protected_kill:
            tooltip_all = "🛡️ Process Whitelist Guard: Danh sách chứa hành động KILL_PROCESS nhắm vào tiến trình hệ thống trọng yếu."
        elif can_approve_all:
            tooltip_all = "Phê duyệt tất cả các hành động phản ứng"
        else:
            tooltip_all = "⚠️ Yêu cầu vai trò SOC Manager để duyệt tất cả do danh sách có hành động rủi ro cao (Cô lập máy / Diệt tiến trình)"
        if st.button("✅ Phê duyệt Tất cả", use_container_width=True, disabled=not can_approve_all, help=tooltip_all):
            for act in state.recommended_actions:
                act.is_approved = True
            state.analyst_approved = True
            state.analyst_feedback = f"Phê duyệt đồng loạt tất cả các hành động bởi {user_role}"
            st.success("Đã phê duyệt tất cả các hành động phản ứng!")
            st.rerun()

    with col_btn2:
        if st.button("❌ Từ chối Tất cả", use_container_width=True):
            for act in state.recommended_actions:
                act.is_approved = False
            state.analyst_approved = False
            state.analyst_feedback = f"Từ chối toàn bộ kế hoạch hành động bởi {user_role}"
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

    if not can_approve_all:
        st.caption("🔒 *Nút 'Phê duyệt Tất cả' bị khóa do danh sách có hành động rủi ro cao cần quyền SOC Manager.*")

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
        elif act.is_approved is True:
            status_badge = "🟢 ĐÃ PHÊ DUYỆT (APPROVED)"
        elif act.is_approved is False:
            status_badge = "🔴 ĐÃ TỪ CHỐI (REJECTED)"
        else:
            status_badge = "🟡 CHỜ DUYỆT (PENDING)"

        with st.expander(
            f"{icon} Hành động #{idx+1}: {act_name} | Target: {act.target} - [{status_badge}]",
            expanded=(act.is_approved is None)
        ):
            st.markdown(f"**Mã hành động (ID):** `{act.action_id}` | **Mô tả:** {act.description}")

            # 1. CẢNH BÁO TRỰC QUAN PROCESS WHITELIST GUARD
            if is_critical_system_process(act.target):
                st.warning(
                    f"🛡️ **Process Whitelist Guard:** Cảnh báo: Mục tiêu `{act.target}` là tiến trình hệ thống quan trọng "
                    "(như svchost.exe, lsass.exe, explorer.exe). "
                    "Can thiệp hoặc diệt tiến trình này có thể gây mất ổn định hoặc sập hệ điều hành (BSOD / System Crash)!"
                )

            # 2. CẢNH BÁO PHÂN QUYỀN SIMPLE RBAC
            can_approve = can_user_approve_action(user_role, act)
            if not can_approve:
                st.warning("⚠️ Yêu cầu vai trò SOC Manager để phê duyệt hành động có rủi ro cao (Cô lập máy / Diệt tiến trình)")

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

            # Kiểm tra nếu người dùng chỉnh sửa mục tiêu thành tiến trình whitelist
            if new_target != act.target and is_critical_system_process(new_target):
                st.warning(
                    f"🛡️ **Process Whitelist Guard:** Cảnh báo: Mục tiêu mới `{new_target}` là tiến trình hệ thống quan trọng!"
                )

            col_a, col_b, col_c = st.columns([1, 1, 1])
            with col_a:
                is_protected_kill = (
                    extract_action_type_str(act) == "KILL_PROCESS"
                    and is_protected_process(new_target)
                )
                btn_disabled = (not can_approve) or is_protected_kill
                if is_protected_kill:
                    btn_tooltip = "🛡️ Process Whitelist Guard: Chặn duyệt KILL_PROCESS trên tiến trình hệ thống trọng yếu!"
                elif not can_approve:
                    btn_tooltip = "⚠️ Yêu cầu vai trò SOC Manager để phê duyệt hành động có rủi ro cao (Cô lập máy / Diệt tiến trình)"
                else:
                    btn_tooltip = f"Phê duyệt hành động #{idx+1}"
                if st.button(
                    f"✅ Duyệt #{idx+1}",
                    key=f"btn_approve_{idx}",
                    use_container_width=True,
                    disabled=btn_disabled,
                    help=btn_tooltip,
                ):
                    apply_hitl_action_decision(
                        state=state,
                        action_idx=idx,
                        decision="APPROVE",
                        edited_target=new_target,
                        edited_priority=int(new_prio),
                        edited_description=new_desc,
                        user_role=user_role,
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
                        user_role=user_role,
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
                        user_role=user_role,
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
# 8. LLM GATEWAY HONEST HEALTH BADGE & TELEMETRY OBSERVABILITY COMPONENTS
# =====================================================================
def _extract_health_attr(obj: Any, attr: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def render_llm_health_badge(
    llm_provider: Any = None,
    health: Any = None,
    key_prefix: str = "llm",
    probe: bool = True,
) -> Dict[str, Any]:
    """Kiểm tra trung thực trạng thái kết nối LLM Gateway và render badge hiển thị.

    - Hỗ trợ cả Pydantic `LLMHealthStatus` lẫn dict mock và provider tối giản.
    - Phân biệt rõ:
      * `🟢 Live Cloud AI ({model} • {latency_ms}ms) [Online]` (omnirouter/openrouter)
      * `🟢 Live Local Ollama ({model} • {latency_ms}ms) [Online]` (ollama)
      * `🟡 Fallback: Deterministic CoT` (+ lý do lỗi ngắn gọn)
      * `⚪ Chưa kiểm tra kết nối`
      * `🔴 Offline`
    - Không bao giờ hiển thị giả `Online` khi Gateway không thể kết nối.
    """
    connected = False
    active_provider = "none"
    configured_mode = "none"
    model = "N/A"
    endpoint = ""
    latency_ms: Optional[float] = None
    detail = ""
    error: Optional[str] = None
    using_dummy_key = False
    enable_fallback = True
    is_unverified = False

    if llm_provider is not None:
        enable_fallback = bool(getattr(llm_provider, "enable_fallback", True))
        configured_mode = str(getattr(llm_provider, "provider_mode", "auto") or "auto")
        model = str(getattr(llm_provider, "model", "default") or "default")
        endpoint = str(getattr(llm_provider, "endpoint", "") or "")
        active_provider = str(
            getattr(llm_provider, "last_used_provider", None)
            or getattr(llm_provider, "provider_type", "unknown")
            or "unknown"
        )
        error = getattr(llm_provider, "last_error", None)

    if health is not None:
        explicit_status = str(_extract_health_attr(health, "status", "") or "").strip().lower()
        explicit_checked = _extract_health_attr(health, "checked", None)
        health_connected = bool(_extract_health_attr(health, "connected", False))
        health_active = str(_extract_health_attr(health, "active_provider", active_provider) or active_provider)

        if explicit_status in {"unverified", "unchecked", "not_checked"} or (
            explicit_checked is False and not health_connected
        ) or health_active.strip().lower() == "unverified":
            is_unverified = True
            connected = False
            active_provider = "unverified"
            detail = str(_extract_health_attr(health, "detail", "") or "Chưa kiểm tra kết nối LLM Gateway.")
        else:
            connected = health_connected
            active_provider = health_active
            configured_mode = str(_extract_health_attr(health, "configured_mode", configured_mode) or configured_mode)
            model = str(_extract_health_attr(health, "model", model) or model)
            endpoint = str(_extract_health_attr(health, "endpoint", endpoint) or endpoint)
            latency_ms = _extract_health_attr(health, "latency_ms", None)
            detail = str(_extract_health_attr(health, "detail", "") or "")
            error = _extract_health_attr(health, "error", error)
            using_dummy_key = bool(_extract_health_attr(health, "using_dummy_key", False))
            if _extract_health_attr(health, "enable_fallback", None) is not None:
                enable_fallback = bool(_extract_health_attr(health, "enable_fallback", True))
            elif llm_provider is None and active_provider.strip().lower() == "none":
                enable_fallback = False
    elif llm_provider is None:
        detail = "Chưa khởi tạo LLM Provider."
        error = "provider_not_configured"
    elif not probe:
        is_unverified = True
        connected = False
        active_provider = "unverified"
        detail = "Chưa kiểm tra kết nối tới LLM Gateway (bấm '🔌 Kiểm tra LLM')."
    elif hasattr(llm_provider, "check_health") and callable(llm_provider.check_health):
        try:
            health_res = llm_provider.check_health()
            connected = bool(_extract_health_attr(health_res, "connected", False))
            active_provider = str(_extract_health_attr(health_res, "active_provider", active_provider) or active_provider)
            configured_mode = str(_extract_health_attr(health_res, "configured_mode", configured_mode) or configured_mode)
            model = str(_extract_health_attr(health_res, "model", model) or model)
            endpoint = str(_extract_health_attr(health_res, "endpoint", endpoint) or endpoint)
            latency_ms = _extract_health_attr(health_res, "latency_ms", None)
            detail = str(_extract_health_attr(health_res, "detail", "") or "")
            error = _extract_health_attr(health_res, "error", error)
            using_dummy_key = bool(_extract_health_attr(health_res, "using_dummy_key", False))
        except Exception as exc:
            connected = False
            error = str(exc)
            detail = f"Kiểm tra kết nối thất bại: {exc}"
    else:
        connected = False
        if active_provider.strip().lower() == "deterministic" or configured_mode.strip().lower() == "deterministic":
            detail = "Chế độ Deterministic Fallback."
        else:
            is_unverified = True
            active_provider = "unverified"
            detail = "Provider không hỗ trợ kiểm tra health trực tiếp."

    active_lower = active_provider.strip().lower()
    mode_lower = configured_mode.strip().lower()
    lat_part = f" • {latency_ms:.0f}ms" if isinstance(latency_ms, (int, float)) else ""

    if connected and active_lower not in {"deterministic", "none", "offline", "unverified", ""}:
        state_key = "online"
        if active_lower == "ollama":
            badge_text = f"🟢 Live Local Ollama ({model}{lat_part}) [Online]"
        else:
            badge_text = f"🟢 Live Cloud AI ({model}{lat_part}) [Online]"
        badge_color = "#34d399"
        badge_bg = "rgba(16, 185, 129, 0.2)"
        badge_border = "rgba(52, 211, 153, 0.4)"
    elif is_unverified:
        state_key = "unverified"
        badge_text = "⚪ Chưa kiểm tra kết nối"
        badge_color = "#cbd5e1"
        badge_bg = "rgba(148, 163, 184, 0.16)"
        badge_border = "rgba(148, 163, 184, 0.4)"
    elif (llm_provider is not None or health is not None) and (
        enable_fallback or active_lower == "deterministic" or mode_lower == "deterministic"
    ) and active_lower != "none":
        state_key = "degraded"
        short_err = str(error).strip().replace("\n", " ")[:60] if error else ""
        badge_text = (
            f"🟡 Fallback: Deterministic CoT ({short_err})"
            if short_err
            else "🟡 Fallback: Deterministic CoT"
        )
        badge_color = "#fbbf24"
        badge_bg = "rgba(245, 158, 11, 0.18)"
        badge_border = "rgba(245, 158, 11, 0.45)"
    elif (llm_provider is not None and enable_fallback and active_lower == "none" and mode_lower == "deterministic"):
        state_key = "degraded"
        badge_text = "🟡 Fallback: Deterministic CoT"
        badge_color = "#fbbf24"
        badge_bg = "rgba(245, 158, 11, 0.18)"
        badge_border = "rgba(245, 158, 11, 0.45)"
    else:
        state_key = "offline"
        badge_text = "🔴 Offline"
        badge_color = "#f87171"
        badge_bg = "rgba(239, 68, 68, 0.18)"
        badge_border = "rgba(239, 68, 68, 0.45)"

    safe_badge = html.escape(badge_text)
    safe_provider = html.escape(active_provider.upper())
    safe_model = html.escape(model)
    detail_text = detail or (str(error) if error else "")
    if using_dummy_key:
        dummy_note = "⚠️ API Key đang là giá trị mẫu/placeholder."
        detail_text = f"{detail_text} • {dummy_note}".strip(" •")
    safe_detail = html.escape(detail_text)

    badge_html = (
        f'<div data-testid="{html.escape(str(key_prefix))}_health_badge" '
        f'style="display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap;">'
        f'<span style="background: {badge_bg}; color: {badge_color}; border: 1px solid {badge_border}; '
        f'font-size: 0.72rem; font-weight: 700; padding: 2px 8px; border-radius: 999px;">'
        f'{safe_badge}</span>'
        f'</div>'
    )

    panel_html = (
        f'<div style="background: #0f172a; border: 1px solid #334155; border-radius: 10px; '
        f'padding: 10px 14px; margin-bottom: 10px;">'
        f'<div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap;">'
        f'<span style="font-weight: 700; color: #38bdf8; font-size: 0.82rem; text-transform: uppercase;">Trạng thái LLM Gateway</span>'
        f'{badge_html}'
        f'</div>'
        f'<div style="margin-top: 6px; font-size: 0.78rem; color: #cbd5e1; line-height: 1.5;">'
        f'• <strong>Provider:</strong> <code style="color: #38bdf8;">{safe_provider}</code> '
        f'• <strong>Model:</strong> <code style="color: #38bdf8;">{safe_model}</code>'
        + (f'<br/><span style="color: #94a3b8;">{safe_detail}</span>' if safe_detail else "")
        + f'</div></div>'
    )

    try:
        st.markdown(panel_html, unsafe_allow_html=True)
    except Exception:
        pass

    return {
        "status": state_key,
        "badge": badge_text,
        "connected": connected,
        "active_provider": active_provider,
        "configured_mode": configured_mode,
        "model": model,
        "endpoint": endpoint,
        "latency_ms": latency_ms,
        "using_dummy_key": using_dummy_key,
        "detail": detail,
        "error": error,
        "badge_html": badge_html,
    }


def format_llm_telemetry_data(state: Optional[IncidentState]) -> List[Dict[str, Any]]:
    """
    Định dạng danh sách `state.llm_telemetry` thành bảng dữ liệu chuẩn cho `st.dataframe`.
    Hỗ trợ an toàn cả `LLMCallTelemetry` Pydantic object và dict.
    """
    if state is None:
        return []
    records = getattr(state, "llm_telemetry", None) or []
    rows: List[Dict[str, Any]] = []
    for item in records:
        agent = str(_telemetry_attr(item, "agent_name", None) or _telemetry_attr(item, "agent", "Unknown") or "Unknown")
        node = str(_telemetry_attr(item, "node", None) or "—")
        provider = str(_telemetry_attr(item, "provider_used", None) or _telemetry_attr(item, "provider", "deterministic") or "deterministic")
        model = str(_telemetry_attr(item, "model", None) or "N/A")
        latency_ms = round(float(_telemetry_attr(item, "latency_ms", 0.0) or 0.0), 2)
        p_tok = int(_telemetry_attr(item, "prompt_tokens", 0) or 0)
        c_tok = int(_telemetry_attr(item, "completion_tokens", 0) or 0)
        tot_tok = int(_telemetry_attr(item, "total_tokens", 0) or (p_tok + c_tok))
        attempts = int(_telemetry_attr(item, "structured_attempts", 1) or 1)
        self_corrected = bool(_telemetry_attr(item, "self_corrected", False) or attempts > 1)
        fallback_reason = _telemetry_attr(item, "fallback_reason", None)

        rows.append(
            {
                "Agent": agent,
                "Node": node,
                "Provider": provider,
                "Model": model,
                "Latency (ms)": latency_ms,
                "Prompt/Completion Tokens": f"{p_tok} / {c_tok} ({tot_tok})",
                "Self-Corrected": "✅ Có" if self_corrected else "Không",
                "Fallback Reason": str(fallback_reason) if fallback_reason else "—",
            }
        )
    return rows


def render_llm_telemetry_panel(state: Optional[IncidentState]) -> Dict[str, Any]:
    """
    Hiển thị bảng tổng hợp hiệu năng điều phối StateGraph và Telemetry LLM
    (Engine, Tổng Tokens, Số lượt gọi Live/Fallback/Tiered, Thời gian điều tra và DataFrame chi tiết).
    """
    exec_metrics = (getattr(state, "execution_metrics", None) or {}) if state is not None else {}
    llm_metrics = (getattr(state, "llm_metrics", None) or {}) if state is not None else {}
    wf_telemetry = (getattr(state, "workflow_telemetry", None) or {}) if state is not None else {}
    telemetry_items = (getattr(state, "llm_telemetry", None) or []) if state is not None else []

    raw_engine_mode = str(
        exec_metrics.get("engine_mode")
        or wf_telemetry.get("engine_mode")
        or "standby"
    )
    mode_lower = raw_engine_mode.lower()
    if "langgraph" in mode_lower:
        engine_label = "LangGraph"
    elif "fallback" in mode_lower:
        engine_label = "Fallback Loop"
    else:
        engine_label = raw_engine_mode

    if telemetry_items:
        total_prompt = 0
        total_completion = 0
        total_tokens = 0
        live_calls = 0
        fallback_calls = 0
        tiered_saved = 0
        real_calls = 0
        sum_llm_ms = 0.0

        for item in telemetry_items:
            prov = str(_telemetry_attr(item, "provider_used", None) or _telemetry_attr(item, "provider", "deterministic") or "deterministic").lower()
            success = bool(_telemetry_attr(item, "success", True))
            fb_reason = _telemetry_attr(item, "fallback_reason", None)
            p_tok = int(_telemetry_attr(item, "prompt_tokens", 0) or 0)
            c_tok = int(_telemetry_attr(item, "completion_tokens", 0) or 0)
            tot_tok = int(_telemetry_attr(item, "total_tokens", 0) or 0)
            if tot_tok == 0 and (p_tok > 0 or c_tok > 0):
                tot_tok = p_tok + c_tok
            lat = float(_telemetry_attr(item, "latency_ms", 0.0) or 0.0)

            total_prompt += p_tok
            total_completion += c_tok
            total_tokens += tot_tok
            sum_llm_ms += lat

            if prov == "skipped_tiered":
                tiered_saved += 1
            else:
                real_calls += 1
                if prov not in {"deterministic", "skipped_tiered"} and success:
                    live_calls += 1
                if fb_reason is not None or prov == "deterministic":
                    fallback_calls += 1
    else:
        total_prompt = int(exec_metrics.get("total_prompt_tokens", llm_metrics.get("total_prompt_tokens", 0)) or 0)
        total_completion = int(exec_metrics.get("total_completion_tokens", llm_metrics.get("total_completion_tokens", 0)) or 0)
        total_tokens = int(exec_metrics.get("total_tokens", llm_metrics.get("total_tokens", 0)) or 0)
        real_calls = int(exec_metrics.get("llm_calls_count", llm_metrics.get("llm_calls_count", 0)) or 0)
        live_calls = int(exec_metrics.get("live_llm_calls_count", llm_metrics.get("live_llm_calls_count", 0)) or 0)
        fallback_calls = int(exec_metrics.get("fallback_calls_count", llm_metrics.get("fallback_calls_count", 0)) or 0)
        tiered_saved = int(exec_metrics.get("tiered_saved_calls_count", llm_metrics.get("tiered_saved_calls_count", 0)) or 0)
        sum_llm_ms = float(exec_metrics.get("total_llm_latency_ms", llm_metrics.get("total_llm_latency_ms", 0.0)) or 0.0)

    node_latencies = exec_metrics.get("node_latencies_ms") or wf_telemetry.get("node_latencies_ms") or {}
    total_investigation_ms = exec_metrics.get("total_pipeline_latency_ms") or wf_telemetry.get("total_pipeline_latency_ms")
    if total_investigation_ms is None:
        if isinstance(node_latencies, dict) and node_latencies:
            total_investigation_ms = sum(float(v or 0.0) for v in node_latencies.values())
        else:
            total_investigation_ms = sum_llm_ms
    total_investigation_ms = round(float(total_investigation_ms or 0.0), 2)

    rows = format_llm_telemetry_data(state)
    calls_breakdown = f"{live_calls} / {fallback_calls} / {tiered_saved}"

    try:
        st.subheader("📊 Giám sát Telemetry LLM & Hiệu năng StateGraph")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Orchestrator Engine", engine_label)
        with col2:
            st.metric(
                "Tổng LLM Tokens",
                f"{total_tokens:,}",
                delta=f"P: {total_prompt:,} / C: {total_completion:,}" if total_tokens > 0 else None,
                delta_color="off",
            )
        with col3:
            st.metric(
                "Lượt gọi AI (Live / Fallback / Tiết kiệm Tiered)",
                calls_breakdown,
                delta=f"Tổng thực thi: {real_calls} lượt",
                delta_color="off",
            )
        with col4:
            st.metric("Tổng thời gian điều tra (ms)", f"{total_investigation_ms:.1f} ms")

        if rows:
            st.dataframe(rows, use_container_width=True)
        else:
            st.info("Chưa ghi nhận bản ghi LLM Telemetry chi tiết nào trong phiên điều tra hiện tại.")
    except Exception:
        pass

    return {
        "engine_mode": engine_label,
        "raw_engine_mode": raw_engine_mode,
        "total_tokens": total_tokens,
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "llm_calls_count": real_calls,
        "live_llm_calls_count": live_calls,
        "fallback_calls_count": fallback_calls,
        "tiered_saved_calls_count": tiered_saved,
        "total_investigation_ms": total_investigation_ms,
        "calls_breakdown": calls_breakdown,
        "rows": rows,
    }


# =====================================================================
# 9. HITECH 4-LANES ARCHITECTURE WORKFLOW DIAGRAM
# =====================================================================
from src.ui.workflow_diagram import (
    get_hitech_workflow_html,
    render_hitech_agent_workflow,
    get_parallel_agent_workflow_html,
    render_parallel_agent_workflow,
)

