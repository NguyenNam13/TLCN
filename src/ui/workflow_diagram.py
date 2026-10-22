# -*- coding: utf-8 -*-
"""
src/ui/workflow_diagram.py
Trực quan hóa Sơ đồ Kiến trúc Hitech 4-Lanes (Signal Flow & Interactive Node Inspector)
cho hệ thống SOC Multi-Agent trên Streamlit Dashboard.
Đề tài Khóa luận Tốt nghiệp TLCN-NAM.
"""

from typing import Optional, Dict, Any
from pathlib import Path
import html
import json
import streamlit as st
import streamlit.components.v1 as components

from src.core.state import IncidentState
from src.core.schemas import IncidentStatus
from src.ui.components import get_graph_node_statuses


def get_hitech_workflow_html(state: Optional[IncidentState] = None) -> str:
    """
    Sinh mã nguồn HTML của Sơ đồ Logic Luồng Hoạt động (Archify Workflow Engine).
    Được biên dịch từ Archify Workflow Spec chuẩn hóa 4 Swimlanes x 5 Stages,
    tích hợp signal animation, mini-map, inspect drawer, trace flow và phân vùng chuẩn NIST SP 800-61.

    :param state: IncidentState hiện tại (hoặc None nếu ở chế độ demo/standby).
    :return: Chuỗi mã HTML/CSS/JS độc lập của Archify Diagram.
    """
    archify_path = Path(__file__).parent / "assets" / "soc_workflow_archify.html"
    if archify_path.exists():
        content = archify_path.read_text(encoding="utf-8")
        incident_id = state.incident_id if state and state.incident_id else "INC-STANDBY-2026"
        return content.replace(
            "<title>Quy trình Điều phối SOC Multi-Agent",
            f"<title>Quy trình Điều phối SOC Multi-Agent [{incident_id}]",
        )
    return "<div>Sơ đồ Archify Workflow không khả dụng</div>"


def render_hitech_agent_workflow(state: Optional[IncidentState] = None, height: int = 740):
    """
    Hiển thị Sơ đồ Kiến trúc Hitech 4-Lanes lên Streamlit Dashboard.
    Sử dụng streamlit.components.v1.html với sandbox an toàn, mượt mà và không giật lag.

    :param state: IncidentState hiện tại cần trực quan hóa.
    :param height: Chiều cao iframe tính bằng pixel (mặc định 740px).
    """
    html_code = get_hitech_workflow_html(state)
    components.html(html_code, height=height, scrolling=True)


def get_parallel_agent_workflow_html(state: Optional[IncidentState] = None) -> str:
    """
    Sinh mã HTML/CSS/SVG độc lập của Sơ đồ Điều phối SOC Multi-Agent Chạy Song Song (Parallel DAG).
    Thiết kế tinh gọn theo mẫu Card Hitech (dark pill 16px, icon bo tròn, chữ to rõ nét, phát quang neon),
    loại bỏ toàn bộ thông tin thừa xung quanh và thể hiện trực quan quá trình xử lý đi được đến đâu
    (Completed = Xanh lá rực rỡ, Active = Hổ phách/Neon nhấp nháy, Pending = Xám mờ tối giản, Skipped = Nét đứt).

    :param state: IncidentState hiện tại (hoặc None nếu ở chế độ demo/standby).
    :return: Chuỗi mã HTML/CSS an toàn nhúng vào Streamlit iframe.
    """
    node_status_map: Dict[str, str] = {}
    if state is not None:
        statuses = get_graph_node_statuses(state)
        for s in statuses:
            node_status_map[s["id"]] = s["status"]

    def get_st(nid: str) -> str:
        return node_status_map.get(nid, "PENDING")

    is_fp_closed = (state is not None and getattr(state, "status", None) == IncidentStatus.CLOSED_FALSE_POSITIVE)
    is_resolved = (state is not None and getattr(state, "status", None) in [IncidentStatus.RESOLVED, IncidentStatus.CONTAINED])

    # Trạng thái từng node
    st_start = "COMPLETED" if state else "PENDING"
    st_ingestion = get_st("ingestion")
    st_triage = get_st("triage")
    st_enrichment = get_st("enrichment")
    st_rca = get_st("rca")
    st_response = get_st("response")
    st_hitl = get_st("hitl_approval")
    st_reporting = get_st("reporting")
    st_resolved = "COMPLETED" if is_resolved else "PENDING"
    st_fp = "COMPLETED" if is_fp_closed else "SKIPPED"

    def cls(st_val: str) -> str:
        mapping = {
            "COMPLETED": "state-completed",
            "ACTIVE": "state-active",
            "PENDING": "state-pending",
            "SKIPPED": "state-skipped"
        }
        return mapping.get(st_val, "state-pending")

    def badge(st_val: str) -> str:
        if st_val == "COMPLETED":
            return '<span class="badge-status badge-completed font-mono">✓ OK</span>'
        elif st_val == "ACTIVE":
            return '<span class="badge-status badge-active font-mono"><span class="dot-pulse"></span> RUNNING</span>'
        elif st_val == "SKIPPED":
            return '<span class="badge-status badge-skipped font-mono">SKIPPED</span>'
        else:
            return '<span class="badge-status badge-pending font-mono">PENDING</span>'

    def edge_attr(src_st: str, active_color: str, active_marker: str) -> str:
        if src_st in ["COMPLETED", "ACTIVE"]:
            return f'stroke="{active_color}" stroke-width="2.5" marker-end="url(#{active_marker})"'
        elif src_st == "SKIPPED":
            return 'stroke="#475569" stroke-width="1.8" stroke-dasharray="6 6" marker-end="url(#arrow-gray)"'
        else:
            return 'stroke="#334155" stroke-width="1.8" stroke-dasharray="4 4" marker-end="url(#arrow-gray)"'

    # SVG Connectors styling
    edge_start_ing = edge_attr(st_start, "#10b981", "arrow-green")
    edge_ing_tri = edge_attr(st_ingestion, "#10b981", "arrow-green")
    edge_tri_ti = edge_attr(st_triage, "#a855f7", "arrow-purple")
    edge_tri_rca = edge_attr(st_triage, "#ec4899", "arrow-pink")
    edge_ti_resp = edge_attr(st_enrichment, "#a855f7", "arrow-purple")
    edge_rca_resp = edge_attr(st_rca, "#ec4899", "arrow-pink")
    edge_resp_hitl = edge_attr(st_response, "#3b82f6", "arrow-blue")
    edge_hitl_rep = edge_attr(st_hitl, "#10b981", "arrow-green")
    edge_rep_res = edge_attr(st_reporting, "#10b981", "arrow-green")

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<title>Sơ Đồ SOC Multi-Agent Chạy Song Song</title>
<style>
    * {{
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        user-select: none;
    }}
    body {{
        background-color: transparent;
        color: #f8fafc;
        overflow: hidden;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
    }}
    .font-mono {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }}
    
    /* 1. KHUNG CANVAS TINH GỌN (CHỈ CÓ SƠ ĐỒ TIẾN TRÌNH) */
    .workflow-canvas {{
        width: 1410px;
        height: 520px;
        position: relative;
        background: #090d16;
        background-image: 
            radial-gradient(rgba(56, 189, 248, 0.08) 1.5px, transparent 1.5px),
            linear-gradient(to right, rgba(255, 255, 255, 0.015) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
        background-size: 26px 26px, 130px 130px, 130px 130px;
        border: 1px solid #1e293b;
        border-radius: 18px;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(56, 189, 248, 0.03);
    }}

    /* 2. CỤM CHẠY SONG SONG THREAT INTEL & RCA */
    .parallel-frame {{
        position: absolute;
        left: 1055px;
        top: 12px;
        width: 330px;
        height: 220px;
        border: 1.5px dashed rgba(168, 85, 247, 0.5);
        background: rgba(168, 85, 247, 0.03);
        border-radius: 20px;
        padding: 8px 14px;
        z-index: 1;
        box-shadow: 0 0 20px rgba(168, 85, 247, 0.05);
    }}
    .frame-title {{
        font-size: 10.5px;
        font-weight: 800;
        color: #c084fc;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        display: flex;
        align-items: center;
        gap: 6px;
    }}

    /* 3. Ô CARD HITECH (THEO ĐÚNG MẪU NGƯỜI DÙNG GỬI) */
    .card-node {{
        position: absolute;
        width: 295px;
        height: 78px;
        background: #111422;
        border-radius: 16px;
        padding: 10px 14px;
        display: flex;
        align-items: center;
        gap: 11px;
        z-index: 2;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }}
    .card-node:hover {{
        transform: translateY(-2px);
    }}
    .icon-container {{
        width: 44px;
        height: 44px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 20px;
        flex-shrink: 0;
    }}
    .node-text {{
        display: flex;
        flex-direction: column;
        justify-content: center;
        overflow: hidden;
        flex: 1;
    }}
    .title-row {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 4px;
    }}
    .title {{
        font-size: 13px;
        font-weight: 700;
        color: #ffffff;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}
    .subtitle {{
        font-size: 10.5px;
        color: #94a3b8;
        margin-top: 2px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }}

    /* 4. CÁC BADGE TRẠNG THÁI TIẾN TRÌNH */
    .badge-status {{
        font-size: 9px;
        font-weight: 800;
        padding: 2px 6px;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        white-space: nowrap;
    }}
    .badge-completed {{
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }}
    .badge-active {{
        background: rgba(251, 191, 36, 0.15);
        color: #fbbf24;
        border: 1px solid rgba(251, 191, 24, 0.4);
        display: flex;
        align-items: center;
        gap: 4px;
    }}
    .badge-pending {{
        background: rgba(51, 65, 85, 0.3);
        color: #64748b;
        border: 1px solid #334155;
    }}
    .badge-skipped {{
        background: rgba(30, 41, 59, 0.3);
        color: #64748b;
        border: 1px dashed #475569;
    }}
    .dot-pulse {{
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: #fbbf24;
        box-shadow: 0 0 6px #fbbf24;
        animation: dot-anim 1.2s infinite;
    }}
    @keyframes dot-anim {{
        0% {{ opacity: 0.4; }}
        50% {{ opacity: 1; }}
        100% {{ opacity: 0.4; }}
    }}

    /* 5. STYLE VIỀN THEO TIẾN TRÌNH THỰC TẾ */
    /* 5.1 COMPLETED: Viền xanh lá rực rỡ */
    .state-completed {{
        border: 1.5px solid #10b981;
        box-shadow: 0 0 16px rgba(16, 185, 129, 0.35), 0 6px 18px rgba(0, 0, 0, 0.6);
    }}
    .state-completed .icon-container {{
        background: rgba(16, 185, 129, 0.18);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #34d399;
    }}

    /* 5.2 ACTIVE: Viền phát quang nhấp nháy */
    .state-active {{
        border: 1.5px solid #fbbf24;
        animation: active-glow-anim 1.8s infinite alternate;
    }}
    .state-active .icon-container {{
        background: rgba(251, 191, 36, 0.2);
        border: 1px solid rgba(251, 191, 36, 0.5);
        color: #fbbf24;
    }}
    @keyframes active-glow-anim {{
        0% {{
            box-shadow: 0 0 8px rgba(251, 191, 36, 0.4), 0 0 0 0 rgba(251, 191, 36, 0.3);
            border-color: #fbbf24;
        }}
        100% {{
            box-shadow: 0 0 24px rgba(251, 191, 36, 0.8), 0 0 12px 2px rgba(251, 191, 36, 0.5);
            border-color: #fde68a;
        }}
    }}

    /* 5.3 PENDING: Viền mờ tối giản */
    .state-pending {{
        border: 1px solid #27354a;
        background: rgba(13, 17, 30, 0.7);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }}
    .state-pending .icon-container {{
        background: rgba(30, 41, 59, 0.4);
        border: 1px solid #1e293b;
        color: #64748b;
    }}
    .state-pending .title {{
        color: #94a3b8;
    }}
    .state-pending .subtitle {{
        color: #475569;
    }}

    /* 5.4 SKIPPED: Viền nét đứt mờ */
    .state-skipped {{
        border: 1.5px dashed #475569;
        background: rgba(15, 23, 42, 0.35);
        opacity: 0.4;
        box-shadow: none;
    }}
    .state-skipped .icon-container {{
        background: rgba(30, 41, 59, 0.2);
        border: 1px dashed #475569;
        color: #64748b;
    }}
    .state-skipped .title {{
        color: #64748b;
    }}
    .state-skipped .subtitle {{
        color: #475569;
    }}

    /* CỔNG KẾT NỐI (PORTS) */
    .port {{
        position: absolute;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        border: 2px solid #090d16;
        top: 50%;
        transform: translateY(-50%);
    }}
    .port-in-left {{ left: -5px; background: #38bdf8; }}
    .port-out-right {{ right: -5px; background: #a855f7; }}
    .port-in-right {{ right: -5px; background: #38bdf8; }}
    .port-out-left {{ left: -5px; background: #a855f7; }}

    /* SVG LINES */
    .svg-layer {{
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1;
        pointer-events: none;
    }}
    .edge-badge {{
        position: absolute;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 10px;
        font-weight: 800;
        transform: translate(-50%, -50%);
        z-index: 3;
        white-space: nowrap;
        background: #0f172a;
        box-shadow: 0 4px 10px rgba(0,0,0,0.6);
    }}
</style>
</head>
<body>

<div class="workflow-canvas">
    <!-- KHUNG SONG SONG -->
    <div class="parallel-frame">
        <div class="frame-title font-mono">⚡ PARALLEL AGENTS (Song song)</div>
    </div>

    <!-- SVG KẾT NỐI CÁC NODE -->
    <svg class="svg-layer" viewBox="0 0 1410 520">
        <defs>
            <marker id="arrow-green" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 8 5 L 0 9 z" fill="#10b981" />
            </marker>
            <marker id="arrow-cyan" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 8 5 L 0 9 z" fill="#38bdf8" />
            </marker>
            <marker id="arrow-purple" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 8 5 L 0 9 z" fill="#a855f7" />
            </marker>
            <marker id="arrow-pink" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 8 5 L 0 9 z" fill="#ec4899" />
            </marker>
            <marker id="arrow-blue" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 8 5 L 0 9 z" fill="#3b82f6" />
            </marker>
            <marker id="arrow-gray" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 8 5 L 0 9 z" fill="#475569" />
            </marker>
        </defs>

        <!-- 1. Start -> Ingestion -->
        <path d="M 320 89 L 370 89" {edge_start_ing} fill="none" />
        
        <!-- 2. Ingestion -> Triage -->
        <path d="M 665 89 L 715 89" {edge_ing_tri} fill="none" />
        
        <!-- 3. Triage -> Threat Intel (Upper branch) -->
        <path d="M 1010 89 C 1045 89, 1045 62, 1072 62" {edge_tri_ti} fill="none" />
        
        <!-- 4. Triage -> RCA (Lower branch) -->
        <path d="M 1010 89 C 1045 89, 1045 162, 1072 162" {edge_tri_rca} fill="none" />
        
        <!-- 5. Triage -> False Positive (Dashed line down to closed_fp) -->
        <path d="M 862 128 L 862 390" stroke="#475569" stroke-width="1.8" stroke-dasharray="6 6" fill="none" marker-end="url(#arrow-gray)" />
        
        <!-- 6. Threat Intel -> Response (Converge) -->
        <path d="M 1367 62 C 1405 62, 1405 312, 1367 312" {edge_ti_resp} fill="none" />
        
        <!-- 7. RCA -> Response (Converge) -->
        <path d="M 1367 162 C 1390 162, 1390 326, 1367 326" {edge_rca_resp} fill="none" />
        
        <!-- 8. Response -> HITL Approval -->
        <path d="M 1072 319 L 1010 319" {edge_resp_hitl} fill="none" />
        
        <!-- 9. HITL Approval -> Reporting -->
        <path d="M 715 319 L 665 319" {edge_hitl_rep} fill="none" />
        
        <!-- 10. Reporting -> Resolved -->
        <path d="M 370 319 L 320 319" {edge_rep_res} fill="none" />
        
        <!-- 11. False Positive -> Resolved (Dashed return) -->
        <path d="M 715 429 C 450 429, 172 400, 172 358" stroke="#475569" stroke-width="1.8" stroke-dasharray="6 6" fill="none" marker-end="url(#arrow-gray)" />
    </svg>

    <!-- NHÃN RẼ NHÁNH -->
    <div class="edge-badge font-mono" style="left: 1040px; top: 110px; color: #38bdf8; border: 1px solid #0284c7;">⚡ True Positive</div>
    <div class="edge-badge font-mono" style="left: 862px; top: 250px; color: #64748b; border: 1px dashed #475569;">False Positive</div>
    <div class="edge-badge font-mono" style="left: 690px; top: 295px; color: #34d399; border: 1px solid #059669; font-size: 9px; padding: 1px 5px;">Duyệt ✓</div>

    <!-- CÁC THẺ CARD -->
    <!-- 0. START -->
    <div class="card-node {cls(st_start)}" style="left: 25px; top: 50px;">
        <div class="icon-container">📡</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">Bắt đầu: Wazuh Logs</span>
                {badge(st_start)}
            </div>
            <div class="subtitle">Wazuh OVA Webhook :8000</div>
        </div>
        <div class="port port-out-right"></div>
    </div>

    <!-- 1. INGESTION -->
    <div class="card-node {cls(st_ingestion)}" style="left: 370px; top: 50px;">
        <div class="port port-in-left"></div>
        <div class="icon-container">📥</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">1. Ingestion Agent</span>
                {badge(st_ingestion)}
            </div>
            <div class="subtitle">Deobfuscator & Normalize</div>
        </div>
        <div class="port port-out-right"></div>
    </div>

    <!-- 2. TRIAGE -->
    <div class="card-node {cls(st_triage)}" style="left: 715px; top: 50px;">
        <div class="port port-in-left"></div>
        <div class="icon-container">⚖️</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">2. Triage Agent</span>
                {badge(st_triage)}
            </div>
            <div class="subtitle">Parallel 3-Model Ensemble</div>
        </div>
        <div class="port port-out-right"></div>
    </div>

    <!-- 3. THREAT INTEL CTI -->
    <div class="card-node {cls(st_enrichment)}" style="left: 1072px; top: 23px;">
        <div class="port port-in-left"></div>
        <div class="icon-container">🌐</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">3. Threat Intel CTI</span>
                {badge(st_enrichment)}
            </div>
            <div class="subtitle">VirusTotal + AbuseIPDB RAG</div>
        </div>
        <div class="port port-out-right"></div>
    </div>

    <!-- 4. ROOT CAUSE ANALYSIS -->
    <div class="card-node {cls(st_rca)}" style="left: 1072px; top: 123px;">
        <div class="port port-in-left"></div>
        <div class="icon-container">🔬</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">4. Root Cause Analysis</span>
                {badge(st_rca)}
            </div>
            <div class="subtitle">Process Tree & Patient Zero</div>
        </div>
        <div class="port port-out-right"></div>
    </div>

    <!-- 5. RESPONSE AGENT -->
    <div class="card-node {cls(st_response)}" style="left: 1072px; top: 280px;">
        <div class="port port-out-left"></div>
        <div class="icon-container">🛡️</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">5. Response Agent</span>
                {badge(st_response)}
            </div>
            <div class="subtitle">NIST SP 800-61 Playbook</div>
        </div>
        <div class="port port-in-right"></div>
    </div>

    <!-- 6. HITL APPROVAL -->
    <div class="card-node {cls(st_hitl)}" style="left: 715px; top: 280px;">
        <div class="port port-in-right"></div>
        <div class="icon-container">🛑</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">6. HITL Approval Gate</span>
                {badge(st_hitl)}
            </div>
            <div class="subtitle">Chuyên viên Thẩm định</div>
        </div>
        <div class="port port-out-left"></div>
    </div>

    <!-- 7. REPORTING AGENT -->
    <div class="card-node {cls(st_reporting)}" style="left: 370px; top: 280px;">
        <div class="port port-in-right"></div>
        <div class="icon-container">📝</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">7. Reporting Agent</span>
                {badge(st_reporting)}
            </div>
            <div class="subtitle">Báo cáo NIST .docx / MD</div>
        </div>
        <div class="port port-out-left"></div>
    </div>

    <!-- 8. RESOLVED -->
    <div class="card-node {cls(st_resolved)}" style="left: 25px; top: 280px;">
        <div class="port port-in-right"></div>
        <div class="icon-container">🏁</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">Hoàn tất: RESOLVED</span>
                {badge(st_resolved)}
            </div>
            <div class="subtitle">Đã ngăn chặn & Lưu vết</div>
        </div>
    </div>

    <!-- 9. FALSE POSITIVE -->
    <div class="card-node {cls(st_fp)}" style="left: 715px; top: 390px;">
        <div class="port port-in-right"></div>
        <div class="icon-container">📁</div>
        <div class="node-text font-mono">
            <div class="title-row">
                <span class="title">Đóng: False Positive</span>
                {badge(st_fp)}
            </div>
            <div class="subtitle">Lưu vết Audit Log & Đóng</div>
        </div>
    </div>
</div>

</body>
</html>"""


def render_parallel_agent_workflow(state: Optional[IncidentState] = None, height: int = 560):
    """
    Hiển thị Sơ đồ Điều phối SOC Multi-Agent Chạy Song Song lên Streamlit Dashboard.
    Sử dụng streamlit.components.v1.html với sandbox an toàn, mượt mà và không giật lag.

    :param state: IncidentState hiện tại cần trực quan hóa.
    :param height: Chiều cao iframe tính bằng pixel (mặc định 560px vừa khít canvas).
    """
    html_code = get_parallel_agent_workflow_html(state)
    components.html(html_code, height=height, scrolling=True)
