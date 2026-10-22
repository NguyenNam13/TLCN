# -*- coding: utf-8 -*-
"""
src/ui/__init__.py
Gói giao diện người dùng Streamlit Dashboard Prototype v1.0.
Đề tài Khóa luận Tốt nghiệp TLCN-NAM.
"""

from src.ui.components import (
    render_kpi_cards,
    get_kpi_metrics,
    render_agent_graph_status,
    generate_mermaid_graph,
    get_graph_node_statuses,
    render_ioc_table,
    format_ioc_table_data,
    render_mitre_matrix,
    extract_mitre_data,
    render_process_tree,
    format_process_tree_data,
    format_timeline_data,
    render_hitl_action_cards,
    apply_hitl_action_decision,
    render_hitech_agent_workflow,
    get_hitech_workflow_html,
    render_parallel_agent_workflow,
    get_parallel_agent_workflow_html,
)

__all__ = [
    "render_kpi_cards",
    "get_kpi_metrics",
    "render_agent_graph_status",
    "generate_mermaid_graph",
    "get_graph_node_statuses",
    "render_ioc_table",
    "format_ioc_table_data",
    "render_mitre_matrix",
    "extract_mitre_data",
    "render_process_tree",
    "format_process_tree_data",
    "format_timeline_data",
    "render_hitl_action_cards",
    "apply_hitl_action_decision",
    "render_hitech_agent_workflow",
    "get_hitech_workflow_html",
    "render_parallel_agent_workflow",
    "get_parallel_agent_workflow_html",
]
