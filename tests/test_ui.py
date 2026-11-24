# -*- coding: utf-8 -*-
"""
tests/test_ui.py
Kiểm thử Unit Tests độc lập cho các thành phần Streamlit Dashboard UI và UI Components (Tuần 10).
Đảm bảo 100% logic trích xuất dữ liệu KPI, biểu đồ Mermaid, bảng IoC, ma trận MITRE,
cây tiến trình Sysmon, duyệt/từ chối/chỉnh sửa HITL và xuất báo cáo (MD, JSON, DOCX) hoạt động chuẩn xác.
"""

import os
import tempfile
import shutil
import inspect
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import json
from src.core.incident_store import IncidentStore

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    IoCItem,
    ThreatIntelEnrichment,
    ProcessNode,
    RootCauseAnalysis,
    RecommendedAction,
    IncidentReport,
    LLMHealthStatus,
    LLMCallTelemetry,
)
from src.core.state import IncidentState
from src.core.orchestrator import StateGraphOrchestrator
from src.ui.components import (
    get_kpi_metrics,
    generate_mermaid_graph,
    get_graph_node_statuses,
    format_ioc_table_data,
    extract_mitre_data,
    format_process_tree_data,
    format_timeline_data,
    apply_hitl_action_decision,
    get_hitech_workflow_html,
    render_hitech_agent_workflow,
    render_llm_health_badge,
    format_llm_telemetry_data,
    render_llm_telemetry_panel,
    render_response_strategy_callout,
    render_hitl_action_cards,
)
from src.ui.dashboard import (
    SCENARIO_CATALOG,
    load_scenario_alerts,
    create_initial_incident_state,
    generate_markdown_report,
    generate_json_report,
    generate_docx_report,
    run_dashboard_headless_check,
    _call_execute_until_interrupt,
    _call_resume_from_interrupt,
    _refresh_llm_health_status,
)


class TestDashboardUI(unittest.TestCase):
    """Bộ kiểm thử cho Giao diện và Thành phần UI Prototype v1.0."""

    def setUp(self):
        """Khởi tạo IncidentState giả lập đầy đủ dữ liệu phục vụ kiểm thử."""
        self.state = IncidentState(
            incident_id="INC-UI-TEST-001",
            status=IncidentStatus.INVESTIGATING,
            raw_logs=[
                RawLogInput(log_source="wazuh", raw_payload='{"test": true}')
            ],
            parsed_events=[
                ParsedEvent(
                    event_id="EVT-001",
                    timestamp=datetime.now(timezone.utc),
                    source_type="sysmon",
                    process_name="powershell.exe",
                    command_line="powershell.exe -enc AAAAA==",
                    source_ip="192.168.1.100",
                    dest_ip="194.26.29.112",
                    host_name="WORKSTATION-01",
                    file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
            ],
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.96,
                severity=SeverityLevel.HIGH,
                summary="Phát hiện thực thi mã độc PowerShell kết nối C2 IP 194.26.29.112",
                rule_or_model="TriageAgent-Model-Ensemble",
            ),
            threat_intel=ThreatIntelEnrichment(
                extracted_iocs=[
                    IoCItem(
                        ioc_type="IPv4",
                        value="194.26.29.112",
                        reputation_score=92,
                        is_malicious=True,
                        threat_actor="Emotet / C2 Infrastructure",
                    ),
                    IoCItem(
                        ioc_type="SHA256",
                        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        reputation_score=15,
                        is_malicious=False,
                    ),
                ],
                related_threat_actors=["Emotet", "TA505"],
                mitre_techniques=["T1059.001", "T1071.001"],
                enrichment_summary="IoC nguy hiểm được ghi nhận trên VirusTotal và AbuseIPDB.",
            ),
            rca_result=RootCauseAnalysis(
                initial_access_vector="Spearphishing Attachment",
                attack_timeline=[
                    "[10:00:01] Người dùng mở tài liệu đính kèm hóa đơn độc hại",
                    "[10:00:05] Word kích hoạt PowerShell thực thi mã tải beacon",
                ],
                process_tree=[
                    ProcessNode(
                        process_id="PID-1001",
                        process_name="WINWORD.EXE",
                        command_line="winword.exe invoice.docx",
                        parent_id=None,
                        is_malicious_origin=True,
                    ),
                    ProcessNode(
                        process_id="PID-1002",
                        process_name="powershell.exe",
                        command_line="powershell.exe -enc AAAAA==",
                        parent_id="PID-1001",
                        is_malicious_origin=True,
                    ),
                ],
                mitre_tactics=["Initial Access", "Execution", "Command and Control"],
                root_cause_summary="Tấn công bắt nguồn từ Spearphishing Word Macro kích hoạt PowerShell.",
            ),
            recommended_actions=[
                RecommendedAction(
                    action_id="ACT-001",
                    action_type=ActionType.ISOLATE_HOST,
                    target="WORKSTATION-01",
                    description="Cô lập máy trạm khỏi mạng nội bộ để ngăn chặn lây lan",
                    priority=1,
                    require_human_approval=True,
                    is_approved=None,
                    parameters={"agent_id": "001", "mode": "complete"},
                ),
                RecommendedAction(
                    action_id="ACT-002",
                    action_type=ActionType.BLOCK_IP,
                    target="194.26.29.112",
                    description="Chặn IP độc hại trên Firewall / Wazuh Active Response",
                    priority=1,
                    require_human_approval=True,
                    is_approved=None,
                    parameters={"command": "firewall-drop", "timeout": 3600},
                ),
                RecommendedAction(
                    action_id="ACT-003",
                    action_type=ActionType.PATCH_SYSTEM,
                    target="WORKSTATION-01",
                    description="Cập nhật bản vá hệ điều hành",
                    priority=4,
                    require_human_approval=False,
                    is_approved=True,
                ),
            ],
        )

    def test_kpi_metrics_extraction(self):
        """Kiểm thử hàm trích xuất KPI metrics từ state."""
        kpis_empty = get_kpi_metrics(None)
        self.assertEqual(kpis_empty["incident_id"], "N/A")
        self.assertEqual(kpis_empty["total_actions"], 0)

        kpis = get_kpi_metrics(self.state)
        self.assertEqual(kpis["incident_id"], "INC-UI-TEST-001")
        self.assertEqual(kpis["status"], IncidentStatus.INVESTIGATING.value)
        self.assertEqual(kpis["severity"], SeverityLevel.HIGH.value)
        self.assertEqual(kpis["confidence_score"], 0.96)
        self.assertIn("attack_type", kpis)
        self.assertIn("attack_category", kpis)
        self.assertEqual(kpis["raw_logs_count"], 1)
        self.assertEqual(kpis["parsed_events_count"], 1)
        self.assertEqual(kpis["ioc_count"], 2)
        self.assertEqual(kpis["malicious_ioc_count"], 1)
        self.assertEqual(kpis["total_actions"], 3)
        self.assertEqual(kpis["pending_actions"], 2)
        self.assertEqual(kpis["approved_actions"], 1)

    def test_mermaid_graph_generation(self):
        """Kiểm thử sinh đồ thị Mermaid phản ánh trạng thái StateGraph."""
        mermaid = generate_mermaid_graph(self.state)
        self.assertIn("flowchart", mermaid)
        self.assertIn("Ingestion", mermaid)
        self.assertIn("Triage", mermaid)
        self.assertIn("HITL", mermaid)
        self.assertIn("Reporting", mermaid)

        node_statuses = get_graph_node_statuses(self.state)
        self.assertEqual(len(node_statuses), 7)
        node_ids = [n["id"] for n in node_statuses]
        self.assertIn("hitl_approval", node_ids)

    def test_hitech_workflow_html_structure_and_partitions(self):
        """
        Kiểm thử chuỗi HTML sinh bởi get_hitech_workflow_html:
        1. Trả về kiểu chuỗi (str) có dung lượng đầy đủ (> 500 ký tự).
        2. Chứa đầy đủ 4 phân vùng kiến trúc chuẩn SOC Multi-Agent.
        3. Nhúng chính xác state.incident_id của sự cố đang xử lý.
        """
        html_code = get_hitech_workflow_html(self.state)
        self.assertIsInstance(html_code, str)
        self.assertGreater(len(html_code), 500)

        self.assertIn("01 / TELEMETRY", html_code)
        self.assertIn("02 / AGENT RUNTIME", html_code)
        self.assertIn("EX / POLICY", html_code)
        self.assertIn("04 / TOOL EXECUTION", html_code)

        self.assertIn(self.state.incident_id, html_code)
        self.assertIn("Ingestion", html_code)
        self.assertIn("Triage", html_code)
        self.assertIn("Threat Intel", html_code)
        self.assertIn("RCA", html_code)
        self.assertIn("Response", html_code)

    def test_hitech_workflow_html_fallback_none_state(self):
        """Kiểm thử get_hitech_workflow_html hoạt động bền bỉ khi state=None (chế độ chờ)."""
        html_code_none = get_hitech_workflow_html(None)
        self.assertIsInstance(html_code_none, str)
        self.assertIn("01 / TELEMETRY", html_code_none)
        self.assertIn("02 / AGENT RUNTIME", html_code_none)
        self.assertIn("EX / POLICY", html_code_none)
        self.assertIn("04 / TOOL EXECUTION", html_code_none)
        self.assertIn("STANDBY", html_code_none)

    @patch("streamlit.components.v1.html")
    def test_render_hitech_agent_workflow(self, mock_html):
        """Kiểm thử hàm render_hitech_agent_workflow thực thi an toàn trong Streamlit."""
        render_hitech_agent_workflow(self.state)
        self.assertTrue(mock_html.called)

        mock_html.reset_mock()
        render_hitech_agent_workflow(None)
        self.assertTrue(mock_html.called)

    def test_ioc_table_formatting(self):
        """Kiểm thử chuẩn hóa dữ liệu bảng IoC cho giao diện."""
        ioc_rows = format_ioc_table_data(self.state.threat_intel)
        self.assertEqual(len(ioc_rows), 2)
        self.assertEqual(ioc_rows[0]["Giá trị Chỉ số"], "194.26.29.112")
        self.assertEqual(ioc_rows[0]["Loại IoC"], "IPv4")
        self.assertEqual(ioc_rows[0]["Điểm Độc hại"], 92)
        self.assertIn("Độc hại", ioc_rows[0]["Đánh giá"])
        self.assertIn("Emotet", ioc_rows[0]["Nhóm Tấn công"])

        # Test với threat_intel None
        empty_rows = format_ioc_table_data(None)
        self.assertEqual(empty_rows, [])

    def test_mitre_extraction(self):
        """Kiểm thử trích xuất thông tin ma trận MITRE ATT&CK."""
        data = extract_mitre_data(self.state.threat_intel, self.state.rca_result)
        self.assertIn("techniques", data)
        self.assertIn("tactics", data)
        self.assertIn("T1059.001", data["techniques"])
        self.assertIn("Execution", data["tactics"])

    def test_process_tree_formatting(self):
        """Kiểm thử định dạng cây tiến trình Sysmon và dòng thời gian."""
        tree_rows = format_process_tree_data(self.state.rca_result)
        self.assertEqual(len(tree_rows), 2)
        self.assertEqual(tree_rows[0]["pid"], "PID-1001")
        self.assertEqual(tree_rows[0]["name"], "WINWORD.EXE")
        self.assertTrue(tree_rows[0]["is_origin"])

        timeline = format_timeline_data(self.state.rca_result)
        self.assertEqual(len(timeline), 2)
        self.assertIn("Word kích hoạt", timeline[1])

    def test_hitl_action_decision_approval(self):
        """Kiểm thử phê duyệt đơn lẻ hành động qua hàm apply_hitl_action_decision."""
        updated_state = apply_hitl_action_decision(
            state=self.state,
            action_idx=0,
            decision="APPROVE",
        )
        self.assertIsNotNone(updated_state)
        act1 = self.state.recommended_actions[0]
        self.assertTrue(act1.is_approved)

    def test_hitl_action_decision_rejection(self):
        """Kiểm thử từ chối hành động qua hàm apply_hitl_action_decision."""
        updated_state = apply_hitl_action_decision(
            state=self.state,
            action_idx=1,
            decision="REJECT",
        )
        self.assertIsNotNone(updated_state)
        act2 = self.state.recommended_actions[1]
        self.assertFalse(act2.is_approved)

    def test_hitl_action_decision_modify(self):
        """Kiểm thử chỉnh sửa tham số hành động trước khi duyệt."""
        updated_state = apply_hitl_action_decision(
            state=self.state,
            action_idx=1,
            decision="EDIT",
            edited_target="194.26.29.200",
            edited_priority=2,
            edited_description="Chặn IP mở rộng",
        )
        self.assertIsNotNone(updated_state)
        act2 = self.state.recommended_actions[1]
        self.assertEqual(act2.target, "194.26.29.200")
        self.assertEqual(act2.priority, 2)
        self.assertEqual(act2.description, "Chặn IP mở rộng")

    def test_report_generation_formats(self):
        """Kiểm thử sinh báo cáo đa định dạng (Markdown, JSON, DOCX)."""
        report = IncidentReport(
            report_id=f"REP-{self.state.incident_id}",
            incident_title="Báo cáo Thử nghiệm Tích hợp UI",
            executive_summary="Tóm lược điều hành cho kiểm thử UI.",
            detailed_findings="Chi tiết kỹ thuật bóc tách tiến trình.",
            mitre_attack_matrix_mapping=["T1059.001"],
            ioc_table=self.state.threat_intel.extracted_iocs,
            action_plan=self.state.recommended_actions,
        )

        md_rep = generate_markdown_report(report)
        self.assertIn("# Báo cáo Thử nghiệm Tích hợp UI", md_rep)
        self.assertIn("194.26.29.112", md_rep)

        json_rep = generate_json_report(report)
        parsed_json = json.loads(json_rep)
        self.assertEqual(parsed_json["report_id"], f"REP-{self.state.incident_id}")

        docx_bytes = generate_docx_report(report)
        self.assertIsInstance(docx_bytes, bytes)
        self.assertGreater(len(docx_bytes), 1000)

    def test_scenario_catalog_and_loading(self):
        """Kiểm thử nạp các kịch bản mẫu từ SCENARIO_CATALOG."""
        for skey in ["malware", "phishing", "network_scan", "benign"]:
            alerts, title = load_scenario_alerts(skey)
            self.assertIsInstance(alerts, list)
            self.assertGreater(len(alerts), 0)
            self.assertIsInstance(title, str)

        # Test custom JSON
        custom_json = json.dumps([{"rule": {"id": "999", "level": 12}, "full_log": "Custom alert log"}])
        alerts_custom, title_custom = load_scenario_alerts("custom", custom_json_content=custom_json)
        self.assertEqual(len(alerts_custom), 1)
        self.assertIn("Tùy chỉnh", title_custom)

        # Test initial state creation
        init_state = create_initial_incident_state("malware", alerts)
        self.assertEqual(init_state.status, IncidentStatus.NEW)
        self.assertEqual(len(init_state.raw_logs), len(alerts))

    def test_headless_integrity_check(self):
        """Kiểm thử chạy hàm headless check toàn diện."""
        result = run_dashboard_headless_check()
        self.assertTrue(result)


# =====================================================================
# BỔ SUNG: KIỂM THỬ TÍNH NĂNG "LỊCH SỬ & BÁO CÁO" VÀ TÍCH HỢP INCIDENT STORE
# =====================================================================
class TestHistoryAndReportingStore(unittest.TestCase):
    """
    Bộ kiểm thử chuyên sâu cho tính năng Lịch sử & Báo cáo điều tra sự cố:
    1. Kiểm chứng tính nhất quán giữa Navigation Menu và Router điều hướng.
    2. Lưu trữ và nạp danh sách báo cáo lịch sử từ IncidentStore.
    3. Xem lại báo cáo lịch sử và kiểm tra tính toàn vẹn khi xuất Markdown, JSON, DOCX.
    4. Xử lý an toàn khi IncidentStore rỗng hoặc chứa file JSON bị hỏng.
    """

    def setUp(self):
        """Khởi tạo môi trường cô lập trong thư mục tạm thời cho IncidentStore."""
        self.test_dir = tempfile.mkdtemp(prefix="test_soc_incidents_")
        self.store = IncidentStore(storage_dir=self.test_dir)

        # Tạo IncidentState mẫu có final_report hoàn chỉnh
        self.sample_report = IncidentReport(
            report_id="REP-INC-HIST-2026-001",
            incident_title="Báo cáo Điều tra Sự cố [HIGH]: INC-HIST-001",
            executive_summary="Tóm lược sự cố mã độc APT trong lịch sử.",
            detailed_findings="Chi tiết phát hiện tiến trình độc hại từ Word Macro.",
            mitre_attack_matrix_mapping=["T1059.001", "T1071.001"],
            ioc_table=[
                IoCItem(
                    ioc_type="IPv4",
                    value="194.26.29.112",
                    reputation_score=95,
                    is_malicious=True,
                    threat_actor="APT29 / Emotet",
                )
            ],
            action_plan=[
                RecommendedAction(
                    action_id="ACT-001",
                    action_type=ActionType.ISOLATE_HOST,
                    target="WORKSTATION-01",
                    description="Cô lập máy trạm khỏi mạng",
                    priority=1,
                    require_human_approval=True,
                    is_approved=True,
                )
            ],
        )

        self.sample_state = IncidentState(
            incident_id="INC-HIST-001",
            status=IncidentStatus.RESOLVED,
            created_at=datetime(2026, 10, 20, 8, 30, 0, tzinfo=timezone.utc),
            attack_type="Trojan/Malware",
            threat_intel=ThreatIntelEnrichment(extracted_iocs=self.sample_report.ioc_table),
            final_report=self.sample_report,
        )

    def tearDown(self):
        """Dọn dẹp thư mục tạm sau khi kết thúc test case."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_navigation_history_and_report_option_consistency(self):
        """
        [PROVE-IT] Kiểm tra tính nhất quán giữa Sidebar Navigation và Router trong dashboard.py:
        Đảm bảo nhãn '🕒 Lịch sử & Báo cáo' trong danh sách menu khớp chính xác với router,
        tránh lỗi mismatch chuỗi khiến màn hình bị rỗng (Silent Blank Page).
        """
        import src.ui.dashboard as dash_mod

        main_source = inspect.getsource(dash_mod.main)

        expected_nav_label = "🕒 Lịch sử & Báo cáo"
        self.assertIn(
            f'"{expected_nav_label}"',
            main_source,
            f"Menu điều hướng phải chứa tùy chọn '{expected_nav_label}'"
        )

        valid_router_branch = (
            f'selected_nav == "{expected_nav_label}"' in main_source
            or f"selected_nav == '{expected_nav_label}'" in main_source
            or f'selected_nav in ["{expected_nav_label}", "🕒 Lịch sử"]' in main_source
            or f'selected_nav.startswith("🕒 Lịch sử")' in main_source
        )
        self.assertTrue(
            valid_router_branch,
            f"Router điều hướng phải có nhánh xử lý khớp với '{expected_nav_label}'."
        )

    def test_incident_store_save_and_list_historical_reports(self):
        """
        Kiểm tra lưu trữ sự cố có báo cáo và truy xuất danh sách lịch sử từ IncidentStore:
        - Lưu nhiều sự cố với thời gian khác nhau.
        - Nạp danh sách sự cố và kiểm tra thứ tự sắp xếp giảm dần theo thời gian.
        - Xác nhận dữ liệu final_report được bảo toàn 100%.
        """
        self.store.save_incident(self.sample_state)

        state_2 = IncidentState(
            incident_id="INC-HIST-002",
            status=IncidentStatus.CONTAINED,
            created_at=datetime(2026, 10, 21, 9, 0, 0, tzinfo=timezone.utc),
            attack_type="Credential Theft",
            final_report=IncidentReport(
                report_id="REP-INC-HIST-2026-002",
                incident_title="Báo cáo Điều tra Sự cố [CRITICAL]: INC-HIST-002",
                executive_summary="Tấn công dò quét mật khẩu diện rộng.",
                detailed_findings="Brute force tài khoản admin.",
                mitre_attack_matrix_mapping=["T1110"],
            ),
        )
        self.store.save_incident(state_2)

        incidents = self.store.list_incidents()
        self.assertEqual(len(incidents), 2)

        self.assertEqual(incidents[0].incident_id, "INC-HIST-002")
        self.assertEqual(incidents[1].incident_id, "INC-HIST-001")

        inc1_reloaded = incidents[1]
        self.assertIsNotNone(inc1_reloaded.final_report)
        self.assertEqual(inc1_reloaded.final_report.report_id, "REP-INC-HIST-2026-001")
        self.assertEqual(len(inc1_reloaded.final_report.ioc_table), 1)
        self.assertEqual(inc1_reloaded.final_report.ioc_table[0].value, "194.26.29.112")

    def test_review_and_export_historical_reports(self):
        """
        Kiểm tra xem lại báo cáo lịch sử và xuất bản thành công sang 3 định dạng:
        Markdown (.md), JSON (.json), và Word (.docx).
        """
        self.store.save_incident(self.sample_state)
        retrieved_state = self.store.get_incident("INC-HIST-001")
        self.assertIsNotNone(retrieved_state)
        report = retrieved_state.final_report
        self.assertIsNotNone(report)

        # 1. Kiểm tra xuất Markdown từ báo cáo lịch sử
        md_output = generate_markdown_report(report)
        self.assertIsInstance(md_output, str)
        self.assertIn("# Báo cáo Điều tra Sự cố [HIGH]: INC-HIST-001", md_output)
        self.assertIn("194.26.29.112", md_output)
        self.assertIn("Tóm lược sự cố mã độc APT", md_output)

        # 2. Kiểm tra xuất JSON từ báo cáo lịch sử
        json_output = generate_json_report(report)
        self.assertIsInstance(json_output, str)
        parsed = json.loads(json_output)
        self.assertEqual(parsed["report_id"], "REP-INC-HIST-2026-001")
        self.assertEqual(len(parsed["ioc_table"]), 1)

        # 3. Kiểm tra xuất DOCX từ báo cáo lịch sử
        docx_bytes = generate_docx_report(report)
        self.assertIsInstance(docx_bytes, bytes)
        self.assertGreater(len(docx_bytes), 1000, "Tệp DOCX phải có kích thước tối thiểu > 1000 bytes")

        # 4. Kiểm tra nạp bảng IoCs từ sự cố lịch sử không bị lỗi thuộc tính (AttributeError)
        ioc_table = format_ioc_table_data(retrieved_state.threat_intel)
        self.assertEqual(len(ioc_table), 1)
        self.assertEqual(ioc_table[0]["Giá trị Chỉ số"], "194.26.29.112")

    def test_incident_store_empty_and_corrupted_json_resilience(self):
        """
        Kiểm tra cơ chế hoạt động bền bỉ (Resilience) của IncidentStore:
        - Khi kho lưu trữ hoàn toàn rỗng -> trả về [] an toàn, không raise exception.
        - Khi có tệp JSON bị hỏng (syntax error / corrupt payload) -> tự động bỏ qua và nạp các tệp hợp lệ.
        """
        # 1. Kho rỗng
        empty_list = self.store.list_incidents()
        self.assertEqual(empty_list, [])

        # 2. Tạo 1 file sự cố hợp lệ
        self.store.save_incident(self.sample_state)

        # 3. Cố tình ghi thêm 1 file JSON hỏng cú pháp vào thư mục lưu trữ
        corrupt_file_path = os.path.join(self.test_dir, "corrupted_incident.json")
        with open(corrupt_file_path, "w", encoding="utf-8") as f:
            f.write("{ INVALID_JSON_SYNTAX: null, broken ...")

        # 4. Tạo thêm 1 file không khớp IncidentState schema
        invalid_schema_path = os.path.join(self.test_dir, "invalid_schema.json")
        with open(invalid_schema_path, "w", encoding="utf-8") as f:
            f.write('{"something_else": 123}')

        # 5. list_incidents() phải xử lý an toàn: bỏ qua 2 file lỗi và trả về 1 sự cố hợp lệ
        valid_incidents = self.store.list_incidents()
        self.assertEqual(len(valid_incidents), 1)
        self.assertEqual(valid_incidents[0].incident_id, "INC-HIST-001")

    def test_historical_incident_retrieval_by_id_and_not_found(self):
        """Kiểm tra nạp sự cố theo ID và xử lý an toàn khi ID không tồn tại."""
        self.store.save_incident(self.sample_state)

        found = self.store.get_incident("INC-HIST-001")
        self.assertIsNotNone(found)
        self.assertEqual(found.incident_id, "INC-HIST-001")

        not_found = self.store.get_incident("INC-NON-EXISTENT-999")
        self.assertIsNone(not_found)


# =====================================================================
# PHASE 3: LLM OBSERVABILITY, TELEMETRY PANEL, STRATEGY CALLOUT & HELPERS
# =====================================================================
class _DummyColumn:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestObservabilityAndPhase3UI(unittest.TestCase):
    """Kiểm thử các thành phần LLM Health Badge, Telemetry Panel, Strategy Callout và Dashboard Helpers."""

    def _build_telemetry_state(self) -> IncidentState:
        state = IncidentState(
            incident_id="INC-OBS-001",
            status=IncidentStatus.AWAITING_APPROVAL,
            response_strategy_summary="Ưu tiên cô lập <script>alert('xss')</script> & chặn C2 194.26.29.112 theo NIST SP 800-61.",
        )
        state.record_workflow_telemetry("ingestion", latency_ms=12.5, engine_mode="langgraph")
        state.record_workflow_telemetry("triage", latency_ms=18.0, engine_mode="langgraph")
        state.record_workflow_telemetry("response", latency_ms=145.5, engine_mode="langgraph")
        state.record_llm_telemetry(
            LLMCallTelemetry(
                call_id="CALL-TIERED-1",
                agent_name="TriageAgent",
                node="triage",
                provider_used="skipped_tiered",
                model="fast-tier",
                latency_ms=1.2,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                success=True,
            )
        )
        state.record_llm_telemetry(
            LLMCallTelemetry(
                call_id="CALL-LIVE-1",
                agent_name="RCAAgent",
                node="rca",
                provider_used="omnirouter",
                model="AICODE",
                latency_ms=320.5,
                prompt_tokens=450,
                completion_tokens=180,
                total_tokens=630,
                structured_attempts=2,
                self_corrected=True,
                success=True,
            )
        )
        state.record_llm_telemetry(
            LLMCallTelemetry(
                call_id="CALL-FB-1",
                agent_name="ResponseAgent",
                node="response",
                provider_used="deterministic",
                model="Deterministic-CoT",
                latency_ms=4.5,
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
                fallback_reason="Gateway timeout",
                success=True,
            )
        )
        return state

    def test_kpi_metrics_additive_telemetry_keys(self):
        empty_kpis = get_kpi_metrics(None)
        self.assertEqual(empty_kpis["total_llm_tokens"], 0)
        self.assertEqual(empty_kpis["llm_calls_count"], 0)
        for req_key in (
            "incident_id", "status", "severity", "confidence_score",
            "raw_logs_count", "parsed_events_count", "ioc_count", "malicious_ioc_count",
            "total_actions", "pending_actions", "approved_actions", "rejected_actions",
            "attack_type", "attack_category",
        ):
            self.assertIn(req_key, empty_kpis)

        state = self._build_telemetry_state()
        kpis = get_kpi_metrics(state)
        self.assertEqual(kpis["total_llm_tokens"], 780)
        self.assertEqual(kpis["llm_calls_count"], 2)  # excludes skipped_tiered

    def test_format_llm_telemetry_data(self):
        self.assertEqual(format_llm_telemetry_data(None), [])

        state = self._build_telemetry_state()
        rows = format_llm_telemetry_data(state)
        self.assertEqual(len(rows), 3)
        expected_cols = {
            "Agent", "Node", "Provider", "Model",
            "Latency (ms)", "Prompt/Completion Tokens",
            "Self-Corrected", "Fallback Reason",
        }
        for row in rows:
            self.assertEqual(set(row.keys()), expected_cols)

        self.assertEqual(rows[1]["Agent"], "RCAAgent")
        self.assertEqual(rows[1]["Provider"], "omnirouter")
        self.assertEqual(rows[1]["Prompt/Completion Tokens"], "450 / 180 (630)")
        self.assertEqual(rows[1]["Self-Corrected"], "✅ Có")
        self.assertEqual(rows[2]["Fallback Reason"], "Gateway timeout")

    @patch("streamlit.info")
    @patch("streamlit.dataframe")
    @patch("streamlit.metric")
    @patch("streamlit.columns")
    @patch("streamlit.subheader")
    def test_render_llm_telemetry_panel_headless_safe(
        self, mock_sub, mock_cols, mock_metric, mock_df, mock_info
    ):
        mock_cols.return_value = [_DummyColumn() for _ in range(4)]

        # Empty state
        empty_summary = render_llm_telemetry_panel(None)
        self.assertEqual(empty_summary["total_tokens"], 0)
        self.assertEqual(empty_summary["llm_calls_count"], 0)
        self.assertTrue(mock_info.called)

        # Populated state
        state = self._build_telemetry_state()
        summary = render_llm_telemetry_panel(state)
        self.assertEqual(summary["engine_mode"], "LangGraph")
        self.assertEqual(summary["total_tokens"], 780)
        self.assertEqual(summary["live_llm_calls_count"], 1)
        self.assertEqual(summary["fallback_calls_count"], 1)
        self.assertEqual(summary["tiered_saved_calls_count"], 1)
        self.assertEqual(summary["total_investigation_ms"], 176.0)
        self.assertEqual(len(summary["rows"]), 3)
        self.assertTrue(mock_df.called)
        self.assertGreaterEqual(mock_metric.call_count, 4)

    @patch("streamlit.markdown")
    def test_render_llm_health_badge_all_states_and_dict_mocks(self, mock_md):
        # 1. Live Cloud AI (Pydantic LLMHealthStatus)
        cloud_health = LLMHealthStatus(
            connected=True,
            active_provider="omnirouter",
            configured_mode="omnirouter",
            model="gpt-4o-mini",
            latency_ms=42.3,
        )
        res_cloud = render_llm_health_badge(health=cloud_health, key_prefix="t_cloud")
        self.assertEqual(res_cloud["status"], "online")
        self.assertTrue(res_cloud["connected"])
        self.assertIn("🟢 Live Cloud AI (gpt-4o-mini • 42ms)", res_cloud["badge"])
        self.assertIn("Online", res_cloud["badge"])

        # 2. Live Local Ollama (dict mock)
        ollama_health = {
            "connected": True,
            "active_provider": "ollama",
            "configured_mode": "ollama",
            "model": "llama3:latest",
            "latency_ms": 18.0,
        }
        res_ollama = render_llm_health_badge(health=ollama_health, key_prefix="t_ollama")
        self.assertEqual(res_ollama["status"], "online")
        self.assertIn("🟢 Live Local Ollama (llama3:latest • 18ms)", res_ollama["badge"])
        self.assertIn("Online", res_ollama["badge"])

        # 3. Fallback: Deterministic CoT with short error reason
        det_health = LLMHealthStatus(
            connected=False,
            active_provider="deterministic",
            configured_mode="auto",
            model="AICODE",
            error="Connection refused on 20128",
        )
        res_det = render_llm_health_badge(health=det_health, key_prefix="t_det")
        self.assertEqual(res_det["status"], "degraded")
        self.assertFalse(res_det["connected"])
        self.assertIn("🟡 Fallback: Deterministic CoT", res_det["badge"])
        self.assertIn("Connection refused", res_det["badge"])
        self.assertNotIn("Online", res_det["badge"])

        # 4. Unverified (probe=False with provider, or unverified dict)
        dummy_provider = MagicMock()
        dummy_provider.enable_fallback = True
        dummy_provider.provider_mode = "auto"
        dummy_provider.model = "AICODE"
        dummy_provider.last_used_provider = None
        dummy_provider.last_error = None
        res_unverified = render_llm_health_badge(dummy_provider, health=None, probe=False, key_prefix="t_unv")
        self.assertEqual(res_unverified["status"], "unverified")
        self.assertFalse(res_unverified["connected"])
        self.assertEqual(res_unverified["badge"], "⚪ Chưa kiểm tra kết nối")

        res_unverified_dict = render_llm_health_badge(health={"status": "unverified"}, key_prefix="t_unv2")
        self.assertEqual(res_unverified_dict["status"], "unverified")
        self.assertEqual(res_unverified_dict["badge"], "⚪ Chưa kiểm tra kết nối")

        # 5. Offline
        res_off = render_llm_health_badge(None, health=None, key_prefix="t_off")
        self.assertEqual(res_off["status"], "offline")
        self.assertEqual(res_off["badge"], "🔴 Offline")
        self.assertTrue(mock_md.called)

    @patch("streamlit.info")
    @patch("streamlit.subheader")
    @patch("streamlit.markdown")
    def test_response_strategy_summary_html_escaped(self, mock_md, mock_sub, mock_info):
        state = self._build_telemetry_state()
        rendered_html = render_response_strategy_callout(state)
        self.assertIsNotNone(rendered_html)
        self.assertIn("🧠 Chiến lược Phản ứng Tổng hợp (RAG + LLM Incident Commander Rationale)", rendered_html)
        self.assertNotIn("<script>", rendered_html)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", rendered_html)

        mock_md.reset_mock()
        render_hitl_action_cards(state)
        md_calls = " ".join(str(c.args[0]) for c in mock_md.call_args_list if c.args)
        self.assertIn("🧠 Chiến lược Phản ứng Tổng hợp (RAG + LLM Incident Commander Rationale)", md_calls)
        self.assertNotIn("<script>", md_calls)

    def test_dashboard_orchestrator_call_guards_and_health_refresh(self):
        state = self._build_telemetry_state()

        # Legacy mock without start_node or allow_feedback_loop
        class LegacyOrch:
            def execute_until_interrupt(self, state):
                return True, state

            def resume_from_interrupt(self, state):
                return state

        legacy = LegacyOrch()
        paused, out = _call_execute_until_interrupt(legacy, state, start_node="triage")
        self.assertTrue(paused)
        self.assertIs(out, state)
        self.assertIs(_call_resume_from_interrupt(legacy, state, allow_feedback_loop=True), state)

        # Modern orchestrator accepting start_node and allow_feedback_loop
        captured = {}

        class ModernOrch:
            def execute_until_interrupt(self, state, start_node=None):
                captured["start_node"] = start_node
                return False, state

            def resume_from_interrupt(self, state, allow_feedback_loop=None):
                captured["allow_feedback_loop"] = allow_feedback_loop
                return state

        modern = ModernOrch()
        _call_execute_until_interrupt(modern, state, start_node="rca")
        self.assertEqual(captured["start_node"], "rca")
        _call_execute_until_interrupt(modern, state, start_node="ingestion")
        self.assertIsNone(captured["start_node"])
        _call_resume_from_interrupt(modern, state, allow_feedback_loop=True)
        self.assertTrue(captured["allow_feedback_loop"])

        # Refresh helper passes force=True safely
        provider = MagicMock()
        expected_health = LLMHealthStatus(connected=True, active_provider="omnirouter", model="AICODE")
        provider.check_health = lambda force=False: expected_health if force else None
        self.assertIs(_refresh_llm_health_status(provider), expected_health)


if __name__ == "__main__":
    unittest.main()

