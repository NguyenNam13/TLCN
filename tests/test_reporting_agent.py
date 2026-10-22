# -*- coding: utf-8 -*-
"""
tests/test_reporting_agent.py
Bộ Unit Tests độc lập toàn diện cho Reporting Agent (Track 2 - Khóa luận Tốt nghiệp TLCN-NAM).

Kiểm thử:
1. Sinh báo cáo IncidentReport hợp lệ từ IncidentState đầy đủ thông tin (Triage + CTI + RCA + Response + HITL).
2. Cơ chế Fallback Graceful khi IncidentState tối giản hoặc thiếu hụt thông tin CTI, RCA.
3. Hàm export_markdown() kiểm tra chuỗi markdown có đầy đủ các đề mục bắt buộc, callout và bảng biểu:
   - Bảng IoC: `| Loại | Giá trị | Điểm nguy cơ | Độc hại |`
   - Bảng Kế hoạch hành động: `| Loại hành động | Mục tiêu | Độ ưu tiên | Cần duyệt | Trạng thái |`
4. Hàm export_json() kiểm tra tính chuẩn hóa và khả năng parse ngược lại JSON thành công.
5. Hàm process_state(state) cập nhật đúng trường state.final_report và lịch sử StateTransition.
6. Xử lý trạng thái False Positive và tùy biến cấu hình organization_name / include_raw_logs.
"""

import json
import unittest
from datetime import datetime, timezone

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
)
from src.core.state import IncidentState
from src.agents.reporting_agent import ReportingAgent


class TestReportingAgent(unittest.TestCase):
    """Bộ kiểm thử đơn vị cho ReportingAgent."""

    def setUp(self):
        """Khởi tạo agent trước mỗi ca kiểm thử."""
        self.default_org = "Hệ thống Điều tra An ninh Mạng HCMUTE"
        self.agent = ReportingAgent()

    # =====================================================================
    # TEST 1: SINH BÁO CÁO TỪ STATE ĐẦY ĐỦ THÔNG TIN (FULL PIPELINE)
    # =====================================================================
    def test_generate_report_full_state(self):
        """
        Kiểm tra sinh IncidentReport hoàn chỉnh từ IncidentState đã qua đủ các Agent:
        Ingestion -> Triage -> Threat Intel (CTI) -> RCA -> Response -> HITL.
        """
        state = IncidentState(
            incident_id="INC-2026-TEST-001",
            status=IncidentStatus.CONTAINED,
            raw_logs=[
                RawLogInput(log_source="Sysmon", raw_payload="<Event>Malicious PowerShell Execution</Event>")
            ],
            parsed_events=[
                ParsedEvent(
                    event_id="Sysmon-1",
                    source_type="Sysmon",
                    host_name="WORKSTATION-01",
                    user_name="hoainam",
                    process_name="powershell.exe",
                    command_line="powershell.exe -enc SQBFAFgA...",
                    dest_ip="194.26.29.112",
                    file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
            ],
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.95,
                severity=SeverityLevel.CRITICAL,
                summary="Phát hiện mã độc PowerShell kết nối tới máy chủ C2 nguy hiểm",
                rule_or_model="Triage-RuleEngine-v2",
            ),
            threat_intel=ThreatIntelEnrichment(
                extracted_iocs=[
                    IoCItem(
                        ioc_type="IP",
                        value="194.26.29.112",
                        reputation_score=92,
                        is_malicious=True,
                        threat_actor="APT29 / Cozy Bear",
                        details={"country": "RU", "abuse_reports": 45},
                    ),
                    IoCItem(
                        ioc_type="SHA256",
                        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        reputation_score=88,
                        is_malicious=True,
                        threat_actor="Unknown",
                        details={"positives": 58},
                    ),
                ],
                related_threat_actors=["APT29 / Cozy Bear"],
                mitre_techniques=["T1059.001", "T1071.001"],
                enrichment_summary="Địa chỉ IP C2 có điểm độc hại cao (92/100) liên kết với nhóm APT29.",
            ),
            rca_result=RootCauseAnalysis(
                initial_access_vector="Spearphishing Attachment (Office Macro)",
                attack_timeline=[
                    "2026-10-19 09:00:00 UTC - Người dùng mở tệp đính kèm Invoice.docm",
                    "2026-10-19 09:00:05 UTC - Macro kích hoạt cmd.exe sinh ra powershell.exe",
                    "2026-10-19 09:00:10 UTC - Kết nối C2 tới IP 194.26.29.112:8080",
                ],
                process_tree=[
                    ProcessNode(
                        process_id="1010",
                        process_name="winword.exe",
                        command_line="winword.exe Invoice.docm",
                        parent_id="500",
                        is_malicious_origin=True,
                    ),
                    ProcessNode(
                        process_id="2020",
                        process_name="cmd.exe",
                        command_line="cmd.exe /c powershell.exe",
                        parent_id="1010",
                        is_malicious_origin=False,
                    ),
                    ProcessNode(
                        process_id="3030",
                        process_name="powershell.exe",
                        command_line="powershell.exe -enc SQBFAFgA...",
                        parent_id="2020",
                        is_malicious_origin=False,
                    ),
                ],
                mitre_tactics=["Initial Access", "Execution", "Command and Control"],
                root_cause_summary="Tài liệu Word chứa macro độc hại thực thi lệnh PowerShell tải mã độc.",
            ),
            recommended_actions=[
                RecommendedAction(
                    action_type=ActionType.ISOLATE_HOST,
                    target="WORKSTATION-01",
                    description="Cô lập máy trạm khỏi mạng LAN để ngăn phát tán",
                    priority=1,
                    require_human_approval=True,
                    is_approved=True,
                ),
                RecommendedAction(
                    action_type=ActionType.BLOCK_IP,
                    target="194.26.29.112",
                    description="Chặn IP máy chủ C2 trên tường lửa biên",
                    priority=1,
                    require_human_approval=True,
                    is_approved=True,
                ),
                RecommendedAction(
                    action_type=ActionType.KILL_PROCESS,
                    target="3030",
                    description="Tiêu diệt tiến trình PowerShell độc hại",
                    priority=2,
                    require_human_approval=False,
                    is_approved=True,
                ),
            ],
            analyst_approved=True,
            analyst_feedback="Chuyên viên SOC đồng ý thực thi toàn bộ kế hoạch ứng phó.",
        )

        report = self.agent.generate_report(state)

        # 1. Kiểm tra cấu trúc IncidentReport
        self.assertIsInstance(report, IncidentReport)
        self.assertEqual(report.report_id, "REP-INC-2026-TEST-001")
        self.assertIn("CRITICAL", report.incident_title)
        self.assertIn("INC-2026-TEST-001", report.incident_title)

        # 2. Kiểm tra Executive Summary
        self.assertIn("INC-2026-TEST-001", report.executive_summary)
        self.assertIn("CRITICAL", report.executive_summary)
        self.assertIn("WORKSTATION-01", report.executive_summary)
        self.assertIn("hoainam", report.executive_summary)
        self.assertIn("Spearphishing Attachment", report.executive_summary)
        self.assertIn("Đã ngăn chặn", report.executive_summary)

        # 3. Kiểm tra Detailed Findings
        self.assertIn("Spearphishing Attachment (Office Macro)", report.detailed_findings)
        self.assertIn("PID `1010`", report.detailed_findings)
        self.assertIn("PATIENT ZERO", report.detailed_findings)
        self.assertIn("194.26.29.112:8080", report.detailed_findings)
        self.assertIn("Tổng số sự kiện an ninh đã bóc tách và chuẩn hóa: 1", report.detailed_findings)

        # 4. Kiểm tra MITRE Matrix Mapping & IoC Table
        self.assertIn("T1059.001", report.mitre_attack_matrix_mapping)
        self.assertIn("T1071.001", report.mitre_attack_matrix_mapping)
        self.assertEqual(len(report.ioc_table), 2)
        ioc_values = [ioc.value for ioc in report.ioc_table]
        self.assertIn("194.26.29.112", ioc_values)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ioc_values)

        # 5. Kiểm tra Action Plan
        self.assertEqual(len(report.action_plan), 3)
        self.assertTrue(all(a.is_approved is True for a in report.action_plan))

    # =====================================================================
    # TEST 2: CƠ CHẾ FALLBACK GRACEFUL KHI THIẾU CTI VÀ RCA
    # =====================================================================
    def test_generate_report_fallback_minimal_state(self):
        """
        Kiểm tra cơ chế Fallback Graceful khi IncidentState tối giản
        (thiếu CTI, thiếu RCA, thiếu Triage, không có recommended actions).
        Đảm bảo không xảy ra lỗi crash/exception và điền giá trị mặc định hợp lý.
        """
        state = IncidentState(
            incident_id="INC-FALLBACK-002",
            status=IncidentStatus.INVESTIGATING,
            parsed_events=[
                ParsedEvent(
                    event_id="Zeek-Conn",
                    source_type="Zeek",
                    dest_ip="45.33.32.156",
                )
            ]
        )

        report = self.agent.generate_report(state)

        # Báo cáo vẫn được sinh thành công
        self.assertIsInstance(report, IncidentReport)
        self.assertEqual(report.report_id, "REP-INC-FALLBACK-002")
        self.assertIn("HIGH", report.incident_title)

        # Executive Summary có fallback hợp lý
        self.assertIn("INC-FALLBACK-002", report.executive_summary)
        self.assertIn("Đang điều tra / Đang xử lý", report.executive_summary)

        # Detailed Findings fallback an toàn
        self.assertIn("Chưa xác định", report.detailed_findings)
        self.assertIn("Không có dữ liệu cây tiến trình", report.detailed_findings)

        # IoC Table quét fallback từ parsed_events
        self.assertGreaterEqual(len(report.ioc_table), 1)
        self.assertEqual(report.ioc_table[0].value, "45.33.32.156")

        # MITRE Mapping fallback an toàn
        self.assertGreaterEqual(len(report.mitre_attack_matrix_mapping), 1)

        # Action plan rỗng nhưng không lỗi
        self.assertEqual(len(report.action_plan), 0)

    # =====================================================================
    # TEST 3: ĐỊNH DẠNG XUẤT BẢN MARKDOWN (STREAMLIT READY)
    # =====================================================================
    def test_export_markdown_headers_and_tables(self):
        """
        Kiểm tra xuất Markdown chuyên nghiệp:
        1. Tiêu đề và Callout block Executive Summary.
        2. Bảng IoC đúng tiêu đề: `| Loại | Giá trị | Điểm nguy cơ | Độc hại |`.
        3. Bảng Action Plan đúng tiêu đề: `| Loại hành động | Mục tiêu | Độ ưu tiên | Cần duyệt | Trạng thái |`.
        4. Các đề mục lớn 1 đến 5.
        """
        report = IncidentReport(
            report_id="REP-TEST-MD-001",
            incident_title="Báo cáo Điều tra Sự cố [HIGH]: INC-TEST-MD-001",
            created_at=datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc),
            executive_summary="Sự cố mã độc được phát hiện trên máy trạm tài chính.",
            detailed_findings="Phân tích kỹ thuật ghi nhận kết nối ra ngoài bất thường.",
            mitre_attack_matrix_mapping=["T1059.001", "T1046"],
            ioc_table=[
                IoCItem(
                    ioc_type="IP",
                    value="198.51.100.25",
                    reputation_score=85,
                    is_malicious=True,
                    threat_actor="CobaltStrike Group",
                )
            ],
            action_plan=[
                RecommendedAction(
                    action_type=ActionType.BLOCK_IP,
                    target="198.51.100.25",
                    description="Chặn IP độc hại trên Firewall",
                    priority=1,
                    require_human_approval=True,
                    is_approved=True,
                ),
                RecommendedAction(
                    action_type=ActionType.ISOLATE_HOST,
                    target="VICTIM-PC",
                    description="Cô lập máy tính",
                    priority=2,
                    require_human_approval=True,
                    is_approved=None,
                ),
            ],
        )

        md = self.agent.export_markdown(report)

        # 1. Kiểm tra tiêu đề chính & Callout
        self.assertIn("# Báo cáo Điều tra Sự cố [HIGH]: INC-TEST-MD-001", md)
        self.assertIn(self.default_org, md)
        self.assertIn("> ### 🚨 TÓM TẮT DÀNH CHO BAN GIÁM ĐỐC (CISO/CIO)", md)
        self.assertIn("> Sự cố mã độc được phát hiện trên máy trạm tài chính.", md)

        # 2. Kiểm tra 5 đề mục cốt lõi
        self.assertIn("## 📌 1. Tóm lược điều hành (Executive Summary)", md)
        self.assertIn("## 🔍 2. Chi tiết kỹ thuật & Phân tích nguyên nhân (Detailed Findings)", md)
        self.assertIn("## 🎯 3. Ma trận kỹ thuật MITRE ATT&CK", md)
        self.assertIn("## 🛡️ 4. Danh sách chỉ số xâm phạm (IoC Table)", md)
        self.assertIn("## 📋 5. Kế hoạch phản ứng & Hành động ứng phó (Action Plan)", md)

        # 3. Kiểm tra định dạng bảng IoC chính xác
        self.assertIn("| Loại | Giá trị | Điểm nguy cơ | Độc hại |", md)
        self.assertIn("| IP | `198.51.100.25` | 85 | Có |", md)

        # 4. Kiểm tra định dạng bảng Kế hoạch hành động chính xác
        self.assertIn("| Loại hành động | Mục tiêu | Độ ưu tiên | Cần duyệt | Trạng thái |", md)
        self.assertIn("| BLOCK_IP | `198.51.100.25` | Mức 1 | Có | Đã duyệt |", md)
        self.assertIn("| ISOLATE_HOST | `VICTIM-PC` | Mức 2 | Có | Chờ duyệt |", md)

    def test_export_markdown_with_empty_tables(self):
        """Kiểm tra export Markdown khi IoC và Action Plan hoàn toàn rỗng."""
        report = IncidentReport(
            report_id="REP-EMPTY-001",
            incident_title="Báo cáo Sự cố [LOW]: INC-EMPTY",
            created_at=datetime.now(timezone.utc),
            executive_summary="Không phát hiện hoạt động độc hại.",
            detailed_findings="Hệ thống vận hành bình thường.",
            mitre_attack_matrix_mapping=[],
            ioc_table=[],
            action_plan=[],
        )

        md = self.agent.export_markdown(report)
        self.assertIn("| Loại | Giá trị | Điểm nguy cơ | Độc hại |", md)
        self.assertIn("| Loại hành động | Mục tiêu | Độ ưu tiên | Cần duyệt | Trạng thái |", md)
        self.assertIn("Không phát hiện IoC bên ngoài", md)
        self.assertIn("Không có hành động nào được đề xuất", md)

    # =====================================================================
    # TEST 4: ĐỊNH DẠNG XUẤT BẢN JSON (STANDARDIZED JSON SCHEMA)
    # =====================================================================
    def test_export_json_validity_and_indentation(self):
        """
        Kiểm tra hàm export_json():
        - Sinh chuỗi JSON hợp lệ.
        - Có thể parse ngược lại bằng json.loads().
        - Thụt lề đúng 2 spaces.
        """
        report = IncidentReport(
            report_id="REP-JSON-001",
            incident_title="Báo cáo Sự cố [MEDIUM]: INC-JSON",
            created_at=datetime(2026, 10, 19, 14, 0, 0, tzinfo=timezone.utc),
            executive_summary="Tóm tắt JSON test.",
            detailed_findings="Chi tiết JSON test.",
            mitre_attack_matrix_mapping=["T1059.001"],
            ioc_table=[
                IoCItem(ioc_type="IP", value="1.1.1.1", reputation_score=10, is_malicious=False)
            ],
            action_plan=[
                RecommendedAction(
                    action_type=ActionType.BLOCK_IP,
                    target="1.1.1.1",
                    description="Thử nghiệm",
                    priority=3,
                    require_human_approval=False,
                    is_approved=True,
                )
            ],
        )

        json_str = self.agent.export_json(report)
        self.assertIsInstance(json_str, str)

        # Kiểm tra thụt lề 2 spaces
        self.assertIn('  "report_id": "REP-JSON-001"', json_str)

        # Kiểm tra deserialize ngược lại
        parsed = json.loads(json_str)
        self.assertEqual(parsed["report_id"], "REP-JSON-001")
        self.assertEqual(parsed["incident_title"], "Báo cáo Sự cố [MEDIUM]: INC-JSON")
        self.assertEqual(len(parsed["ioc_table"]), 1)
        self.assertEqual(parsed["ioc_table"][0]["value"], "1.1.1.1")
        self.assertEqual(len(parsed["action_plan"]), 1)
        self.assertEqual(parsed["action_plan"][0]["target"], "1.1.1.1")

    # =====================================================================
    # TEST 5: TÍCH HỢP STATEGRAPH VÀ CẬP NHẬT STATE (PROCESS_STATE)
    # =====================================================================
    def test_process_state_updates_final_report_and_transition(self):
        """
        Kiểm tra hàm process_state(state):
        1. Gọi generate_report(state).
        2. Gán kết quả vào state.final_report.
        3. Ghi nhận bước chuyển dịch trạng thái (record_transition) sang RESOLVED.
        4. Trả về state với đầy đủ lịch sử.
        """
        state = IncidentState(
            incident_id="INC-STATE-001",
            status=IncidentStatus.INVESTIGATING,
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.9,
                severity=SeverityLevel.HIGH,
                summary="Sự cố kiểm thử StateGraph",
            ),
        )

        initial_history_len = len(state.history)
        result_state = self.agent.process_state(state)

        # 1. State trả về là chính state được cập nhật
        self.assertIs(result_state, state)
        self.assertIsNotNone(result_state.final_report)
        self.assertIsInstance(result_state.final_report, IncidentReport)
        self.assertEqual(result_state.final_report.report_id, "REP-INC-STATE-001")

        # 2. Trạng thái chuyển thành RESOLVED
        self.assertEqual(result_state.status, IncidentStatus.RESOLVED)

        # 3. Lịch sử chuyển dịch ghi nhận node 'reporting'
        self.assertEqual(len(result_state.history), initial_history_len + 1)
        latest_transition = result_state.history[-1]
        self.assertEqual(latest_transition.node, "reporting")
        self.assertEqual(latest_transition.to_status, IncidentStatus.RESOLVED)
        self.assertIn("report_id", latest_transition.metadata)
        self.assertEqual(latest_transition.metadata["report_id"], "REP-INC-STATE-001")

    def test_process_state_preserves_false_positive_status(self):
        """Kiểm tra nếu state là CLOSED_FALSE_POSITIVE thì giữ nguyên trạng thái đóng."""
        state = IncidentState(
            incident_id="INC-FP-002",
            status=IncidentStatus.CLOSED_FALSE_POSITIVE,
            triage_result=TriageOutput(
                is_incident=False,
                confidence_score=0.99,
                severity=SeverityLevel.LOW,
                summary="Cảnh báo dương tính giả",
            ),
        )

        result_state = self.agent.process_state(state)
        self.assertEqual(result_state.status, IncidentStatus.CLOSED_FALSE_POSITIVE)
        latest_transition = result_state.history[-1]
        self.assertEqual(latest_transition.to_status, IncidentStatus.CLOSED_FALSE_POSITIVE)

    # =====================================================================
    # TEST 6: CẤU HÌNH VÀ BẢO VỆ DỮ LIỆU ĐẦU VÀO
    # =====================================================================
    def test_custom_organization_and_include_raw_logs(self):
        """Kiểm tra tùy chỉnh tên tổ chức và cờ include_raw_logs."""
        custom_org = "Cơ quan An ninh Mạng Quốc Gia Việt Nam"
        agent = ReportingAgent(organization_name=custom_org, include_raw_logs=True)

        state = IncidentState(
            incident_id="INC-CUSTOM-003",
            raw_logs=[
                RawLogInput(log_source="Firewall", raw_payload="DROP TCP 10.0.0.1 -> 8.8.8.8")
            ]
        )

        report = agent.generate_report(state)
        md = agent.export_markdown(report)

        self.assertIn(custom_org, md)
        self.assertIn("Trích lục nhật ký thô (Raw Logs Excerpt)", report.detailed_findings)
        self.assertIn("DROP TCP 10.0.0.1", report.detailed_findings)

    def test_invalid_state_raises_value_error(self):
        """Kiểm tra truyền state không hợp lệ hoặc thiếu incident_id."""
        with self.assertRaises(ValueError):
            self.agent.generate_report(None)  # type: ignore

        invalid_state = IncidentState(incident_id="")
        with self.assertRaises(ValueError):
            self.agent.generate_report(invalid_state)


if __name__ == "__main__":
    unittest.main()
