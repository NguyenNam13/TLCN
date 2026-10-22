# -*- coding: utf-8 -*-
"""
tests/test_response_agent.py
Bộ kiểm thử đơn vị độc lập cho Response Recommendation Agent (Tuân thủ NIST SP 800-61).
Kiểm thử toàn diện:
1. Đề xuất hành động ứng phó cho sự cố Endpoint Malware (ISOLATE_HOST, KILL_PROCESS, BLOCK_IP).
2. Đề xuất hành động cho sự cố Phishing & Credential Compromise (REVOKE_USER, RESET_PASSWORD, BLOCK_IP).
3. Tích hợp Wazuh Active Response (firewall-drop, host-isolate, kill-process).
4. Kiểm tra phân cấp ưu tiên (Priority Sorting 1 -> 5) và cờ phê duyệt chuyên viên (require_human_approval).
5. Kiểm tra cơ chế tự động phê duyệt rủi ro thấp (auto_approve_low_risk=True vs False).
6. Khử trùng lặp hành động (Deduplication) theo target & action_type.
7. Kiểm tra hàm process_state cập nhật đúng state.recommended_actions và ghi nhận State Transition.
8. Xử lý kịch bản False Positive (không đề xuất hành động).
9. Xử lý kịch bản sự cố đa tầng kết hợp (Combined Phishing + Malware).
"""

import unittest
from datetime import datetime, timezone

from src.core.schemas import (
    ActionType,
    RecommendedAction,
    IncidentStatus,
    SeverityLevel,
    ParsedEvent,
    TriageOutput,
    ThreatIntelEnrichment,
    IoCItem,
    RootCauseAnalysis,
    ProcessNode,
)
from src.core.state import IncidentState
from src.agents.response_agent import ResponseAgent
from src.tools.playbooks import ResponsePlaybooks
from src.tools.wazuh_client import WazuhClientTool


class TestResponseAgent(unittest.TestCase):
    """Bộ kiểm thử đơn vị cho ResponseAgent."""

    def setUp(self):
        """Khởi tạo agent mặc định và dữ liệu mốc thời gian."""
        self.agent = ResponseAgent(
            require_approval_by_default=True,
            auto_approve_low_risk=False,
            enable_wazuh_active_response=True,
        )
        self.now = datetime(2026, 10, 19, 14, 0, 0, tzinfo=timezone.utc)

    # =====================================================================
    # TEST 1: KHỞI TẠO VÀ CẤU HÌNH MẶC ĐỊNH
    # =====================================================================
    def test_initialization_and_default_configs(self):
        """Kiểm tra khởi tạo ResponseAgent với cấu hình mặc định."""
        agent = ResponseAgent()
        self.assertTrue(agent.require_approval_by_default)
        self.assertFalse(agent.auto_approve_low_risk)
        self.assertTrue(agent.enable_wazuh_active_response)
        self.assertIsNotNone(agent.system_prompt)
        self.assertEqual(agent.playbooks, ResponsePlaybooks)
        self.assertEqual(agent.wazuh_client, WazuhClientTool)

    # =====================================================================
    # TEST 2: ĐỀ XUẤT HÀNH ĐỘNG CHO SỰ CỐ MALWARE (NIST CONTAINMENT P1)
    # =====================================================================
    def test_malware_incident_recommendations(self):
        """
        Kiểm thử đề xuất hành động cho sự cố Endpoint Malware:
        Phải bao gồm: ISOLATE_HOST, KILL_PROCESS, BLOCK_IP.
        """
        event = ParsedEvent(
            event_id="Sysmon-1",
            timestamp=self.now,
            source_type="Sysmon",
            host_name="VICTIM-PC-01",
            user_name="hoainam",
            process_name="powershell.exe",
            command_line="powershell.exe -enc SQBFAFgAIAA...",
            dest_ip="194.26.29.112",
            dest_port=8080,
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

        triage = TriageOutput(
            is_incident=True,
            confidence_score=0.95,
            severity=SeverityLevel.HIGH,
            summary="Phát hiện mã độc thực thi PowerShell kết nối máy chủ C2 bên ngoài.",
        )

        rca = RootCauseAnalysis(
            initial_access_vector="Spearphishing Attachment Macro / Malware Execution",
            attack_timeline=["Nhận email lừa đảo", "Chạy macro tài liệu", "Kích hoạt powershell.exe"],
            process_tree=[
                ProcessNode(
                    process_id="1000",
                    process_name="powershell.exe",
                    command_line="powershell.exe -enc ...",
                    is_malicious_origin=True,
                )
            ],
            mitre_tactics=["Execution", "Command and Control"],
            root_cause_summary="Mã độc lây nhiễm qua file đính kèm.",
        )

        state = IncidentState(
            incident_id="INC-MALWARE-01",
            parsed_events=[event],
            triage_result=triage,
            rca_result=rca,
        )

        actions = self.agent.recommend_actions(state)

        # 1. Kiểm tra có đủ các loại hành động trọng yếu
        action_types = [a.action_type for a in actions]
        self.assertIn(ActionType.ISOLATE_HOST, action_types)
        self.assertIn(ActionType.KILL_PROCESS, action_types)
        self.assertIn(ActionType.BLOCK_IP, action_types)

        # 2. Kiểm tra mục tiêu target của từng hành động
        targets = {a.action_type: a.target for a in actions}
        self.assertEqual(targets[ActionType.ISOLATE_HOST], "VICTIM-PC-01")
        self.assertEqual(targets[ActionType.BLOCK_IP], "194.26.29.112")
        self.assertEqual(targets[ActionType.KILL_PROCESS], "powershell.exe")

    # =====================================================================
    # TEST 3: ĐỀ XUẤT HÀNH ĐỘNG CHO SỰ CỐ PHISHING / CREDENTIAL COMPROMISE
    # =====================================================================
    def test_phishing_credential_compromise_recommendations(self):
        """
        Kiểm thử đề xuất hành động cho sự cố lừa đảo đánh cắp danh tính:
        Phải bao gồm: REVOKE_USER, RESET_PASSWORD, BLOCK_IP.
        """
        event = ParsedEvent(
            event_id="EVTX-4625",
            timestamp=self.now,
            source_type="WindowsSecurity",
            host_name="AUTH-SERVER",
            user_name="hoainam",
            source_ip="185.220.101.5",  # IP Tor / Attacker
            raw_attributes={"logon_type": "10"},
        )

        triage = TriageOutput(
            is_incident=True,
            confidence_score=0.9,
            severity=SeverityLevel.HIGH,
            summary="Đăng nhập bất thường từ IP lạ sau khi người dùng nhận email phishing.",
        )

        rca = RootCauseAnalysis(
            initial_access_vector="Spearphishing Link / Credential Harvesting",
            attack_timeline=["Bấm link phishing", "Lộ mật khẩu", "Đăng nhập RDP từ IP lạ"],
            process_tree=[],
            mitre_tactics=["Initial Access", "Credential Access"],
            root_cause_summary="Đánh cắp thông tin tài khoản qua trang web giả mạo.",
        )

        state = IncidentState(
            incident_id="INC-PHISH-01",
            parsed_events=[event],
            triage_result=triage,
            rca_result=rca,
        )

        actions = self.agent.recommend_actions(state)

        action_types = [a.action_type for a in actions]
        self.assertIn(ActionType.REVOKE_USER, action_types)
        self.assertIn(ActionType.RESET_PASSWORD, action_types)
        self.assertIn(ActionType.BLOCK_IP, action_types)

        # Kiểm tra mục tiêu tài khoản bị xâm phạm
        user_actions = [a for a in actions if a.action_type in {ActionType.REVOKE_USER, ActionType.RESET_PASSWORD}]
        for act in user_actions:
            self.assertEqual(act.target, "hoainam")

    # =====================================================================
    # TEST 4: TẠO HÀNH ĐỘNG WAZUH ACTIVE RESPONSE
    # =====================================================================
    def test_wazuh_active_response_generation(self):
        """
        Kiểm thử tạo hành động Wazuh Active Response qua WazuhClientTool:
        - firewall-drop (chặn IP)
        - host-isolate (cô lập host)
        - kill-process (tiêu diệt tiến trình)
        """
        # 1. Kiểm tra lệnh firewall-drop
        act_fw = self.agent.create_wazuh_active_response(
            agent_id="001",
            command="firewall-drop",
            target_ip="194.26.29.112",
        )
        self.assertEqual(act_fw.action_type, ActionType.BLOCK_IP)
        self.assertEqual(act_fw.target, "194.26.29.112")
        self.assertIn("firewall-drop", act_fw.description)
        self.assertTrue(act_fw.require_human_approval)

        # 2. Kiểm tra lệnh host-isolate
        act_iso = self.agent.create_wazuh_active_response(
            agent_id="002",
            command="host-isolate",
        )
        self.assertEqual(act_iso.action_type, ActionType.ISOLATE_HOST)
        self.assertEqual(act_iso.target, "Agent-002")
        self.assertIn("host-isolate", act_iso.description)
        self.assertTrue(act_iso.require_human_approval)

        # 3. Kiểm tra lệnh dùng trực tiếp action_type WAZUH_ACTIVE_RESPONSE
        act_custom = self.agent.create_wazuh_active_response(
            agent_id="003",
            command="custom-script",
            use_wazuh_action_type=True,
        )
        self.assertEqual(act_custom.action_type, ActionType.WAZUH_ACTIVE_RESPONSE)
        self.assertEqual(act_custom.target, "Agent-003")
        self.assertTrue(act_custom.require_human_approval)

        # 4. Kiểm tra sự cố có dữ liệu Wazuh SIEM tự động sinh Active Response
        wazuh_event = ParsedEvent(
            event_id="Wazuh-100200",
            timestamp=self.now,
            source_type="WazuhSIEM",
            host_name="UBUNTU-SERVER",
            dest_ip="203.0.113.55",
            raw_attributes={
                "wazuh_agent_id": "005",
                "wazuh_agent_name": "UBUNTU-SERVER",
                "wazuh_rule_id": "100200",
            },
        )
        state_wazuh = IncidentState(
            incident_id="INC-WAZUH-01",
            parsed_events=[wazuh_event],
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.9,
                severity=SeverityLevel.HIGH,
                summary="Wazuh phát hiện tấn công brute-force và C2",
            ),
        )
        wazuh_actions = self.agent.recommend_actions(state_wazuh)
        # Phải có ít nhất một hành động liên quan tới Agent-005
        has_agent_action = any("005" in a.description or a.target == "Agent-005" for a in wazuh_actions)
        self.assertTrue(has_agent_action, "Phải sinh hành động Wazuh Active Response tương ứng agent_id 005")

    # =====================================================================
    # TEST 5: PHÂN CẤP ƯU TIÊN VÀ CỜ PHÊ DUYỆT CHUYÊN VIÊN (REQUIRE_APPROVAL)
    # =====================================================================
    def test_priority_sorting_and_approval_flags(self):
        """
        Kiểm tra:
        1. Danh sách hành động sắp xếp theo thứ tự ưu tiên tăng dần (Priority 1 -> 5).
        2. Các hành động rủi ro cao (ISOLATE_HOST, BLOCK_IP, RESET_PASSWORD, WAZUH_ACTIVE_RESPONSE)
           LUÔN yêu cầu require_human_approval = True.
        """
        actions = [
            RecommendedAction(
                action_type=ActionType.PATCH_SYSTEM,
                target="SERVER-01",
                description="Vá lỗ hổng hệ điều hành",
                priority=3,
                require_human_approval=False,
            ),
            RecommendedAction(
                action_type=ActionType.ISOLATE_HOST,
                target="SERVER-01",
                description="Cô lập server khỏi mạng",
                priority=1,
                require_human_approval=True,
            ),
            RecommendedAction(
                action_type=ActionType.RESET_PASSWORD,
                target="admin",
                description="Buộc đặt lại mật khẩu",
                priority=2,
                require_human_approval=True,
            ),
            RecommendedAction(
                action_type=ActionType.BLOCK_IP,
                target="1.2.3.4",
                description="Chặn IP tấn công",
                priority=1,
                require_human_approval=True,
            ),
        ]

        sorted_actions = self.agent.deduplicate_and_sort_actions(actions)

        # 1. Kiểm tra sắp xếp theo priority tăng dần
        priorities = [a.priority for a in sorted_actions]
        self.assertEqual(priorities, sorted(priorities))
        self.assertEqual(sorted_actions[0].priority, 1)

        # 2. Kiểm tra cờ require_human_approval trên các hành động rủi ro cao
        for act in sorted_actions:
            if act.action_type in ResponseAgent.HIGH_RISK_ACTIONS:
                self.assertTrue(
                    act.require_human_approval,
                    f"Hành động {act.action_type} bắt buộc phải có require_human_approval=True",
                )

    # =====================================================================
    # TEST 6: CHÍNH SÁCH AUTO APPROVE CHO HÀNH ĐỘNG RỦI RO THẤP
    # =====================================================================
    def test_auto_approve_low_risk_policy(self):
        """
        Kiểm thử cấu hình auto_approve_low_risk:
        - Khi auto_approve_low_risk = True: các hành động rủi ro thấp (KILL_PROCESS, REVOKE_USER)
          có require_human_approval = False. Các hành động rủi ro cao vẫn giữ True.
        - Khi auto_approve_low_risk = False và require_approval_by_default = True:
          tất cả hành động đều có require_human_approval = True.
        """
        # Trường hợp 1: auto_approve_low_risk = True
        agent_auto = ResponseAgent(
            require_approval_by_default=True,
            auto_approve_low_risk=True,
        )
        self.assertFalse(agent_auto.determine_approval_requirement(ActionType.KILL_PROCESS))
        self.assertFalse(agent_auto.determine_approval_requirement(ActionType.REVOKE_USER))
        self.assertFalse(agent_auto.determine_approval_requirement(ActionType.PATCH_SYSTEM))
        # Rủi ro cao vẫn phải True
        self.assertTrue(agent_auto.determine_approval_requirement(ActionType.ISOLATE_HOST))
        self.assertTrue(agent_auto.determine_approval_requirement(ActionType.BLOCK_IP))
        self.assertTrue(agent_auto.determine_approval_requirement(ActionType.RESET_PASSWORD))

        # Trường hợp 2: auto_approve_low_risk = False và require_approval_by_default = True
        agent_strict = ResponseAgent(
            require_approval_by_default=True,
            auto_approve_low_risk=False,
        )
        self.assertTrue(agent_strict.determine_approval_requirement(ActionType.KILL_PROCESS))
        self.assertTrue(agent_strict.determine_approval_requirement(ActionType.ISOLATE_HOST))

    # =====================================================================
    # TEST 7: KHỬ TRÙNG LẶP HÀNH ĐỘNG (DEDUPLICATION)
    # =====================================================================
    def test_deduplication_mechanism(self):
        """
        Kiểm tra loại bỏ hành động trùng lặp theo target và action_type:
        Giữ lại hành động có mức ưu tiên cao hơn (chỉ số priority nhỏ hơn).
        """
        dup_actions = [
            RecommendedAction(
                action_type=ActionType.BLOCK_IP,
                target="194.26.29.112",
                description="Chặn IP trên Firewall biên",
                priority=2,
                require_human_approval=True,
            ),
            RecommendedAction(
                action_type=ActionType.BLOCK_IP,
                target=" 194.26.29.112 ",  # Trùng lặp có khoảng trắng thừa
                description="Chặn khẩn cấp IP C2",
                priority=1,  # Độ ưu tiên cao hơn
                require_human_approval=True,
            ),
            RecommendedAction(
                action_type=ActionType.ISOLATE_HOST,
                target="PC-01",
                description="Cô lập máy trạm PC-01",
                priority=1,
                require_human_approval=True,
            ),
            RecommendedAction(
                action_type=ActionType.ISOLATE_HOST,
                target="pc-01",  # Trùng lặp viết thường
                description="Cô lập máy trạm pc-01 lần 2",
                priority=1,
                require_human_approval=True,
            ),
        ]

        deduped = self.agent.deduplicate_and_sort_actions(dup_actions)

        # Sau khi khử trùng lặp, chỉ còn 2 hành động duy nhất
        self.assertEqual(len(deduped), 2)

        # Kiểm tra BLOCK_IP giữ lại phiên bản có priority=1
        block_action = next(a for a in deduped if a.action_type == ActionType.BLOCK_IP)
        self.assertEqual(block_action.priority, 1)

    # =====================================================================
    # TEST 8: PROCESS_STATE CẬP NHẬT INCIDENT_STATE VÀ STATE TRANSITION
    # =====================================================================
    def test_process_state_updates_state_and_transition(self):
        """
        Kiểm thử process_state:
        1. Cập nhật state.recommended_actions.
        2. Ghi nhận StateTransition với node='response', to_status=IncidentStatus.INVESTIGATING.
        3. Lưu trữ metadata đầy đủ (action_count, actions, high_priority_count).
        """
        state = IncidentState(
            incident_id="INC-PIPELINE-TEST",
            parsed_events=[
                ParsedEvent(
                    event_id="1",
                    timestamp=self.now,
                    source_type="Sysmon",
                    host_name="FINANCE-PC",
                    dest_ip="198.51.100.22",
                    process_name="cmd.exe",
                )
            ],
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.9,
                severity=SeverityLevel.HIGH,
                summary="Phát hiện cmd.exe gọi kết nối bất thường",
            ),
        )

        initial_history_len = len(state.history)

        processed_state = self.agent.process_state(state)

        # 1. Trả về đúng đối tượng state
        self.assertIs(processed_state, state)

        # 2. recommended_actions được cập nhật và không rỗng
        self.assertGreaterEqual(len(processed_state.recommended_actions), 1)

        # 3. Ghi nhận State Transition mới
        self.assertEqual(len(processed_state.history), initial_history_len + 1)
        transition = processed_state.history[-1]
        self.assertEqual(transition.node, "response")
        self.assertEqual(transition.to_status, IncidentStatus.INVESTIGATING)
        self.assertIn("action_count", transition.metadata)
        self.assertEqual(transition.metadata["action_count"], len(processed_state.recommended_actions))

    # =====================================================================
    # TEST 9: XỬ LÝ KỊCH BẢN FALSE POSITIVE
    # =====================================================================
    def test_false_positive_short_circuit(self):
        """
        Khi Triage phân loại là False Positive (is_incident = False),
        ResponseAgent không đề xuất hành động ngăn chặn (trả về danh sách rỗng).
        """
        state_fp = IncidentState(
            incident_id="INC-FP-001",
            parsed_events=[
                ParsedEvent(
                    event_id="4624",
                    timestamp=self.now,
                    source_type="WindowsSecurity",
                    host_name="DOMAIN-CONTROLLER",
                    user_name="admin",
                )
            ],
            triage_result=TriageOutput(
                is_incident=False,
                confidence_score=0.98,
                severity=SeverityLevel.LOW,
                summary="Hoạt động bảo trì định kỳ của quản trị viên hệ thống (False Positive).",
            ),
        )

        actions = self.agent.recommend_actions(state_fp)
        self.assertEqual(len(actions), 0, "Không được đề xuất hành động ngăn chặn đối với sự cố False Positive")

    # =====================================================================
    # TEST 10: SỰ CỐ ĐA TẦNG KẾT HỢP (PHISHING + MALWARE INTRUSION)
    # =====================================================================
    def test_combined_multistage_incident(self):
        """
        Kiểm thử sự cố phức tạp kết hợp:
        1. Người dùng bấm link phishing làm lộ tài khoản.
        2. Kẻ tấn công dùng tài khoản đăng nhập và tải malware (powershell).
        ResponseAgent phải đề xuất cả hành động xử lý tài khoản và cô lập máy trạm.
        """
        events = [
            ParsedEvent(
                event_id="EVTX-4624",
                timestamp=self.now,
                source_type="WindowsSecurity",
                host_name="WS-ACCOUNTING",
                user_name="victim_user",
                source_ip="185.220.101.5",
            ),
            ParsedEvent(
                event_id="Sysmon-1",
                timestamp=self.now,
                source_type="Sysmon",
                host_name="WS-ACCOUNTING",
                process_name="powershell.exe",
                command_line="powershell.exe -enc AAAA...",
                dest_ip="194.26.29.112",
            ),
        ]

        state_combined = IncidentState(
            incident_id="INC-COMBINED-01",
            parsed_events=events,
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.95,
                severity=SeverityLevel.CRITICAL,
                summary="Chuỗi tấn công đa tầng từ Spearphishing đến thực thi mã độc C2.",
            ),
            rca_result=RootCauseAnalysis(
                initial_access_vector="Spearphishing Link -> Credential Abuse -> Malware Execution",
                attack_timeline=["Phishing Link", "Credential Abuse", "PowerShell C2"],
                process_tree=[
                    ProcessNode(process_id="1000", process_name="powershell.exe", command_line="...", is_malicious_origin=True)
                ],
                mitre_tactics=["Initial Access", "Credential Access", "Execution", "Command and Control"],
                root_cause_summary="Tài khoản bị lộ lọt dẫn đến thực thi mã độc có chủ đích.",
            ),
        )

        actions = self.agent.recommend_actions(state_combined)
        action_types = {a.action_type for a in actions}

        # Phải chứa cả hành động xử lý tài khoản và xử lý máy trạm/mạng
        self.assertIn(ActionType.REVOKE_USER, action_types)
        self.assertIn(ActionType.RESET_PASSWORD, action_types)
        self.assertIn(ActionType.ISOLATE_HOST, action_types)
        self.assertIn(ActionType.KILL_PROCESS, action_types)
        self.assertIn(ActionType.BLOCK_IP, action_types)


if __name__ == "__main__":
    unittest.main()
