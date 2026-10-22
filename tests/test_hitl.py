# -*- coding: utf-8 -*-
"""
tests/test_hitl.py
Bộ kiểm thử đơn vị (Unit Tests) cho module Human-In-The-Loop (HITL) Manager và Session Store.
Bao gồm:
- test_get_pending_actions: Lọc các hành động yêu cầu phê duyệt
- test_approve_single_action: Phê duyệt một hành động cụ thể
- test_reject_single_action: Từ chối một hành động cụ thể
- test_modify_action_parameters: Sửa đổi tham số hành động và phê duyệt
- test_approve_all: Phê duyệt đồng loạt toàn bộ hành động
- test_reject_all: Từ chối đồng loạt toàn bộ hành động
- test_is_approval_complete: Kiểm tra trạng thái hoàn tất phê duyệt
- test_session_store_save_load: Lưu trữ và nạp phiên làm việc (in-memory & JSON file)
"""

import unittest
import tempfile
import os
from pathlib import Path
from datetime import datetime

from src.core.schemas import ActionType, IncidentStatus, RecommendedAction
from src.core.state import IncidentState
from src.core.hitl_manager import (
    DecisionType,
    HITLDecision,
    HITLManager,
    HITLSessionStore,
)


class TestHITLManager(unittest.TestCase):
    """Bộ kiểm thử cho HITLManager và HITLSessionStore."""

    def setUp(self):
        """Khởi tạo môi trường test trước mỗi test case."""
        self.manager = HITLManager()
        self.store = HITLSessionStore(hitl_manager=self.manager)

        # Tạo một IncidentState mẫu với 3 hành động:
        # Action 1: Cần duyệt, chưa duyệt (is_approved=None)
        # Action 2: Cần duyệt, chưa duyệt (is_approved=None)
        # Action 3: Không cần duyệt (require_human_approval=False, is_approved=None)
        self.action1 = RecommendedAction(
            action_id="ACT-001",
            action_type=ActionType.ISOLATE_HOST,
            target="WORKSTATION-01",
            description="Cô lập máy trạm khỏi mạng nội bộ",
            priority=1,
            require_human_approval=True,
            is_approved=None,
            parameters={"interface": "eth0", "timeout_sec": 3600}
        )
        self.action2 = RecommendedAction(
            action_id="ACT-002",
            action_type=ActionType.BLOCK_IP,
            target="194.26.29.112",
            description="Chặn IP C2 độc hại trên Firewall",
            priority=1,
            require_human_approval=True,
            is_approved=None,
            parameters={"firewall_zone": "external", "direction": "in_out"}
        )
        self.action3 = RecommendedAction(
            action_id="ACT-003",
            action_type=ActionType.KILL_PROCESS,
            target="PID-4420",
            description="Diệt tiến trình powershell.exe độc hại",
            priority=2,
            require_human_approval=False,
            is_approved=True,
            parameters={"pid": 4420, "force": True}
        )

        self.state = IncidentState(
            incident_id="INC-HITL-TEST-001",
            status=IncidentStatus.INVESTIGATING,
            recommended_actions=[self.action1, self.action2, self.action3]
        )

    def test_get_pending_actions(self):
        """Kiểm tra việc lọc danh sách các hành động đang chờ phê duyệt."""
        pending = self.manager.get_pending_actions(self.state)

        # Chỉ có action1 và action2 có require_human_approval=True và is_approved=None
        self.assertEqual(len(pending), 2)
        pending_ids = [a.action_id for a in pending]
        self.assertIn("ACT-001", pending_ids)
        self.assertIn("ACT-002", pending_ids)
        self.assertNotIn("ACT-003", pending_ids)

        # Kiểm tra nếu action chưa có action_id thì manager tự sinh ID
        action_no_id = RecommendedAction(
            action_id=None,
            action_type=ActionType.RESET_PASSWORD,
            target="victim_user",
            description="Đặt lại mật khẩu tài khoản người dùng",
            priority=3,
            require_human_approval=True,
            is_approved=None
        )
        state_with_no_id = IncidentState(
            incident_id="INC-NO-ID",
            recommended_actions=[action_no_id]
        )
        pending_no_id = self.manager.get_pending_actions(state_with_no_id)
        self.assertEqual(len(pending_no_id), 1)
        self.assertIsNotNone(pending_no_id[0].action_id)

    def test_approve_single_action(self):
        """Kiểm tra phê duyệt một hành động đơn lẻ."""
        decision = HITLDecision(
            decision_type=DecisionType.APPROVE,
            action_id="ACT-001",
            analyst_id="soc_senior_02",
            feedback_notes="Phê duyệt cách ly máy trạm để điều tra pháp chứng"
        )
        updated_state = self.manager.submit_decision(self.state, decision)

        # Action 1 phải được chuyển sang is_approved=True
        act1 = next(a for a in updated_state.recommended_actions if a.action_id == "ACT-001")
        self.assertTrue(act1.is_approved)

        # Action 2 vẫn chưa được duyệt
        act2 = next(a for a in updated_state.recommended_actions if a.action_id == "ACT-002")
        self.assertIsNone(act2.is_approved)

        # Kiểm tra ghi nhận transition
        transitions = [t for t in updated_state.history if t.node == "hitl_manager"]
        self.assertGreaterEqual(len(transitions), 1)
        last_t = transitions[-1]
        self.assertIn("APPROVE", last_t.message)
        self.assertEqual(last_t.metadata.get("analyst_id"), "soc_senior_02")

    def test_reject_single_action(self):
        """Kiểm tra từ chối một hành động đơn lẻ."""
        decision = HITLDecision(
            decision_type=DecisionType.REJECT,
            action_id="ACT-001",
            analyst_id="soc_analyst_01",
            feedback_notes="Không cô lập máy trạm vì đây là máy chủ quan trọng"
        )
        updated_state = self.manager.submit_decision(self.state, decision)

        act1 = next(a for a in updated_state.recommended_actions if a.action_id == "ACT-001")
        self.assertFalse(act1.is_approved)

        # Ghi nhận phản hồi của analyst
        self.assertEqual(updated_state.analyst_feedback, "Không cô lập máy trạm vì đây là máy chủ quan trọng")

    def test_modify_action_parameters(self):
        """Kiểm tra hiệu chỉnh tham số hành động và chấp thuận thi hành (MODIFY)."""
        modified_params = {
            "interface": "eth1",
            "timeout_sec": 7200,
            "target": "WORKSTATION-01-VLAN2",
            "description": "Cô lập máy trạm trên phân đoạn VLAN 2"
        }
        decision = HITLDecision(
            decision_type=DecisionType.MODIFY,
            action_id="ACT-001",
            modified_parameters=modified_params,
            analyst_id="soc_lead_01",
            feedback_notes="Điều chỉnh cổng mạng và thời gian cách ly thành 2 giờ"
        )
        updated_state = self.manager.submit_decision(self.state, decision)

        act1 = next(a for a in updated_state.recommended_actions if a.action_id == "ACT-001")
        self.assertTrue(act1.is_approved)
        self.assertEqual(act1.parameters.get("interface"), "eth1")
        self.assertEqual(act1.parameters.get("timeout_sec"), 7200)
        self.assertEqual(act1.target, "WORKSTATION-01-VLAN2")
        self.assertEqual(act1.description, "Cô lập máy trạm trên phân đoạn VLAN 2")

    def test_approve_all(self):
        """Kiểm tra phê duyệt toàn bộ các hành động đang chờ."""
        updated_state = self.manager.approve_all(
            self.state,
            analyst_id="soc_admin",
            notes="Đồng ý thực hiện toàn bộ kế hoạch ứng phó khẩn cấp"
        )

        # Cả 2 action chờ duyệt đều phải thành is_approved=True
        pending_after = self.manager.get_pending_actions(updated_state)
        self.assertEqual(len(pending_after), 0)
        for act in updated_state.recommended_actions:
            self.assertTrue(act.is_approved)

        self.assertTrue(updated_state.analyst_approved)
        self.assertEqual(updated_state.status, IncidentStatus.CONTAINED)
        self.assertIn("Đồng ý thực hiện toàn bộ", updated_state.analyst_feedback)

    def test_reject_all(self):
        """Kiểm tra từ chối toàn bộ các hành động đang chờ."""
        updated_state = self.manager.reject_all(
            self.state,
            analyst_id="soc_admin",
            notes="Hủy toàn bộ hành động do báo động giả"
        )

        pending_after = self.manager.get_pending_actions(updated_state)
        self.assertEqual(len(pending_after), 0)

        act1 = next(a for a in updated_state.recommended_actions if a.action_id == "ACT-001")
        act2 = next(a for a in updated_state.recommended_actions if a.action_id == "ACT-002")
        self.assertFalse(act1.is_approved)
        self.assertFalse(act2.is_approved)

        self.assertFalse(updated_state.analyst_approved)
        self.assertIn("Hủy toàn bộ hành động", updated_state.analyst_feedback)

    def test_is_approval_complete(self):
        """Kiểm tra phương thức kiểm tra mức độ hoàn tất phê duyệt."""
        # Ban đầu còn 2 action chờ duyệt -> False
        self.assertFalse(self.manager.is_approval_complete(self.state))

        # Duyệt action 1 -> vẫn còn action 2 -> False
        self.manager.submit_decision(
            self.state,
            HITLDecision(decision_type=DecisionType.APPROVE, action_id="ACT-001")
        )
        self.assertFalse(self.manager.is_approval_complete(self.state))

        # Từ chối action 2 -> hết pending -> True
        self.manager.submit_decision(
            self.state,
            HITLDecision(decision_type=DecisionType.REJECT, action_id="ACT-002")
        )
        self.assertTrue(self.manager.is_approval_complete(self.state))

    def test_session_store_save_load(self):
        """Kiểm tra tính năng lưu và nạp phiên làm việc của HITLSessionStore (in-memory & file JSON)."""
        # 1. Kiểm tra in-memory save & load
        saved_id = self.store.save_session(self.state)
        self.assertEqual(saved_id, self.state.incident_id)

        loaded_mem = self.store.load_session(incident_id=self.state.incident_id)
        self.assertIsNotNone(loaded_mem)
        self.assertEqual(loaded_mem.incident_id, self.state.incident_id)

        # Kiểm tra danh sách pending sessions
        pending_sessions = self.store.list_pending_sessions()
        self.assertIn(self.state.incident_id, pending_sessions)

        # 2. Kiểm tra export & load file JSON
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_file = Path(tmp_dir) / "hitl_session_test.json"
            out_path = self.store.save_session(self.state, file_path=json_file)
            self.assertTrue(Path(out_path).exists())

            # Load lại từ file
            loaded_file = self.store.load_session(file_path=json_file)
            self.assertIsNotNone(loaded_file)
            self.assertEqual(loaded_file.incident_id, self.state.incident_id)
            self.assertEqual(len(loaded_file.recommended_actions), 3)

        # 3. Kiểm tra load session không tồn tại
        self.assertIsNone(self.store.load_session(incident_id="NON-EXISTENT"))
        with self.assertRaises(FileNotFoundError):
            self.store.load_session(file_path="/tmp/non_existent_hitl_session_xyz.json")


if __name__ == "__main__":
    unittest.main()
