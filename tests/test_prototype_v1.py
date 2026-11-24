# -*- coding: utf-8 -*-
"""
tests/test_prototype_v1.py
Kiểm thử Tích hợp Toàn diện Prototype v1.0 (Tuần 10).
Xác thực sự kết nối hoàn chỉnh giữa 6 Agent trong StateGraph Orchestrator,
cơ chế Human-In-The-Loop (HITL) ngắt/tiếp tục, đồng bộ với Dashboard UI logic,
và đo lường hiệu năng (Latency Benchmark) trên dữ liệu EVE-NG Wazuh alert thực tế.
"""

import unittest
import time
import json
from datetime import datetime, timezone

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    RawLogInput,
    ParsedEvent,
    RecommendedAction,
)
from src.core.state import IncidentState
from src.core.hitl_manager import HITLManager, HITLDecision, DecisionType, HITLSessionStore
from src.core.orchestrator import create_full_soc_pipeline, StateGraphOrchestrator, END
from src.ui.dashboard import load_scenario_alerts, create_initial_incident_state


class TestPrototypeV1Integration(unittest.TestCase):
    """Bộ kiểm thử tích hợp toàn diện Prototype v1.0."""

    def setUp(self):
        """Khởi tạo pipeline SOC hoàn chỉnh và HITL Manager."""
        self.hitl_manager = HITLManager()
        self.pipeline = create_full_soc_pipeline(
            hitl_manager=self.hitl_manager,
            auto_approve=False,  # Bật chế độ HITL ngắt nhịp chờ chuyên viên
            auto_instantiate_missing=True,
        )

    def test_prototype_v1_malware_end_to_end_with_hitl_approval(self):
        """
        Kiểm thử Kịch bản 1: Lây nhiễm Malware thực tế từ EVE-NG Wazuh.
        Pipeline tự động ngắt tại node hitl_approval (AWAITING_APPROVAL),
        Chuyên viên SOC duyệt hành động và pipeline chạy tiếp đến RESOLVED.
        """
        raw_alerts, title = load_scenario_alerts("malware")
        self.assertGreater(len(raw_alerts), 0)

        initial_state = create_initial_incident_state("malware", raw_alerts)
        self.assertEqual(initial_state.status, IncidentStatus.NEW)

        # 1. Chạy pipeline đến điểm ngắt HITL
        is_paused, paused_state = self.pipeline.execute_until_interrupt(initial_state)
        self.assertTrue(is_paused, "Pipeline phải tạm dừng khi có hành động cần chuyên viên duyệt")
        self.assertEqual(paused_state.status, IncidentStatus.AWAITING_APPROVAL)

        # Kiểm tra kết quả các node trước đó
        self.assertIsNotNone(paused_state.triage_result)
        self.assertTrue(paused_state.triage_result.is_incident)
        self.assertIsNotNone(paused_state.attack_type)
        self.assertIn("Malware", paused_state.attack_type)
        self.assertIsNotNone(paused_state.threat_intel)
        self.assertGreater(len(paused_state.threat_intel.extracted_iocs), 0)
        self.assertIsNotNone(paused_state.rca_result)
        self.assertGreater(len(paused_state.rca_result.process_tree), 0)
        self.assertGreater(len(paused_state.recommended_actions), 0)

        # Kiểm tra danh sách hành động chờ duyệt
        pending_actions = self.hitl_manager.get_pending_actions(paused_state)
        self.assertGreater(len(pending_actions), 0)

        # 2. Chuyên viên duyệt toàn bộ hành động
        approved_state = self.hitl_manager.approve_all(
            paused_state,
            analyst_id="soc_analyst_nam",
            notes="Phê duyệt cô lập máy trạm và chặn IP C2 theo NIST SP 800-61"
        )
        self.assertTrue(self.hitl_manager.is_approval_complete(approved_state))

        # 3. Tiếp tục thực thi pipeline đến hoàn tất
        final_state = self.pipeline.resume_from_interrupt(approved_state)
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        self.assertIsNotNone(final_state.final_report)
        self.assertIn("Báo cáo", final_state.final_report.incident_title)
        self.assertIsNotNone(final_state.final_report.attack_type)
        self.assertIn("Malware", final_state.final_report.attack_type)
        self.assertEqual(len(final_state.final_report.action_plan), len(final_state.recommended_actions))

        # Xác nhận lịch sử chuyển trạng thái
        nodes_in_history = [t.node for t in final_state.history]
        self.assertIn("ingestion", nodes_in_history)
        self.assertIn("triage", nodes_in_history)
        self.assertTrue(any(n in nodes_in_history for n in ["enrichment", "ThreatIntelAgent"]))
        self.assertIn("rca", nodes_in_history)
        self.assertIn("response", nodes_in_history)
        self.assertIn("hitl_approval", nodes_in_history)
        self.assertIn("reporting", nodes_in_history)

    def test_prototype_v1_analyst_modify_action_parameters(self):
        """
        Kiểm thử Kịch bản 2: Chuyên viên SOC tùy biến tham số hành động trước khi duyệt.
        (Ví dụ đổi cổng, thời gian timeout của active response firewall-drop).
        """
        raw_alerts, _ = load_scenario_alerts("malware")
        initial_state = create_initial_incident_state("malware", raw_alerts)

        is_paused, paused_state = self.pipeline.execute_until_interrupt(initial_state)
        self.assertTrue(is_paused)

        pending = self.hitl_manager.get_pending_actions(paused_state)
        target_action = pending[0]

        # Gửi quyết định MODIFY
        decision = HITLDecision(
            decision_type=DecisionType.MODIFY,
            action_id=target_action.action_id,
            modified_parameters={"timeout": 7200, "interface": "eth0", "custom_flag": True},
            analyst_id="soc_senior_do",
            feedback_notes="Kéo dài thời gian khóa firewall lên 2 giờ"
        )
        modified_state = self.hitl_manager.submit_decision(paused_state, decision)

        # Duyệt nốt các hành động còn lại nếu có
        for act in self.hitl_manager.get_pending_actions(modified_state):
            self.hitl_manager.submit_decision(
                modified_state,
                HITLDecision(
                    decision_type=DecisionType.APPROVE,
                    action_id=act.action_id,
                    analyst_id="soc_senior_do",
                )
            )

        # Chạy tiếp
        final_state = self.pipeline.resume_from_interrupt(modified_state)
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)

        # Xác nhận tham số chỉnh sửa được bảo toàn trong final report
        matched_action = next(a for a in final_state.final_report.action_plan if a.action_id == target_action.action_id)
        self.assertTrue(matched_action.is_approved)
        self.assertEqual(matched_action.parameters.get("timeout"), 7200)
        self.assertEqual(matched_action.parameters.get("interface"), "eth0")

    def test_prototype_v1_analyst_reject_all_actions(self):
        """
        Kiểm thử Kịch bản 3: Chuyên viên SOC từ chối toàn bộ hành động (false alert hoặc can thiệp thủ công).
        """
        raw_alerts, _ = load_scenario_alerts("phishing")
        initial_state = create_initial_incident_state("phishing", raw_alerts)

        is_paused, paused_state = self.pipeline.execute_until_interrupt(initial_state)
        self.assertTrue(is_paused)

        # Từ chối toàn bộ
        rejected_state = self.hitl_manager.reject_all(
            paused_state,
            analyst_id="soc_lead_nam",
            notes="Tài khoản nội bộ đã được đổi mật khẩu thủ công qua AD"
        )
        self.assertTrue(self.hitl_manager.is_approval_complete(rejected_state))

        final_state = self.pipeline.resume_from_interrupt(rejected_state)
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        self.assertTrue(all(a.is_approved is False for a in final_state.recommended_actions))

    def test_prototype_v1_benign_false_positive_short_circuit(self):
        """
        Kiểm thử Kịch bản 4: Sự cố bình thường (Benign / False Positive).
        Pipeline tự động rẽ nhánh sang closed_fp và không bao giờ gọi HITL hoặc Response.
        """
        raw_alerts, _ = load_scenario_alerts("benign")
        initial_state = create_initial_incident_state("benign", raw_alerts)

        is_paused, final_state = self.pipeline.execute_until_interrupt(initial_state)
        self.assertFalse(is_paused, "Sự cố False Positive không được tạm dừng chờ HITL")
        self.assertEqual(final_state.status, IncidentStatus.CLOSED_FALSE_POSITIVE)
        self.assertIsNotNone(final_state.attack_type)
        self.assertIn("Benign", final_state.attack_type)

        # Xác nhận không có hành động nào và dừng sớm
        self.assertEqual(len(final_state.recommended_actions), 0)
        nodes_executed = [t.node for t in final_state.history]
        self.assertIn("closed_fp", nodes_executed)
        self.assertNotIn("hitl_approval", nodes_executed)
        self.assertNotIn("reporting", nodes_executed)

    def test_prototype_v1_session_persistence_integration(self):
        """
        Kiểm thử Kịch bản 5: Lưu trữ và nạp phiên làm việc qua HITLSessionStore khi pipeline ngắt quãng.
        """
        raw_alerts, _ = load_scenario_alerts("malware")
        initial_state = create_initial_incident_state("malware", raw_alerts)

        is_paused, paused_state = self.pipeline.execute_until_interrupt(initial_state)
        self.assertTrue(is_paused)

        store = HITLSessionStore()
        saved_id = store.save_session(paused_state)
        self.assertEqual(saved_id, paused_state.incident_id)

        # Nạp lại từ store
        restored_state = store.load_session(saved_id)
        self.assertIsNotNone(restored_state)
        self.assertEqual(restored_state.incident_id, paused_state.incident_id)
        self.assertEqual(restored_state.status, IncidentStatus.AWAITING_APPROVAL)

        # Chuyên viên duyệt trên state được khôi phục
        self.hitl_manager.approve_all(restored_state)
        final_state = self.pipeline.resume_from_interrupt(restored_state)
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)

    def test_prototype_v1_end_to_end_latency_benchmark(self):
        """
        Kiểm thử Benchmark Hiệu năng (MTTI - Mean Time to Investigate).
        Xác nhận chu trình phân tích tự động (Ingestion -> Triage -> CTI -> RCA -> Response)
        hoàn tất trong vòng dưới 1000ms đối với dữ liệu EVE-NG Wazuh thực tế.
        """
        raw_alerts, _ = load_scenario_alerts("malware")
        initial_state = create_initial_incident_state("malware", raw_alerts)

        start_time = time.perf_counter()
        is_paused, paused_state = self.pipeline.execute_until_interrupt(initial_state)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        self.assertTrue(is_paused)
        self.assertLess(elapsed_ms, 1000.0, f"Độ trễ phân tích ({elapsed_ms:.2f}ms) vượt quá ngưỡng cho phép 1000ms")
        print(f"\n[BENCHMARK] Prototype v1.0 Pipeline Automated Investigation Latency: {elapsed_ms:.2f} ms")


if __name__ == "__main__":
    unittest.main()
