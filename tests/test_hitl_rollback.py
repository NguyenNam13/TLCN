# -*- coding: utf-8 -*-
"""
tests/test_hitl_rollback.py
Bộ kiểm thử tính năng Hoàn tác (Rollback) hành động phản ứng cho HITLManager.
Đảm bảo an toàn theo khuyến nghị của Security Auditor, Code Reviewer và Test Engineer:
- Không cho phép rollback hành động chưa được phê duyệt.
- Từ chối rollback hành động phá hủy/bất khả nghịch (KILL_PROCESS).
- Chuyển trạng thái linh hoạt theo RollbackReason (FALSE_POSITIVE, SERVICE_DISRUPTION, RECOVERY_COMPLETE).
- Lưu giữ snapshot checkpoint và ghi vết kiểm toán (record_transition) đầy đủ.
"""

import pytest
from datetime import datetime, timezone

from src.core.schemas import IncidentStatus, ActionType, RecommendedAction, SeverityLevel
from src.core.state import IncidentState
from src.core.hitl_manager import HITLManager, RollbackReason, HITLSessionStore
from src.tools.playbooks import create_bundle


@pytest.fixture
def base_incident_state() -> IncidentState:
    """Tạo IncidentState mẫu với các hành động phản ứng kèm script_bundle chuẩn."""
    action_isolate = RecommendedAction(
        action_id="ACT-001",
        action_type=ActionType.ISOLATE_HOST,
        target="192.168.1.100",
        priority=1,
        description="Cô lập máy trạm 192.168.1.100",
        is_approved=True,
        script_bundle=create_bundle("ACT-001", ActionType.ISOLATE_HOST, "192.168.1.100"),
    )
    action_block = RecommendedAction(
        action_id="ACT-002",
        action_type=ActionType.BLOCK_IP,
        target="45.33.32.156",
        priority=2,
        description="Chặn IP độc hại 45.33.32.156",
        is_approved=True,
        script_bundle=create_bundle("ACT-002", ActionType.BLOCK_IP, "45.33.32.156"),
    )
    action_kill = RecommendedAction(
        action_id="ACT-003",
        action_type=ActionType.KILL_PROCESS,
        target="4588",
        priority=1,
        description="Diệt tiến trình độc hại PID 4588",
        is_approved=True,
        script_bundle=create_bundle("ACT-003", ActionType.KILL_PROCESS, "4588"),
    )

    state = IncidentState(
        incident_id="INC-ROLLBACK-TEST-01",
        status=IncidentStatus.CONTAINED,
        severity=SeverityLevel.HIGH,
        recommended_actions=[action_isolate, action_block, action_kill],
    )
    return state


def test_rollback_single_action_success(base_incident_state):
    """Kiểm tra rollback thành công 1 hành động có khả năng đảo ngược (ISOLATE_HOST)."""
    mgr = HITLManager()
    state = mgr.rollback_action(
        state=base_incident_state,
        action_id="ACT-001",
        reason=RollbackReason.SERVICE_DISRUPTION,
        analyst_id="analyst_alice",
        notes="Máy chủ kế toán bị cô lập nhầm làm gián đoạn thanh toán",
    )

    # 1. Action ACT-001 phải được đánh dấu rollback
    act1 = state.recommended_actions[0]
    assert act1.is_approved is False
    assert act1.parameters.get("rollback_executed") is True
    assert act1.parameters.get("rollback_reason") == RollbackReason.SERVICE_DISRUPTION.value
    assert act1.parameters.get("rollback_by") == "analyst_alice"

    # 2. Do lý do là SERVICE_DISRUPTION, trạng thái phải đưa về INVESTIGATING
    assert state.status == IncidentStatus.INVESTIGATING

    # 3. Phải tạo checkpoint trước khi rollback
    checkpoint_keys = [k for k in state.checkpoints.keys() if k.startswith("pre_rollback_ACT-001")]
    assert len(checkpoint_keys) >= 1

    # 4. Phải ghi vết chuyển đổi trạng thái với transition history
    last_transition = state.history[-1]
    assert last_transition.node == "hitl_rollback"
    assert "analyst_alice" in last_transition.message
    assert last_transition.metadata.get("rollback_reason") == RollbackReason.SERVICE_DISRUPTION.value
    assert "Remove-NetFirewallRule" in last_transition.metadata.get("rollback_command", "")


def test_rollback_unapproved_action_raises_error(base_incident_state):
    """Không cho phép rollback một hành động chưa từng được duyệt."""
    mgr = HITLManager()
    # Chuyển ACT-001 về trạng thái chưa duyệt
    base_incident_state.recommended_actions[0].is_approved = None

    with pytest.raises(ValueError, match="chưa được phê duyệt"):
        mgr.rollback_action(
            state=base_incident_state,
            action_id="ACT-001",
            reason=RollbackReason.FALSE_POSITIVE,
        )


def test_rollback_irreversible_action_raises_error(base_incident_state):
    """Từ chối hoàn tác hành động KILL_PROCESS vì không khả nghịch."""
    mgr = HITLManager()
    with pytest.raises(ValueError, match="không thể hoàn tác"):
        mgr.rollback_action(
            state=base_incident_state,
            action_id="ACT-003",  # KILL_PROCESS
            reason=RollbackReason.FALSE_POSITIVE,
        )


def test_rollback_reason_false_positive_closes_incident(base_incident_state):
    """Khi lý do là FALSE_POSITIVE và tất cả action đã rollback -> đóng sự cố."""
    mgr = HITLManager()
    # Giả sử chỉ có 1 hành động duy nhất được duyệt
    base_incident_state.recommended_actions = [base_incident_state.recommended_actions[0]]

    state = mgr.rollback_action(
        state=base_incident_state,
        action_id="ACT-001",
        reason=RollbackReason.FALSE_POSITIVE,
        analyst_id="analyst_bob",
        notes="Báo cáo giả từ công cụ giám sát kiểm thử định kỳ",
    )

    assert state.status == IncidentStatus.CLOSED_FALSE_POSITIVE


def test_rollback_reason_recovery_complete_resolves_incident(base_incident_state):
    """Khi lý do là RECOVERY_COMPLETE và không còn action đang chặn -> RESOLVED."""
    mgr = HITLManager()
    base_incident_state.recommended_actions = [base_incident_state.recommended_actions[0]]

    state = mgr.rollback_action(
        state=base_incident_state,
        action_id="ACT-001",
        reason=RollbackReason.RECOVERY_COMPLETE,
        analyst_id="analyst_charlie",
        notes="Đã gỡ bỏ cô lập sau khi vá lỗ hổng triệt để",
    )

    assert state.status == IncidentStatus.RESOLVED


def test_rollback_all_multiple_actions(base_incident_state):
    """Kiểm tra hoàn tác đồng loạt toàn bộ hành động khả nghịch."""
    mgr = HITLManager()
    # ACT-001 và ACT-002 là khả nghịch, ACT-003 là bất khả nghịch (KILL_PROCESS)
    state = mgr.rollback_all(
        state=base_incident_state,
        reason=RollbackReason.FALSE_POSITIVE,
        analyst_id="lead_analyst",
        notes="Dương tính giả toàn diện trong đợt diễn tập Red Team",
    )

    act1 = state.recommended_actions[0]
    act2 = state.recommended_actions[1]
    act3 = state.recommended_actions[2]

    # ACT-001 và ACT-002 được rollback
    assert act1.is_approved is False
    assert act1.parameters.get("rollback_executed") is True
    assert act2.is_approved is False
    assert act2.parameters.get("rollback_executed") is True

    # ACT-003 giữ nguyên vì là bất khả nghịch
    assert act3.is_approved is True
    assert not (act3.parameters and act3.parameters.get("rollback_executed"))

    # Trạng thái tổng thể đóng sự cố
    assert state.status == IncidentStatus.CLOSED_FALSE_POSITIVE

    # Checkpoint tổng thể được tạo
    assert any(k.startswith("pre_rollback_all") for k in state.checkpoints.keys())


def test_hitl_session_store_preserves_rollback_state(tmp_path, base_incident_state):
    """Kiểm tra SessionStore lưu trữ và phục hồi trạng thái sau rollback chính xác."""
    mgr = HITLManager()
    store = HITLSessionStore(hitl_manager=mgr)

    # Thực hiện rollback
    mgr.rollback_action(
        state=base_incident_state,
        action_id="ACT-001",
        reason=RollbackReason.SERVICE_DISRUPTION,
        analyst_id="analyst_dave",
        notes="Gián đoạn dịch vụ kế toán",
    )

    # Lưu vào file JSON
    save_file = tmp_path / "session_rollback_test.json"
    store.save_session(base_incident_state, file_path=save_file)

    # Tải lại từ file
    loaded_state = store.load_session(file_path=save_file)
    assert loaded_state is not None
    assert loaded_state.incident_id == base_incident_state.incident_id
    assert loaded_state.status == IncidentStatus.INVESTIGATING
    assert loaded_state.recommended_actions[0].parameters.get("rollback_executed") is True
    assert len(loaded_state.checkpoints) >= 1


def test_reporting_reflects_rollback_status(base_incident_state):
    """Kiểm tra ReportingAgent hiển thị chính xác trạng thái Hoàn tác trong Báo cáo."""
    from src.agents.reporting_agent import ReportingAgent
    mgr = HITLManager()
    state = mgr.rollback_action(
        state=base_incident_state,
        action_id="ACT-001",
        reason=RollbackReason.FALSE_POSITIVE,
        analyst_id="analyst_test",
        notes="Báo cáo kiểm thử định kỳ",
    )

    agent = ReportingAgent()
    report = agent.generate_report(state)
    md = agent.export_markdown(report)

    # 1. Bảng Action Plan phải hiển thị trạng thái hoàn tác kèm lý do
    assert "Đã hoàn tác (FALSE_POSITIVE)" in md

    # 2. Báo cáo kỹ thuật phải có mục 2.6 Nhật ký hoàn tác
    assert "2.6. Nhật ký Hoàn tác & Khôi phục Hiện trạng" in report.detailed_findings
    assert "Remove-NetFirewallRule" in report.detailed_findings

    # 3. Header thời gian phải được định dạng theo giờ Việt Nam (ICT)
    assert "(ICT / Giờ Việt Nam)" in md


def test_rollback_auto_regenerates_final_report(base_incident_state):
    """Kiểm tra khi đã có final_report, rollback_action sẽ tự động cập nhật lại final_report."""
    from src.agents.reporting_agent import ReportingAgent
    agent = ReportingAgent()
    # Sinh báo cáo ban đầu khi chưa rollback
    base_incident_state.final_report = agent.generate_report(base_incident_state)
    initial_action_status = [a.is_approved for a in base_incident_state.final_report.action_plan]
    assert initial_action_status[0] is True

    # Kích hoạt Rollback
    mgr = HITLManager()
    state = mgr.rollback_action(
        state=base_incident_state,
        action_id="ACT-001",
        reason=RollbackReason.SERVICE_DISRUPTION,
        analyst_id="lead_analyst",
        notes="Gián đoạn dịch vụ thanh toán",
    )

    # Báo cáo final_report phải được tự động tái tạo và cập nhật trạng thái mới
    assert state.final_report is not None
    act1_in_report = state.final_report.action_plan[0]
    assert act1_in_report.parameters.get("rollback_executed") is True
    assert act1_in_report.parameters.get("rollback_reason") == RollbackReason.SERVICE_DISRUPTION.value


def test_vietnam_timezone_conversion():
    """Kiểm tra chuyển đổi thời gian UTC sang múi giờ Việt Nam (ICT, UTC+7).
    Trường hợp từ ảnh người dùng: 2026-10-22 07:24:38 UTC -> phải chuyển thành 14:24:38 tại Việt Nam.
    """
    from datetime import datetime, timezone
    from src.core.time_utils import to_vn_time, format_vn_time

    # Giờ trong ảnh của người dùng
    utc_dt = datetime(2026, 10, 22, 7, 24, 38, tzinfo=timezone.utc)
    vn_dt = to_vn_time(utc_dt)

    assert vn_dt.hour == 14
    assert vn_dt.minute == 24
    assert vn_dt.second == 38
    assert vn_dt.day == 22

    formatted = format_vn_time(utc_dt)
    assert formatted == "2026-10-22 14:24:38 (ICT)"

