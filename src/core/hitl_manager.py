# -*- coding: utf-8 -*-
"""
src/core/hitl_manager.py
Module quản lý tương tác Người Trong Vòng Lặp (Human-In-The-Loop - HITL) nâng cao.
Cung cấp khả năng thẩm định, phê duyệt (APPROVE), từ chối (REJECT) hoặc hiệu chỉnh tham số (MODIFY)
cho từng hành động ứng phó (RecommendedAction), cũng như lưu trữ phiên làm việc (HITLSessionStore).
"""

import uuid
import json
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any, Union
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from src.core.schemas import IncidentStatus, RecommendedAction, ActionType
from src.core.state import IncidentState


class RollbackReason(str, Enum):
    """Lý do thực hiện hoàn tác (Rollback) hành động phản ứng."""
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SERVICE_DISRUPTION = "SERVICE_DISRUPTION"
    RECOVERY_COMPLETE = "RECOVERY_COMPLETE"


class DecisionType(str, Enum):
    """Phân loại quyết định của chuyên viên SOC đối với hành động ứng phó."""
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    MODIFY = "MODIFY"


class HITLDecision(BaseModel):
    """Mô hình quyết định của chuyên viên SOC đối với một hành động cụ thể."""
    decision_id: str = Field(
        default_factory=lambda: f"DEC-{uuid.uuid4().hex[:8].upper()}",
        description="ID duy nhất của quyết định thẩm định"
    )
    decision_type: DecisionType = Field(
        ...,
        description="Loại quyết định: APPROVE (chấp thuận), REJECT (từ chối), MODIFY (sửa tham số & chấp thuận)"
    )
    action_id: str = Field(
        ...,
        description="ID của hành động phản ứng (RecommendedAction.action_id) được áp dụng"
    )
    modified_parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Các tham số thực thi được điều chỉnh nếu decision_type=MODIFY"
    )
    analyst_id: str = Field(
        default="soc_analyst_01",
        description="Mã định danh chuyên viên phân tích SOC thực hiện quyết định"
    )
    feedback_notes: Optional[str] = Field(
        default=None,
        description="Ghi chú, lý do hoặc chỉ dẫn nghiệp vụ của chuyên viên"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Thời điểm chuyên viên đưa ra quyết định"
    )


class HITLManager:
    """Quản lý các thao tác tương tác và phê duyệt của con người trong quy trình SOC."""

    def __init__(self, default_analyst_id: str = "soc_analyst_01"):
        self.default_analyst_id = default_analyst_id

    def get_pending_actions(self, state: IncidentState) -> List[RecommendedAction]:
        """Lọc danh sách các hành động ứng phó đang chờ chuyên viên phê duyệt.
        
        Điều kiện: require_human_approval=True và is_approved is None.
        Tự động đảm bảo mỗi hành động đều có action_id hợp lệ.
        """
        pending: List[RecommendedAction] = []
        for idx, action in enumerate(state.recommended_actions):
            if action.action_id is None:
                action.action_id = f"ACT-{idx+1:03d}"

            if action.require_human_approval and action.is_approved is None:
                pending.append(action)
        return pending

    def submit_decision(self, state: IncidentState, decision: HITLDecision) -> IncidentState:
        """Áp dụng quyết định của chuyên viên lên một hành động phản ứng cụ thể trong state."""
        # Đảm bảo các actions đều có action_id trước khi tìm kiếm
        for idx, act in enumerate(state.recommended_actions):
            if act.action_id is None:
                act.action_id = f"ACT-{idx+1:03d}"

        target_action: Optional[RecommendedAction] = None
        for action in state.recommended_actions:
            if action.action_id == decision.action_id:
                target_action = action
                break

        if target_action is None:
            raise ValueError(f"Không tìm thấy hành động với action_id='{decision.action_id}' trong IncidentState")

        # Áp dụng quyết định
        if decision.decision_type == DecisionType.APPROVE:
            target_action.is_approved = True
        elif decision.decision_type == DecisionType.REJECT:
            target_action.is_approved = False
        elif decision.decision_type == DecisionType.MODIFY:
            if target_action.parameters is None:
                target_action.parameters = {}
            if decision.modified_parameters:
                target_action.parameters.update(decision.modified_parameters)
                # Nếu có sửa đổi trực tiếp target, description, priority thì đồng bộ
                if "target" in decision.modified_parameters:
                    target_action.target = str(decision.modified_parameters["target"])
                if "description" in decision.modified_parameters:
                    target_action.description = str(decision.modified_parameters["description"])
                if "priority" in decision.modified_parameters:
                    target_action.priority = int(decision.modified_parameters["priority"])
            target_action.is_approved = True

        # Ghi nhận phản hồi vào state
        if decision.feedback_notes:
            state.analyst_feedback = decision.feedback_notes

        # Ghi vết chuyển đổi trạng thái
        msg = f"Chuyên viên {decision.analyst_id} ra quyết định {decision.decision_type.value} cho action '{decision.action_id}'"
        if decision.feedback_notes:
            msg += f": {decision.feedback_notes}"

        state.record_transition(
            node="hitl_manager",
            to_status=state.status,
            message=msg,
            metadata={
                "decision_id": decision.decision_id,
                "action_id": decision.action_id,
                "decision_type": decision.decision_type.value,
                "analyst_id": decision.analyst_id,
                "modified_parameters": decision.modified_parameters,
                "feedback_notes": decision.feedback_notes,
            }
        )

        # Cập nhật tổng thể analyst_approved nếu tất cả hành động đã được giải quyết
        pending = self.get_pending_actions(state)
        if len(pending) == 0:
            approved_any = any(a.is_approved is True for a in state.recommended_actions)
            state.analyst_approved = approved_any

        return state

    def approve_all(
        self,
        state: IncidentState,
        analyst_id: str = "soc_analyst_01",
        notes: Optional[str] = None
    ) -> IncidentState:
        """Phê duyệt toàn bộ các hành động ứng phó đang chờ."""
        pending = self.get_pending_actions(state)
        for action in pending:
            decision = HITLDecision(
                decision_type=DecisionType.APPROVE,
                action_id=action.action_id,
                analyst_id=analyst_id,
                feedback_notes=notes or "Phê duyệt hành động"
            )
            self.submit_decision(state, decision)

        state.analyst_approved = True
        state.analyst_feedback = notes or "Phê duyệt toàn bộ hành động ứng phó"
        state.record_transition(
            node="hitl_manager",
            to_status=IncidentStatus.CONTAINED,
            message=f"Chuyên viên {analyst_id} phê duyệt toàn bộ {len(pending)} hành động",
            metadata={"approved_all": True, "count": len(pending), "analyst_id": analyst_id}
        )
        return state

    def reject_all(
        self,
        state: IncidentState,
        analyst_id: str = "soc_analyst_01",
        notes: Optional[str] = None
    ) -> IncidentState:
        """Từ chối toàn bộ các hành động ứng phó đang chờ."""
        pending = self.get_pending_actions(state)
        for action in pending:
            decision = HITLDecision(
                decision_type=DecisionType.REJECT,
                action_id=action.action_id,
                analyst_id=analyst_id,
                feedback_notes=notes or "Từ chối hành động"
            )
            self.submit_decision(state, decision)

        state.analyst_approved = False
        state.analyst_feedback = notes or "Từ chối toàn bộ hành động ứng phó"
        state.record_transition(
            node="hitl_manager",
            to_status=IncidentStatus.INVESTIGATING,
            message=f"Chuyên viên {analyst_id} từ chối toàn bộ {len(pending)} hành động",
            metadata={"rejected_all": True, "count": len(pending), "analyst_id": analyst_id}
        )
        return state

    def is_approval_complete(self, state: IncidentState) -> bool:
        """Kiểm tra xem toàn bộ các hành động yêu cầu phê duyệt đã có quyết định hay chưa."""
        return len(self.get_pending_actions(state)) == 0

    def rollback_action(
        self,
        state: IncidentState,
        action_id: str,
        reason: RollbackReason,
        analyst_id: str = "soc_analyst_01",
        notes: Optional[str] = None
    ) -> IncidentState:
        """Thực hiện hoàn tác (Rollback) một hành động phản ứng đã được phê duyệt và áp dụng.
        
        Quy trình an toàn:
        1. Kiểm tra action_id tồn tại.
        2. Xác thực action đã được duyệt (is_approved is True).
        3. Kiểm tra tính khả nghịch (khác KILL_PROCESS, có script_bundle.rollback_script).
        4. Lưu snapshot state vào checkpoints.
        5. Cập nhật action status và metadata.
        6. Chuyển đổi trạng thái Incident theo RollbackReason phù hợp:
           - FALSE_POSITIVE: Nếu tất cả action đã rollback/reject -> CLOSED_FALSE_POSITIVE.
           - SERVICE_DISRUPTION: INVESTIGATING (để chuyên viên điều chỉnh chiến thuật).
           - RECOVERY_COMPLETE: RESOLVED (hoặc giữ nguyên nếu còn action khác).
        """
        target_action: Optional[RecommendedAction] = None
        for act in state.recommended_actions:
            if act.action_id == action_id:
                target_action = act
                break

        if target_action is None:
            raise ValueError(f"Không tìm thấy hành động với action_id='{action_id}' trong IncidentState")

        if target_action.is_approved is not True:
            raise ValueError(
                f"Hành động '{action_id}' chưa được phê duyệt (is_approved={target_action.is_approved}). "
                "Chỉ có thể hoàn tác các hành động đã được phê duyệt và thực thi."
            )

        # Kiểm tra tính khả nghịch
        if (
            target_action.action_type == ActionType.KILL_PROCESS
            or target_action.script_bundle is None
            or target_action.script_bundle.rollback_script is None
        ):
            raise ValueError(
                f"Hành động '{action_id}' ({target_action.action_type.value}) không thể hoàn tác "
                "(hành động không khả nghịch hoặc thiếu kịch bản rollback_script)."
            )

        # Lưu checkpoint trước khi rollback
        checkpoint_key = f"pre_rollback_{action_id}_{int(datetime.now(timezone.utc).timestamp())}"
        state.checkpoints[checkpoint_key] = state.model_dump(mode="json")

        # Đánh dấu hoàn tác trên action
        target_action.is_approved = False
        if target_action.parameters is None:
            target_action.parameters = {}
        target_action.parameters["rollback_executed"] = True
        target_action.parameters["rollback_reason"] = reason.value
        target_action.parameters["rollback_by"] = analyst_id
        target_action.parameters["rollback_at"] = datetime.now(timezone.utc).isoformat()

        # Định tuyến trạng thái IncidentState theo RollbackReason
        if reason == RollbackReason.FALSE_POSITIVE:
            # Kiểm tra xem còn action nào đang được duyệt mà chưa hoàn tác không
            remaining_active = [
                a for a in state.recommended_actions
                if a.is_approved is True and not (a.parameters and a.parameters.get("rollback_executed"))
            ]
            if len(remaining_active) == 0:
                state.status = IncidentStatus.CLOSED_FALSE_POSITIVE
        elif reason == RollbackReason.SERVICE_DISRUPTION:
            state.status = IncidentStatus.INVESTIGATING
        elif reason == RollbackReason.RECOVERY_COMPLETE:
            remaining_active = [
                a for a in state.recommended_actions
                if a.is_approved is True and not (a.parameters and a.parameters.get("rollback_executed"))
            ]
            if len(remaining_active) == 0:
                state.status = IncidentStatus.RESOLVED

        # Ghi vết chuyển đổi trạng thái
        rollback_cmd = target_action.script_bundle.rollback_script
        msg = (
            f"Chuyên viên {analyst_id} đã hoàn tác (Rollback) hành động '{action_id}' "
            f"({target_action.action_type.value}). Lý do: {reason.value}."
        )
        if notes:
            msg += f" Ghi chú: {notes}"

        state.record_transition(
            node="hitl_rollback",
            to_status=state.status,
            message=msg,
            metadata={
                "action_id": action_id,
                "action_type": target_action.action_type.value,
                "rollback_reason": reason.value,
                "rollback_command": rollback_cmd,
                "analyst_id": analyst_id,
                "notes": notes,
                "target": target_action.target,
            }
        )

        # Tự động đồng bộ và tái tạo lại Báo cáo điều tra nếu báo cáo đã được sinh trước đó
        if state.final_report is not None:
            try:
                from src.agents.reporting_agent import ReportingAgent
                state.final_report = ReportingAgent().generate_report(state)
            except Exception:
                pass

        return state

    def rollback_all(
        self,
        state: IncidentState,
        reason: RollbackReason,
        analyst_id: str = "soc_analyst_01",
        notes: Optional[str] = None
    ) -> IncidentState:
        """Hoàn tác toàn bộ các hành động phản ứng đã được phê duyệt và có khả năng rollback."""
        approved_actions = [
            act for act in state.recommended_actions
            if act.is_approved is True
            and act.action_type != ActionType.KILL_PROCESS
            and act.script_bundle is not None
            and act.script_bundle.rollback_script is not None
        ]

        if not approved_actions:
            raise ValueError("Không có hành động nào đã phê duyệt thỏa mãn điều kiện hoàn tác (hoặc tất cả là bất khả nghịch).")

        # Lưu checkpoint tổng thể
        checkpoint_key = f"pre_rollback_all_{int(datetime.now(timezone.utc).timestamp())}"
        state.checkpoints[checkpoint_key] = state.model_dump(mode="json")

        rolled_back_ids: List[str] = []
        for act in approved_actions:
            act.is_approved = False
            if act.parameters is None:
                act.parameters = {}
            act.parameters["rollback_executed"] = True
            act.parameters["rollback_reason"] = reason.value
            act.parameters["rollback_by"] = analyst_id
            act.parameters["rollback_at"] = datetime.now(timezone.utc).isoformat()
            rolled_back_ids.append(act.action_id)

        # Cập nhật trạng thái tổng thể
        if reason == RollbackReason.FALSE_POSITIVE:
            state.status = IncidentStatus.CLOSED_FALSE_POSITIVE
        elif reason == RollbackReason.SERVICE_DISRUPTION:
            state.status = IncidentStatus.INVESTIGATING
        elif reason == RollbackReason.RECOVERY_COMPLETE:
            state.status = IncidentStatus.RESOLVED

        state.analyst_approved = False
        state.analyst_feedback = f"Rollback toàn bộ ({reason.value}): {notes or 'Không có ghi chú'}"

        state.record_transition(
            node="hitl_rollback_all",
            to_status=state.status,
            message=f"Chuyên viên {analyst_id} hoàn tác hàng loạt {len(rolled_back_ids)} hành động ({reason.value}).",
            metadata={
                "rolled_back_action_ids": rolled_back_ids,
                "rollback_reason": reason.value,
                "analyst_id": analyst_id,
                "notes": notes
            }
        )

        # Tự động đồng bộ và tái tạo lại Báo cáo điều tra nếu báo cáo đã được sinh trước đó
        if state.final_report is not None:
            try:
                from src.agents.reporting_agent import ReportingAgent
                state.final_report = ReportingAgent().generate_report(state)
            except Exception:
                pass

        return state


class HITLSessionStore:
    """Quản lý lưu trữ phiên làm việc của chuyên viên SOC (In-Memory và JSON File Export/Load)."""

    def __init__(self, hitl_manager: Optional[HITLManager] = None):
        self._sessions: Dict[str, IncidentState] = {}
        self.hitl_manager = hitl_manager or HITLManager()

    def save_session(self, state: IncidentState, file_path: Optional[Union[str, Path]] = None) -> str:
        """Lưu trữ IncidentState vào session store in-memory và xuất file JSON nếu có chỉ định file_path."""
        self._sessions[state.incident_id] = state

        if file_path is not None:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(state.model_dump_json(indent=2))
            return str(path)

        return state.incident_id

    def load_session(
        self,
        incident_id: Optional[str] = None,
        file_path: Optional[Union[str, Path]] = None
    ) -> Optional[IncidentState]:
        """Tải phiên làm việc từ file JSON hoặc từ bộ nhớ in-memory."""
        if file_path is not None:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"Tệp phiên làm việc không tồn tại: {file_path}")
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            state = IncidentState.model_validate_json(content)
            self._sessions[state.incident_id] = state
            return state

        if incident_id is not None and incident_id in self._sessions:
            return self._sessions[incident_id]

        return None

    def list_pending_sessions(self) -> List[str]:
        """Liệt kê danh sách các incident_id của những phiên đang có hành động chờ phê duyệt."""
        pending_ids: List[str] = []
        for inc_id, state in self._sessions.items():
            if not self.hitl_manager.is_approval_complete(state):
                pending_ids.append(inc_id)
        return pending_ids
