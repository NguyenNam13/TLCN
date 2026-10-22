# -*- coding: utf-8 -*-
"""
src/core/state.py
Quản lý trạng thái tập trung (Central State) cho LangGraph StateGraph.
Định nghĩa cấu trúc State luân chuyển giữa các Agent trong hệ thống Multi-Agent.
"""

from typing import List, Optional, Dict, Any, TypedDict
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    ThreatIntelEnrichment,
    RootCauseAnalysis,
    RecommendedAction,
    IncidentReport,
)


class StateTransition(BaseModel):
    """Lưu vết từng bước chuyển đổi trạng thái (State Transition Record)."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    node: str = Field(..., description="Tên node thực thi chuyển dịch")
    from_status: IncidentStatus = Field(..., description="Trạng thái trước khi chuyển")
    to_status: IncidentStatus = Field(..., description="Trạng thái sau khi chuyển")
    message: Optional[str] = Field(None, description="Ghi chú hoặc lý do chuyển trạng thái")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Thông tin phụ trợ (scores, rules, alerts)")


class IncidentState(BaseModel):
    """Mô hình Pydantic cho Trạng thái sự cố xuyên suốt pipeline."""
    incident_id: str = Field(..., description="ID định danh duy nhất của sự cố")
    status: IncidentStatus = Field(IncidentStatus.NEW, description="Trạng thái hiện tại của sự cố")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # 1. Dữ liệu thô và đã xử lý
    raw_logs: List[RawLogInput] = Field(default_factory=list)
    parsed_events: List[ParsedEvent] = Field(default_factory=list)
    
    # 2. Kết quả từ Triage Agent
    triage_result: Optional[TriageOutput] = None
    
    # 3. Kết quả từ Threat Intel Agent
    threat_intel: Optional[ThreatIntelEnrichment] = None
    
    # 4. Kết quả từ RCA Agent
    rca_result: Optional[RootCauseAnalysis] = None
    
    # 5. Kết quả từ Response Agent
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    
    # 6. Kết quả từ Reporting Agent
    final_report: Optional[IncidentReport] = None
    
    # 7. Nhận diện loại tấn công (Attack Classification)
    attack_type: Optional[str] = Field(default=None, description="Định danh loại tấn công chính được phát hiện")

    # 8. Thông tin điều khiển / Human-in-the-loop (HITL)
    analyst_approved: Optional[bool] = None
    analyst_feedback: Optional[str] = None
    next_node: Optional[str] = None
    error_message: Optional[str] = None

    # 9. Cơ chế Quay lui & Phân tích lại (Backtracking & Feedback Loop)
    reanalysis_count: int = Field(default=0, description="Số lần quay lui phân tích lại khi phát hiện sai lệch hoặc bị từ chối")
    max_reanalysis: int = Field(default=2, description="Giới hạn số lần quay lui tối đa để tránh lặp vô tận")
    reanalysis_reason: Optional[str] = Field(default=None, description="Lý do kích hoạt quay lui phân tích lại")

    # 10. State Transition History & Checkpoints
    history: List[StateTransition] = Field(default_factory=list, description="Lịch sử chuyển dịch trạng thái qua các node")
    checkpoints: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Checkpoints snapshot lưu trữ tại từng node")

    def record_transition(
        self,
        node: str,
        to_status: IncidentStatus,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> StateTransition:
        """Ghi nhận một bước chuyển dịch trạng thái mới và cập nhật status."""
        from_status = self.status
        self.status = to_status
        self.updated_at = datetime.now(timezone.utc)
        record = StateTransition(
            timestamp=self.updated_at,
            node=node,
            from_status=from_status,
            to_status=to_status,
            message=message,
            metadata=metadata or {}
        )
        self.history.append(record)
        return record

    @property
    def severity(self) -> Optional[SeverityLevel]:
        """Thuộc tính tiện ích trích xuất mức độ nghiêm trọng từ triage_result nếu có."""
        if self.triage_result and hasattr(self.triage_result, "severity"):
            return self.triage_result.severity
        return None


class IncidentStateDict(TypedDict, total=False):
    """Định dạng TypedDict chuẩn tương thích 100% với LangGraph StateGraph."""
    incident_id: str
    status: str
    created_at: str
    updated_at: str
    raw_logs: List[Dict[str, Any]]
    parsed_events: List[Dict[str, Any]]
    triage_result: Optional[Dict[str, Any]]
    threat_intel: Optional[Dict[str, Any]]
    rca_result: Optional[Dict[str, Any]]
    recommended_actions: List[Dict[str, Any]]
    final_report: Optional[Dict[str, Any]]
    analyst_approved: Optional[bool]
    analyst_feedback: Optional[str]
    next_node: Optional[str]
    error_message: Optional[str]
    history: List[Dict[str, Any]]
    checkpoints: Dict[str, Any]
