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
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    ThreatIntelEnrichment,
    RootCauseAnalysis,
    RecommendedAction,
    IncidentReport,
)


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
    
    # 7. Thông tin điều khiển / Human-in-the-loop (HITL)
    analyst_approved: Optional[bool] = None
    analyst_feedback: Optional[str] = None
    next_node: Optional[str] = None
    error_message: Optional[str] = None


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
