# -*- coding: utf-8 -*-
"""
src/core/state.py
Quản lý trạng thái tập trung (Central State) cho LangGraph StateGraph.
Định nghĩa cấu trúc State luân chuyển giữa các Agent trong hệ thống Multi-Agent.
"""

from typing import List, Optional, Dict, Any, TypedDict, Union
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
    LLMCallTelemetry,
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
    response_strategy_summary: Optional[str] = Field(default=None, description="Bản tóm tắt chiến lược phản ứng tổng hợp từ RAG & LLM (Incident Commander Rationale)")
    
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

    # 11. LLM & Workflow Telemetry (Additive, backward-compatible)
    llm_telemetry: List[LLMCallTelemetry] = Field(
        default_factory=list,
        description="Nhật ký chi tiết từng lượt gọi LLM trong pipeline và Copilot",
    )
    execution_metrics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Chỉ số thực thi tổng hợp của pipeline (engine_mode, node_latencies_ms, tokens, calls)",
    )
    llm_metrics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Tổng hợp metrics LLM (provider/model thực tế, fallback events, latency, token/call count)",
    )
    workflow_telemetry: Dict[str, Any] = Field(
        default_factory=dict,
        description="Telemetry điều phối luồng xử lý StateGraph (node latencies, engine mode, step trace)",
    )

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

    def record_llm_telemetry(
        self,
        entry: Union[LLMCallTelemetry, Dict[str, Any]],
    ) -> LLMCallTelemetry:
        """Ghi nhận một bản ghi LLMCallTelemetry (chống trùng lặp theo call_id) và đồng bộ metrics."""
        item = (
            entry
            if isinstance(entry, LLMCallTelemetry)
            else LLMCallTelemetry.model_validate(entry)
        )

        for existing in self.llm_telemetry:
            if existing.call_id == item.call_id:
                return existing

        self.llm_telemetry.append(item)
        self._recompute_llm_aggregates()
        return item

    def _recompute_llm_aggregates(self) -> None:
        """Tính lại nhất quán llm_metrics và phần LLM trong execution_metrics từ llm_telemetry."""
        real_calls = [t for t in self.llm_telemetry if t.provider_used != "skipped_tiered"]
        live_calls = [
            t
            for t in real_calls
            if t.provider_used not in {"deterministic", "skipped_tiered"} and t.success
        ]
        fallback_calls = [
            t
            for t in real_calls
            if t.fallback_reason is not None or t.provider_used == "deterministic"
        ]
        tiered_saved = [t for t in self.llm_telemetry if t.provider_used == "skipped_tiered"]

        providers_used: List[str] = []
        models_used: List[str] = []
        fallback_events: List[Dict[str, Any]] = []

        for t in self.llm_telemetry:
            if t.provider_used and t.provider_used not in providers_used:
                providers_used.append(t.provider_used)
            if t.model and t.model not in models_used:
                models_used.append(t.model)
            if t.fallback_reason:
                fallback_events.append(
                    {
                        "call_id": t.call_id,
                        "agent_name": t.agent_name,
                        "provider_used": t.provider_used,
                        "fallback_reason": t.fallback_reason,
                    }
                )

        summary = {
            "llm_calls_count": len(real_calls),
            "live_llm_calls_count": len(live_calls),
            "fallback_calls_count": len(fallback_calls),
            "tiered_saved_calls_count": len(tiered_saved),
            "total_prompt_tokens": sum(t.prompt_tokens for t in self.llm_telemetry),
            "total_completion_tokens": sum(t.completion_tokens for t in self.llm_telemetry),
            "total_tokens": sum(t.total_tokens for t in self.llm_telemetry),
            "total_llm_latency_ms": round(sum(t.latency_ms for t in self.llm_telemetry), 2),
            "providers_used": providers_used,
            "models_used": models_used,
            "last_provider_used": self.llm_telemetry[-1].provider_used if self.llm_telemetry else None,
            "last_model_used": self.llm_telemetry[-1].model if self.llm_telemetry else None,
            "fallback_events": fallback_events,
        }
        self.llm_metrics.update(summary)
        self.execution_metrics.update(summary)

    def record_workflow_telemetry(
        self,
        node: str,
        latency_ms: Optional[float] = None,
        engine_mode: Optional[str] = None,
        status: Optional[str] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Ghi nhận telemetry thực thi từng node vào workflow_telemetry và execution_metrics."""
        if engine_mode is not None:
            self.workflow_telemetry["engine_mode"] = engine_mode
            self.execution_metrics["engine_mode"] = engine_mode

        node_latencies = self.workflow_telemetry.setdefault("node_latencies_ms", {})
        exec_latencies = self.execution_metrics.setdefault("node_latencies_ms", {})
        if latency_ms is not None:
            rounded_ms = round(float(latency_ms), 2)
            node_latencies[node] = rounded_ms
            exec_latencies[node] = rounded_ms
            total_ms = round(sum(float(v) for v in node_latencies.values()), 2)
            self.workflow_telemetry["total_pipeline_latency_ms"] = total_ms
            self.execution_metrics["total_pipeline_latency_ms"] = total_ms

        steps = self.workflow_telemetry.setdefault("steps", [])
        step_entry: Dict[str, Any] = {
            "node": node,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if latency_ms is not None:
            step_entry["latency_ms"] = round(float(latency_ms), 2)
        if status is not None:
            step_entry["status"] = status
        if extra:
            step_entry.update(extra)
        steps.append(step_entry)
        return self.workflow_telemetry

    @property
    def severity(self) -> Optional[SeverityLevel]:
        """Thuộc tính tiện ích trích xuất mức độ nghiêm trọng từ triage_result nếu có."""
        return self.triage_result.severity if self.triage_result else None


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
    response_strategy_summary: Optional[str]
    final_report: Optional[Dict[str, Any]]
    attack_type: Optional[str]
    analyst_approved: Optional[bool]
    analyst_feedback: Optional[str]
    next_node: Optional[str]
    error_message: Optional[str]
    reanalysis_count: int
    max_reanalysis: int
    reanalysis_reason: Optional[str]
    history: List[Dict[str, Any]]
    checkpoints: Dict[str, Any]
    llm_telemetry: List[Dict[str, Any]]
    execution_metrics: Dict[str, Any]
    llm_metrics: Dict[str, Any]
    workflow_telemetry: Dict[str, Any]
