# -*- coding: utf-8 -*-
"""
src/core/orchestrator.py
Khung Điều phối Trung tâm (Central Orchestrator) dựa trên triết lý StateGraph của LangGraph.
Quản lý vòng đời IncidentState, điều hướng luồng thực thi qua các Node, hỗ trợ Rẽ nhánh có điều kiện
(Conditional Edges: True Positive vs False Positive short-circuit), Checkpoints,
State Transition History và Human-In-The-Loop (HITL) Analyst Approval Hook.
"""

from typing import Dict, Any, List, Optional, Callable, Tuple, Generator, Union
from datetime import datetime, timezone
import concurrent.futures
import contextvars
import hashlib
import inspect
import ipaddress
import json
import logging
import re
import threading
import time
import uuid
import zlib

# Tích hợp LangGraph chính thống theo mô hình Adapter/Facade Pattern
try:
    from langgraph.graph import StateGraph as LangGraphStateGraph, START as LG_START, END as LG_END
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False
    LG_START = "__start__"
    LG_END = "__end__"
    JsonPlusSerializer = None

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    IncidentPhase,
    AttackCategory,
    WazuhMitreInfo,
    WazuhRuleInfo,
    WazuhAgentInfo,
    WazuhAlert,
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    TriageCoTSteps,
    TriageLLMResult,
    MultiDimensionalCTIScore,
    IoCItem,
    ThreatIntelEnrichment,
    ThreatIntelLLMAnalysis,
    ProcessNode,
    HighFidelityProcessNode,
    RootCauseAnalysis,
    RCALLMAnalysis,
    ActionScriptBundle,
    RecommendedAction,
    ActionAdjustment,
    ResponseLLMStrategy,
    OperationalMetrics,
    CIADimension,
    ImpactAssessment,
    DeepRCABreakdown,
    VerificationGateItem,
    CAPAItem,
    ReportingLLMSynthesis,
    IncidentReport,
    LLMHealthStatus,
    LLMCallTelemetry,
    LLMCompletionResult,
)
from src.core.state import IncidentState, StateTransition
from src.core.hitl_manager import HITLManager, HITLDecision
from src.tools.parsers import LogParserTool
from src.tools.playbooks import ResponsePlaybooks

logger = logging.getLogger("StateGraphOrchestrator")

# Hằng số định danh điểm đầu và điểm cuối tương thích LangGraph
START = "__start__"
END = "__end__"

_ALLOWED_MSGPACK_MODULES = [
    SeverityLevel,
    IncidentStatus,
    ActionType,
    IncidentPhase,
    AttackCategory,
    WazuhMitreInfo,
    WazuhRuleInfo,
    WazuhAgentInfo,
    WazuhAlert,
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    TriageCoTSteps,
    TriageLLMResult,
    MultiDimensionalCTIScore,
    IoCItem,
    ThreatIntelEnrichment,
    ThreatIntelLLMAnalysis,
    ProcessNode,
    HighFidelityProcessNode,
    RootCauseAnalysis,
    RCALLMAnalysis,
    ActionScriptBundle,
    RecommendedAction,
    ActionAdjustment,
    ResponseLLMStrategy,
    OperationalMetrics,
    CIADimension,
    ImpactAssessment,
    DeepRCABreakdown,
    VerificationGateItem,
    CAPAItem,
    ReportingLLMSynthesis,
    IncidentReport,
    LLMHealthStatus,
    LLMCallTelemetry,
    LLMCompletionResult,
    StateTransition,
    IncidentState,
]

_RESUME_FEEDBACK_OVERRIDE: contextvars.ContextVar[Optional[bool]] = contextvars.ContextVar(
    "orchestrator_resume_feedback_override", default=None
)

_MANUAL_CLOSE_FEEDBACK_KEYWORDS = (
    "thủ công",
    "đã xử lý",
    "đóng sự cố",
    "false alert",
    "báo động giả",
    "manual",
    "close",
)

_RCA_FEEDBACK_KEYWORDS = (
    "nguyên nhân",
    "root cause",
    "tiến trình cha",
    "vector",
    "tái điều tra",
    "sai rca",
)

_NODE_TO_AGENT_NAME = {
    "ingestion": "IngestionAgent",
    "triage": "TriageAgent",
    "enrichment": "ThreatIntelAgent",
    "rca": "RCAAgent",
    "rca_correlation": "RCAAgent",
    "parallel_investigation": "ParallelInvestigation",
    "response": "ResponseAgent",
    "hitl_approval": "HITLApproval",
    "reporting": "ReportingAgent",
    "closed_fp": "ClosedFalsePositive",
}


class StateGraphOrchestrator:
    """Khung điều phối StateGraph quản lý vòng đời điều tra sự cố an ninh mạng.
    
    Tuân thủ triết lý LangGraph (Adapter/Facade Pattern):
    - Bên ngoài: Duy trì 100% API tương thích ngược (.invoke, .stream, .step, .nodes, .edges, .conditional_edges).
    - Bên trong: Đồng bộ hóa cấu trúc đồ thị vào `langgraph.graph.StateGraph(IncidentState)` chính thống.
    - Checkpointer: Lưu trữ trạng thái sau từng Node.
    - HITL Hook & HITL Manager: Tạm dừng hoặc yêu cầu phê duyệt từ chuyên viên SOC trước khi thực hiện hành động ngăn chặn.
    """

    def __init__(
        self,
        checkpointer: Optional[Dict[str, Any]] = None,
        hitl_hook: Optional[Callable[[IncidentState], IncidentState]] = None,
        hitl_manager: Optional[HITLManager] = None,
        auto_approve: bool = False,
        enable_feedback_loop: bool = True,
        max_reanalysis: int = 2,
        ingestion_agent: Optional[Any] = None,
        triage_agent: Optional[Any] = None,
        threat_intel_agent: Optional[Any] = None,
        rca_agent: Optional[Any] = None,
        response_agent: Optional[Any] = None,
        reporting_agent: Optional[Any] = None,
        enable_parallel_investigation: bool = False,
        llm_provider: Optional[Any] = None,
        rag_kb: Optional[Any] = None,
        use_langgraph_engine: bool = True,
    ):
        self.checkpointer = checkpointer if checkpointer is not None else {}
        self.hitl_hook = hitl_hook
        self.hitl_manager = hitl_manager
        self.auto_approve = auto_approve
        self.enable_feedback_loop = enable_feedback_loop
        self.max_reanalysis = max_reanalysis
        self.ingestion_agent = ingestion_agent
        self.triage_agent = triage_agent
        self.threat_intel_agent = threat_intel_agent
        self.rca_agent = rca_agent
        self.response_agent = response_agent
        self.reporting_agent = reporting_agent
        self.enable_parallel_investigation = enable_parallel_investigation
        self.llm_provider = llm_provider
        self.rag_kb = rag_kb
        self.use_langgraph_engine = bool(use_langgraph_engine)

        if self.llm_provider is not None:
            for agent in (
                self.ingestion_agent,
                self.triage_agent,
                self.threat_intel_agent,
                self.rca_agent,
                self.response_agent,
                self.reporting_agent,
            ):
                if agent is not None and getattr(agent, "llm_provider", None) is None:
                    setattr(agent, "llm_provider", self.llm_provider)

        if self.rag_kb is not None and self.response_agent is not None:
            if getattr(self.response_agent, "rag_kb", None) is None:
                setattr(self.response_agent, "rag_kb", self.rag_kb)

        # Cấu trúc đồ thị điều phối (Facade attributes)
        self.nodes: Dict[str, Callable[[IncidentState], IncidentState]] = {}
        self.edges: Dict[str, str] = {}
        self.conditional_edges: Dict[str, Tuple[Callable[[IncidentState], str], Dict[str, str]]] = {}
        self.entry_point: str = "ingestion"

        # Internal LangGraph StateGraph Adapter & Safe MemorySaver Checkpointer
        self._lg_builder: Optional[Any] = None
        self._compiled_app: Optional[Any] = None
        self._compiled_interrupt_app: Optional[Any] = None
        self._active_threads: Dict[str, str] = {}
        self._thread_lock = threading.Lock()
        if HAS_LANGGRAPH:
            serde = (
                JsonPlusSerializer(allowed_msgpack_modules=_ALLOWED_MSGPACK_MODULES)
                if JsonPlusSerializer is not None
                else None
            )
            self._memory_saver = MemorySaver(serde=serde) if serde is not None else MemorySaver()
        else:
            self._memory_saver = None
        self._checkpoint_lock = threading.Lock()

        # Khởi tạo đồ thị chuẩn
        self._build_default_graph()

    # =====================================================================
    # 1. GRAPH DEFINITION & REGISTRATION (Tương thích LangGraph StateGraph)
    # =====================================================================
    def _invalidate_compiled_caches(self) -> None:
        self._compiled_app = None
        self._compiled_interrupt_app = None
        self._lg_builder = None

    def add_node(self, name: str, func: Callable[[IncidentState], IncidentState]) -> "StateGraphOrchestrator":
        """Đăng ký một Node xử lý vào đồ thị Facade và làm sạch cache biên dịch LangGraph."""
        self.nodes[name] = func
        self._invalidate_compiled_caches()
        return self

    def add_edge(self, from_node: str, to_node: str) -> "StateGraphOrchestrator":
        """Đăng ký một Cạnh chuyển tiếp trực tiếp giữa 2 Node."""
        self.edges[from_node] = to_node
        self._invalidate_compiled_caches()
        return self

    def add_conditional_edges(
        self,
        source_node: str,
        condition_fn: Callable[[IncidentState], str],
        path_map: Dict[str, str]
    ) -> "StateGraphOrchestrator":
        """Đăng ký Cạnh rẽ nhánh có điều kiện dựa trên kết quả của Node nguồn."""
        self.conditional_edges[source_node] = (condition_fn, path_map)
        self._invalidate_compiled_caches()
        return self

    def set_entry_point(self, node_name: str) -> "StateGraphOrchestrator":
        """Thiết lập Node đầu vào của đồ thị."""
        self.entry_point = node_name
        self._invalidate_compiled_caches()
        return self

    def _resolve_node_provider(self, node_name: str) -> Optional[Any]:
        """Tìm LLM provider gắn với node/agent hiện tại."""
        agent_attr_map = {
            "ingestion": "ingestion_agent",
            "triage": "triage_agent",
            "enrichment": "threat_intel_agent",
            "rca": "rca_agent",
            "rca_correlation": "rca_agent",
            "response": "response_agent",
            "reporting": "reporting_agent",
        }
        attr = agent_attr_map.get(node_name)
        if attr:
            agent = getattr(self, attr, None)
            if agent is not None and getattr(agent, "llm_provider", None) is not None:
                return getattr(agent, "llm_provider")
        return self.llm_provider

    def _run_node_with_metrics(
        self,
        node_name: str,
        fn: Callable[[IncidentState], IncidentState],
        state: IncidentState,
        engine_mode: Optional[str] = None,
    ) -> IncidentState:
        """Thực thi một node trong Telemetry Scope, gom LLM telemetry và đo latency."""
        current_state = self._coerce_state(state)
        resolved_mode = engine_mode or (
            "langgraph" if (HAS_LANGGRAPH and self.use_langgraph_engine) else "fallback_loop"
        )
        provider = self._resolve_node_provider(node_name)
        agent_name = _NODE_TO_AGENT_NAME.get(node_name, node_name)
        history_before = len(current_state.history)

        scope_token = None
        has_scope_api = (
            provider is not None
            and hasattr(provider, "begin_telemetry_scope")
            and hasattr(provider, "end_telemetry_scope")
        )
        if has_scope_api:
            scope_token = provider.begin_telemetry_scope(
                current_state,
                agent_name=agent_name,
                node=node_name,
            )

        t0 = time.perf_counter()
        records: List[Any] = []
        try:
            updated_state = self._coerce_state(fn(current_state))
        finally:
            if has_scope_api:
                try:
                    records = provider.end_telemetry_scope(scope_token) or []
                except Exception as exc:
                    logger.debug(f"Không thể đóng telemetry scope cho node '{node_name}': {exc}")
                    records = []

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        for rec in records:
            updated_state.record_llm_telemetry(rec)

        # Ghi nhận tiered fast-path telemetry nếu TriageAgent short-circuit bỏ qua LLM
        if node_name == "triage" and not records:
            new_transitions = updated_state.history[history_before:]
            tiered_meta = next(
                (
                    t.metadata
                    for t in new_transitions
                    if isinstance(t.metadata, dict)
                    and t.metadata.get("tiered_routing") == "fast_heuristic"
                    and not t.metadata.get("llm_called")
                ),
                None,
            )
            if tiered_meta is not None:
                updated_state.record_llm_telemetry(
                    LLMCallTelemetry(
                        agent_name="TriageAgent",
                        node="triage",
                        model_tier="fast",
                        provider_used="skipped_tiered",
                        model="Tiered-Fast-Heuristic",
                        latency_ms=elapsed_ms,
                        prompt_tokens=0,
                        completion_tokens=0,
                        total_tokens=0,
                        success=True,
                        fallback_reason="tiered_fast_heuristic",
                    )
                )

        status_val = (
            updated_state.status.value
            if hasattr(updated_state.status, "value")
            else str(updated_state.status)
        )
        updated_state.record_workflow_telemetry(
            node=node_name,
            latency_ms=elapsed_ms,
            engine_mode=resolved_mode,
            status=status_val,
        )
        return updated_state

    def _wrap_node_for_langgraph(
        self,
        node_name: str,
        func: Callable[[IncidentState], IncidentState],
    ) -> Callable[[Any], IncidentState]:
        """Bọc node thành adapter an toàn cho LangGraph StateGraph(IncidentState)."""
        def _node_adapter(state: Any) -> IncidentState:
            return self._run_node_with_metrics(
                node_name=node_name,
                fn=func,
                state=state,
                engine_mode="langgraph",
            )
        return _node_adapter

    def _build_langgraph_builder(self) -> Any:
        """Dựng mới hoàn toàn LangGraphStateGraph(IncidentState) từ registry của Facade."""
        builder = LangGraphStateGraph(IncidentState)
        for name, func in self.nodes.items():
            builder.add_node(name, self._wrap_node_for_langgraph(name, func))

        if self.entry_point and self.entry_point in self.nodes and START not in self.edges:
            builder.add_edge(LG_START, self.entry_point)

        for from_node, to_node in self.edges.items():
            src = LG_START if from_node == START else from_node
            dst = LG_END if to_node == END else to_node
            builder.add_edge(src, dst)

        for source_node, (condition_fn, path_map) in self.conditional_edges.items():
            lg_path_map = {k: (LG_END if v == END else v) for k, v in path_map.items()}

            def _cond_adapter(state_in: Any, _fn: Callable[[IncidentState], str] = condition_fn) -> str:
                return _fn(self._coerce_state(state_in))

            builder.add_conditional_edges(source_node, _cond_adapter, lg_path_map)

        return builder

    def compile(
        self,
        checkpointer: Any = None,
        interrupt_before: Optional[List[str]] = None,
        interrupt_after: Optional[List[str]] = None,
    ) -> Any:
        """Biên dịch sang CompiledGraph chính thức của LangGraph từ đồ thị Facade hiện hành."""
        if not HAS_LANGGRAPH:
            raise RuntimeError("Thư viện 'langgraph' chưa được cài đặt hoặc không khả dụng.")
        builder = self._build_langgraph_builder()
        self._lg_builder = builder
        cp = checkpointer if checkpointer is not None else self._memory_saver
        compile_kwargs: Dict[str, Any] = {"checkpointer": cp}
        if interrupt_before:
            compile_kwargs["interrupt_before"] = list(interrupt_before)
        if interrupt_after:
            compile_kwargs["interrupt_after"] = list(interrupt_after)
        compiled = builder.compile(**compile_kwargs)
        if checkpointer is None and not interrupt_before and not interrupt_after:
            self._compiled_app = compiled
        return compiled

    def get_langgraph_app(self) -> Any:
        """Lấy đối tượng CompiledGraph của LangGraph đã được biên dịch."""
        if self._compiled_app is None:
            return self.compile()
        return self._compiled_app

    def get_langgraph_interrupt_app(self) -> Any:
        """Lấy CompiledGraph có interrupt_before=['hitl_approval'] dùng cho HITL pause/resume."""
        if self._compiled_interrupt_app is None:
            ib = ["hitl_approval"] if "hitl_approval" in self.nodes else None
            self._compiled_interrupt_app = self.compile(interrupt_before=ib)
        return self._compiled_interrupt_app

    def _allocate_thread_id(self, incident_id: str) -> str:
        tid = f"{incident_id}:{uuid.uuid4().hex[:8]}"
        with self._thread_lock:
            self._active_threads[incident_id] = tid
        return tid

    def _hitl_predecessor(self) -> Optional[str]:
        if "response" in self.nodes:
            return "response"
        for src, dst in self.edges.items():
            if dst == "hitl_approval" and src != START:
                return src
        return None

    def _build_default_graph(self):
        """Xây dựng đồ thị điều phối chuẩn của hệ thống SOC Multi-Agent."""
        # Thiết lập Entry Point đầu vào cho đồ thị
        self.set_entry_point("ingestion")

        # Đăng ký các Node
        self.add_node("ingestion", self.ingestion_node)
        self.add_node("triage", self.triage_node)
        self.add_node("closed_fp", self.closed_false_positive_node)
        self.add_node("enrichment", self.enrichment_node)
        self.add_node("rca", self.rca_node)
        self.add_node("parallel_investigation", self.parallel_investigation_node)
        self.add_node("response", self.response_node)
        self.add_node("hitl_approval", self.hitl_approval_node)
        self.add_node("reporting", self.reporting_node)

        # Cạnh nối từ Entry Point sang Triage
        self.add_edge("ingestion", "triage")

        # Cạnh kết thúc của False Positive
        self.add_edge("closed_fp", END)

        if getattr(self, "enable_parallel_investigation", False):
            # Nhánh điều tra song song (Fork-Join DAG tương ứng cụm PARALLEL AGENTS trên sơ đồ)
            self.add_conditional_edges(
                source_node="triage",
                condition_fn=self.route_triage_decision,
                path_map={
                    "investigate": "parallel_investigation",
                    "false_positive": "closed_fp"
                }
            )
            self.add_edge("parallel_investigation", "response")
            # Đảm bảo cạnh rca -> response luôn có sẵn nếu chuyên viên yêu cầu retry_rca từ Feedback Loop
            self.add_edge("rca", "response")
        else:
            # Pipeline điều tra chuyên sâu tuần tự mặc định (Enrichment -> RCA -> Response)
            self.add_conditional_edges(
                source_node="triage",
                condition_fn=self.route_triage_decision,
                path_map={
                    "investigate": "enrichment",
                    "false_positive": "closed_fp"
                }
            )
            self.add_edge("enrichment", "rca")
            self.add_edge("rca", "response")

        self.add_edge("response", "hitl_approval")

        # Cạnh điều kiện từ HITL (Feedback Loop & Backtracking):
        # - proceed_reporting: Khi được phê duyệt hoặc đã hết số lượt điều chỉnh tối đa
        # - retry_response: Quay lại Response Agent điều chỉnh kế hoạch hành động
        # - retry_rca: Quay lại RCA Agent điều tra lại nguyên nhân gốc rễ
        self.add_conditional_edges(
            source_node="hitl_approval",
            condition_fn=self.route_hitl_decision,
            path_map={
                "proceed_reporting": "reporting",
                "retry_response": "response",
                "retry_rca": "rca",
                "awaiting_approval": END
            }
        )
        self.add_edge("reporting", END)

    def set_llm_provider(self, llm_provider: Any) -> None:
        """Cập nhật LLM Provider dùng chung và đồng bộ sang toàn bộ 6 Agents."""
        self.llm_provider = llm_provider
        for agent in (
            self.ingestion_agent,
            self.triage_agent,
            self.threat_intel_agent,
            self.rca_agent,
            self.response_agent,
            self.reporting_agent,
        ):
            if agent is None:
                continue
            if hasattr(agent, "set_llm_provider") and callable(agent.set_llm_provider):
                agent.set_llm_provider(llm_provider)
            else:
                setattr(agent, "llm_provider", llm_provider)

    @staticmethod
    def _raw_log_key(log_source: Optional[str], raw_payload: Any) -> str:
        """Khóa định danh ngắn gọn cho RawLogInput để đảm bảo ingestion idempotent."""
        src = str(log_source or "").strip().lower()
        if isinstance(raw_payload, dict):
            canonical = json.dumps(raw_payload, sort_keys=True, ensure_ascii=False)
        else:
            raw_str = str(raw_payload or "").strip()
            canonical = raw_str
            if raw_str.startswith("{") or raw_str.startswith("["):
                try:
                    canonical = json.dumps(json.loads(raw_str), sort_keys=True, ensure_ascii=False)
                except Exception:
                    canonical = raw_str
        payload_bytes = canonical.encode("utf-8", errors="ignore")
        short_digest = hashlib.sha256(payload_bytes).hexdigest()[:16]
        return f"{src}:{zlib.crc32(payload_bytes):08x}:{len(payload_bytes)}:{short_digest}"

    @staticmethod
    def _event_signature(event: ParsedEvent) -> Tuple[Any, ...]:
        """Chữ ký ổn định của ParsedEvent phục vụ khử trùng lặp idempotent."""
        raw_eid = str(event.event_id or "").strip()
        if re.match(r"^(?:Suricata|LinuxSyslog|UNKNOWN)-.*-[0-9a-fA-F]{6}$", raw_eid):
            norm_eid = re.sub(r"-[0-9a-fA-F]{6}$", "", raw_eid)
        elif raw_eid.startswith("EVT-UNKNOWN-"):
            norm_eid = "EVT-UNKNOWN"
        else:
            norm_eid = raw_eid

        attrs = event.raw_attributes or {}
        return (
            norm_eid,
            str(event.source_type or "").strip().lower(),
            str(event.host_name or "").strip().lower(),
            str(event.user_name or "").strip().lower(),
            str(event.process_name or "").strip().lower(),
            str(event.process_path or "").strip().lower(),
            str(event.command_line or "").strip(),
            str(event.parent_process or "").strip().lower(),
            str(event.source_ip or "").strip(),
            event.source_port,
            str(event.dest_ip or "").strip(),
            event.dest_port,
            str(event.file_hash or "").strip().lower(),
            str(attrs.get("wazuh_alert_id") or ""),
            str(attrs.get("wazuh_rule_id") or ""),
            str(attrs.get("zeek_ts") or ""),
            str(attrs.get("raw_payload") or attrs.get("raw_log") or ""),
        )

    # =====================================================================
    # 2. NODE IMPLEMENTATIONS (Triển khai các nút nghiệp vụ)
    # =====================================================================
    def ingestion_node(self, state: IncidentState) -> IncidentState:
        """Node Ingestion: Tiếp nhận dữ liệu log thô / Wazuh alerts và chuẩn hóa sang ParsedEvent (idempotent)."""
        logger.info(f"[{state.incident_id}] Thực thi Ingestion Node...")

        # 1. Gọi IngestionAgent nếu đã được tiêm hoặc import được
        if self.ingestion_agent is not None:
            if hasattr(self.ingestion_agent, "process_state"):
                state = self.ingestion_agent.process_state(state)
            elif hasattr(self.ingestion_agent, "parse_logs"):
                seen_sigs = {self._event_signature(e) for e in state.parsed_events}
                ingested_keys = state.workflow_telemetry.setdefault("ingested_raw_keys", [])
                seen_raw_keys = set(ingested_keys)
                all_already_ingested = bool(state.raw_logs) and all(
                    self._raw_log_key(r.log_source, r.raw_payload) in seen_raw_keys
                    for r in state.raw_logs
                )
                if not all_already_ingested:
                    parsed = self.ingestion_agent.parse_logs(state.raw_logs)
                    for evt in parsed:
                        sig = self._event_signature(evt)
                        if sig not in seen_sigs:
                            seen_sigs.add(sig)
                            state.parsed_events.append(evt)
                    for r in state.raw_logs:
                        rk = self._raw_log_key(r.log_source, r.raw_payload)
                        if rk not in seen_raw_keys:
                            seen_raw_keys.add(rk)
                            ingested_keys.append(rk)
        else:
            # Fallback/Built-in Ingestion Engine qua LogParserTool & WazuhClientTool (idempotent)
            deduped_existing: List[ParsedEvent] = []
            seen_sigs = set()
            for existing_evt in state.parsed_events:
                sig = self._event_signature(existing_evt)
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    deduped_existing.append(existing_evt)
            if len(deduped_existing) != len(state.parsed_events):
                state.parsed_events = deduped_existing

            ingested_keys = state.workflow_telemetry.setdefault("ingested_raw_keys", [])
            seen_raw_keys = set(ingested_keys)

            for raw_item in state.raw_logs:
                raw_key = self._raw_log_key(raw_item.log_source, raw_item.raw_payload)
                if raw_key in seen_raw_keys:
                    continue

                source = (raw_item.log_source or "").lower()
                payload = raw_item.raw_payload

                try:
                    if "wazuh" in source:
                        parsed_event = LogParserTool.parse_wazuh_alert(payload)
                    elif "sysmon" in source:
                        parsed_event = LogParserTool.parse_sysmon(payload)
                    elif "zeek" in source:
                        parsed_event = LogParserTool.parse_zeek_conn(payload)
                    elif "evtx" in source or "windows" in source:
                        parsed_event = LogParserTool.parse_windows_evtx(payload)
                    else:
                        # Dự phòng trích xuất thông qua Sysmon parser hoặc fallback
                        parsed_event = LogParserTool.parse_sysmon(payload)
                except Exception as ex:
                    logger.warning(f"Lỗi parse raw log ({source}): {ex}")
                    # Vẫn tạo một ParsedEvent fallback để không làm đứt chuỗi
                    parsed_event = ParsedEvent(
                        event_id=f"EVT-UNKNOWN-{len(state.parsed_events)+1}",
                        timestamp=datetime.now(timezone.utc),
                        source_type=raw_item.log_source,
                        raw_attributes={"raw_payload": payload, "parse_error": str(ex)}
                    )

                sig = self._event_signature(parsed_event)
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    state.parsed_events.append(parsed_event)

                seen_raw_keys.add(raw_key)
                ingested_keys.append(raw_key)

        # Lưu vết chuyển đổi trạng thái
        state.record_transition(
            node="ingestion",
            to_status=IncidentStatus.NEW,
            message=f"Bóc tách thành công {len(state.parsed_events)} sự kiện ParsedEvent từ {len(state.raw_logs)} raw logs",
            metadata={"parsed_count": len(state.parsed_events), "raw_count": len(state.raw_logs)}
        )
        self._checkpoint(state, "ingestion")
        return state

    def triage_node(self, state: IncidentState) -> IncidentState:
        """Node Triage: Đánh giá phân loại True/False Positive và mức độ nghiêm trọng."""
        logger.info(f"[{state.incident_id}] Thực thi Triage Node...")

        # 1. Gọi TriageAgent nếu được cấu hình
        if self.triage_agent is not None:
            if hasattr(self.triage_agent, "triage_state"):
                state = self.triage_agent.triage_state(state)
            elif hasattr(self.triage_agent, "triage"):
                state = self.triage_agent.triage(state)
            elif hasattr(self.triage_agent, "evaluate"):
                try:
                    sig = inspect.signature(self.triage_agent.evaluate)
                    if "incident_state" in sig.parameters:
                        state.triage_result = self.triage_agent.evaluate(
                            state.parsed_events, incident_state=state
                        )
                    else:
                        state.triage_result = self.triage_agent.evaluate(state.parsed_events)
                except (ValueError, TypeError):
                    state.triage_result = self.triage_agent.evaluate(state.parsed_events)
            elif hasattr(self.triage_agent, "evaluate_models_parallel"):
                try:
                    sig = inspect.signature(self.triage_agent.evaluate_models_parallel)
                    if "incident_state" in sig.parameters:
                        res = self.triage_agent.evaluate_models_parallel(
                            state.parsed_events, incident_state=state
                        )
                    else:
                        res = self.triage_agent.evaluate_models_parallel(state.parsed_events)
                except (ValueError, TypeError):
                    res = self.triage_agent.evaluate_models_parallel(state.parsed_events)
                state.triage_result = res.get("consensus")
        else:
            # Fallback/Built-in Heuristic & Rule Engine
            state.triage_result = self._builtin_heuristic_triage(state)

        # 2. Cập nhật trạng thái sự cố dựa trên kết quả Triage
        triage = state.triage_result
        if triage is not None:
            if triage.is_incident:
                next_status = IncidentStatus.INVESTIGATING
                msg = f"Xác nhận sự cố thực sự (True Positive) - {triage.severity.value}: {triage.summary}"
            else:
                next_status = IncidentStatus.CLOSED_FALSE_POSITIVE
                msg = f"Đóng sự cố - Dương tính giả (False Positive): {triage.summary}"
        else:
            next_status = IncidentStatus.TRIAGED
            msg = "Hoàn tất Triage sơ bộ"

        state.record_transition(
            node="triage",
            to_status=next_status,
            message=msg,
            metadata={
                "is_incident": triage.is_incident if triage else None,
                "confidence_score": triage.confidence_score if triage else 0.0,
                "severity": triage.severity.value if triage else "UNKNOWN",
                "rule_or_model": triage.rule_or_model if triage else "N/A"
            }
        )
        self._checkpoint(state, "triage")
        return state

    def route_triage_decision(self, state: IncidentState) -> str:
        """Cạnh điều kiện (Conditional Edge): Định tuyến dựa trên kết quả Triage."""
        if state.triage_result is not None and state.triage_result.is_incident:
            logger.info(f"[{state.incident_id}] Rẽ nhánh điều tra chuyên sâu (True Positive -> investigate)")
            return "investigate"
        else:
            logger.info(f"[{state.incident_id}] Rẽ nhánh kết thúc sớm (False Positive -> false_positive)")
            return "false_positive"

    def route_hitl_decision(self, state: IncidentState) -> str:
        """Pure Conditional Edge từ HITL Node (KHÔNG đột biến state trong LangGraph Pregel).
        Định tuyến chỉ dựa trên state.status / state.next_node (hoặc đánh giá thuần túy không side-effect):
        - awaiting_approval: Khi đang chờ chuyên viên phê duyệt.
        - proceed_reporting: Khi chuyên viên phê duyệt hoặc đã đạt giới hạn lặp tối đa.
        - retry_response: Quay lại Response Node để lập lại kế hoạch theo chỉ dẫn của con người.
        - retry_rca: Quay lại RCA Node nếu chuyên viên yêu cầu rà soát lại nguyên nhân gốc rễ.
        """
        if state.status == IncidentStatus.AWAITING_APPROVAL:
            return "awaiting_approval"

        if state.next_node in ("retry_response", "retry_rca", "proceed_reporting", "awaiting_approval"):
            return state.next_node

        if state.analyst_approved is not False:
            return "proceed_reporting"

        effective_max = self.max_reanalysis if self.max_reanalysis is not None else state.max_reanalysis
        if getattr(self, "enable_feedback_loop", True) and state.reanalysis_count < effective_max:
            feedback_lower = (state.analyst_feedback or "").lower()
            if self.hitl_hook is None and any(
                kw in feedback_lower for kw in _MANUAL_CLOSE_FEEDBACK_KEYWORDS
            ):
                return "proceed_reporting"
            if any(k in feedback_lower for k in _RCA_FEEDBACK_KEYWORDS):
                return "retry_rca"
            return "retry_response"

        return "proceed_reporting"

    def closed_false_positive_node(self, state: IncidentState) -> IncidentState:
        """Node Đóng sự cố False Positive: Ghi nhận trạng thái hoàn tất và short-circuit."""
        logger.info(f"[{state.incident_id}] Thực thi Closed False Positive Node (Short-circuit)...")
        state.record_transition(
            node="closed_fp",
            to_status=IncidentStatus.CLOSED_FALSE_POSITIVE,
            message="Sự cố đã được đóng tự động do phân loại False Positive hoặc hoạt động bình thường",
            metadata={"closed_at": datetime.now(timezone.utc).isoformat()}
        )
        state.next_node = END
        self._checkpoint(state, "closed_fp")
        return state

    def enrichment_node(self, state: IncidentState) -> IncidentState:
        """Node Threat Intel Enrichment (CTI): Làm giàu ngữ cảnh IoC & MITRE ATT&CK (Tuần 8 Integration)."""
        logger.info(f"[{state.incident_id}] Thực thi Threat Intel Enrichment Node...")
        
        # 1. Gọi ThreatIntelAgent nếu được cấu hình
        if self.threat_intel_agent is not None:
            if hasattr(self.threat_intel_agent, "enrich_state"):
                state = self.threat_intel_agent.enrich_state(state)
            elif hasattr(self.threat_intel_agent, "enrich_events"):
                state.threat_intel = self.threat_intel_agent.enrich_events(state.parsed_events)
        else:
            extracted_iocs: List[IoCItem] = []
            seen_ioc_keys = set()
            mitre_techniques: List[str] = []
            threat_actors: List[str] = []
            from src.tools.threat_intel import ThreatIntelTools

            # Trích xuất IoC từ ParsedEvents
            for event in state.parsed_events:
                # Tra cứu IP
                for ip in [event.source_ip, event.dest_ip]:
                    if ip and not self._is_private_ip(ip):
                        ip_clean = str(ip).strip()
                        ioc = ThreatIntelTools.lookup_ip(ip_clean)
                        if ioc:
                            ip_key = (str(ioc.ioc_type or "IP").upper(), str(ioc.value or ip_clean).strip().lower())
                            if ip_key not in seen_ioc_keys:
                                seen_ioc_keys.add(ip_key)
                                extracted_iocs.append(ioc)
                                if ioc.threat_actor and ioc.threat_actor not in threat_actors:
                                    threat_actors.append(ioc.threat_actor)

                # Tra cứu Process/MITRE
                if event.process_name:
                    p_lower = event.process_name.lower()
                    if "powershell" in p_lower:
                        mitre_techniques.append("T1059.001")
                    elif "cmd" in p_lower:
                        mitre_techniques.append("T1059.003")

                # Tra cứu Hash nếu có (tách danh sách Sysmon & bỏ tiền tố SHA256=/MD5=/SHA1= trước khi kiểm tra độ dài)
                if event.file_hash:
                    for raw_part in str(event.file_hash).split(","):
                        h_clean = raw_part.strip()
                        if not h_clean:
                            continue
                        explicit_prefix = None
                        lower_part = h_clean.lower()
                        for prefix, label in (("sha256=", "SHA256"), ("md5=", "MD5"), ("sha1=", "SHA1"), ("imphash=", "IMPHASH")):
                            if lower_part.startswith(prefix):
                                explicit_prefix = label
                                h_clean = h_clean[len(prefix):].strip()
                                break
                        else:
                            if "=" in h_clean:
                                p_label, h_clean = h_clean.split("=", 1)
                                explicit_prefix = p_label.strip().upper() or None
                                h_clean = h_clean.strip()

                        if not h_clean:
                            continue

                        if len(h_clean) == 64:
                            h_type = "SHA256"
                        elif len(h_clean) == 40:
                            h_type = "SHA1"
                        elif len(h_clean) == 32:
                            h_type = explicit_prefix if explicit_prefix == "IMPHASH" else "MD5"
                        elif explicit_prefix in {"SHA256", "SHA1", "MD5"}:
                            h_type = explicit_prefix
                        else:
                            continue

                        h_key = (h_type, h_clean.lower())
                        if h_key not in seen_ioc_keys:
                            seen_ioc_keys.add(h_key)
                            extracted_iocs.append(
                                IoCItem(
                                    ioc_type=h_type,
                                    value=h_clean,
                                    reputation_score=85,
                                    is_malicious=True,
                                    threat_actor="Known Malware Sample",
                                )
                            )

            # Lấy thêm MITRE tags từ raw_attributes nếu từ Wazuh
            for event in state.parsed_events:
                w_mitre = event.raw_attributes.get("mitre_ids", [])
                for m_id in w_mitre:
                    if m_id not in mitre_techniques:
                        mitre_techniques.append(m_id)

            state.threat_intel = ThreatIntelEnrichment(
                extracted_iocs=extracted_iocs,
                related_threat_actors=threat_actors if threat_actors else ["Unknown / Commodity Threat"],
                mitre_techniques=list(set(mitre_techniques)) if mitre_techniques else ["T1059.001"],
                enrichment_summary=f"Đã phát hiện và làm giàu {len(extracted_iocs)} IoCs, ánh xạ {len(mitre_techniques)} kỹ thuật MITRE ATT&CK."
            )

        # 2. Cơ chế Tự động Hiệu chỉnh Sai lệch (Self-Correction Escalation Loop):
        # Nếu Triage ban đầu đánh giá mức LOW/MEDIUM nhưng Threat Intel phát hiện IoC có Threat Score cao (>= 80)
        if state.threat_intel and state.triage_result:
            highest_score = max([ioc.reputation_score or 0 for ioc in state.threat_intel.extracted_iocs], default=0)
            if highest_score >= 80 and state.triage_result.severity in [SeverityLevel.LOW, SeverityLevel.MEDIUM]:
                old_sev = state.triage_result.severity
                state.triage_result.severity = SeverityLevel.CRITICAL
                state.triage_result.summary += f" [Self-Correction: Tự động nâng cấp mức độ nguy hiểm từ {old_sev.value} lên CRITICAL do phát hiện IoC có điểm đe dọa CTI cao: {highest_score}/100]"
                state.record_transition(
                    node="enrichment",
                    to_status=IncidentStatus.INVESTIGATING,
                    message=f"Tự động hiệu chỉnh sai lệch: Nâng cấp severity từ {old_sev.value} lên CRITICAL dựa trên CTI (Threat Score: {highest_score})",
                    metadata={"escalated": True, "highest_threat_score": highest_score}
                )

        state.record_transition(
            node="enrichment",
            to_status=IncidentStatus.INVESTIGATING,
            message="Hoàn tất làm giàu dữ liệu tình báo mối đe dọa (CTI Enrichment)",
            metadata={
                "ioc_count": len(state.threat_intel.extracted_iocs) if state.threat_intel else 0,
                "mitre_count": len(state.threat_intel.mitre_techniques) if state.threat_intel else 0
            }
        )
        self._checkpoint(state, "enrichment")
        return state

    def rca_node(self, state: IncidentState) -> IncidentState:
        """Node Root Cause Analysis (RCA): Tái hiện chuỗi tiến trình và xác định điểm bắt nguồn (Tuần 8 Integration)."""
        logger.info(f"[{state.incident_id}] Thực thi RCA Node...")

        # 1. Gọi RCAAgent nếu được cấu hình
        if self.rca_agent is not None:
            if hasattr(self.rca_agent, "analyze_state"):
                state = self.rca_agent.analyze_state(state)
            elif hasattr(self.rca_agent, "analyze_events"):
                state.rca_result = self.rca_agent.analyze_events(state.parsed_events, threat_intel=state.threat_intel)
            self._checkpoint(state, "rca")
            return state

        process_tree: List[ProcessNode] = []
        timeline: List[str] = []

        for idx, event in enumerate(state.parsed_events):
            if event.process_name or event.command_line:
                p_node = ProcessNode(
                    process_id=f"PID-{1000 + idx}",
                    process_name=event.process_name or "unknown.exe",
                    command_line=event.command_line or "",
                    parent_id=f"PID-{999 + idx}" if idx > 0 else None,
                    is_malicious_origin=(idx == 0)
                )
                process_tree.append(p_node)
                timeline.append(
                    f"[{event.timestamp.strftime('%H:%M:%S')}] {p_node.process_name} thực thi: {p_node.command_line[:60]}"
                )

        initial_vector = "Spearphishing Email / Malicious Attachment"
        if state.parsed_events and any("zeek" in e.source_type.lower() for e in state.parsed_events):
            initial_vector = "Network Exploitation / External Vulnerability Scan"

        state.rca_result = RootCauseAnalysis(
            initial_access_vector=initial_vector,
            attack_timeline=timeline if timeline else ["Bắt đầu ghi nhận cảnh báo bất thường trên máy trạm"],
            process_tree=process_tree,
            mitre_tactics=["Initial Access", "Execution", "Defense Evasion"],
            root_cause_summary=f"Tấn công khởi nguồn từ {initial_vector}, thực thi chuỗi tiến trình độc hại qua {len(process_tree)} bước."
        )

        state.record_transition(
            node="rca",
            to_status=IncidentStatus.INVESTIGATING,
            message="Tái hiện thành công chuỗi tiến trình (Process Lineage) và nguyên nhân gốc rễ",
            metadata={"tree_depth": len(process_tree), "initial_vector": initial_vector}
        )
        self._checkpoint(state, "rca")
        return state

    def _run_rca_phase1(self, state: IncidentState) -> IncidentState:
        """Pha 1 của điều tra song song: chạy RCA deterministic (run_llm=False nếu hỗ trợ)."""
        if self.rca_agent is not None:
            if hasattr(self.rca_agent, "analyze_state"):
                try:
                    sig = inspect.signature(self.rca_agent.analyze_state)
                    accepts_var_kw = any(
                        p.kind == inspect.Parameter.VAR_KEYWORD
                        for p in sig.parameters.values()
                    )
                    if "run_llm" in sig.parameters or accepts_var_kw:
                        state = self.rca_agent.analyze_state(state, run_llm=False)
                    else:
                        state = self.rca_agent.analyze_state(state)
                except (ValueError, TypeError):
                    state = self.rca_agent.analyze_state(state)
            elif hasattr(self.rca_agent, "analyze_events"):
                state.rca_result = self.rca_agent.analyze_events(
                    state.parsed_events, threat_intel=state.threat_intel
                )
            self._checkpoint(state, "rca")
            return state
        return self.rca_node(state)

    def _reconcile_cti_and_rca(self, state: IncidentState) -> IncidentState:
        """Hợp nhất ngữ cảnh CTI <-> RCA ở pha Join khi RCAAgent không có correlate_with_threat_intel."""
        if state.rca_result is None or state.threat_intel is None:
            return state

        rca_res = state.rca_result
        cti = state.threat_intel

        # 1. Ánh xạ bổ sung MITRE Tactics từ CTI techniques vào RCA
        tactic_hints = {
            "T1059": "Execution",
            "T1027": "Defense Evasion",
            "T1071": "Command and Control",
            "T1105": "Command and Control",
            "T1110": "Credential Access",
            "T1046": "Discovery",
            "T1595": "Reconnaissance",
            "T1566": "Initial Access",
            "T1021": "Lateral Movement",
            "T1548": "Privilege Escalation",
        }
        existing_tactics = list(rca_res.mitre_tactics or [])
        for tech in cti.mitre_techniques or []:
            prefix = str(tech).split(".")[0].upper()
            inferred = tactic_hints.get(prefix)
            if inferred and inferred not in existing_tactics:
                existing_tactics.append(inferred)
        rca_res.mitre_tactics = existing_tactics

        # 2. Bổ sung C2 IP độc hại từ CTI vào attack_scope & root_cause_summary
        iocs = cti.extracted_iocs or cti.indicators or []
        malicious_ext_ips = sorted(
            {
                ioc.value
                for ioc in iocs
                if ioc.is_malicious
                and str(ioc.ioc_type or "").upper() == "IP"
                and ioc.value
                and not self._is_private_ip(ioc.value)
            }
        )
        if malicious_ext_ips:
            current_scope = rca_res.attack_scope or ""
            missing_ips = [ip for ip in malicious_ext_ips if ip not in current_scope]
            if missing_ips:
                extra = f"Kết nối C2 ngoại lai (CTI): {', '.join(missing_ips)}"
                rca_res.attack_scope = f"{current_scope} | {extra}" if current_scope else extra

            actors = [a for a in (cti.related_threat_actors or []) if a and "Unknown" not in a]
            actor_note = f" (Threat Actors: {', '.join(actors)})" if actors else ""
            c2_line = f"5. Bối cảnh CTI & C2: Ghi nhận máy chủ C2 ngoại lai {', '.join(malicious_ext_ips)}{actor_note}."
            if "Không ghi nhận máy chủ C2 ngoài mạng" in (rca_res.root_cause_summary or ""):
                rca_res.root_cause_summary = re.sub(
                    r"5\.\s*Bối cảnh CTI & C2:\s*Không ghi nhận máy chủ C2 ngoài mạng\.?",
                    c2_line,
                    rca_res.root_cause_summary,
                )
            elif not any(ip in (rca_res.root_cause_summary or "") for ip in malicious_ext_ips):
                rca_res.root_cause_summary = (
                    f"{rca_res.root_cause_summary}\n{c2_line}"
                    if rca_res.root_cause_summary
                    else c2_line
                )

        # 3. Phản hồi ngược mã MITRE từ high_fidelity_tree vào threat_intel.mitre_techniques
        existing_techs = list(cti.mitre_techniques or [])
        for node in getattr(rca_res, "high_fidelity_tree", None) or []:
            for tech in getattr(node, "mitre_techniques", None) or []:
                if tech and tech not in existing_techs:
                    existing_techs.append(tech)
        cti.mitre_techniques = existing_techs
        return state

    def parallel_investigation_node(self, state: IncidentState) -> IncidentState:
        """Node điều tra song song 2 pha (Fork-Join DAG):
        Pha 1 (Fork): Threat Intel CTI || RCA deterministic (run_llm=False).
        Pha 2 (Fan-In Join): Gộp history/telemetry không drop escalation + correlate_with_threat_intel(run_llm=True).
        """
        logger.info(f"[{state.incident_id}] Kích hoạt Parallel Investigation Node (Threat Intel CTI || RCA)...")

        base_history_len = len(state.history)
        base_tel_len = len(state.llm_telemetry)
        engine_mode = (
            (state.execution_metrics or {}).get("engine_mode")
            or (state.workflow_telemetry or {}).get("engine_mode")
            or ("langgraph" if (HAS_LANGGRAPH and self.use_langgraph_engine) else "fallback_loop")
        )

        # Pha 1 Fork: Tạo 2 bản sao độc lập và lan truyền ContextVar an toàn qua ThreadPoolExecutor
        state_cti = state.model_copy(deep=True)
        state_rca = state.model_copy(deep=True)

        ctx_cti = contextvars.copy_context()
        ctx_rca = contextvars.copy_context()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_cti = executor.submit(
                ctx_cti.run,
                self._run_node_with_metrics,
                "enrichment",
                self.enrichment_node,
                state_cti,
                engine_mode,
            )
            future_rca = executor.submit(
                ctx_rca.run,
                self._run_node_with_metrics,
                "rca",
                self._run_rca_phase1,
                state_rca,
                engine_mode,
            )

            try:
                res_cti = future_cti.result()
            except Exception as ex_cti:
                logger.error(f"[{state.incident_id}] Lỗi thực thi nhánh Threat Intel song song: {ex_cti}", exc_info=True)
                res_cti = state_cti
                res_cti.threat_intel = ThreatIntelEnrichment(enrichment_summary=f"Lỗi tra cứu CTI: {ex_cti}")

            try:
                res_rca = future_rca.result()
            except Exception as ex_rca:
                logger.error(f"[{state.incident_id}] Lỗi thực thi nhánh RCA song song: {ex_rca}", exc_info=True)
                res_rca = state_rca
                res_rca.rca_result = RootCauseAnalysis(
                    initial_access_vector="Unknown (Analysis Failed)",
                    root_cause_summary=f"Phân tích RCA gặp sự cố ngoại lệ: {ex_rca}"
                )

        # Pha 2 Fan-In Join: Tổng hợp kết quả từ hai nhánh điều tra
        state.threat_intel = res_cti.threat_intel
        state.rca_result = res_rca.rca_result
        if res_rca.attack_type:
            state.attack_type = res_rca.attack_type

        if getattr(res_cti, "checkpoints", None):
            state.checkpoints.update(res_cti.checkpoints)
        if getattr(res_rca, "checkpoints", None):
            state.checkpoints.update(res_rca.checkpoints)

        # Cập nhật mức độ nghiêm trọng nếu Threat Intel phát hiện IoC nguy hiểm (Self-Correction)
        if res_cti.triage_result and state.triage_result:
            if res_cti.triage_result.severity != state.triage_result.severity:
                state.triage_result.severity = res_cti.triage_result.severity
                state.triage_result.summary = res_cti.triage_result.summary

        # Hợp nhất lịch sử mới từ 2 nhánh theo thứ tự thời gian (KHÔNG lọc theo seen node names để bảo toàn Self-Correction!)
        new_transitions = list(res_cti.history[base_history_len:]) + list(res_rca.history[base_history_len:])
        new_transitions.sort(key=lambda t: t.timestamp)
        state.history.extend(new_transitions)
        if state.history:
            state.status = state.history[-1].to_status

        # Gộp LLM telemetry & node latencies từ hai nhánh
        for tel_entry in list(res_cti.llm_telemetry[base_tel_len:]) + list(res_rca.llm_telemetry[base_tel_len:]):
            state.record_llm_telemetry(tel_entry)

        for branch_res in (res_cti, res_rca):
            branch_wf_lat = (branch_res.workflow_telemetry or {}).get("node_latencies_ms", {})
            branch_ex_lat = (branch_res.execution_metrics or {}).get("node_latencies_ms", {})
            merged_lat = {**branch_ex_lat, **branch_wf_lat}
            if merged_lat:
                state.workflow_telemetry.setdefault("node_latencies_ms", {}).update(merged_lat)
                state.execution_metrics.setdefault("node_latencies_ms", {}).update(merged_lat)
            branch_steps = (branch_res.workflow_telemetry or {}).get("steps", [])
            if branch_steps:
                existing_steps = state.workflow_telemetry.setdefault("steps", [])
                for st_item in branch_steps:
                    if st_item not in existing_steps:
                        existing_steps.append(st_item)

        # Chạy bước đối chiếu liên nhánh CTI <-> RCA (và tổng hợp LLM RCA có đủ CTI context)
        if self.rca_agent is not None and hasattr(self.rca_agent, "correlate_with_threat_intel"):
            def _run_corr(s: IncidentState) -> IncidentState:
                try:
                    sig = inspect.signature(self.rca_agent.correlate_with_threat_intel)
                    accepts_var_kw = any(
                        p.kind == inspect.Parameter.VAR_KEYWORD
                        for p in sig.parameters.values()
                    )
                    if "run_llm" in sig.parameters or accepts_var_kw:
                        return self.rca_agent.correlate_with_threat_intel(s, run_llm=True)
                    return self.rca_agent.correlate_with_threat_intel(s)
                except (ValueError, TypeError):
                    return self.rca_agent.correlate_with_threat_intel(s)

            state = self._run_node_with_metrics(
                "rca_correlation",
                _run_corr,
                state,
                engine_mode=engine_mode,
            )
        else:
            state = self._reconcile_cti_and_rca(state)

        state.record_transition(
            node="parallel_investigation",
            to_status=IncidentStatus.INVESTIGATING,
            message="Hoàn tất điều tra song song 2 pha (Threat Intel CTI || RCA + Correlation Join)",
            metadata={
                "parallel_workers": 2,
                "has_threat_intel": state.threat_intel is not None,
                "has_rca": state.rca_result is not None,
                "cti_correlated": True,
            }
        )
        self._checkpoint(state, "parallel_investigation")
        return state

    def response_node(self, state: IncidentState) -> IncidentState:
        """Node Response Recommendation: Đề xuất hành động ngăn chặn & khắc phục theo NIST SP 800-61."""
        logger.info(f"[{state.incident_id}] Thực thi Response Node...")

        # 1. Gọi ResponseAgent nếu được cấu hình
        if self.response_agent is not None:
            if hasattr(self.response_agent, "process_state"):
                state = self.response_agent.process_state(state)
            elif hasattr(self.response_agent, "analyze_state"):
                state = self.response_agent.analyze_state(state)
            elif hasattr(self.response_agent, "recommend_actions"):
                state.recommended_actions = self.response_agent.recommend_actions(state)
            self._checkpoint(state, "response")
            return state

        host: Optional[str] = None
        malicious_ip: Optional[str] = None
        proc: Optional[str] = None

        known_clean_ips = set()
        if state.threat_intel:
            extracted = getattr(state.threat_intel, "extracted_iocs", None) or []
            for ioc in extracted:
                ioc_val = str(getattr(ioc, "value", "") or "").strip()
                if isinstance(getattr(ioc, "details", None), dict) and ioc.details.get("status") == "known_clean_ip":
                    if ioc_val:
                        known_clean_ips.add(ioc_val)
            for ioc in extracted:
                ioc_val = str(getattr(ioc, "value", "") or "").strip()
                if (
                    str(getattr(ioc, "ioc_type", "")).upper() == "IP"
                    and getattr(ioc, "is_malicious", False)
                    and ioc_val
                    and not self._is_private_ip(ioc_val)
                ):
                    malicious_ip = ioc_val
                    break
            if not malicious_ip:
                for ioc in extracted:
                    ioc_val = str(getattr(ioc, "value", "") or "").strip()
                    if (
                        str(getattr(ioc, "ioc_type", "")).upper() == "IP"
                        and ioc_val
                        and ioc_val not in known_clean_ips
                        and not self._is_private_ip(ioc_val)
                    ):
                        malicious_ip = ioc_val
                        break

        for event in state.parsed_events:
            if event.host_name and event.host_name != "UNKNOWN-HOST":
                host = event.host_name
            if not malicious_ip:
                for candidate_ip in (event.dest_ip, event.source_ip):
                    if (
                        candidate_ip
                        and candidate_ip not in known_clean_ips
                        and not self._is_private_ip(candidate_ip)
                    ):
                        malicious_ip = candidate_ip.strip()
                        break
            if event.process_name:
                proc = event.process_name

        resolved_host = host or "WORKSTATION-01"
        if malicious_ip and proc:
            actions = ResponsePlaybooks.malware_incident_playbook(
                host_name=resolved_host,
                malicious_ip=malicious_ip,
                process_name=proc,
            )
        else:
            actions = [
                RecommendedAction(
                    action_id="ACT-MALW-ISOLATE",
                    action_type=ActionType.ISOLATE_HOST,
                    target=resolved_host,
                    description=f"Cô lập máy trạm {resolved_host} khỏi mạng nội bộ để ngăn chặn lây lan.",
                    priority=1,
                    require_human_approval=True,
                    phase=IncidentPhase.CONTAINMENT,
                    script_bundle=ResponsePlaybooks.create_bundle(
                        "ACT-MALW-ISOLATE", ActionType.ISOLATE_HOST, resolved_host, IncidentPhase.CONTAINMENT
                    ),
                )
            ]
            if proc:
                is_crit = ResponsePlaybooks.is_critical_system_process(proc)
                actions.append(
                    RecommendedAction(
                        action_id="ACT-MALW-KILL",
                        action_type=ActionType.KILL_PROCESS,
                        target=proc,
                        description=(
                            f"CẢNH BÁO: Tiến trình {proc} là tiến trình hệ thống trọng yếu. Đề xuất cô lập máy trạm thay vì tiêu diệt."
                            if is_crit
                            else f"Tiêu diệt tiến trình độc hại {proc} đang chạy trên máy trạm."
                        ),
                        priority=1 if is_crit else 2,
                        require_human_approval=True if is_crit else False,
                        phase=IncidentPhase.CONTAINMENT,
                        script_bundle=ResponsePlaybooks.create_bundle(
                            "ACT-MALW-KILL", ActionType.KILL_PROCESS, proc, IncidentPhase.CONTAINMENT
                        ),
                    )
                )
            if malicious_ip:
                actions.append(
                    RecommendedAction(
                        action_id="ACT-MALW-BLOCK",
                        action_type=ActionType.BLOCK_IP,
                        target=malicious_ip,
                        description=f"Chặn địa chỉ IP C2 {malicious_ip} trên Firewall và Web Proxy.",
                        priority=1,
                        require_human_approval=True,
                        phase=IncidentPhase.CONTAINMENT,
                        script_bundle=ResponsePlaybooks.create_bundle(
                            "ACT-MALW-BLOCK", ActionType.BLOCK_IP, malicious_ip, IncidentPhase.CONTAINMENT
                        ),
                    )
                )
        state.recommended_actions = actions

        state.record_transition(
            node="response",
            to_status=IncidentStatus.INVESTIGATING,
            message=f"Đã đề xuất {len(actions)} hành động ứng phó khẩn cấp theo NIST SP 800-61",
            metadata={"action_count": len(actions)}
        )
        self._checkpoint(state, "response")
        return state

    def hitl_approval_node(self, state: IncidentState) -> IncidentState:
        """Node Human-In-The-Loop: Chuyên viên SOC kiểm định và phê duyệt các hành động phản ứng."""
        logger.info(f"[{state.incident_id}] Thực thi HITL Approval Node...")

        # 1. Gọi hook nếu được cấu hình từ ngoài
        if self.hitl_hook is not None:
            state = self.hitl_hook(state)
        else:
            hitl_mgr = self.hitl_manager or HITLManager()
            pending = hitl_mgr.get_pending_actions(state)
            if state.analyst_approved is None:
                if pending and not self.auto_approve:
                    state.record_transition(
                        node="hitl_approval",
                        to_status=IncidentStatus.AWAITING_APPROVAL,
                        message=f"Tạm dừng chờ chuyên viên phê duyệt {len(pending)} hành động ứng phó",
                        metadata={"pending_count": len(pending), "awaiting_approval": True}
                    )
                    state.next_node = "awaiting_approval"
                    self._checkpoint(state, "hitl_approval")
                    return state
                elif self.auto_approve:
                    if self.hitl_manager is not None:
                        state = self.hitl_manager.approve_all(
                            state,
                            analyst_id="soc_analyst_01",
                            notes="Tự động phê duyệt bởi Giám sát An toàn (Automated Safety Policy)"
                        )
                    else:
                        state.analyst_approved = True
                        state.analyst_feedback = "Tự động phê duyệt bởi Giám sát An toàn (Automated Safety Policy)"
                else:
                    state.analyst_approved = True
                    state.analyst_feedback = "Không có hành động yêu cầu phê duyệt thủ công"

        # Cập nhật trạng thái từng hành động nếu chưa được gán
        for action in state.recommended_actions:
            if state.analyst_approved is False:
                action.is_approved = False
            elif action.is_approved is None:
                action.is_approved = state.analyst_approved if action.require_human_approval else True

        if state.analyst_approved:
            new_status = IncidentStatus.CONTAINED
            msg = f"Chuyên viên phê duyệt hành động ứng phó: {state.analyst_feedback or 'Đồng ý thực thi'}"
        else:
            new_status = IncidentStatus.INVESTIGATING
            msg = f"Chuyên viên từ chối hoặc bảo lưu kế hoạch: {state.analyst_feedback or 'Yêu cầu rà soát bổ sung'}"

        state.record_transition(
            node="hitl_approval",
            to_status=new_status,
            message=msg,
            metadata={"approved": state.analyst_approved, "feedback": state.analyst_feedback}
        )

        # 2. Xử lý Feedback Loop / Backtracking ngay trong node (tránh đột biến state ở conditional edge)
        if state.analyst_approved is False:
            effective_max = self.max_reanalysis if self.max_reanalysis is not None else state.max_reanalysis
            feedback_override = _RESUME_FEEDBACK_OVERRIDE.get()
            feedback = state.analyst_feedback or ""
            feedback_lower = feedback.lower()

            if feedback_override is False:
                should_loop = False
            elif feedback_override is True:
                should_loop = getattr(self, "enable_feedback_loop", True) and state.reanalysis_count < effective_max
            else:
                if self.hitl_hook is None and any(
                    kw in feedback_lower for kw in _MANUAL_CLOSE_FEEDBACK_KEYWORDS
                ):
                    should_loop = False
                else:
                    should_loop = getattr(self, "enable_feedback_loop", True) and state.reanalysis_count < effective_max

            if should_loop:
                state.reanalysis_count += 1
                if any(k in feedback_lower for k in _RCA_FEEDBACK_KEYWORDS):
                    target_route = "retry_rca"
                    fb_msg = (
                        f"Kích hoạt Feedback Loop (Lần {state.reanalysis_count}/{effective_max}): "
                        f"Quay lại RCA Agent do chuyên viên yêu cầu rà soát nguyên nhân gốc rễ."
                    )
                else:
                    target_route = "retry_response"
                    fb_msg = (
                        f"Kích hoạt Feedback Loop (Lần {state.reanalysis_count}/{effective_max}): "
                        f"Quay lại Response Agent do chuyên viên từ chối/yêu cầu điều chỉnh kế hoạch."
                    )

                state.analyst_approved = None
                state.reanalysis_reason = feedback or "Chuyên viên từ chối phương án"
                state.next_node = target_route

                state.record_transition(
                    node="hitl_approval",
                    to_status=IncidentStatus.INVESTIGATING,
                    message=fb_msg,
                    metadata={
                        "reanalysis_count": state.reanalysis_count,
                        "target_route": target_route,
                        "feedback": feedback,
                    }
                )
                self._checkpoint(state, "hitl_approval")
                return state

        state.next_node = "proceed_reporting"
        self._checkpoint(state, "hitl_approval")
        return state

    def reporting_node(self, state: IncidentState) -> IncidentState:
        """Node Reporting: Tổng hợp toàn bộ IncidentState thành báo cáo điều tra chuẩn hóa IncidentReport."""
        logger.info(f"[{state.incident_id}] Thực thi Reporting Node...")

        # 1. Gọi ReportingAgent nếu được cấu hình
        if self.reporting_agent is not None:
            if hasattr(self.reporting_agent, "process_state"):
                state = self.reporting_agent.process_state(state)
            elif hasattr(self.reporting_agent, "generate_report"):
                state.final_report = self.reporting_agent.generate_report(state)
                state.record_transition(
                    node="reporting",
                    to_status=IncidentStatus.RESOLVED,
                    message="Đã xuất bản thành công Báo cáo Điều tra Toàn diện qua ReportingAgent",
                    metadata={"report_id": state.final_report.report_id}
                )
            state.next_node = END
            self._checkpoint(state, "reporting")
            return state

        triage = state.triage_result
        sev = triage.severity.value if triage else "HIGH"
        summary = triage.summary if triage else "Phát hiện sự cố an ninh nghiêm trọng"

        attack_type = (
            state.attack_type
            or (state.rca_result.confirmed_attack_type if state.rca_result else None)
            or (triage.attack_type if triage else None)
            or ("Normal Administrative Activity (Benign)" if (triage and not triage.is_incident) else "Endpoint Malware & C2 Reverse Shell")
        )
        if not state.attack_type:
            state.attack_type = attack_type

        if triage and triage.attack_category:
            attack_category = triage.attack_category.value if hasattr(triage.attack_category, "value") else str(triage.attack_category)
        elif "Malware" in attack_type or "Reverse Shell" in attack_type:
            attack_category = "MALWARE"
        elif "Password" in attack_type or "Credential" in attack_type:
            attack_category = "CREDENTIAL_ACCESS"
        elif "Scanning" in attack_type or "Discovery" in attack_type:
            attack_category = "RECONNAISSANCE"
        elif "Web" in attack_type:
            attack_category = "WEB_ATTACK"
        elif "Benign" in attack_type or "Normal" in attack_type:
            attack_category = "BENIGN"
        else:
            attack_category = "UNKNOWN"

        confidence_level = float(triage.confidence_score) if (triage and triage.confidence_score is not None) else 0.90

        report = IncidentReport(
            report_id=f"REP-{state.incident_id}",
            incident_title=f"Báo cáo Điều tra Sự cố [{sev}]: {attack_type} - {state.incident_id}",
            created_at=datetime.now(timezone.utc),
            executive_summary=(
                f"Sự cố {state.incident_id} được phát hiện và xử lý tự động bởi hệ thống SOC Multi-Agent. "
                f"Đánh giá rủi ro: {sev}. Định danh loại tấn công: {attack_type}. {summary} "
                f"Đã kích hoạt {len(state.recommended_actions)} biện pháp ngăn chặn kịp thời."
            ),
            detailed_findings=(
                f"1. Tổng số sự kiện phân tích: {len(state.parsed_events)}\n"
                f"2. Nguồn xâm nhập ban đầu: {state.rca_result.initial_access_vector if state.rca_result else 'Chưa xác định'}\n"
                f"3. Tóm lược phân tích nguyên nhân: {state.rca_result.root_cause_summary if state.rca_result else 'N/A'}"
            ),
            mitre_attack_matrix_mapping=state.threat_intel.mitre_techniques if state.threat_intel else ["T1059.001"],
            ioc_table=state.threat_intel.extracted_iocs if state.threat_intel else [],
            action_plan=state.recommended_actions,
            attack_type=attack_type,
            attack_category=attack_category,
            confidence_level=confidence_level,
        )
        state.final_report = report

        state.record_transition(
            node="reporting",
            to_status=IncidentStatus.RESOLVED,
            message="Đã xuất bản thành công Báo cáo Điều tra Toàn diện (Final Incident Report)",
            metadata={"report_id": report.report_id}
        )
        state.next_node = END
        self._checkpoint(state, "reporting")
        return state

    # =====================================================================
    # 3. WORKFLOW EXECUTION ENGINES (invoke, stream, step, resume)
    # =====================================================================
    def _get_next_node(self, current_node: str, state: IncidentState) -> str:
        """Xác định Node kế tiếp trong đồ thị dựa trên conditional_edges hoặc edges."""
        if current_node in self.conditional_edges:
            condition_fn, path_map = self.conditional_edges[current_node]
            branch_key = condition_fn(state)
            next_node = path_map.get(branch_key, END)
            logger.debug(f"Conditional Edge [{current_node}] -> '{branch_key}' -> [{next_node}]")
            return next_node
        if current_node in self.edges:
            return self.edges[current_node]
        return END

    def _invoke_fallback_loop(
        self,
        current_state: IncidentState,
        max_steps: int = 25,
        start_node: Optional[str] = None,
    ) -> IncidentState:
        """Fallback thực thi tuần tự khi LangGraph không khả dụng hoặc use_langgraph_engine=False."""
        current_node = start_node or self.entry_point
        step_count = 0

        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                raise ValueError(f"Node không hợp lệ hoặc chưa đăng ký trong đồ thị: '{current_node}'")

            current_state = self._run_node_with_metrics(
                current_node,
                self.nodes[current_node],
                current_state,
                engine_mode="fallback_loop",
            )

            if current_state.status == IncidentStatus.AWAITING_APPROVAL:
                logger.info(
                    f"[{current_state.incident_id}] Pipeline tạm dừng tại Node '{current_node}' "
                    f"với trạng thái AWAITING_APPROVAL để chờ phê duyệt từ chuyên viên SOC."
                )
                break

            current_node = self._get_next_node(current_node, current_state)

        if step_count >= max_steps:
            logger.warning(f"Pipeline dừng do đạt giới hạn số bước tối đa ({max_steps})")

        current_state.workflow_telemetry["engine_mode"] = "fallback_loop"
        current_state.execution_metrics["engine_mode"] = "fallback_loop"
        return current_state

    def invoke(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        max_steps: int = 25
    ) -> IncidentState:
        """Thực thi toàn bộ đồ thị StateGraph qua CompiledStateGraph (hoặc fallback loop)."""
        current_state = self._coerce_state(state)
        logger.info(f"Khởi động pipeline StateGraph cho sự cố: {current_state.incident_id}")

        if HAS_LANGGRAPH and self.use_langgraph_engine:
            app = self.get_langgraph_app()
            tid = self._allocate_thread_id(current_state.incident_id)
            cfg = {
                "configurable": {"thread_id": tid},
                "recursion_limit": max(max_steps + 5, 25),
            }
            raw_out = app.invoke(current_state, config=cfg)
            result_state = self._coerce_state(raw_out)
            result_state.workflow_telemetry["engine_mode"] = "langgraph"
            result_state.execution_metrics["engine_mode"] = "langgraph"
            return result_state

        return self._invoke_fallback_loop(current_state, max_steps=max_steps)

    def stream(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        max_steps: int = 25
    ) -> Generator[Tuple[str, IncidentState], None, None]:
        """Thực thi đồ thị dưới dạng Stream từng Node (cho phép theo dõi tiến trình thời gian thực)."""
        current_state = self._coerce_state(state)

        if HAS_LANGGRAPH and self.use_langgraph_engine:
            app = self.get_langgraph_app()
            tid = self._allocate_thread_id(current_state.incident_id)
            cfg = {
                "configurable": {"thread_id": tid},
                "recursion_limit": max(max_steps + 5, 25),
            }
            for chunk in app.stream(current_state, config=cfg, stream_mode="updates"):
                if not isinstance(chunk, dict):
                    continue
                for node_name, node_output in chunk.items():
                    if node_name == "__interrupt__":
                        continue
                    coerced = self._coerce_state(node_output)
                    coerced.workflow_telemetry["engine_mode"] = "langgraph"
                    coerced.execution_metrics["engine_mode"] = "langgraph"
                    yield (node_name, coerced)
                    if coerced.status == IncidentStatus.AWAITING_APPROVAL:
                        logger.info(f"[{coerced.incident_id}] Stream dừng tại trạng thái AWAITING_APPROVAL.")
                        return
            return

        current_node = self.entry_point
        step_count = 0
        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                break

            current_state = self._run_node_with_metrics(
                current_node,
                self.nodes[current_node],
                current_state,
                engine_mode="fallback_loop",
            )
            yield (current_node, current_state)

            if current_state.status == IncidentStatus.AWAITING_APPROVAL:
                logger.info(f"[{current_state.incident_id}] Stream dừng tại trạng thái AWAITING_APPROVAL.")
                break

            current_node = self._get_next_node(current_node, current_state)

    def step(
        self,
        current_node: str,
        state: Union[IncidentState, Dict[str, Any]]
    ) -> Tuple[Optional[str], IncidentState]:
        """Thực thi đơn lẻ một bước (Node) và trả về Node tiếp theo kèm State đã cập nhật."""
        current_state = self._coerce_state(state)
        if current_node not in self.nodes:
            raise ValueError(f"Node không tồn tại: '{current_node}'")

        engine_mode = "langgraph" if (HAS_LANGGRAPH and self.use_langgraph_engine) else "fallback_loop"
        current_state = self._run_node_with_metrics(
            current_node,
            self.nodes[current_node],
            current_state,
            engine_mode=engine_mode,
        )

        # Nếu sau bước này trạng thái là AWAITING_APPROVAL, giữ ở hitl_approval
        if current_state.status == IncidentStatus.AWAITING_APPROVAL:
            return ("hitl_approval", current_state)

        next_node = self._get_next_node(current_node, current_state)
        return (next_node if next_node != END else None, current_state)

    def _pause_before_hitl_state(self, current_state: IncidentState) -> IncidentState:
        """Ghi nhận transition AWAITING_APPROVAL và checkpoint khi tạm dừng trước node hitl_approval."""
        hitl_mgr = self.hitl_manager or HITLManager()
        pending = hitl_mgr.get_pending_actions(current_state)
        if current_state.status != IncidentStatus.AWAITING_APPROVAL:
            current_state.record_transition(
                node="hitl_approval",
                to_status=IncidentStatus.AWAITING_APPROVAL,
                message="Pipeline tạm dừng tại điểm ngắt HITL - Đang chờ chuyên viên phê duyệt hành động",
                metadata={"awaiting_approval": True, "pending_count": len(pending)},
            )
        current_state.next_node = "awaiting_approval"
        self._checkpoint(current_state, "hitl_approval")
        return current_state

    def _execute_until_interrupt_fallback(
        self,
        current_state: IncidentState,
        max_steps: int = 25,
        start_node: Optional[str] = None,
    ) -> Tuple[bool, IncidentState]:
        """Fallback loop cho execute_until_interrupt khi tắt LangGraph."""
        current_node = start_node or self.entry_point
        step_count = 0

        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                raise ValueError(f"Node không hợp lệ hoặc chưa đăng ký trong đồ thị: '{current_node}'")

            if current_node == "hitl_approval":
                hitl_mgr = self.hitl_manager or HITLManager()
                pending = hitl_mgr.get_pending_actions(current_state)
                if (
                    pending
                    and not self.auto_approve
                    and current_state.analyst_approved is None
                    and self.hitl_hook is None
                ):
                    current_state = self._pause_before_hitl_state(current_state)
                    current_state.workflow_telemetry["engine_mode"] = "fallback_loop"
                    current_state.execution_metrics["engine_mode"] = "fallback_loop"
                    return (True, current_state)

            current_state = self._run_node_with_metrics(
                current_node,
                self.nodes[current_node],
                current_state,
                engine_mode="fallback_loop",
            )

            if current_state.status == IncidentStatus.AWAITING_APPROVAL:
                return (True, current_state)

            current_node = self._get_next_node(current_node, current_state)

        current_state.workflow_telemetry["engine_mode"] = "fallback_loop"
        current_state.execution_metrics["engine_mode"] = "fallback_loop"
        return (False, current_state)

    def execute_until_interrupt(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        max_steps: int = 25,
        start_node: Optional[str] = None,
    ) -> Tuple[bool, IncidentState]:
        """Thực thi StateGraph từ entry_point (hoặc start_node) cho đến điểm ngắt HITL hoặc END."""
        current_state = self._coerce_state(state)
        logger.info(f"Khởi động execute_until_interrupt cho sự cố: {current_state.incident_id}")

        if not (HAS_LANGGRAPH and self.use_langgraph_engine):
            return self._execute_until_interrupt_fallback(
                current_state, max_steps=max_steps, start_node=start_node
            )

        app_int = self.get_langgraph_interrupt_app()
        tid = self._allocate_thread_id(current_state.incident_id)
        cfg = {
            "configurable": {"thread_id": tid},
            "recursion_limit": max(max_steps + 5, 25),
        }

        if start_node is not None and start_node != self.entry_point:
            if start_node not in self.nodes:
                raise ValueError(f"Node không hợp lệ hoặc chưa đăng ký trong đồ thị: '{start_node}'")
            if start_node == "hitl_approval":
                predecessor = self._hitl_predecessor()
                if predecessor:
                    app_int.update_state(cfg, current_state.model_dump(), as_node=predecessor)
                    raw_out: Any = current_state.model_dump()
                else:
                    return self._execute_until_interrupt_fallback(
                        current_state, max_steps=max_steps, start_node=start_node
                    )
            else:
                current_state = self._run_node_with_metrics(
                    start_node,
                    self.nodes[start_node],
                    current_state,
                    engine_mode="langgraph",
                )
                if current_state.status == IncidentStatus.AWAITING_APPROVAL:
                    return (True, current_state)
                app_int.update_state(cfg, current_state.model_dump(), as_node=start_node)
                snap_mid = app_int.get_state(cfg)
                if snap_mid and snap_mid.next:
                    raw_out = app_int.invoke(None, config=cfg)
                else:
                    raw_out = current_state
        else:
            raw_out = app_int.invoke(current_state, config=cfg)

        snap = app_int.get_state(cfg)
        coerced = self._coerce_state(raw_out)
        coerced.workflow_telemetry["engine_mode"] = "langgraph"
        coerced.execution_metrics["engine_mode"] = "langgraph"

        if snap and "hitl_approval" in (snap.next or ()):
            hitl_mgr = self.hitl_manager or HITLManager()
            pending = hitl_mgr.get_pending_actions(coerced)
            if (
                pending
                and not self.auto_approve
                and coerced.analyst_approved is None
                and self.hitl_hook is None
            ):
                coerced = self._pause_before_hitl_state(coerced)
                predecessor = self._hitl_predecessor()
                if predecessor:
                    app_int.update_state(cfg, coerced.model_dump(), as_node=predecessor)
                logger.info(f"[{coerced.incident_id}] Pipeline tạm dừng (is_paused=True) tại Node hitl_approval.")
                return (True, coerced)

            # Không cần tạm dừng (auto_approve=True, hoặc không có pending, hoặc có hitl_hook): chạy tiếp
            loop_guard = 0
            while snap and "hitl_approval" in (snap.next or ()) and loop_guard < max_steps:
                loop_guard += 1
                raw_out = app_int.invoke(None, config=cfg)
                coerced = self._coerce_state(raw_out)
                coerced.workflow_telemetry["engine_mode"] = "langgraph"
                coerced.execution_metrics["engine_mode"] = "langgraph"
                if coerced.status == IncidentStatus.AWAITING_APPROVAL:
                    return (True, coerced)
                snap = app_int.get_state(cfg)
            return (False, coerced)

        return (False, coerced)

    def _resume_fallback_from_hitl(
        self,
        current_state: IncidentState,
        max_steps: int = 25,
        allow_feedback_loop: Optional[bool] = None,
    ) -> IncidentState:
        """Fallback resume khi tắt LangGraph hoặc không tìm thấy node hitl_approval."""
        tok = _RESUME_FEEDBACK_OVERRIDE.set(allow_feedback_loop)
        try:
            current_state = self._run_node_with_metrics(
                "hitl_approval",
                self.nodes.get("hitl_approval", self.hitl_approval_node),
                current_state,
                engine_mode="fallback_loop",
            )
        finally:
            _RESUME_FEEDBACK_OVERRIDE.reset(tok)

        if current_state.status == IncidentStatus.AWAITING_APPROVAL:
            return current_state

        current_node = self._get_next_node("hitl_approval", current_state)
        step_count = 0
        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                break
            if current_node == "hitl_approval":
                current_state = self._pause_before_hitl_state(current_state)
                break
            current_state = self._run_node_with_metrics(
                current_node,
                self.nodes[current_node],
                current_state,
                engine_mode="fallback_loop",
            )
            current_node = self._get_next_node(current_node, current_state)

        current_state.workflow_telemetry["engine_mode"] = "fallback_loop"
        current_state.execution_metrics["engine_mode"] = "fallback_loop"
        return current_state

    def _resume_langgraph_from_hitl(
        self,
        current_state: IncidentState,
        max_steps: int = 25,
        allow_feedback_loop: Optional[bool] = None,
    ) -> IncidentState:
        """Hợp nhất cơ chế resume từ HITL & cold-thread hydration trên CompiledStateGraph."""
        if not (HAS_LANGGRAPH and self.use_langgraph_engine) or "hitl_approval" not in self.nodes:
            return self._resume_fallback_from_hitl(
                current_state, max_steps=max_steps, allow_feedback_loop=allow_feedback_loop
            )

        app_int = self.get_langgraph_interrupt_app()
        predecessor = self._hitl_predecessor()
        if not predecessor:
            return self._resume_fallback_from_hitl(
                current_state, max_steps=max_steps, allow_feedback_loop=allow_feedback_loop
            )

        with self._thread_lock:
            tid = self._active_threads.get(current_state.incident_id)

        need_cold_hydration = True
        if tid:
            cfg_existing = {"configurable": {"thread_id": tid}}
            try:
                snap_existing = app_int.get_state(cfg_existing)
                if snap_existing and "hitl_approval" in (snap_existing.next or ()):
                    need_cold_hydration = False
            except Exception:
                need_cold_hydration = True

        if need_cold_hydration:
            tid = self._allocate_thread_id(current_state.incident_id)

        cfg = {
            "configurable": {"thread_id": tid},
            "recursion_limit": max(max_steps + 5, 25),
        }
        # Hydrate/đồng bộ trạng thái mới nhất (decisions/approve/reject/JSON cold load) vào checkpoint ngay trước hitl_approval
        app_int.update_state(cfg, current_state.model_dump(), as_node=predecessor)

        tok = _RESUME_FEEDBACK_OVERRIDE.set(allow_feedback_loop)
        try:
            raw_out = app_int.invoke(None, config=cfg)
        finally:
            _RESUME_FEEDBACK_OVERRIDE.reset(tok)

        coerced = self._coerce_state(raw_out)
        coerced.workflow_telemetry["engine_mode"] = "langgraph"
        coerced.execution_metrics["engine_mode"] = "langgraph"

        snap_after = app_int.get_state(cfg)
        if snap_after and "hitl_approval" in (snap_after.next or ()):
            # Feedback Loop (retry_response / retry_rca) đã chạy lại nhánh điều tra và tự ngắt trước hitl_approval
            coerced = self._pause_before_hitl_state(coerced)
            app_int.update_state(cfg, coerced.model_dump(), as_node=predecessor)

        return coerced

    def resume_after_hitl(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        analyst_approved: bool,
        analyst_feedback: Optional[str] = None,
        allow_feedback_loop: Optional[bool] = None,
    ) -> IncidentState:
        """Tiếp tục điều phối sau khi chuyên viên SOC can thiệp và phê duyệt kế hoạch."""
        current_state = self._coerce_state(state)
        current_state.analyst_approved = analyst_approved
        current_state.analyst_feedback = analyst_feedback
        return self._resume_langgraph_from_hitl(
            current_state=current_state,
            max_steps=25,
            allow_feedback_loop=allow_feedback_loop,
        )

    def resume_from_interrupt(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        decisions: Optional[List[HITLDecision]] = None,
        max_steps: int = 25,
        allow_feedback_loop: Optional[bool] = None,
    ) -> IncidentState:
        """Tiếp tục điều phối StateGraph sau khi chuyên viên đưa ra quyết định tại điểm ngắt HITL."""
        current_state = self._coerce_state(state)

        if decisions:
            manager = self.hitl_manager or HITLManager()
            for decision in decisions:
                current_state = manager.submit_decision(current_state, decision)

        return self._resume_langgraph_from_hitl(
            current_state=current_state,
            max_steps=max_steps,
            allow_feedback_loop=allow_feedback_loop,
        )

    # =====================================================================
    # 4. CHECKPOINT & STATE HISTORY UTILITIES
    # =====================================================================
    def _checkpoint(self, state: IncidentState, node_name: str):
        """Lưu snapshot dữ liệu vào bộ nhớ checkpoints một cách an toàn đa luồng."""
        snapshot = {
            "node": node_name,
            "status": state.status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "parsed_events_count": len(state.parsed_events),
            "has_triage": state.triage_result is not None,
            "has_threat_intel": state.threat_intel is not None,
            "has_rca": state.rca_result is not None,
            "has_report": state.final_report is not None,
        }
        state.checkpoints[node_name] = snapshot
        lock = getattr(self, "_checkpoint_lock", None)
        if lock is not None:
            with lock:
                inc_cps = self.checkpointer.setdefault(state.incident_id, {})
                inc_cps[node_name] = snapshot
        else:
            if state.incident_id not in self.checkpointer:
                self.checkpointer[state.incident_id] = {}
            self.checkpointer[state.incident_id][node_name] = snapshot

    def get_checkpoint(self, state: IncidentState, node_name: str) -> Optional[Dict[str, Any]]:
        """Lấy snapshot checkpoint tại một node bất kỳ."""
        return state.checkpoints.get(node_name)

    def get_transition_history(self, state: IncidentState) -> List[StateTransition]:
        """Lấy toàn bộ danh sách lịch sử chuyển đổi trạng thái."""
        return state.history

    # =====================================================================
    # 5. HELPER ENGINES & GRAPH VISUALIZATION
    # =====================================================================
    def _coerce_state(self, state_input: Union[IncidentState, Dict[str, Any]]) -> IncidentState:
        """Đảm bảo State luôn là Pydantic IncidentState."""
        if isinstance(state_input, IncidentState):
            return state_input
        elif isinstance(state_input, dict):
            return IncidentState(**state_input)
        raise TypeError(f"State phải là IncidentState hoặc dict, nhận được: {type(state_input)}")

    def _is_private_ip(self, ip: str) -> bool:
        """Kiểm tra IP nội bộ / private RFC 1918, loopback, link-local hoặc chuỗi không phải IP."""
        if not ip or not isinstance(ip, str):
            return True
        cleaned = ip.strip()
        if ":" in cleaned and not cleaned.startswith("[") and cleaned.count(":") == 1:
            cleaned = cleaned.split(":")[0]
        if cleaned.startswith("10.") or cleaned.startswith("192.168.") or cleaned.startswith("127."):
            return True
        if cleaned.startswith("169.254.") or cleaned.startswith("0."):
            return True
        if cleaned.startswith("172."):
            parts = cleaned.split(".")
            if len(parts) >= 2 and parts[1].isdigit():
                sec = int(parts[1])
                if 16 <= sec <= 31:
                    return True
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            if (
                ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            ):
                return True
            # Cho phép RFC 5737 TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) dùng trong test/lab
            if ip_obj.version == 4:
                octets = cleaned.split(".")
                if len(octets) == 4:
                    a, b = int(octets[0]), int(octets[1])
                    if (a == 192 and b == 0 and int(octets[2]) == 2) or (a == 198 and b == 51 and int(octets[2]) == 100) or (a == 203 and b == 0 and int(octets[2]) == 113):
                        return False
                return bool(ip_obj.is_private)
            return bool(ip_obj.is_private)
        except ValueError:
            return True

    def _builtin_heuristic_triage(self, state: IncidentState) -> TriageOutput:
        """Bộ luật Thẩm định Heuristic tích hợp sẵn (phục vụ fallback hoặc chạy độc lập)."""
        if not state.parsed_events:
            return TriageOutput(
                is_incident=False,
                confidence_score=0.9,
                severity=SeverityLevel.LOW,
                summary="Không tìm thấy sự kiện nào trong parsed_events để thẩm định.",
                rule_or_model="Builtin-Heuristic-Engine"
            )

        high_risk_keywords = [
            "-enc", "powershell -enc", "mimikatz", "c2", "beacon",
            "vssadmin delete shadows", "certutil -urlcache", "whoami /all",
            "rundll32", "psexec", "invoke-expression", "iex"
        ]

        is_attack = False
        confidence = 0.8
        severity = SeverityLevel.LOW
        reasons = []

        for evt in state.parsed_events:
            cmd = (evt.command_line or "").lower()
            proc = (evt.process_name or "").lower()
            raw_attrs = evt.raw_attributes or {}

            # Kiểm tra Wazuh rule level nếu có
            wazuh_level = raw_attrs.get("wazuh_rule_level")
            if wazuh_level is not None:
                if wazuh_level >= 10:
                    is_attack = True
                    severity = SeverityLevel.CRITICAL if wazuh_level >= 12 else SeverityLevel.HIGH
                    confidence = 0.95
                    reasons.append(f"Wazuh Rule Level cao ({wazuh_level}): {raw_attrs.get('wazuh_rule_desc', '')}")
                elif wazuh_level >= 7:
                    is_attack = True
                    severity = SeverityLevel.MEDIUM
                    confidence = 0.85
                    reasons.append(f"Wazuh Rule Level trung bình ({wazuh_level})")

            # Kiểm tra từ khóa tấn công trong dòng lệnh
            for kw in high_risk_keywords:
                if kw in cmd:
                    is_attack = True
                    confidence = 0.95
                    severity = SeverityLevel.HIGH if severity != SeverityLevel.CRITICAL else severity
                    reasons.append(f"Phát hiện mẫu lệnh độc hại nguy hiểm '{kw}'")
                    break

            # Kiểm tra IP đích độc hại đã biết
            from src.tools.threat_intel import ThreatIntelTools
            if evt.dest_ip in ThreatIntelTools.KNOWN_MALICIOUS_IPS:
                is_attack = True
                confidence = 0.98
                severity = SeverityLevel.CRITICAL
                reasons.append(f"Kết nối tới IP độc hại C2 đã biết: {evt.dest_ip}")

            # Kiểm tra đăng nhập thất bại liên tục (EVTX-4625 brute force)
            if "4625" in evt.event_id:
                is_attack = True
                severity = SeverityLevel.MEDIUM
                reasons.append("Ghi nhận sự kiện đăng nhập thất bại Windows (Event 4625)")

        # Nếu không có dấu hiệu tấn công và chỉ là sự kiện thường nhật (4624 Logon, Zeek bình thường)
        if not is_attack:
            return TriageOutput(
                is_incident=False,
                confidence_score=0.92,
                severity=SeverityLevel.LOW,
                summary="Hoạt động thường nhật / Đăng nhập hợp lệ của người dùng, không có dấu hiệu xâm nhập (False Positive).",
                rule_or_model="Builtin-Heuristic-Engine"
            )

        summary_text = "; ".join(reasons) if reasons else "Phát hiện hành vi bất thường trên hệ thống"
        return TriageOutput(
            is_incident=True,
            confidence_score=confidence,
            severity=severity,
            summary=summary_text,
            rule_or_model="Builtin-Heuristic-Engine"
        )

    def to_mermaid(self, use_langgraph_engine: bool = False) -> str:
        """Xuất biểu đồ quy trình điều phối StateGraph sang cú pháp Mermaid Flowchart.
        
        :param use_langgraph_engine: Nếu True và có compiled LangGraph app, dùng draw_mermaid() của LangGraph.
                                     Mặc định False để duy trì 100% định dạng flowchart TD mà các unit tests kiểm tra.
        """
        if use_langgraph_engine and HAS_LANGGRAPH:
            try:
                app = self.get_langgraph_app()
                return app.get_graph().draw_mermaid()
            except Exception as e:
                logger.warning(f"Không thể sinh mermaid từ LangGraph app: {e}")

        mermaid_lines = [
            "flowchart TD",
            "    START([__start__]) --> ingestion[Ingestion Node]",
            "    ingestion --> triage[Triage Node]",
            "    triage --> cond{Is Incident?}",
            "    cond -- False (False Positive) --> closed_fp[Closed False Positive Node]",
            "    closed_fp --> END_FP([__end__])",
            "    cond -- True (True Positive) --> enrichment[Threat Intel Node]",
            "    enrichment --> rca[Root Cause Analysis Node]",
            "    rca --> response[Response Playbook Node]",
            "    response --> hitl[HITL Analyst Approval Node]",
            "    hitl -- Approved --> reporting[Final Reporting Node]",
            "    hitl -. Rejected / Feedback Loop .-> response",
            "    reporting --> END_TP([__end__])",
            "    style cond fill:#fef3c7,stroke:#d97706,stroke-width:2px",
            "    style closed_fp fill:#fee2e2,stroke:#ef4444,stroke-width:2px",
            "    style hitl fill:#e0e7ff,stroke:#6366f1,stroke-width:2px",
            "    style reporting fill:#dcfce7,stroke:#22c55e,stroke-width:2px"
        ]
        return "\n".join(mermaid_lines)


def _build_default_llm_provider() -> Optional[Any]:
    """Khởi tạo HybridLLMProvider chuẩn hóa từ cấu hình tập trung src.core.config."""
    try:
        from src.core.config import (
            get_llm_provider_mode,
            get_omnirouter_api_key,
            get_omnirouter_endpoint,
            get_llm_model,
            get_ollama_url,
            get_ollama_model,
            get_llm_timeout,
        )
        from src.copilot.llm_provider import HybridLLMProvider

        mode = get_llm_provider_mode()
        return HybridLLMProvider(
            api_key=get_omnirouter_api_key(),
            endpoint=get_omnirouter_endpoint(provider_mode=mode),
            model=get_llm_model(),
            ollama_url=get_ollama_url(),
            ollama_model=get_ollama_model(),
            provider_mode=mode,
            timeout=get_llm_timeout(),
            enable_fallback=True,
        )
    except Exception as exc:
        logger.warning(f"Không thể khởi tạo HybridLLMProvider mặc định: {exc}")
        return None


def _build_default_rag_kb() -> Optional[Any]:
    """Khởi tạo RAGKnowledgeBaseTool dùng chung cho pipeline."""
    try:
        from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool

        return RAGKnowledgeBaseTool()
    except Exception as exc:
        logger.warning(f"Không thể khởi tạo RAGKnowledgeBaseTool mặc định: {exc}")
        return None


def _instantiate_agent_safe(agent_cls: Any, **kwargs: Any) -> Any:
    """Khởi tạo Agent chỉ truyền các kwargs mà __init__ của lớp đó hỗ trợ."""
    try:
        sig = inspect.signature(agent_cls.__init__)
        accepts_var_kw = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values()
        )
        if accepts_var_kw:
            filtered = kwargs
        else:
            allowed = set(sig.parameters.keys()) - {"self"}
            filtered = {k: v for k, v in kwargs.items() if k in allowed}
        return agent_cls(**filtered)
    except (ValueError, TypeError):
        return agent_cls()


def create_full_soc_pipeline(
    checkpointer: Optional[Dict[str, Any]] = None,
    hitl_hook: Optional[Callable[[IncidentState], IncidentState]] = None,
    hitl_manager: Optional[Any] = None,
    auto_approve: bool = False,
    enable_feedback_loop: bool = True,
    max_reanalysis: int = 2,
    ingestion_agent: Optional[Any] = None,
    triage_agent: Optional[Any] = None,
    threat_intel_agent: Optional[Any] = None,
    rca_agent: Optional[Any] = None,
    response_agent: Optional[Any] = None,
    reporting_agent: Optional[Any] = None,
    enable_parallel_investigation: bool = False,
    auto_instantiate_missing: bool = True,
    llm_provider: Optional[Any] = None,
    rag_kb: Optional[Any] = None,
    llm_enabled: bool = True,
    enable_tiered_routing: bool = True,
    enable_rag: bool = True,
    enable_parallel_ensemble: bool = True,
    enable_security_guard: bool = True,
    use_langgraph_engine: bool = True,
) -> StateGraphOrchestrator:
    """Tạo đối tượng StateGraphOrchestrator với đầy đủ 6 Agent chuyên biệt (Prototype v0.1).
    
    Hỗ trợ đầy đủ cờ Ablation (`llm_enabled`, `enable_tiered_routing`, `enable_rag`,
    `enable_parallel_ensemble`, `enable_security_guard`, `use_langgraph_engine`) cùng
    shared `llm_provider` và shared `rag_kb`.
    """
    if not enable_rag:
        rag_kb = None

    if auto_instantiate_missing:
        from src.agents import (
            IngestionAgent,
            TriageAgent,
            ThreatIntelAgent,
            RCAAgent,
            ResponseAgent,
            ReportingAgent,
        )

        if llm_provider is None and llm_enabled:
            llm_provider = _build_default_llm_provider()

        if enable_rag and rag_kb is None:
            if response_agent is not None and getattr(response_agent, "rag_kb", None) is not None:
                rag_kb = response_agent.rag_kb
            elif threat_intel_agent is not None and getattr(threat_intel_agent, "rag_kb", None) is not None:
                rag_kb = threat_intel_agent.rag_kb
            elif rca_agent is not None and getattr(rca_agent, "rag_kb", None) is not None:
                rag_kb = rca_agent.rag_kb
            else:
                rag_kb = _build_default_rag_kb()

        if ingestion_agent is None:
            ingestion_agent = _instantiate_agent_safe(
                IngestionAgent,
                llm_provider=llm_provider,
                enable_llm_fallback=llm_enabled,
                enable_security_guard=enable_security_guard,
            )
        if triage_agent is None:
            triage_agent = _instantiate_agent_safe(
                TriageAgent,
                llm_provider=llm_provider,
                llm_enabled=llm_enabled,
                enable_tiered_routing=enable_tiered_routing,
                enable_parallel_ensemble=enable_parallel_ensemble,
                enable_security_guard=enable_security_guard,
            )
        if threat_intel_agent is None:
            threat_intel_agent = _instantiate_agent_safe(
                ThreatIntelAgent,
                llm_provider=llm_provider,
                llm_enabled=llm_enabled,
                rag_kb=rag_kb if enable_rag else None,
                enable_rag=enable_rag,
                enable_security_guard=enable_security_guard,
            )
        if rca_agent is None:
            rca_agent = _instantiate_agent_safe(
                RCAAgent,
                llm_provider=llm_provider,
                llm_enabled=llm_enabled,
                rag_kb=rag_kb if enable_rag else None,
                enable_rag=enable_rag,
                enable_security_guard=enable_security_guard,
            )
        if response_agent is None:
            response_agent = _instantiate_agent_safe(
                ResponseAgent,
                rag_kb=rag_kb if enable_rag else None,
                llm_provider=llm_provider,
                llm_enabled=llm_enabled,
                enable_rag=enable_rag,
                enable_security_guard=enable_security_guard,
            )
        if reporting_agent is None:
            reporting_agent = _instantiate_agent_safe(
                ReportingAgent,
                llm_provider=llm_provider,
                llm_enabled=llm_enabled,
                rag_kb=rag_kb if enable_rag else None,
                enable_security_guard=enable_security_guard,
            )

    return StateGraphOrchestrator(
        checkpointer=checkpointer,
        hitl_hook=hitl_hook,
        hitl_manager=hitl_manager,
        auto_approve=auto_approve,
        enable_feedback_loop=enable_feedback_loop,
        enable_parallel_investigation=enable_parallel_investigation,
        max_reanalysis=max_reanalysis,
        ingestion_agent=ingestion_agent,
        triage_agent=triage_agent,
        threat_intel_agent=threat_intel_agent,
        rca_agent=rca_agent,
        response_agent=response_agent,
        reporting_agent=reporting_agent,
        llm_provider=llm_provider,
        rag_kb=rag_kb,
        use_langgraph_engine=use_langgraph_engine,
    )
