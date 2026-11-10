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
import logging
import threading

# Tích hợp LangGraph chính thống theo mô hình Adapter/Facade Pattern
try:
    from langgraph.graph import StateGraph as LangGraphStateGraph, START as LG_START, END as LG_END
    from langgraph.checkpoint.memory import MemorySaver
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False
    LG_START = "__start__"
    LG_END = "__end__"

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ParsedEvent,
    TriageOutput,
    IoCItem,
    ThreatIntelEnrichment,
    ProcessNode,
    RootCauseAnalysis,
    RecommendedAction,
    ActionType,
    IncidentReport,
)
from src.core.state import IncidentState, StateTransition
from src.core.hitl_manager import HITLManager, HITLDecision
from src.tools.parsers import LogParserTool
from src.tools.playbooks import ResponsePlaybooks

logger = logging.getLogger("StateGraphOrchestrator")

# Hằng số định danh điểm đầu và điểm cuối tương thích LangGraph
START = "__start__"
END = "__end__"


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
        
        # Cấu trúc đồ thị điều phối (Facade attributes)
        self.nodes: Dict[str, Callable[[IncidentState], IncidentState]] = {}
        self.edges: Dict[str, str] = {}
        self.conditional_edges: Dict[str, Tuple[Callable[[IncidentState], str], Dict[str, str]]] = {}
        self.entry_point: str = "ingestion"

        # Internal LangGraph StateGraph Adapter & MemorySaver Checkpointer
        self._lg_builder: Optional[Any] = LangGraphStateGraph(IncidentState) if HAS_LANGGRAPH else None
        self._compiled_app: Optional[Any] = None
        self._memory_saver = MemorySaver() if HAS_LANGGRAPH else None
        self._checkpoint_lock = threading.Lock()
        
        # Khởi tạo đồ thị chuẩn
        self._build_default_graph()

    # =====================================================================
    # 1. GRAPH DEFINITION & REGISTRATION (Tương thích LangGraph StateGraph)
    # =====================================================================
    def add_node(self, name: str, func: Callable[[IncidentState], IncidentState]) -> "StateGraphOrchestrator":
        """Đăng ký một Node xử lý vào đồ thị Facade và đồng bộ vào LangGraph StateGraph."""
        self.nodes[name] = func
        if self._lg_builder is not None:
            def _node_adapter(state: IncidentState) -> IncidentState:
                return func(state)
            self._lg_builder.add_node(name, _node_adapter)
        self._compiled_app = None
        return self

    def add_edge(self, from_node: str, to_node: str) -> "StateGraphOrchestrator":
        """Đăng ký một Cạnh chuyển tiếp trực tiếp giữa 2 Node."""
        self.edges[from_node] = to_node
        if self._lg_builder is not None:
            src = LG_START if from_node == START else from_node
            dst = LG_END if to_node == END else to_node
            self._lg_builder.add_edge(src, dst)
        self._compiled_app = None
        return self

    def add_conditional_edges(
        self,
        source_node: str,
        condition_fn: Callable[[IncidentState], str],
        path_map: Dict[str, str]
    ) -> "StateGraphOrchestrator":
        """Đăng ký Cạnh rẽ nhánh có điều kiện dựa trên kết quả của Node nguồn."""
        self.conditional_edges[source_node] = (condition_fn, path_map)
        if self._lg_builder is not None:
            lg_path_map = {k: (LG_END if v == END else v) for k, v in path_map.items()}
            self._lg_builder.add_conditional_edges(source_node, condition_fn, lg_path_map)
        self._compiled_app = None
        return self

    def set_entry_point(self, node_name: str) -> "StateGraphOrchestrator":
        """Thiết lập Node đầu vào của đồ thị."""
        self.entry_point = node_name
        if self._lg_builder is not None:
            self._lg_builder.add_edge(LG_START, node_name)
        self._compiled_app = None
        return self

    def compile(self, checkpointer: Any = None) -> Any:
        """Biên dịch sang CompiledGraph chính thức của LangGraph."""
        if not HAS_LANGGRAPH or self._lg_builder is None:
            raise RuntimeError("Thư viện 'langgraph' chưa được cài đặt hoặc không khả dụng.")
        cp = checkpointer if checkpointer is not None else self._memory_saver
        self._compiled_app = self._lg_builder.compile(checkpointer=cp)
        return self._compiled_app

    def get_langgraph_app(self) -> Any:
        """Lấy đối tượng CompiledGraph của LangGraph đã được biên dịch."""
        if self._compiled_app is None:
            return self.compile()
        return self._compiled_app

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

    # =====================================================================
    # 2. NODE IMPLEMENTATIONS (Triển khai các nút nghiệp vụ)
    # =====================================================================
    def ingestion_node(self, state: IncidentState) -> IncidentState:
        """Node Ingestion: Tiếp nhận dữ liệu log thô / Wazuh alerts và chuẩn hóa sang ParsedEvent."""
        logger.info(f"[{state.incident_id}] Thực thi Ingestion Node...")

        # 1. Gọi IngestionAgent nếu đã được tiêm hoặc import được
        if self.ingestion_agent is not None:
            if hasattr(self.ingestion_agent, "process_state"):
                state = self.ingestion_agent.process_state(state)
            elif hasattr(self.ingestion_agent, "parse_logs"):
                parsed = self.ingestion_agent.parse_logs(state.raw_logs)
                state.parsed_events.extend(parsed)
        else:
            # Fallback/Built-in Ingestion Engine qua LogParserTool & WazuhClientTool
            for raw_item in state.raw_logs:
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
                    
                    state.parsed_events.append(parsed_event)
                except Exception as ex:
                    logger.warning(f"Lỗi parse raw log ({source}): {ex}")
                    # Vẫn tạo một ParsedEvent fallback để không làm đứt chuỗi
                    state.parsed_events.append(
                        ParsedEvent(
                            event_id=f"EVT-UNKNOWN-{len(state.parsed_events)+1}",
                            timestamp=datetime.now(timezone.utc),
                            source_type=raw_item.log_source,
                            raw_attributes={"raw_payload": payload, "parse_error": str(ex)}
                        )
                    )

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
                state.triage_result = self.triage_agent.evaluate(state.parsed_events)
            elif hasattr(self.triage_agent, "evaluate_models_parallel"):
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
        """Cạnh điều kiện (Conditional Edge) từ HITL Node (hỗ trợ Feedback Loop & Backtracking):
        - proceed_reporting: Khi chuyên viên phê duyệt hoặc đã đạt giới hạn lặp tối đa.
        - retry_response: Quay lại Response Node để lập lại kế hoạch theo chỉ dẫn của con người.
        - retry_rca: Quay lại RCA Node nếu chuyên viên yêu cầu rà soát lại nguyên nhân gốc rễ.
        """
        if state.status == IncidentStatus.AWAITING_APPROVAL:
            return "awaiting_approval"

        if state.analyst_approved is not False:
            return "proceed_reporting"

        # Nếu chuyên viên từ chối (analyst_approved is False)
        if getattr(self, "enable_feedback_loop", True) and state.reanalysis_count < state.max_reanalysis:
            state.reanalysis_count += 1
            feedback = state.analyst_feedback or ""
            feedback_lower = feedback.lower()

            rca_keywords = ["nguyên nhân", "root cause", "tiến trình cha", "vector", "tái điều tra", "sai rca"]
            if any(k in feedback_lower for k in rca_keywords):
                target_route = "retry_rca"
                msg = f"Kích hoạt Feedback Loop (Lần {state.reanalysis_count}/{state.max_reanalysis}): Quay lại RCA Agent do chuyên viên yêu cầu rà soát nguyên nhân gốc rễ."
            else:
                target_route = "retry_response"
                msg = f"Kích hoạt Feedback Loop (Lần {state.reanalysis_count}/{state.max_reanalysis}): Quay lại Response Agent do chuyên viên từ chối/yêu cầu điều chỉnh kế hoạch."

            # Reset cờ analyst_approved để vòng lặp kế tiếp có thể phê duyệt lại
            state.analyst_approved = None
            state.reanalysis_reason = feedback or "Chuyên viên từ chối phương án"

            state.record_transition(
                node="hitl_approval",
                to_status=IncidentStatus.INVESTIGATING,
                message=msg,
                metadata={
                    "reanalysis_count": state.reanalysis_count,
                    "target_route": target_route,
                    "feedback": feedback
                }
            )
            return target_route

        # Đã hết số lần lặp tối đa hoặc không bật feedback loop -> chuyển sang reporting để chốt hồ sơ
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
            mitre_techniques: List[str] = []
            threat_actors: List[str] = []
            from src.tools.threat_intel import ThreatIntelTools

            # Trích xuất IoC từ ParsedEvents
            for event in state.parsed_events:
                # Tra cứu IP
                for ip in [event.source_ip, event.dest_ip]:
                    if ip and not self._is_private_ip(ip):
                        ioc = ThreatIntelTools.lookup_ip(ip)
                        if ioc and not any(existing.value == ip for existing in extracted_iocs):
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

                # Tra cứu Hash nếu có
                if event.file_hash:
                    extracted_iocs.append(
                        IoCItem(
                            ioc_type="SHA256" if len(event.file_hash) == 64 else "MD5",
                            value=event.file_hash,
                            reputation_score=85,
                            is_malicious=True,
                            threat_actor="Known Malware Sample"
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

    def parallel_investigation_node(self, state: IncidentState) -> IncidentState:
        """Node điều tra song song (Fork-Join DAG): Threat Intel CTI || Root Cause Analysis (RCA).
        
        Thực thi đồng thời Threat Intel enrichment và RCA phân tích chuỗi tiến trình bằng ThreadPoolExecutor.
        Sau đó Fan-in (Join) tổng hợp kết quả CTI và RCA vào chung IncidentState.
        """
        import concurrent.futures

        logger.info(f"[{state.incident_id}] Kích hoạt Parallel Investigation Node (Threat Intel CTI || RCA)...")

        # Fork: Tạo 2 bản sao độc lập của state để tránh xung đột dữ liệu khi chạy song song
        state_cti = state.model_copy(deep=True)
        state_rca = state.model_copy(deep=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_cti = executor.submit(self.enrichment_node, state_cti)
            future_rca = executor.submit(self.rca_node, state_rca)

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

        # Join: Tổng hợp kết quả từ hai nhánh điều tra
        state.threat_intel = res_cti.threat_intel
        state.rca_result = res_rca.rca_result
        if res_rca.attack_type:
            state.attack_type = res_rca.attack_type

        # Gộp snapshots từ checkpoints của hai nhánh
        if hasattr(res_cti, "checkpoints") and res_cti.checkpoints:
            state.checkpoints.update(res_cti.checkpoints)
        if hasattr(res_rca, "checkpoints") and res_rca.checkpoints:
            state.checkpoints.update(res_rca.checkpoints)

        # Cập nhật mức độ nghiêm trọng nếu Threat Intel phát hiện IoC nguy hiểm
        if res_cti.triage_result and state.triage_result:
            if res_cti.triage_result.severity != state.triage_result.severity:
                state.triage_result.severity = res_cti.triage_result.severity
                state.triage_result.summary = res_cti.triage_result.summary

        # Hợp nhất lịch sử chuyển trạng thái từ hai nhánh
        existing_nodes = {h.node for h in state.history}
        for transition in res_cti.history:
            if transition.node in ("enrichment", "ThreatIntelAgent") and transition.node not in existing_nodes:
                state.history.append(transition)
                existing_nodes.add(transition.node)
        for transition in res_rca.history:
            if transition.node in ("rca", "RCAAgent") and transition.node not in existing_nodes:
                state.history.append(transition)
                existing_nodes.add(transition.node)

        state.record_transition(
            node="parallel_investigation",
            to_status=IncidentStatus.INVESTIGATING,
            message="Hoàn tất điều tra song song đa tác tử (Threat Intel CTI || RCA) theo mô hình Fork-Join",
            metadata={
                "parallel_workers": 2,
                "has_threat_intel": state.threat_intel is not None,
                "has_rca": state.rca_result is not None,
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

        host = "WORKSTATION-01"
        malicious_ip = "194.26.29.112"
        proc = "powershell.exe"

        for event in state.parsed_events:
            if event.host_name and event.host_name != "UNKNOWN-HOST":
                host = event.host_name
            if event.dest_ip and not self._is_private_ip(event.dest_ip):
                malicious_ip = event.dest_ip
            if event.process_name:
                proc = event.process_name

        # Sử dụng PlaybookTool có sẵn
        actions = ResponsePlaybooks.malware_incident_playbook(
            host_name=host,
            malicious_ip=malicious_ip,
            process_name=proc
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

    def invoke(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        max_steps: int = 25
    ) -> IncidentState:
        """Thực thi toàn bộ đồ thị StateGraph từ entry_point đến khi kết thúc (END).
        
        Tương đương `graph.compile().invoke(...)` trong LangGraph.
        """
        # Chuẩn hóa đầu vào sang Pydantic IncidentState
        current_state = self._coerce_state(state)
        current_node = self.entry_point
        step_count = 0

        logger.info(f"Khởi động pipeline StateGraph cho sự cố: {current_state.incident_id}")

        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                raise ValueError(f"Node không hợp lệ hoặc chưa đăng ký trong đồ thị: '{current_node}'")

            # Thực thi Node hiện tại
            node_fn = self.nodes[current_node]
            current_state = node_fn(current_state)

            # Nếu pipeline chuyển sang AWAITING_APPROVAL, dừng ngay lập tức (không chuyển sang reporting)
            if current_state.status == IncidentStatus.AWAITING_APPROVAL:
                logger.info(
                    f"[{current_state.incident_id}] Pipeline tạm dừng tại Node '{current_node}' "
                    f"với trạng thái AWAITING_APPROVAL để chờ phê duyệt từ chuyên viên SOC."
                )
                break

            current_node = self._get_next_node(current_node, current_state)

        if step_count >= max_steps:
            logger.warning(f"Pipeline dừng do đạt giới hạn số bước tối đa ({max_steps})")

        return current_state

    def stream(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        max_steps: int = 25
    ) -> Generator[Tuple[str, IncidentState], None, None]:
        """Thực thi đồ thị dưới dạng Stream từng Node (cho phép theo dõi tiến trình thời gian thực)."""
        current_state = self._coerce_state(state)
        current_node = self.entry_point
        step_count = 0

        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                break

            node_fn = self.nodes[current_node]
            current_state = node_fn(current_state)
            yield (current_node, current_state)

            # Dừng stream nếu rơi vào trạng thái chờ duyệt
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

        node_fn = self.nodes[current_node]
        current_state = node_fn(current_state)

        # Nếu sau bước này trạng thái là AWAITING_APPROVAL, giữ ở hitl_approval
        if current_state.status == IncidentStatus.AWAITING_APPROVAL:
            return ("hitl_approval", current_state)

        next_node = self._get_next_node(current_node, current_state)
        return (next_node if next_node != END else None, current_state)

    def resume_after_hitl(
        self,
        state: IncidentState,
        analyst_approved: bool,
        analyst_feedback: Optional[str] = None
    ) -> IncidentState:
        """Tiếp tục điều phối sau khi chuyên viên SOC can thiệp và phê duyệt kế hoạch."""
        state.analyst_approved = analyst_approved
        state.analyst_feedback = analyst_feedback

        # Thực thi tiếp từ node hitl_approval
        state = self.hitl_approval_node(state)

        # Định tuyến theo conditional edge của hitl_approval thay vì cưỡng bức nhảy sang reporting
        current_node = (
            self._get_next_node("hitl_approval", state)
            if "hitl_approval" in self.conditional_edges
            else "reporting"
        )
        step_count = 0
        while current_node != END and step_count < 25:
            step_count += 1
            if current_node not in self.nodes:
                break
            node_fn = self.nodes[current_node]
            state = node_fn(state)
            current_node = self._get_next_node(current_node, state)

        return state

    def execute_until_interrupt(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        max_steps: int = 25
    ) -> Tuple[bool, IncidentState]:
        """Thực thi StateGraph từ entry_point cho đến khi chạm điểm ngắt HITL hoặc kết thúc đồ thị (END).
        
        Trả về:
        - Tuple[bool, IncidentState]: (is_paused, current_state)
          + is_paused = True nếu đồ thị tạm dừng tại điểm ngắt HITL (chờ duyệt).
          + is_paused = False nếu đồ thị đã chạy hoàn tất đến END (hoặc đóng False Positive).
        """
        current_state = self._coerce_state(state)
        current_node = self.entry_point
        step_count = 0

        logger.info(f"Khởi động execute_until_interrupt cho sự cố: {current_state.incident_id}")

        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                raise ValueError(f"Node không hợp lệ hoặc chưa đăng ký trong đồ thị: '{current_node}'")

            # Kiểm tra điểm ngắt HITL trước khi thực thi node hitl_approval
            if current_node == "hitl_approval":
                hitl_mgr = self.hitl_manager or HITLManager()
                pending = hitl_mgr.get_pending_actions(current_state)
                if pending and not self.auto_approve and current_state.analyst_approved is None:
                    current_state.record_transition(
                        node="hitl_approval",
                        to_status=IncidentStatus.AWAITING_APPROVAL,
                        message="Pipeline tạm dừng tại điểm ngắt HITL - Đang chờ chuyên viên phê duyệt hành động",
                        metadata={"awaiting_approval": True, "pending_count": len(pending)}
                    )
                    self._checkpoint(current_state, "hitl_approval")
                    logger.info(f"[{current_state.incident_id}] Pipeline tạm dừng (is_paused=True) tại Node hitl_approval.")
                    return (True, current_state)

            # Thực thi Node hiện tại
            node_fn = self.nodes[current_node]
            current_state = node_fn(current_state)

            # Nếu sau khi chạy node, trạng thái là AWAITING_APPROVAL thì tạm dừng
            if current_state.status == IncidentStatus.AWAITING_APPROVAL:
                return (True, current_state)

            current_node = self._get_next_node(current_node, current_state)

        return (False, current_state)

    def resume_from_interrupt(
        self,
        state: Union[IncidentState, Dict[str, Any]],
        decisions: Optional[List[HITLDecision]] = None,
        max_steps: int = 25
    ) -> IncidentState:
        """Tiếp tục điều phối StateGraph sau khi chuyên viên đưa ra quyết định tại điểm ngắt HITL.
        
        - Áp dụng danh sách decisions (nếu có).
        - Thực thi node hitl_approval để chuyển tiếp trạng thái (CONTAINED / INVESTIGATING).
        - Tiếp tục điều hướng đồ thị qua Reporting Node cho đến END.
        """
        current_state = self._coerce_state(state)

        # 1. Áp dụng các quyết định HITLDecision
        if decisions:
            manager = self.hitl_manager or HITLManager()
            for decision in decisions:
                current_state = manager.submit_decision(current_state, decision)

        # 2. Thực thi node hitl_approval để hoàn tất chuyển đổi trạng thái
        current_state = self.hitl_approval_node(current_state)

        # Nếu vẫn còn hành động chờ duyệt (chưa hoàn tất), không chạy tiếp reporting
        if current_state.status == IncidentStatus.AWAITING_APPROVAL:
            return current_state

        # 3. Tiếp tục đồ thị từ Node kế tiếp (thông thường là 'reporting') đến END
        current_node = self.edges.get("hitl_approval", "reporting")
        step_count = 0

        while current_node != END and step_count < max_steps:
            step_count += 1
            if current_node not in self.nodes:
                break

            node_fn = self.nodes[current_node]
            current_state = node_fn(current_state)
            current_node = self._get_next_node(current_node, current_state)

        return current_state

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
        """Kiểm tra IP nội bộ / private RFC 1918."""
        if not ip:
            return True
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2 and parts[1].isdigit():
                sec = int(parts[1])
                if 16 <= sec <= 31:
                    return True
        return False

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
) -> StateGraphOrchestrator:
    """Tạo đối tượng StateGraphOrchestrator với đầy đủ 6 Agent chuyên biệt (Prototype v0.1).
    
    Tự động khởi tạo các Agent còn thiếu từ module src.agents nếu auto_instantiate_missing=True:
    1. IngestionAgent
    2. TriageAgent
    3. ThreatIntelAgent
    4. RCAAgent
    5. ResponseAgent
    6. ReportingAgent
    """
    if auto_instantiate_missing:
        from src.agents import (
            IngestionAgent,
            TriageAgent,
            ThreatIntelAgent,
            RCAAgent,
            ResponseAgent,
            ReportingAgent,
        )

        if ingestion_agent is None:
            ingestion_agent = IngestionAgent()
        if triage_agent is None:
            triage_agent = TriageAgent()
        if threat_intel_agent is None:
            threat_intel_agent = ThreatIntelAgent()
        if rca_agent is None:
            rca_agent = RCAAgent()
        if response_agent is None:
            response_agent = ResponseAgent()
        if reporting_agent is None:
            reporting_agent = ReportingAgent()

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
    )
