# -*- coding: utf-8 -*-
"""
tests/test_wazuh.py
Unit tests kiểm tra bộ công cụ Wazuh SIEM client và chuyển đổi dữ liệu cảnh báo.
"""

import os
import unittest
from src.tools.wazuh_client import WazuhClientTool
from src.core.schemas import SeverityLevel, ActionType


class TestWazuhIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data_dir = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "wazuh")

    def test_load_wazuh_malware_alert(self):
        fpath = os.path.join(self.data_dir, "wazuh_alerts_scenario2_malware.json")
        alerts = WazuhClientTool.load_alerts_from_file(fpath)
        self.assertEqual(len(alerts), 1)
        
        alert = alerts[0]
        self.assertEqual(alert.rule.id, "92211")
        self.assertEqual(alert.rule.level, 12)
        self.assertIn("sysmon", alert.rule.groups)
        self.assertEqual(alert.agent.name, "WIN10-VICTIM-01")

    def test_convert_to_parsed_event(self):
        fpath = os.path.join(self.data_dir, "wazuh_alerts_scenario2_malware.json")
        alert = WazuhClientTool.load_alerts_from_file(fpath)[0]
        event = WazuhClientTool.convert_to_parsed_event(alert)

        self.assertEqual(event.source_type, "WazuhSIEM")
        self.assertEqual(event.process_name, "powershell.exe")
        self.assertIn("encoded_payload", event.raw_attributes)
        self.assertEqual(event.raw_attributes["wazuh_rule_level"], 12)
        self.assertEqual(event.dest_ip, "194.26.29.112")

    def test_rule_level_to_severity(self):
        self.assertEqual(WazuhClientTool.map_rule_level_to_severity(14), SeverityLevel.CRITICAL)
        self.assertEqual(WazuhClientTool.map_rule_level_to_severity(10), SeverityLevel.HIGH)
        self.assertEqual(WazuhClientTool.map_rule_level_to_severity(6), SeverityLevel.MEDIUM)
        self.assertEqual(WazuhClientTool.map_rule_level_to_severity(3), SeverityLevel.LOW)

    def test_wazuh_active_response(self):
        action = WazuhClientTool.execute_active_response(
            agent_id="002",
            command="firewall-drop",
            target_ip="194.26.29.112"
        )
        self.assertEqual(action.action_type, ActionType.BLOCK_IP)
        self.assertEqual(action.target, "194.26.29.112")
        self.assertTrue(action.require_human_approval)


if __name__ == "__main__":
    unittest.main()
