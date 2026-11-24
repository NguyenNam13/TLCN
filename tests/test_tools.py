# -*- coding: utf-8 -*-
"""
tests/test_tools.py
Unit tests kiểm tra hoạt động của các bộ công cụ (Tools) cho các Agent.
"""

import unittest
from src.tools.parsers import LogParserTool
from src.tools.threat_intel import ThreatIntelTools
from src.tools.playbooks import ResponsePlaybooks
from src.core.schemas import ActionType


class TestTools(unittest.TestCase):

    def test_parse_sysmon(self):
        payload = '{"EventID": 1, "Image": "C:\\\\Windows\\\\System32\\\\powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgA"}'
        event = LogParserTool.parse_sysmon(payload)
        self.assertEqual(event.event_id, "Sysmon-1")
        self.assertEqual(event.process_name, "powershell.exe")
        self.assertIn("encoded_payload", event.raw_attributes)

    def test_threat_intel_ip_lookup(self):
        # Known malicious IP
        res = ThreatIntelTools.lookup_ip("194.26.29.112")
        self.assertTrue(res.is_malicious)
        self.assertEqual(res.reputation_score, 92)
        self.assertIn("Cobalt Strike", res.threat_actor)

        # Unknown / clean IP
        clean_res = ThreatIntelTools.lookup_ip("8.8.8.8")
        self.assertFalse(clean_res.is_malicious)

    def test_mitre_mapping(self):
        matches = ThreatIntelTools.match_mitre_technique("powershell.exe -enc")
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0]["mitre_id"], "T1059.001")

    def test_response_playbook(self):
        actions = ResponsePlaybooks.malware_incident_playbook("PC-FINANCE", "194.26.29.112", "powershell.exe")
        self.assertEqual(len(actions), 3)
        self.assertEqual(actions[0].action_type, ActionType.ISOLATE_HOST)
        self.assertTrue(actions[0].require_human_approval)


if __name__ == "__main__":
    unittest.main()
