# -*- coding: utf-8 -*-
"""
tests/test_schemas.py
Unit tests kiểm tra tính toàn vẹn và cơ chế xác thực dữ liệu của Pydantic Schemas
bằng thư viện chuẩn unittest (không phụ thuộc pytest).
"""

import unittest
from datetime import datetime
from pydantic import ValidationError

from src.core.schemas import (
    SeverityLevel,
    IncidentStatus,
    ActionType,
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    IoCItem,
    ThreatIntelEnrichment,
    ProcessNode,
    RootCauseAnalysis,
    RecommendedAction,
    IncidentReport,
)
from src.core.state import IncidentState


class TestSchemas(unittest.TestCase):

    def test_raw_log_input(self):
        log = RawLogInput(log_source="Sysmon", raw_payload='{"EventID": 1, "Image": "powershell.exe"}')
        self.assertEqual(log.log_source, "Sysmon")
        self.assertIsInstance(log.collected_at, datetime)

    def test_triage_output_validation(self):
        # Valid Triage
        triage = TriageOutput(
            is_incident=True,
            confidence_score=0.95,
            severity=SeverityLevel.HIGH,
            summary="Phát hiện PowerShell bypass execution policy kết nối ra ngoài",
            rule_or_model="LLM-Triage-v1"
        )
        self.assertTrue(triage.is_incident)
        self.assertEqual(triage.confidence_score, 0.95)
        self.assertEqual(triage.severity, SeverityLevel.HIGH)

        # Invalid confidence score > 1.0 (should raise ValidationError)
        with self.assertRaises(ValidationError):
            TriageOutput(
                is_incident=True,
                confidence_score=1.5,
                severity=SeverityLevel.HIGH,
                summary="Invalid score"
            )

    def test_recommended_action(self):
        action = RecommendedAction(
            action_type=ActionType.ISOLATE_HOST,
            target="WORKSTATION-01",
            description="Cô lập máy trạm bị nhiễm mã độc",
            priority=1,
            require_human_approval=True
        )
        self.assertEqual(action.action_type, ActionType.ISOLATE_HOST)
        self.assertTrue(action.require_human_approval)

    def test_incident_state_flow(self):
        state = IncidentState(incident_id="INC-2026-001")
        self.assertEqual(state.status, IncidentStatus.NEW)
        self.assertEqual(len(state.raw_logs), 0)

        # Add parsed event
        event = ParsedEvent(
            event_id="Sysmon-1",
            source_type="Sysmon",
            host_name="PC-FINANCE-01",
            process_name="powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA"
        )
        state.parsed_events.append(event)
        self.assertEqual(len(state.parsed_events), 1)
        self.assertEqual(state.parsed_events[0].process_name, "powershell.exe")


if __name__ == "__main__":
    unittest.main()
