# -*- coding: utf-8 -*-
"""
tests/test_copilot.py
Bộ kiểm thử đơn vị toàn diện (Unit Tests) cho SOC AI Copilot Engine & LLM Provider.
Bao gồm:
- TestHybridLLMProvider:
  + Cấu hình khởi tạo và defaults (OmniRouter API Key, Endpoint, Model)
  + Mock kết nối OmniRouter / OpenRouter API (Non-streaming & Streaming)
  + Mock kết nối Local Ollama API (Non-streaming & Streaming)
  + Fallback tự động về Tier 3 Deterministic CoT Engine khi mạng mất kết nối hoặc API lỗi
  + Khả năng suy luận CoT theo ngữ cảnh (RCA, IoC, Executive Summary)
- TestSOCCopilotEngine:
  + Nén context sự cố chuẩn kỹ thuật < 800 tokens (serialize_incident_context)
  + Bóc tách ý định người dùng (Intent Routing: RCA, IoC, Summary, Approve, Reject)
  + Tích hợp và đồng bộ trực tiếp với HITLManager (Approve single, Reject single, Approve all, Reject all)
  + Ghi vết chuyển đổi trạng thái (state.record_transition)
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import requests
import json

from src.core.schemas import (
    IncidentStatus,
    SeverityLevel,
    ActionType,
    RecommendedAction,
    TriageOutput,
    RootCauseAnalysis,
    ProcessNode,
    ThreatIntelEnrichment,
    IoCItem,
)
from src.core.state import IncidentState
from src.copilot.llm_provider import (
    HybridLLMProvider,
    DEFAULT_OMNIROUTER_API_KEY,
    DEFAULT_OPENROUTER_ENDPOINT,
    DEFAULT_OMNIROUTER_ENDPOINT,
    DEFAULT_MODEL,
)
from src.copilot.engine import (
    SOCCopilotEngine,
    CopilotIntent,
    CopilotResponse,
)


class TestHybridLLMProvider(unittest.TestCase):
    """Kiểm thử cho module HybridLLMProvider."""

    def setUp(self):
        self.provider = HybridLLMProvider(
            api_key=DEFAULT_OMNIROUTER_API_KEY,
            endpoint=DEFAULT_OPENROUTER_ENDPOINT,
            model=DEFAULT_MODEL,
            provider_mode="auto",
            enable_fallback=True,
            timeout=5.0,
        )

        # Tạo IncidentState mẫu
        self.state = IncidentState(
            incident_id="INC-2026-TEST01",
            status=IncidentStatus.INVESTIGATING,
            attack_type="Phishing with PowerShell",
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.95,
                severity=SeverityLevel.HIGH,
                summary="Phát hiện PowerShell tải mã độc từ máy chủ C2 ngoài mạng",
                rule_or_model="TriageEngine-v1",
            ),
            rca_result=RootCauseAnalysis(
                initial_access_vector="Spearphishing Attachment (Office Macro)",
                attack_timeline=["08:00 Mở file Word", "08:01 Gọi PowerShell tải payload"],
                process_tree=[
                    ProcessNode(
                        process_id="PID-100",
                        process_name="winword.exe",
                        command_line="winword.exe invoice.docm",
                        is_malicious_origin=False,
                    ),
                    ProcessNode(
                        process_id="PID-4420",
                        process_name="powershell.exe",
                        command_line="powershell.exe -enc SQBYAE0A...",
                        parent_id="PID-100",
                        is_malicious_origin=True,
                    ),
                ],
                mitre_tactics=["Execution (TA0002)", "Defense Evasion (TA0005)"],
                root_cause_summary="Macro trong file invoice.docm kích hoạt PowerShell thực thi mã độc độc lập",
            ),
            threat_intel=ThreatIntelEnrichment(
                extracted_iocs=[
                    IoCItem(
                        value="194.26.29.112",
                        ioc_type="IP",
                        is_malicious=True,
                        reputation_score=95,
                        threat_actor="CobaltStrike",
                    )
                ],
                enrichment_summary="Phát hiện IP C2 CobaltStrike độc hại 95/100",
            ),
            recommended_actions=[
                RecommendedAction(
                    action_id="ACT-001",
                    action_type=ActionType.ISOLATE_HOST,
                    target="WORKSTATION-01",
                    description="Cô lập máy trạm bị nhiễm",
                    priority=1,
                    require_human_approval=True,
                    is_approved=None,
                )
            ],
        )

    def test_init_defaults(self):
        """Kiểm tra các giá trị cấu hình mặc định."""
        p = HybridLLMProvider()
        self.assertEqual(p.api_key, DEFAULT_OMNIROUTER_API_KEY)
        self.assertEqual(p.endpoint, DEFAULT_OMNIROUTER_ENDPOINT)
        self.assertEqual(p.model, DEFAULT_MODEL)
        self.assertTrue(p.enable_fallback)

    @patch("requests.post")
    def test_omnirouter_generate_response_mock(self, mock_post):
        """Kiểm thử gửi request thành công tới OmniRouter / OpenRouter API."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Phát hiện tấn công Phishing nghiêm trọng, khuyến nghị cô lập ngay máy trạm."
                    }
                }
            ]
        }
        mock_post.return_value = mock_response

        reply = self.provider.generate_response("Phân tích sự cố này giúp tôi")
        self.assertIn("Phát hiện tấn công Phishing", reply)
        self.assertEqual(self.provider.last_used_provider, "omnirouter")

        # Kiểm tra headers gửi đi
        args, kwargs = mock_post.call_args
        self.assertIn("Authorization", kwargs["headers"])
        self.assertTrue(kwargs["headers"]["Authorization"].startswith("Bearer sk-"))
        self.assertEqual(kwargs["json"]["model"], DEFAULT_MODEL)

    @patch("requests.post")
    def test_omnirouter_streaming_response_mock(self, mock_post):
        """Kiểm thử stream phản hồi (SSE) từ OmniRouter."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_lines.return_value = [
            b'data: {"choices": [{"delta": {"content": "Ph\xc3\xa1t hi\xe1\xbb\x87n "}}]}',
            b'data: {"choices": [{"delta": {"content": "m\xc3\xa3 \xc4\x91\xe1\xbb\x99c."}}]}',
            b"data: [DONE]",
        ]
        mock_post.return_value = mock_response

        gen = self.provider.stream_response("Stream test")
        chunks = list(gen)
        full_text = "".join(chunks)
        self.assertEqual(full_text, "Phát hiện mã độc.")

    @patch("requests.post")
    def test_ollama_fallback_mock(self, mock_post):
        """Kiểm thử fallback sang Local Ollama khi OmniRouter trả về mã lỗi 500."""
        # Lần gọi 1 (OmniRouter) -> lỗi 500
        # Lần gọi 2 (Ollama) -> thành công 200
        fail_response = MagicMock()
        fail_response.status_code = 500
        fail_response.text = "Internal Server Error"

        ollama_response = MagicMock()
        ollama_response.status_code = 200
        ollama_response.json.return_value = {
            "message": {"content": "Phản hồi từ Local Ollama Model."}
        }

        mock_post.side_effect = [fail_response, ollama_response]

        reply = self.provider.generate_response("Kiểm tra Ollama")
        self.assertEqual(reply, "Phản hồi từ Local Ollama Model.")
        self.assertEqual(self.provider.last_used_provider, "ollama")

    @patch("requests.post")
    def test_deterministic_fallback_when_network_fails(self, mock_post):
        """Kiểm thử chuyển tầng xuống Tier 3 Deterministic CoT Engine khi mạng sập hoàn toàn."""
        # Giả lập requests.post văng ngoại lệ ConnectionError ở cả 2 tầng API
        mock_post.side_effect = requests.RequestException("Network is unreachable")

        reply = self.provider.generate_response(
            prompt="Nguyên nhân gốc rễ RCA là gì?",
            incident_state=self.state,
        )

        self.assertEqual(self.provider.last_used_provider, "deterministic")
        self.assertIn("[Deterministic CoT]", reply)
        self.assertIn("Spearphishing Attachment", reply)
        self.assertIn("PID-4420", reply)

    def test_deterministic_streaming(self):
        """Kiểm thử generator streaming của Tier 3 Deterministic CoT Engine."""
        p = HybridLLMProvider(provider_mode="deterministic")
        chunks = list(p.stream_response("Tóm tắt điều hành sự cố", incident_state=self.state))
        self.assertTrue(len(chunks) > 5)
        full_text = "".join(chunks)
        self.assertIn("[Deterministic CoT] Tóm tắt Sự cố", full_text)
        self.assertIn(self.state.incident_id, full_text)

    def test_deterministic_cot_ioc_lookup(self):
        """Kiểm thử Tier 3 CoT khi truy vấn thông tin IoC."""
        p = HybridLLMProvider(provider_mode="deterministic")
        reply = p.generate_response("Cho tôi xem danh sách IoC và IP độc hại", incident_state=self.state)
        self.assertIn("194.26.29.112", reply)
        self.assertIn("95/100", reply)


class TestSOCCopilotEngine(unittest.TestCase):
    """Kiểm thử cho SOCCopilotEngine."""

    def setUp(self):
        # Dùng provider ở chế độ deterministic để kiểm thử engine hoàn toàn độc lập với Internet
        self.llm_provider = HybridLLMProvider(provider_mode="deterministic")
        self.engine = SOCCopilotEngine(
            llm_provider=self.llm_provider,
            analyst_id="copilot_analyst_test",
        )

        # Chuẩn bị IncidentState đầy đủ
        self.state = IncidentState(
            incident_id="INC-2026-0042",
            status=IncidentStatus.INVESTIGATING,
            attack_type="Ransomware Dropper via Macro",
            triage_result=TriageOutput(
                is_incident=True,
                confidence_score=0.98,
                severity=SeverityLevel.CRITICAL,
                summary="Phát hiện Office Macro khởi tạo PowerShell tải tệp nhị phân mã hóa",
                rule_or_model="Sigma-Rule-Detect-Macro-PowerShell",
            ),
            rca_result=RootCauseAnalysis(
                initial_access_vector="Spearphishing Attachment",
                attack_timeline=["09:15 Mở Word", "09:16 PowerShell invoke WebClient"],
                process_tree=[
                    ProcessNode(
                        process_id="PID-1024",
                        process_name="winword.exe",
                        command_line="winword.exe resume.docm",
                        is_malicious_origin=False,
                    ),
                    ProcessNode(
                        process_id="PID-3048",
                        process_name="powershell.exe",
                        command_line="powershell.exe -w hidden -enc JAB3AGMA...",
                        parent_id="PID-1024",
                        is_malicious_origin=True,
                    ),
                ],
                mitre_tactics=["Execution", "Command and Control", "Impact"],
                root_cause_summary="Tập tin resume.docm kích hoạt payload PowerShell ngầm tải ransomware",
            ),
            threat_intel=ThreatIntelEnrichment(
                extracted_iocs=[
                    IoCItem(
                        value="185.220.101.5",
                        ioc_type="IP",
                        is_malicious=True,
                        reputation_score=99,
                        threat_actor="LockBit Affiliate",
                    ),
                    IoCItem(
                        value="malware.update-service.cc",
                        ioc_type="DOMAIN",
                        is_malicious=True,
                        reputation_score=90,
                    ),
                ],
                enrichment_summary="Phát hiện IP C2 LockBit và tên miền độc hại",
            ),
            recommended_actions=[
                RecommendedAction(
                    action_id="ACT-001",
                    action_type=ActionType.ISOLATE_HOST,
                    target="FINANCE-PC-02",
                    description="Ngắt kết nối mạng máy trạm phòng tài chính",
                    priority=1,
                    require_human_approval=True,
                    is_approved=None,
                ),
                RecommendedAction(
                    action_id="ACT-002",
                    action_type=ActionType.BLOCK_IP,
                    target="185.220.101.5",
                    description="Chặn IP C2 trên Firewall",
                    priority=1,
                    require_human_approval=True,
                    is_approved=None,
                ),
            ],
        )

    def test_copilot_engine_provider_property(self):
        """Kiểm tra thuộc tính engine.provider tương thích ngược với engine.llm_provider."""
        self.assertIsNotNone(self.engine.provider)
        self.assertIs(self.engine.provider, self.engine.llm_provider)
        self.assertEqual(self.engine.provider.provider_type, self.llm_provider.provider_type)
        self.assertEqual(self.engine.provider.model, self.llm_provider.model)

    def test_serialize_incident_context_compression(self):
        """Kiểm tra context nén dưới 800 tokens và chứa các trường kỹ thuật cốt lõi."""
        context = self.engine.serialize_incident_context(self.state)
        
        # 800 tokens tương đương tối đa khoảng 3000-3200 ký tự (trung bình 4 ký tự/token)
        self.assertLess(len(context), 2800)
        
        # Đảm bảo các thông tin cốt lõi hiện diện
        self.assertIn("INC-2026-0042", context)
        self.assertIn("INVESTIGATING", context)
        self.assertIn("CRITICAL", context)
        self.assertIn("Spearphishing Attachment", context)
        self.assertIn("PID-3048", context)
        self.assertIn("185.220.101.5", context)
        self.assertIn("ACT-001", context)

    def test_intent_classification(self):
        """Kiểm tra phân loại chính xác các Intent phổ biến của chuyên viên SOC."""
        self.assertEqual(
            self.engine.classify_intent("Nguyên nhân gốc rễ và cây tiến trình sự cố này là gì?"),
            CopilotIntent.EXPLAIN_RCA,
        )
        self.assertEqual(
            self.engine.classify_intent("Cây tiến trình process tree có những tiến trình con nào?"),
            CopilotIntent.EXPLAIN_RCA,
        )
        self.assertEqual(
            self.engine.classify_intent("Cho tôi danh sách các IoC, IP độc hại và điểm VirusTotal"),
            CopilotIntent.LOOKUP_IOC,
        )
        self.assertEqual(
            self.engine.classify_intent("Tóm tắt điều hành sự cố cho lãnh đạo"),
            CopilotIntent.EXECUTIVE_SUMMARY,
        )
        self.assertEqual(
            self.engine.classify_intent("Phê duyệt hành động ACT-001"),
            CopilotIntent.APPROVE_ACTION,
        )
        self.assertEqual(
            self.engine.classify_intent("Duyệt tất cả hành động ứng phó"),
            CopilotIntent.APPROVE_ACTION,
        )
        self.assertEqual(
            self.engine.classify_intent("Từ chối action ACT-002 do IP nội bộ"),
            CopilotIntent.REJECT_ACTION,
        )
        self.assertEqual(
            self.engine.classify_intent("Không duyệt các hành động trên"),
            CopilotIntent.REJECT_ACTION,
        )
        self.assertEqual(
            self.engine.classify_intent("Xin chào Copilot, hôm nay có gì mới không?"),
            CopilotIntent.GENERAL_QUERY,
        )

    def test_hitl_approve_single_action(self):
        """Kiểm thử duyệt 1 action cụ thể qua tin nhắn chat."""
        msg = "Tôi đồng ý duyệt action ACT-001 ngay"
        resp = self.engine.process_message(msg, self.state)

        self.assertEqual(resp.intent, CopilotIntent.APPROVE_ACTION.value)
        self.assertIn("Đã phê duyệt thành công hành động `ACT-001`", resp.response)

        # Kiểm tra cập nhật trực tiếp trên RecommendedAction
        act1 = next(a for a in resp.state.recommended_actions if a.action_id == "ACT-001")
        self.assertTrue(act1.is_approved)

        # Action 2 chưa được duyệt
        act2 = next(a for a in resp.state.recommended_actions if a.action_id == "ACT-002")
        self.assertIsNone(act2.is_approved)

        # Kiểm tra ghi vết chuyển đổi trạng thái
        history_nodes = [h.node for h in resp.state.history]
        self.assertIn("hitl_manager", history_nodes)
        latest_transition = resp.state.history[-1]
        self.assertIn("ACT-001", latest_transition.message)

    def test_hitl_reject_single_action(self):
        """Kiểm thử từ chối 1 action qua tin nhắn chat."""
        msg = "Từ chối action ACT-002 vì cần xác minh thêm"
        resp = self.engine.process_message(msg, self.state)

        self.assertEqual(resp.intent, CopilotIntent.REJECT_ACTION.value)
        self.assertIn("Đã từ chối hành động `ACT-002`", resp.response)

        act2 = next(a for a in resp.state.recommended_actions if a.action_id == "ACT-002")
        self.assertFalse(act2.is_approved)

        # Kiểm tra lịch sử chuyển đổi trạng thái
        latest_transition = resp.state.history[-1]
        self.assertIn("ACT-002", latest_transition.message)
        self.assertEqual(latest_transition.metadata.get("decision_type"), "REJECT")

    def test_hitl_approve_all_actions(self):
        """Kiểm thử duyệt toàn bộ hành động (Approve All) qua tin nhắn chat."""
        msg = "Phê duyệt tất cả hành động ứng phó"
        resp = self.engine.process_message(msg, self.state)

        self.assertEqual(resp.intent, CopilotIntent.APPROVE_ACTION.value)
        self.assertIn("Đã phê duyệt toàn bộ (2) hành động", resp.response)

        # Tất cả action đều là True
        for act in resp.state.recommended_actions:
            self.assertTrue(act.is_approved)

        # Sự cố tự động chuyển sang CONTAINED
        self.assertEqual(resp.state.status, IncidentStatus.CONTAINED)
        self.assertTrue(resp.state.analyst_approved)

    def test_hitl_reject_all_actions(self):
        """Kiểm thử từ chối toàn bộ hành động qua tin nhắn chat."""
        msg = "Bác bỏ và từ chối toàn bộ kế hoạch ứng phó này"
        resp = self.engine.process_message(msg, self.state)

        self.assertEqual(resp.intent, CopilotIntent.REJECT_ACTION.value)
        self.assertIn("Đã từ chối toàn bộ (2) hành động", resp.response)

        for act in resp.state.recommended_actions:
            self.assertFalse(act.is_approved)

        self.assertFalse(resp.state.analyst_approved)

    def test_process_message_explain_rca(self):
        """Kiểm thử hỏi giải thích RCA qua Copilot."""
        msg = "Giải thích nguyên nhân gốc rễ và chuỗi tấn công của sự cố này"
        resp = self.engine.process_message(msg, self.state)

        self.assertEqual(resp.intent, CopilotIntent.EXPLAIN_RCA.value)
        self.assertIn("Phân tích Nguyên nhân Gốc rễ", resp.response)
        self.assertIn("Spearphishing Attachment", resp.response)
        self.assertIn("PID-3048", resp.response)

    def test_process_message_with_chat_history(self):
        """Kiểm thử truyền lịch sử trò chuyện (chat_history) vào Copilot."""
        history = [
            {"role": "user", "content": "Sự cố này nghiêm trọng không?"},
            {"role": "assistant", "content": "Sự cố ở mức CRITICAL."},
        ]
        resp = self.engine.process_message(
            user_message="Tóm tắt lại tình hình",
            state=self.state,
            chat_history=history,
        )
        self.assertEqual(resp.intent, CopilotIntent.EXECUTIVE_SUMMARY.value)
        self.assertIn("Tóm tắt Sự cố", resp.response)

    def test_process_message_streaming(self):
        """Kiểm thử xử lý tin nhắn ở chế độ streaming."""
        resp = self.engine.process_message(
            user_message="Cho tôi biết danh mục IoC độc hại",
            state=self.state,
            stream=True,
        )
        self.assertEqual(resp.intent, CopilotIntent.LOOKUP_IOC.value)
        self.assertIsNotNone(resp.raw_stream)
        chunks = list(resp.raw_stream)
        self.assertTrue(len(chunks) > 0)
        full_text = "".join(chunks)
        self.assertIn("185.220.101.5", full_text)


if __name__ == "__main__":
    unittest.main()
