# -*- coding: utf-8 -*-
"""
tests/test_rag.py
Unit tests kiểm tra hoạt động của Cơ sở tri thức RAG và Vector Store (RAGKnowledgeBaseTool).
Kiểm thử các bài toán tìm kiếm ngữ nghĩa MITRE ATT&CK và Wazuh Ruleset.
"""

import unittest
from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool


class TestRAGKnowledgeBase(unittest.TestCase):
    """Bộ kiểm thử cho module RAGKnowledgeBaseTool."""

    @classmethod
    def setUpClass(cls):
        """Khởi tạo RAG Knowledge Base trước khi chạy các bài test."""
        cls.kb = RAGKnowledgeBaseTool()

    def test_knowledge_base_populated(self):
        """Kiểm tra cơ sở tri thức đã nạp đủ số lượng kỹ thuật và quy tắc tối thiểu."""
        self.assertGreaterEqual(self.kb.count_mitre_techniques(), 10)
        self.assertGreaterEqual(self.kb.count_wazuh_rules(), 10)

    def test_query_powershell_download_script(self):
        """
        Truy vấn liên quan đến powershell tải script -> trả về T1059.001.
        """
        query = "truy vấn liên quan đến powershell tải script"
        results = self.kb.query_mitre_technique(query, n_results=3)

        self.assertGreater(len(results), 0)
        top_technique = results[0]
        self.assertEqual(top_technique["technique_id"], "T1059.001")
        self.assertIn("PowerShell", top_technique["name"])
        self.assertEqual(top_technique["tactic"], "Execution")
        self.assertIn("mitigations", top_technique)
        self.assertIn("detection", top_technique)
        self.assertGreater(top_technique["score"], 0.0)

    def test_query_phishing_password(self):
        """
        Truy vấn liên quan đến lừa đảo lấy mật khẩu -> trả về T1566.002 hoặc T1078.002.
        """
        query = "truy vấn liên quan đến lừa đảo lấy mật khẩu"
        results = self.kb.query_mitre_technique(query, n_results=3)

        self.assertGreater(len(results), 0)
        top_ids = [r["technique_id"] for r in results]
        
        # Kết quả top phải chứa ít nhất một trong hai kỹ thuật:
        # T1566.002 (Spearphishing Link) hoặc T1078.002 (Valid Accounts: Domain Accounts)
        self.assertTrue(
            "T1566.002" in top_ids or "T1078.002" in top_ids,
            f"Kỳ vọng T1566.002 hoặc T1078.002 trong top kết quả nhưng nhận: {top_ids}"
        )
        # Đồng thời kiểm tra top 1 là một trong hai
        self.assertIn(results[0]["technique_id"], ["T1566.002", "T1078.002"])

    def test_query_port_scan(self):
        """
        Truy vấn quét cổng mạng -> trả về T1046 (Network Service Discovery).
        """
        query = "truy vấn quét cổng mạng"
        results = self.kb.query_mitre_technique(query, n_results=3)

        self.assertGreater(len(results), 0)
        top_technique = results[0]
        self.assertEqual(top_technique["technique_id"], "T1046")
        self.assertEqual(top_technique["name"], "Network Service Discovery")
        self.assertEqual(top_technique["tactic"], "Discovery")

    def test_query_wazuh_rule_92211(self):
        """
        Truy vấn Wazuh Rule 92211 (SQL Injection attack).
        """
        query = "Wazuh Rule 92211"
        results = self.kb.query_wazuh_rule(query, n_results=3)

        self.assertGreater(len(results), 0)
        top_rule = results[0]
        self.assertEqual(top_rule["rule_id"], "92211")
        self.assertEqual(top_rule["level"], 10)
        self.assertIn("SQL Injection", top_rule["description"])
        self.assertIn("remediation", top_rule)
        self.assertIn("T1190", top_rule["mitre_ids"])

    def test_query_wazuh_rule_60106(self):
        """
        Truy vấn Wazuh Rule 60106 (PowerShell encoded / suspicious execution).
        """
        query = "Wazuh Rule 60106"
        results = self.kb.query_wazuh_rule(query, n_results=3)

        self.assertGreater(len(results), 0)
        top_rule = results[0]
        self.assertEqual(top_rule["rule_id"], "60106")
        self.assertEqual(top_rule["level"], 8)
        self.assertIn("PowerShell", top_rule["description"])
        self.assertIn("T1059.001", top_rule["mitre_ids"])
        self.assertIn("remediation", top_rule)

    def test_get_exact_records(self):
        """Kiểm tra hàm get trực tiếp theo ID chính xác."""
        item = self.kb.get_mitre_technique("T1059.001")
        self.assertIsNotNone(item)
        self.assertEqual(item["name"], "Command and Scripting Interpreter: PowerShell")

        rule = self.kb.get_wazuh_rule("92211")
        self.assertIsNotNone(rule)
        self.assertEqual(rule["level"], 10)

    def test_fallback_store_consistency(self):
        """Kiểm tra cơ chế hoạt động độc lập của Fallback store khi không có ChromaDB."""
        # Khởi tạo bản sao với force_fallback=True
        fallback_kb = RAGKnowledgeBaseTool(force_fallback=True)
        self.assertEqual(fallback_kb.backend, "fallback")

        res = fallback_kb.query_mitre_technique("powershell", n_results=1)
        self.assertGreater(len(res), 0)
        self.assertEqual(res[0]["technique_id"], "T1059.001")

    def test_mordor_techniques_presence(self):
        """Khẳng định tất cả các kỹ thuật thực tế từ Mordor đều hiện diện trong RAG Knowledge Base."""
        mordor_techs = ["T1059.001", "T1056.002", "T1046", "T1018", "T1087", "T1078.002"]
        for tech_id in mordor_techs:
            item = self.kb.get_mitre_technique(tech_id)
            self.assertIsNotNone(item, f"Kỹ thuật Mordor {tech_id} phải tồn tại trong RAG Knowledge Base.")
            self.assertEqual(item["technique_id"], tech_id)
            self.assertTrue(len(item["description"]) > 0)
            self.assertTrue(len(item["mitigations"]) > 0)
            self.assertTrue(len(item["detection"]) > 0)

    def test_query_mordor_icmp_remote_discovery(self):
        """Truy vấn tìm kiếm kỹ thuật dò quét hệ thống từ xa qua ICMP ping sweep (T1018)."""
        query = "ICMP ping sweep dò quét máy chủ mạng nội bộ Remote System Discovery"
        results = self.kb.query_mitre_technique(query, n_results=3)
        self.assertGreater(len(results), 0)
        top_ids = [r["technique_id"] for r in results]
        self.assertIn("T1018", top_ids)
        self.assertEqual(results[0]["technique_id"], "T1018")

    def test_query_mordor_gui_input_capture(self):
        """Truy vấn kỹ thuật lừa đảo hộp thoại GUI đánh cắp thông tin (T1056.002)."""
        query = "GUI input capture fake dialog credential prompt"
        results = self.kb.query_mitre_technique(query, n_results=3)
        self.assertGreater(len(results), 0)
        top_ids = [r["technique_id"] for r in results]
        self.assertIn("T1056.002", top_ids)
        self.assertEqual(results[0]["technique_id"], "T1056.002")

    def test_query_mordor_account_discovery(self):
        """Truy vấn kỹ thuật dò quét tài khoản người dùng và quản trị miền (T1087 / T1087.002)."""
        query = "Account Discovery liệt kê tài khoản người dùng domain admin Active Directory"
        results = self.kb.query_mitre_technique(query, n_results=3)
        self.assertGreater(len(results), 0)
        top_ids = [r["technique_id"] for r in results]
        self.assertTrue("T1087" in top_ids or "T1087.002" in top_ids)


if __name__ == "__main__":
    unittest.main()

