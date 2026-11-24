# -*- coding: utf-8 -*-
"""
tests/test_rag_semantic_upgrade.py
Bộ kiểm thử toàn diện cho Phase 1: RAG Knowledge Base Semantic Upgrade.
Bao phủ:
  1. Chuẩn hóa URL Embeddings (resolve_openai_embeddings_url & resolve_ollama_embed_urls).
  2. LocalCharNgramDenseProvider song ngữ VI <-> EN & Persistent Atomic Disk Hash Cache.
  3. FallbackVectorStore Cached BM25, Case-Insensitive MITRE ID, Batch Upsert/Flush & Core ID Guards.
  4. Multi-Backend Vector Store (numpy_dense, qdrant :memory:, fallback) & get_backend_info().
  5. Hybrid RRF Retrieval trên truy vấn tiếng Việt và truy vấn hành vi OOD (LOLBins / Cloud / AD).
  6. Đồng bộ đủ 20 file OTRF YAML vào collection thứ 4 `knowledge_docs`, query_collection("all")
     và retrieve_incident_knowledge().
"""

import os
import re
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from src.tools.rag_embeddings import (
    BILINGUAL_SOC_SYNONYMS,
    DUMMY_API_KEYS,
    OpenAICompatibleEmbeddingProvider,
    resolve_openai_embeddings_url,
    resolve_ollama_embed_urls,
    LocalCharNgramDenseProvider,
    EmbeddingProviderFactory,
    expand_bilingual_query,
)
from src.tools.rag_knowledge_base import (
    FallbackVectorStore,
    RAGKnowledgeBaseTool,
    CORE_PROTECTED_MITRE_IDS,
    CORE_PROTECTED_WAZUH_RULE_IDS,
    QDRANT_AVAILABLE,
)
from src.tools.dataset_trainer import PublicDatasetTrainer


class TestRAGSemanticUpgrade(unittest.TestCase):
    """Kiểm thử nâng cấp ngữ nghĩa RAG Multi-Backend, Hybrid RRF và 4th Collection knowledge_docs."""

    @classmethod
    def setUpClass(cls):
        cls.kb = RAGKnowledgeBaseTool()

    def test_resolve_openai_embeddings_url_variants(self):
        """Kiểm tra chuẩn hóa URL OpenAI/OmniRoute/OpenRouter embeddings qua mọi biến thể."""
        self.assertEqual(
            resolve_openai_embeddings_url("http://localhost:20128/v1/chat/completions"),
            "http://localhost:20128/v1/embeddings",
        )
        self.assertEqual(
            resolve_openai_embeddings_url("https://openrouter.ai/api/v1/chat/completions/"),
            "https://openrouter.ai/api/v1/embeddings",
        )
        self.assertEqual(
            resolve_openai_embeddings_url("http://localhost:20128/v1/models"),
            "http://localhost:20128/v1/embeddings",
        )
        self.assertEqual(
            resolve_openai_embeddings_url("http://localhost:20128/v1/embeddings"),
            "http://localhost:20128/v1/embeddings",
        )
        self.assertEqual(
            resolve_openai_embeddings_url("http://localhost:20128/v1"),
            "http://localhost:20128/v1/embeddings",
        )
        self.assertEqual(
            resolve_openai_embeddings_url("http://localhost:20128"),
            "http://localhost:20128/v1/embeddings",
        )

        with patch.dict(
            os.environ,
            {"OMNIROUTE_BASE_URL": "http://127.0.0.1:20128/v1/chat/completions"},
            clear=False,
        ):
            os.environ.pop("RAG_EMBEDDING_URL", None)
            os.environ.pop("RAG_EMBEDDING_BASE_URL", None)
            self.assertEqual(
                resolve_openai_embeddings_url(),
                "http://127.0.0.1:20128/v1/embeddings",
            )

    def test_resolve_ollama_embed_urls_variants(self):
        """Kiểm tra chuẩn hóa bộ 3 URL Ollama (/api/embed, /api/embeddings, /api/tags)."""
        expected = (
            "http://localhost:11434/api/embed",
            "http://localhost:11434/api/embeddings",
            "http://localhost:11434/api/tags",
        )
        self.assertEqual(resolve_ollama_embed_urls("http://localhost:11434/api/chat"), expected)
        self.assertEqual(resolve_ollama_embed_urls("http://localhost:11434/api/generate/"), expected)
        self.assertEqual(resolve_ollama_embed_urls("http://localhost:11434/api/embeddings"), expected)
        self.assertEqual(resolve_ollama_embed_urls("http://localhost:11434/api/tags"), expected)
        self.assertEqual(resolve_ollama_embed_urls("http://localhost:11434"), expected)

    def test_local_char_ngram_dense_provider_bilingual_and_disk_cache(self):
        """Kiểm tra độ tương đồng ngữ nghĩa song ngữ VI <-> EN và Persistent Disk Embedding Cache."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            provider = LocalCharNgramDenseProvider(dim=512, cache_dir=tmp_dir)
            self.assertEqual(provider.provider_name, "local_hash")
            self.assertEqual(provider.dim, 512)

            texts = [
                "truy vấn liên quan đến lừa đảo lấy mật khẩu qua email",
                "Phishing Spearphishing Link credential harvesting password login lure T1566.002",
                "Network Service Discovery port scan SYN probing listening ports T1046",
                "xóa bản sao lưu hệ thống shadow copy bằng vssadmin",
                "Inhibit System Recovery vssadmin delete shadows Volume Shadow Copies T1490",
            ]
            mat = provider.embed_texts(texts)
            self.assertEqual(mat.shape, (5, 512))
            self.assertEqual(mat.dtype, np.float32)

            # Kiểm tra chuẩn hóa L2 (norm ~ 1.0)
            norms = np.linalg.norm(mat, axis=1)
            for n_val in norms:
                self.assertAlmostEqual(float(n_val), 1.0, places=4)

            # Tương đồng ngữ nghĩa cặp đúng (VI phishing <-> EN phishing) phải cao hơn hẳn cặp chéo (VI phishing <-> EN port scan)
            sim_phish_vi_en = float(mat[0] @ mat[1])
            sim_phish_vs_scan = float(mat[0] @ mat[2])
            self.assertGreater(sim_phish_vi_en, 0.35)
            self.assertGreater(sim_phish_vi_en, sim_phish_vs_scan + 0.20)

            # Tương đồng cặp VI xóa bản sao lưu <-> EN Inhibit System Recovery
            sim_shadow_vi_en = float(mat[3] @ mat[4])
            sim_shadow_vs_scan = float(mat[3] @ mat[2])
            self.assertGreater(sim_shadow_vi_en, 0.35)
            self.assertGreater(sim_shadow_vi_en, sim_shadow_vs_scan + 0.20)

            # Kiểm tra Disk Cache Hit khi gọi lại và khi khởi tạo provider mới trên cùng cache_dir
            self.assertIsNotNone(provider.cache)
            initial_hits = provider.cache.hits
            _ = provider.embed_texts([texts[0], texts[3]])
            self.assertEqual(provider.cache.hits, initial_hits + 2)
            self.assertTrue(os.path.exists(provider.cache.npz_path))
            self.assertTrue(os.path.exists(provider.cache.index_path))

            provider_reloaded = EmbeddingProviderFactory.create(mode="local_hash", cache_dir=tmp_dir, dim=512)
            self.assertEqual(provider_reloaded.cache.size(), 5)
            vec_cached = provider_reloaded.embed_query(texts[0])
            self.assertEqual(provider_reloaded.cache.hits, 1)
            self.assertTrue(np.allclose(mat[0], vec_cached, atol=1e-6))

    def test_fallback_vector_store_cached_bm25_and_batch_upsert(self):
        """Kiểm tra lazy BM25 index cache, case-insensitive MITRE ID và batch upsert/flush."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_file = os.path.join(tmp_dir, "test_fallback.json")
            store = FallbackVectorStore(db_file)

            items = [
                (
                    "t1059.001",
                    "PowerShell execution download script encodedcommand",
                    {"technique_id": "t1059.001", "name": "PowerShell", "tactic": "Execution"},
                ),
                (
                    "T1046",
                    "Network Service Discovery port scan syn probing",
                    {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
                ),
            ]
            count = store.upsert_batch("mitre_attack", items, defer_save=True)
            self.assertEqual(count, 2)
            # Khi defer_save=True, file chưa bị ghi cho tới khi flush()
            self.assertFalse(os.path.exists(db_file))
            store.flush()
            self.assertTrue(os.path.exists(db_file))

            # Tra cứu không phân biệt hoa/thường cho mitre_attack
            tech_lower = store.get("mitre_attack", "t1059.001")
            tech_upper = store.get("mitre_attack", "T1059.001")
            self.assertIsNotNone(tech_lower)
            self.assertIsNotNone(tech_upper)
            self.assertEqual(tech_lower["technique_id"], "T1059.001")

            # Lazy BM25 rebuild: sau lần query đầu tiên, _index_dirty["mitre_attack"] phải là False
            self.assertTrue(store._index_dirty["mitre_attack"])
            res = store.query("mitre_attack", "thực thi powershell tải script", n_results=2)
            self.assertFalse(store._index_dirty["mitre_attack"])
            self.assertGreater(len(res), 0)
            self.assertEqual(res[0]["technique_id"], "T1059.001")

    def test_core_protected_mitre_and_wazuh_rule_92211_guard(self):
        """Đảm bảo CORE_PROTECTED_MITRE_IDS và CORE_PROTECTED_WAZUH_RULE_IDS (Rule 92211 SQLi) không bao giờ bị ghi đè."""
        self.assertIn("T1059.001", CORE_PROTECTED_MITRE_IDS)
        self.assertIn("92211", CORE_PROTECTED_WAZUH_RULE_IDS)

        # Thử ghi đè Rule 92211 thành Sysmon PowerShell với protect_core=True
        self.kb.add_wazuh_rule(
            rule_id="92211",
            level=12,
            description="Sysmon - Event 1: PowerShell execution attempt overwrite",
            mitre_ids=["T1059.001"],
            remediation="Fake remediation",
            protect_core=True,
        )
        rule_92211 = self.kb.get_wazuh_rule("92211")
        self.assertIsNotNone(rule_92211)
        self.assertEqual(rule_92211["level"], 10)
        self.assertIn("SQL Injection", rule_92211["description"])
        self.assertIn("T1190", rule_92211["mitre_ids"])

        # Case-insensitive lookup trên RAGKnowledgeBaseTool
        t_case = self.kb.get_mitre_technique("t1059.001")
        self.assertIsNotNone(t_case)
        self.assertEqual(t_case["technique_id"], "T1059.001")

    def test_multi_backend_modes_and_backend_info(self):
        """Kiểm tra các chế độ backend: force_fallback=True, numpy_dense, và qdrant (:memory:)."""
        # 1. force_fallback=True -> backend == "fallback"
        fb_kb = RAGKnowledgeBaseTool(force_fallback=True)
        self.assertEqual(fb_kb.backend, "fallback")

        # 2. numpy_dense backend
        dense_kb = RAGKnowledgeBaseTool(backend="numpy_dense")
        self.assertEqual(dense_kb.backend, "numpy_dense")
        info = dense_kb.get_backend_info()
        self.assertEqual(info["backend"], "numpy_dense")
        self.assertIn("embedding_provider", info)
        self.assertIn("embedding_dim", info)
        self.assertGreaterEqual(info["counts"]["mitre_attack"], 40)
        self.assertGreaterEqual(info["counts"]["wazuh_rules"], 19)
        self.assertGreaterEqual(info["counts"]["knowledge_docs"], 20)

        # 3. qdrant (:memory:) backend nếu qdrant-client khả dụng
        if QDRANT_AVAILABLE:
            q_kb = RAGKnowledgeBaseTool(backend="qdrant_memory")
            self.assertEqual(q_kb.backend, "qdrant")
            q_res = q_kb.query_mitre_technique("powershell encoded script download", n_results=3)
            self.assertGreater(len(q_res), 0)
            self.assertEqual(q_res[0]["technique_id"], "T1059.001")

    def test_hybrid_rrf_bilingual_and_ood_behavioral_queries(self):
        """Kiểm tra Hybrid RRF trên các truy vấn tiếng Việt và hành vi OOD (Ransomware, LSASS, AWS S3, AD DACL)."""
        queries_and_expected = [
            ("kẻ tấn công xóa bản sao lưu hệ thống bằng vssadmin trước khi mã hóa tống tiền", ["T1490", "T1486"]),
            ("trích xuất bộ nhớ tiến trình lsass để đánh cắp mật khẩu ntlm", ["T1003.001"]),
            ("xóa nhật ký sự kiện windows event log bằng wevtutil cl security", ["T1070.001"]),
            ("tải công cụ độc hại từ máy chủ c2 bằng certutil urlcache", ["T1105"]),
            ("leo thang đặc quyền lên root qua lỗ hổng cấu hình sudo trên linux", ["T1548.003"]),
        ]
        for query_text, expected_ids in queries_and_expected:
            results = self.kb.query_mitre_technique(query_text, n_results=3, search_mode="hybrid_rrf")
            self.assertGreater(len(results), 0, f"Không tìm thấy kết quả cho query: {query_text}")
            top_ids = [r["technique_id"] for r in results]
            self.assertTrue(
                any(eid in top_ids for eid in expected_ids),
                f"Query '{query_text}' kỳ vọng {expected_ids} trong top-3 nhưng nhận {top_ids}",
            )
            self.assertGreaterEqual(results[0]["score"], 0.28)

    def test_knowledge_docs_collection_and_unified_query_collection(self):
        """Kiểm tra đủ 20 file OTRF YAML trong collection `knowledge_docs`, query_collection('all') và retrieve_incident_knowledge."""
        self.assertGreaterEqual(self.kb.count_knowledge_docs(), 20)

        # Truy vấn OTRF knowledge_docs cho AD DACL DCSync (SDWIN-190301125905)
        ad_docs = self.kb.query_knowledge_docs("Empire PowerView Add-DomainObjectAcl DCSync", n_results=3)
        self.assertGreater(len(ad_docs), 0)
        ad_ids = [d["doc_id"] for d in ad_docs]
        self.assertIn("SDWIN-190301125905", ad_ids)
        top_ad = next(d for d in ad_docs if d["doc_id"] == "SDWIN-190301125905")
        self.assertIn("T1222.001", top_ad["mitre_ids"])
        self.assertTrue(len(top_ad.get("adversary_commands", "")) > 0)
        self.assertTrue(len(top_ad.get("tools", [])) > 0)

        # Truy vấn OTRF knowledge_docs có lọc platform="AWS" (SDAWS-200914011940)
        aws_docs = self.kb.query_knowledge_docs("EC2 reverse proxy S3 bucket exfiltration", n_results=3, platform="AWS")
        self.assertGreater(len(aws_docs), 0)
        self.assertTrue(all("AWS" in d.get("platform", "") for d in aws_docs))
        self.assertIn("SDAWS-200914011940", [d["doc_id"] for d in aws_docs])

        # Truy vấn OTRF knowledge_docs cho Linux ARP Cache (SDLIN-201110074812 -> T1018)
        lin_docs = self.kb.query_knowledge_docs("arp cache discovery arp -a", n_results=3, platform="Linux")
        self.assertGreater(len(lin_docs), 0)
        self.assertIn("SDLIN-201110074812", [d["doc_id"] for d in lin_docs])

        # Kiểm tra query_collection("all") gắn nhãn source_collection
        unified = self.kb.query_collection(
            collection="all",
            query_text="PowerShell encoded command T1059.001 Rule 60106",
            n_results=5,
        )
        self.assertGreater(len(unified), 0)
        for item in unified:
            self.assertIn("source_collection", item)
            self.assertIn(
                item["source_collection"],
                ("mitre_attack", "wazuh_rules", "threat_feed", "knowledge_docs"),
            )

        # Kiểm tra retrieve_incident_knowledge bảo toàn 4 khóa cũ + matched_knowledge_docs
        bundle = self.kb.retrieve_incident_knowledge(
            query_text="Empire PowerView Add-DomainObjectAcl Active Directory DCSync",
            mitre_ids=["T1059.001"],
            rule_ids=["60106"],
            n_results=3,
            include_knowledge_docs=True,
        )
        for key in (
            "matched_techniques",
            "matched_rules",
            "nist_mitigations",
            "nist_remediations",
            "matched_knowledge_docs",
        ):
            self.assertIn(key, bundle)
        self.assertGreater(len(bundle["matched_techniques"]), 0)
        self.assertGreater(len(bundle["matched_rules"]), 0)
        self.assertGreater(len(bundle["matched_knowledge_docs"]), 0)

        # Kiểm tra PublicDatasetTrainer.ingest_knowledge_docs() trích xuất đầy đủ trường YAML
        trainer = PublicDatasetTrainer(rag_kb=self.kb)
        ingested = trainer.ingest_knowledge_docs(rag_kb=self.kb)
        self.assertGreaterEqual(ingested, 20)
        self.assertGreaterEqual(len(trainer._last_ingested_docs), 20)
        sample_doc = next(d for d in trainer._last_ingested_docs if d["id"] == "SDWIN-190301125905")
        self.assertIn("tools", sample_doc)
        self.assertIn("adversary_commands", sample_doc)
        self.assertTrue(len(sample_doc["adversary_commands"]) > 0)

    def test_bilingual_synonyms_contain_no_target_id_leakage(self):
        """Regression guard: BILINGUAL_SOC_SYNONYMS chỉ chứa thuật ngữ tự nhiên VI<->EN, KHÔNG rò rỉ doc/rule/MITRE IDs."""
        self.assertGreaterEqual(len(BILINGUAL_SOC_SYNONYMS), 40)
        mitre_re = re.compile(r"\bT\d{4}(?:\.\d{3})?\b|\bTA\d{4}\b", re.IGNORECASE)
        otrf_doc_re = re.compile(r"\bSD(?:WIN|LIN|AWS)-\d+\b", re.IGNORECASE)
        numeric_rule_or_event_re = re.compile(r"\b\d{3,6}\b")

        for phrase, mapped_terms in BILINGUAL_SOC_SYNONYMS:
            for side in (phrase, mapped_terms):
                self.assertIsNone(
                    mitre_re.search(side),
                    f"Phát hiện rò rỉ MITRE ID trong BILINGUAL_SOC_SYNONYMS: {side!r}",
                )
                self.assertIsNone(
                    otrf_doc_re.search(side),
                    f"Phát hiện rò rỉ OTRF doc ID trong BILINGUAL_SOC_SYNONYMS: {side!r}",
                )
                self.assertIsNone(
                    numeric_rule_or_event_re.search(side),
                    f"Phát hiện rò rỉ Wazuh rule/Event ID trong BILINGUAL_SOC_SYNONYMS: {side!r}",
                )

    def test_openai_embedding_provider_omnirouter_env_and_dummy_key(self):
        """Kiểm tra nhận OMNIROUTER_API_KEY và chặn key giả sk-soc-copilot-dev-dummy-key."""
        self.assertIn("sk-soc-copilot-dev-dummy-key", DUMMY_API_KEYS)

        clean_env = {
            "RAG_EMBEDDING_API_KEY": "",
            "OMNIROUTER_API_KEY": "sk-soc-copilot-dev-dummy-key",
            "OMNIROUTE_API_KEY": "",
            "OPENROUTER_API_KEY": "",
            "OPENAI_API_KEY": "",
        }
        with patch.dict(os.environ, clean_env, clear=False):
            prov_dummy = OpenAICompatibleEmbeddingProvider(dim=64)
            self.assertEqual(prov_dummy.api_key, "sk-soc-copilot-dev-dummy-key")
            self.assertFalse(prov_dummy.has_valid_api_key())

        valid_env = {
            "RAG_EMBEDDING_API_KEY": "",
            "OMNIROUTER_API_KEY": "sk-live-omnirouter-unit-test-999",
            "OMNIROUTE_API_KEY": "",
            "OPENROUTER_API_KEY": "",
            "OPENAI_API_KEY": "",
        }
        with patch.dict(os.environ, valid_env, clear=False):
            prov_valid = OpenAICompatibleEmbeddingProvider(dim=64)
            self.assertEqual(prov_valid.api_key, "sk-live-omnirouter-unit-test-999")
            self.assertTrue(prov_valid.has_valid_api_key())


if __name__ == "__main__":
    unittest.main()
