# -*- coding: utf-8 -*-
"""
src/tools/rag_knowledge_base.py
Cơ sở tri thức RAG (Retrieval-Augmented Generation) & Multi-Backend Vector Store phục vụ điều tra an ninh mạng.
Quản lý 4 collections chuẩn:
  1. mitre_attack: Kỹ thuật, chiến thuật, cách phát hiện và biện pháp giảm thiểu ATT&CK.
  2. wazuh_rules: Bộ quy tắc Wazuh Detection Ruleset và hướng dẫn khắc phục (Remediation).
  3. threat_feed: Chỉ báo đe dọa IoC động (IP, Domain, Hash, URL).
  4. knowledge_docs: Tài liệu tri thức thực chiến OTRF Security Datasets & Playbooks (YAML/JSON/MD).

Kiến trúc Multi-Backend chịu lỗi (Python 3.10 - 3.14):
- Hỗ trợ `numpy_dense` (mặc định trên Python 3.14, lock-free `.npz` an toàn đa tiến trình),
  `qdrant` (server / `:memory:` / disk kèm portalocker fallback), `chromadb` (Python < 3.14),
  và `fallback` (Cached BM25 + Bilingual VI<->EN Expansion).
- Hybrid Retrieval kết hợp Lexical BM25 và Dense Semantic Vector bằng Reciprocal Rank Fusion (RRF, k=60).
"""

import os
import re
import sys
import uuid
import math
import json
import time
import hashlib
import logging
import argparse
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple, Union

import numpy as np

from src.tools.rag_embeddings import (
    BaseEmbeddingProvider,
    EmbeddingProviderFactory,
    expand_bilingual_tokens,
)

logger = logging.getLogger(__name__)

# Kiểm tra sự sẵn sàng của thư viện chromadb (chỉ tương thích ổn định trên Python < 3.14)
try:
    if sys.version_info < (3, 14):
        import chromadb  # type: ignore
        CHROMADB_AVAILABLE = True
    else:
        chromadb = None  # type: ignore
        CHROMADB_AVAILABLE = False
except (ImportError, Exception):
    chromadb = None  # type: ignore
    CHROMADB_AVAILABLE = False

# Kiểm tra sự sẵn sàng của thư viện qdrant-client
try:
    from qdrant_client import QdrantClient  # type: ignore
    from qdrant_client.models import Distance, VectorParams, PointStruct  # type: ignore
    QDRANT_AVAILABLE = True
except (ImportError, Exception):
    QdrantClient = None  # type: ignore
    Distance = None  # type: ignore
    VectorParams = None  # type: ignore
    PointStruct = None  # type: ignore
    QDRANT_AVAILABLE = False


# Danh sách kỹ thuật MITRE cốt lõi được bảo vệ tuyệt đối không ghi đè khi đồng bộ tài liệu ngoài
CORE_PROTECTED_MITRE_IDS = {
    "T1059.001",
    "T1566.002",
    "T1078.002",
    "T1046",
    "T1018",
    "T1056.002",
    "T1087",
    "T1087.002",
}

# Danh sách quy tắc Wazuh cốt lõi được bảo vệ tuyệt đối (bảo toàn Rule 92211 SQL Injection, 60106, v.v.)
CORE_PROTECTED_WAZUH_RULE_IDS = {
    "60106",
    "92211",
    "92215",
    "5710",
    "5712",
    "5715",
    "60100",
    "60105",
    "60115",
    "100002",
    "31103",
    "31168",
    "5402",
    "100501",
    "201001",
}

MITRE_TACTIC_ID_MAP = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

ALL_COLLECTION_NAMES = ("mitre_attack", "wazuh_rules", "threat_feed", "knowledge_docs")


def parse_otrf_knowledge_doc(content: str, filename: str) -> Dict[str, Any]:
    """
    Phân tích toàn diện tài liệu tri thức OTRF (.yaml/.yml/.json/.md) trong data/knowledge_docs/.
    Trích xuất đầy đủ:
      - id, title, platform, tags, description
      - mitre_techniques, tactics
      - tools (từ simulation.tools[*])
      - adversary_commands (từ simulation.adversary_view, tối đa 1200 ký tự)
      - notebooks (từ notebooks[*])
      - source_file
    Hỗ trợ cả PyYAML (`yaml.safe_load`) lẫn Regex fallback chịu lỗi khi YAML có ký tự đặc biệt.
    """
    ext = os.path.splitext(filename)[1].lower()
    parsed_dict: Optional[Dict[str, Any]] = None

    if ext == ".json":
        try:
            obj = json.loads(content)
            if isinstance(obj, dict):
                parsed_dict = obj
        except Exception:
            parsed_dict = None
    elif ext in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
            obj = yaml.safe_load(content)
            if isinstance(obj, dict):
                parsed_dict = obj
        except Exception:
            parsed_dict = None

    if isinstance(parsed_dict, dict):
        title = str(parsed_dict.get("title") or os.path.splitext(filename)[0]).strip()
        doc_id = str(parsed_dict.get("id") or os.path.splitext(filename)[0]).strip()
        desc = str(parsed_dict.get("description") or "").strip()
        if not desc:
            desc = f"Tài liệu tri thức an ninh OTRF ({title})"

        # Platform
        raw_platform = parsed_dict.get("platform")
        platforms: List[str] = []
        if isinstance(raw_platform, list):
            platforms = [str(p).strip() for p in raw_platform if p and str(p).strip()]
        elif isinstance(raw_platform, str) and raw_platform.strip():
            platforms = [raw_platform.strip()]
        if not platforms:
            if doc_id.upper().startswith("SDAWS"):
                platforms = ["AWS"]
            elif doc_id.upper().startswith("SDLIN"):
                platforms = ["Linux"]
            else:
                platforms = ["Windows"]
        platform_str = ", ".join(platforms)

        # Tags
        raw_tags = parsed_dict.get("tags")
        tags: List[str] = []
        if isinstance(raw_tags, list):
            tags = [str(t).strip() for t in raw_tags if t and str(t).strip()]
        elif isinstance(raw_tags, str) and raw_tags.strip():
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]

        # Attack mappings
        raw_mappings = parsed_dict.get("attack_mappings") or []
        techniques: List[str] = []
        tactics: List[str] = []
        if isinstance(raw_mappings, list):
            for m in raw_mappings:
                if not isinstance(m, dict):
                    continue
                tech = str(m.get("technique") or "").strip().upper()
                sub = m.get("sub-technique") or m.get("sub_technique")
                if tech:
                    if sub and str(sub).strip() and str(sub).strip().lower() != "none" and "." not in tech:
                        sub_clean = str(sub).strip().zfill(3) if str(sub).strip().isdigit() else str(sub).strip()
                        full_tid = f"{tech}.{sub_clean}"
                    else:
                        full_tid = tech
                    if full_tid not in techniques:
                        techniques.append(full_tid)
                raw_tacs = m.get("tactics") or []
                if isinstance(raw_tacs, list):
                    for t in raw_tacs:
                        t_str = str(t).strip()
                        mapped_tac = MITRE_TACTIC_ID_MAP.get(t_str.upper(), t_str)
                        if mapped_tac and mapped_tac not in tactics:
                            tactics.append(mapped_tac)

        # Notebooks
        raw_notebooks = parsed_dict.get("notebooks") or []
        notebooks: List[str] = []
        if isinstance(raw_notebooks, list):
            for nb in raw_notebooks:
                if isinstance(nb, dict):
                    nb_name = str(nb.get("name") or nb.get("project") or "").strip()
                    nb_link = str(nb.get("link") or "").strip()
                    if nb_name and nb_link:
                        notebooks.append(f"{nb_name} ({nb_link})")
                    elif nb_name or nb_link:
                        notebooks.append(nb_name or nb_link)
                elif isinstance(nb, str) and nb.strip():
                    notebooks.append(nb.strip())

        # Simulation tools & adversary_view
        sim = parsed_dict.get("simulation")
        tools: List[str] = []
        adversary_commands = ""
        if isinstance(sim, dict):
            raw_tools = sim.get("tools") or []
            if isinstance(raw_tools, list):
                for tool in raw_tools:
                    if isinstance(tool, dict):
                        t_name = str(tool.get("name") or "").strip()
                        t_mod = str(tool.get("module") or "").strip()
                        if t_name and t_mod and t_mod.lower() != t_name.lower():
                            tools.append(f"{t_name} ({t_mod})")
                        elif t_name or t_mod:
                            tools.append(t_name or t_mod)
                    elif isinstance(tool, str) and tool.strip():
                        tools.append(tool.strip())
            adv_view = sim.get("adversary_view")
            if adv_view:
                adv_lines = [ln.strip() for ln in str(adv_view).splitlines() if ln.strip()]
                adversary_commands = "\n".join(adv_lines)[:1200]

        return {
            "id": doc_id,
            "title": title,
            "platform": platform_str,
            "platforms": platforms,
            "tags": tags,
            "description": desc,
            "mitre_techniques": techniques,
            "tactics": tactics or ["Discovery"],
            "tools": tools,
            "adversary_commands": adversary_commands,
            "notebooks": notebooks,
            "source_file": filename,
        }

    # Regex fallback cho YAML / Markdown khi không dùng được yaml.safe_load
    title_match = re.search(r"^title:\s*(.+)$", content, re.MULTILINE)
    title = title_match.group(1).strip().strip("'\"") if title_match else os.path.splitext(filename)[0]

    id_match = re.search(r"^id:\s*(.+)$", content, re.MULTILINE)
    doc_id = id_match.group(1).strip().strip("'\"") if id_match else os.path.splitext(filename)[0]

    # Platform
    platforms = []
    plat_match = re.search(r"^platform:\s*\r?\n((?:[ \t]*-\s*.+\r?\n?)+)", content, re.MULTILINE)
    if plat_match:
        for ln in plat_match.group(1).splitlines():
            m = re.match(r"^\s*-\s*(.+)$", ln)
            if m and m.group(1).strip():
                platforms.append(m.group(1).strip().strip("'\""))
    if not platforms:
        if doc_id.upper().startswith("SDAWS"):
            platforms = ["AWS"]
        elif doc_id.upper().startswith("SDLIN"):
            platforms = ["Linux"]
        else:
            platforms = ["Windows"]
    platform_str = ", ".join(platforms)

    # Tags
    tags = []
    tags_match = re.search(r"^tags:\s*\r?\n((?:[ \t]*-\s*.+\r?\n?)+)", content, re.MULTILINE)
    if tags_match:
        for ln in tags_match.group(1).splitlines():
            m = re.match(r"^\s*-\s*(.+)$", ln)
            if m and m.group(1).strip():
                tags.append(m.group(1).strip().strip("'\""))

    # Description
    desc = ""
    desc_block_match = re.search(
        r"^description:\s*\|-?\s*\r?\n((?:[ \t]+.*\r?\n?)+)",
        content,
        re.MULTILINE,
    )
    if desc_block_match:
        lines = [ln.strip() for ln in desc_block_match.group(1).splitlines() if ln.strip()]
        desc = " ".join(lines)
    else:
        desc_inline = re.search(r"^description:\s*([^\r\n]+)$", content, re.MULTILINE)
        if desc_inline:
            desc = desc_inline.group(1).strip().strip("'\"")
    if not desc:
        desc = f"Tài liệu tri thức an ninh OTRF ({title})"

    # Attack mappings
    techniques = []
    tactics = []
    am_match = re.search(
        r"^attack_mappings:\s*\r?\n((?:[ \t]+.*|\s*-\s+.*\r?\n?)+?)(?=^[a-zA-Z0-9_]+:|\Z)",
        content,
        re.MULTILINE,
    )
    am_block = am_match.group(1) if am_match else content
    entry_chunks = re.split(r"(?m)^\s*-\s*technique:", am_block)
    for idx, chunk in enumerate(entry_chunks):
        if idx == 0 and "technique:" not in chunk:
            continue
        chunk_text = chunk if idx == 0 else f"technique:{chunk}"
        t_match = re.search(r"technique:\s*['\"]?(T\d{4}(?:\.\d{3})?)['\"]?", chunk_text, re.IGNORECASE)
        if t_match:
            base_tech = t_match.group(1).upper()
            sub_match = re.search(r"sub[-_]technique:\s*['\"]?(\d{3})['\"]?", chunk_text, re.IGNORECASE)
            if sub_match and "." not in base_tech:
                full_tid = f"{base_tech}.{sub_match.group(1)}"
            else:
                full_tid = base_tech
            if full_tid not in techniques:
                techniques.append(full_tid)

        for tac_id in re.findall(r"\b(TA\d{4})\b", chunk_text, re.IGNORECASE):
            tac_upper = tac_id.upper()
            mapped_tac = MITRE_TACTIC_ID_MAP.get(tac_upper, tac_upper)
            if mapped_tac not in tactics:
                tactics.append(mapped_tac)

    if not techniques:
        for tid in re.findall(r"\b(T\d{4}(?:\.\d{3})?)\b", content):
            tid_up = tid.upper()
            if tid_up not in techniques:
                techniques.append(tid_up)

    # Tools
    tools = []
    for t_name_m in re.finditer(r"^\s*name:\s*(.+)$", content, re.MULTILINE):
        val = t_name_m.group(1).strip().strip("'\"")
        if val and val not in tools:
            tools.append(val)

    # Adversary view
    adversary_commands = ""
    adv_match = re.search(
        r"adversary_view:\s*\|-?\s*\r?\n((?:[ \t]+.*\r?\n?|\r?\n)+)",
        content,
        re.MULTILINE,
    )
    if adv_match:
        adv_lines = [ln.strip() for ln in adv_match.group(1).splitlines() if ln.strip()]
        adversary_commands = "\n".join(adv_lines)[:1200]

    return {
        "id": doc_id,
        "title": title,
        "platform": platform_str,
        "platforms": platforms,
        "tags": tags,
        "description": desc,
        "mitre_techniques": techniques,
        "tactics": tactics or ["Discovery"],
        "tools": tools,
        "adversary_commands": adversary_commands,
        "notebooks": [],
        "source_file": filename,
    }


class FallbackVectorStore:
    """
    Vector Store Lexical tối ưu sử dụng thuật toán Cached Okapi BM25 (k1=1.5, b=0.75)
    và TF-IDF Cosine Similarity kèm mở rộng từ điển song ngữ VI <-> EN.
    Lưu trữ bền vững (Persistent) vào tệp JSON trong thư mục data/chromadb với cơ chế batch flush.
    """

    BM25_K1 = 1.5
    BM25_B = 0.75

    def __init__(self, storage_file: str):
        self.storage_file = storage_file
        self.collections: Dict[str, Dict[str, Dict[str, Any]]] = {
            "mitre_attack": {},
            "wazuh_rules": {},
            "threat_feed": {},
            "knowledge_docs": {},
        }
        self._index_dirty: Dict[str, bool] = {col: True for col in ALL_COLLECTION_NAMES}
        self._cached_index: Dict[str, Dict[str, Any]] = {}
        self._storage_dirty: bool = False
        self._load()

    @staticmethod
    def _normalize_doc_id(collection_name: str, doc_id: str) -> str:
        cleaned = str(doc_id).strip()
        if collection_name == "mitre_attack":
            return cleaned.upper()
        return cleaned

    def _load(self):
        """Nạp dữ liệu từ file JSON nếu tồn tại."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for col, items in data.items():
                            if isinstance(items, dict):
                                if col == "mitre_attack":
                                    normalized_items: Dict[str, Dict[str, Any]] = {}
                                    for k, v in items.items():
                                        norm_k = str(k).strip().upper()
                                        if isinstance(v, dict):
                                            v = dict(v)
                                            v["id"] = norm_k
                                            meta = dict(v.get("metadata", {}))
                                            if "technique_id" in meta:
                                                meta["technique_id"] = norm_k
                                            v["metadata"] = meta
                                        normalized_items[norm_k] = v
                                    self.collections[col] = normalized_items
                                else:
                                    self.collections[col] = items
                                self._index_dirty[col] = True
            except Exception:
                pass
        for col in ALL_COLLECTION_NAMES:
            self.collections.setdefault(col, {})
            self._index_dirty.setdefault(col, True)

    def _save(self):
        """Lưu trữ dữ liệu bền vững ra file JSON bằng atomic write (tmp -> os.replace)."""
        dir_path = os.path.dirname(self.storage_file)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        temp_file = f"{self.storage_file}.{os.getpid()}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(self.collections, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, self.storage_file)
        self._storage_dirty = False

    def flush(self):
        """Ghi dữ liệu đang chờ (deferred) xuống đĩa nếu có thay đổi."""
        if self._storage_dirty:
            self._save()

    @staticmethod
    def tokenize(text: str) -> List[str]:
        """Tách từ hỗ trợ tiếng Việt có dấu và các ký tự định danh kỹ thuật (T1059.001, powershell.exe...)."""
        if not text:
            return []
        return re.findall(r"[\w\.\-]+", text.lower(), re.UNICODE)

    @classmethod
    def _expand_bilingual_tokens(cls, q_tokens: List[str], query_text: str = "") -> List[str]:
        """Mở rộng danh sách token truy vấn bằng từ điển song ngữ An ninh mạng VI <-> EN."""
        return expand_bilingual_tokens(q_tokens, raw_text=query_text)

    def upsert(
        self,
        collection_name: str,
        doc_id: str,
        document: str,
        metadata: Dict[str, Any],
        defer_save: bool = False,
    ):
        """Thêm hoặc cập nhật bản ghi trong collection (hỗ trợ defer_save để gom batch)."""
        if collection_name not in self.collections:
            self.collections[collection_name] = {}
        norm_id = self._normalize_doc_id(collection_name, doc_id)
        norm_meta = dict(metadata) if isinstance(metadata, dict) else {}
        if collection_name == "mitre_attack" and "technique_id" in norm_meta:
            norm_meta["technique_id"] = norm_id

        self.collections[collection_name][norm_id] = {
            "id": norm_id,
            "document": document,
            "metadata": norm_meta,
        }
        self._index_dirty[collection_name] = True
        self._storage_dirty = True
        if not defer_save:
            self._save()

    def upsert_batch(
        self,
        collection_name: str,
        items: List[Union[Tuple[str, str, Dict[str, Any]], Dict[str, Any]]],
        defer_save: bool = False,
    ) -> int:
        """
        Thêm/cập nhật hàng loạt bản ghi vào collection và chỉ ghi đĩa 1 lần duy nhất.
        Mỗi phần tử trong `items` có thể là tuple `(doc_id, document, metadata)`
        hoặc dict `{"id": doc_id, "document": document, "metadata": metadata}`.
        """
        if not items:
            return 0
        if collection_name not in self.collections:
            self.collections[collection_name] = {}

        count = 0
        for item in items:
            if isinstance(item, tuple) and len(item) == 3:
                raw_id, doc_text, meta = item
            elif isinstance(item, dict) and "id" in item:
                raw_id = item["id"]
                doc_text = item.get("document", "")
                meta = item.get("metadata", {})
            else:
                continue

            norm_id = self._normalize_doc_id(collection_name, raw_id)
            norm_meta = dict(meta) if isinstance(meta, dict) else {}
            if collection_name == "mitre_attack" and "technique_id" in norm_meta:
                norm_meta["technique_id"] = norm_id

            self.collections[collection_name][norm_id] = {
                "id": norm_id,
                "document": str(doc_text),
                "metadata": norm_meta,
            }
            count += 1

        if count > 0:
            self._index_dirty[collection_name] = True
            self._storage_dirty = True
            if not defer_save:
                self._save()
        return count

    def get(self, collection_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
        """Lấy bản ghi theo ID (hỗ trợ chuẩn hóa không phân biệt hoa/thường cho mitre_attack)."""
        if not doc_id:
            return None
        col = self.collections.get(collection_name, {})
        norm_id = self._normalize_doc_id(collection_name, doc_id)
        entry = col.get(norm_id)
        if entry is None and collection_name in ("mitre_attack", "knowledge_docs"):
            target_lower = str(doc_id).strip().lower()
            for k, v in col.items():
                if k.lower() == target_lower:
                    entry = v
                    break
        if entry:
            res = dict(entry.get("metadata", {}))
            res["document"] = entry.get("document", "")
            return res
        return None

    def count(self, collection_name: str) -> int:
        """Đếm số bản ghi trong collection."""
        return len(self.collections.get(collection_name, {}))

    def clear(self, collection_name: Optional[str] = None):
        """Xóa sạch collection hoặc toàn bộ store."""
        if collection_name:
            if collection_name in self.collections:
                self.collections[collection_name] = {}
                self._index_dirty[collection_name] = True
                self._cached_index.pop(collection_name, None)
        else:
            self.collections = {col: {} for col in ALL_COLLECTION_NAMES}
            self._index_dirty = {col: True for col in ALL_COLLECTION_NAMES}
            self._cached_index.clear()
        self._storage_dirty = True
        self._save()

    def _rebuild_index(self, collection_name: str):
        """
        Xây dựng và lưu cache chỉ mục BM25 + TF-IDF cho `collection_name`.
        Chỉ được gọi khi `self._index_dirty[collection_name]` là True (Lazy Rebuild).
        """
        col = self.collections.get(collection_name, {})
        doc_items = list(col.values())
        N = len(doc_items)
        if N == 0:
            self._cached_index[collection_name] = {
                "N": 0,
                "doc_ids": [],
                "doc_tfs": {},
                "doc_lens": {},
                "avgdl": 1.0,
                "idfs": {},
                "tfidf_idfs": {},
                "doc_tfidf_vecs": {},
                "doc_norms": {},
            }
            self._index_dirty[collection_name] = False
            return

        doc_ids: List[str] = []
        doc_tfs: Dict[str, Counter] = {}
        doc_lens: Dict[str, int] = {}
        dfs: Counter = Counter()

        for item in doc_items:
            doc_id = item["id"]
            meta = item.get("metadata", {})
            meta_str = " ".join(
                " ".join(str(x) for x in v) if isinstance(v, list) else str(v)
                for v in meta.values()
            )
            full_text = f"{item.get('document', '')} {meta_str}"
            tokens = self.tokenize(full_text)
            tf_counter = Counter(tokens)
            doc_ids.append(doc_id)
            doc_tfs[doc_id] = tf_counter
            doc_lens[doc_id] = max(1, len(tokens))
            dfs.update(tf_counter.keys())

        avgdl = sum(doc_lens.values()) / float(N) if N > 0 else 1.0

        # BM25 IDF (Okapi chuẩn, luôn dương) & Smoothed TF-IDF IDF
        bm25_idfs: Dict[str, float] = {}
        tfidf_idfs: Dict[str, float] = {}
        for term, df in dfs.items():
            bm25_idfs[term] = math.log(1.0 + (N - df + 0.5) / (df + 0.5))
            tfidf_idfs[term] = math.log((1.0 + N) / (1.0 + df)) + 1.0

        doc_tfidf_vecs: Dict[str, Dict[str, float]] = {}
        doc_norms: Dict[str, float] = {}
        for doc_id in doc_ids:
            d_tf = doc_tfs[doc_id]
            d_vec = {t: count * tfidf_idfs.get(t, 1.0) for t, count in d_tf.items()}
            d_norm = math.sqrt(sum(w * w for w in d_vec.values()))
            doc_tfidf_vecs[doc_id] = d_vec
            doc_norms[doc_id] = d_norm

        self._cached_index[collection_name] = {
            "N": N,
            "doc_ids": doc_ids,
            "doc_tfs": doc_tfs,
            "doc_lens": doc_lens,
            "avgdl": avgdl,
            "idfs": bm25_idfs,
            "tfidf_idfs": tfidf_idfs,
            "doc_tfidf_vecs": doc_tfidf_vecs,
            "doc_norms": doc_norms,
        }
        self._index_dirty[collection_name] = False

    def query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 3,
        use_bm25: bool = True,
        expand_bilingual: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Truy vấn tìm kiếm lexical theo Cached Okapi BM25 (mặc định) hoặc Legacy TF-IDF Cosine.
        Hỗ trợ mở rộng từ khóa song ngữ VI <-> EN và cộng trọng số ưu tiên khi khớp ID kỹ thuật / Rule ID.
        """
        col = self.collections.get(collection_name, {})
        if not col or not query_text:
            return []

        base_tokens = self.tokenize(query_text)
        if not base_tokens:
            return []

        if self._index_dirty.get(collection_name, True) or collection_name not in self._cached_index:
            self._rebuild_index(collection_name)

        idx_data = self._cached_index.get(collection_name, {})
        if not idx_data or idx_data.get("N", 0) == 0:
            return []

        if expand_bilingual:
            expanded_tokens = self._expand_bilingual_tokens(base_tokens, query_text=query_text)
        else:
            expanded_tokens = list(base_tokens)

        base_token_set = set(base_tokens)
        doc_ids: List[str] = idx_data["doc_ids"]
        doc_tfs: Dict[str, Counter] = idx_data["doc_tfs"]
        doc_lens: Dict[str, int] = idx_data["doc_lens"]
        avgdl: float = idx_data["avgdl"]
        bm25_idfs: Dict[str, float] = idx_data["idfs"]
        tfidf_idfs: Dict[str, float] = idx_data["tfidf_idfs"]
        doc_tfidf_vecs: Dict[str, Dict[str, float]] = idx_data["doc_tfidf_vecs"]
        doc_norms: Dict[str, float] = idx_data["doc_norms"]

        # Vector TF-IDF cho query
        q_tf = Counter(expanded_tokens)
        q_tfidf_vec: Dict[str, float] = {}
        for t, count in q_tf.items():
            weight_mult = 1.0 if t in base_token_set else 0.55
            q_tfidf_vec[t] = count * weight_mult * tfidf_idfs.get(t, 1.0)
        q_norm = math.sqrt(sum(w * w for w in q_tfidf_vec.values()))
        if q_norm == 0.0:
            return []

        q_text_lower = query_text.lower()
        scored_results: List[Tuple[float, Dict[str, Any]]] = []
        k1 = self.BM25_K1
        b = self.BM25_B

        for doc_id in doc_ids:
            item = col.get(doc_id)
            if not item:
                continue
            d_tf = doc_tfs[doc_id]
            d_vec = doc_tfidf_vecs[doc_id]
            d_norm = doc_norms[doc_id]

            # 1. Điểm Cosine TF-IDF
            if d_norm == 0.0:
                tfidf_sim = 0.0
            else:
                dot = sum(q_w * d_vec.get(t, 0.0) for t, q_w in q_tfidf_vec.items() if t in d_vec)
                tfidf_sim = dot / (q_norm * d_norm)

            # 2. Điểm Okapi BM25
            if use_bm25:
                dl = doc_lens[doc_id]
                norm_factor = k1 * (1.0 - b + b * (dl / avgdl))
                raw_bm25 = 0.0
                for t, q_count in q_tf.items():
                    tf_val = d_tf.get(t, 0)
                    if tf_val <= 0:
                        continue
                    idf_val = bm25_idfs.get(t, 0.0)
                    if idf_val <= 0.0:
                        continue
                    term_weight = 1.0 if t in base_token_set else 0.55
                    tf_sat = (tf_val * (k1 + 1.0)) / (tf_val + norm_factor)
                    raw_bm25 += term_weight * idf_val * tf_sat

                # Chuẩn hóa mượt BM25 về [0, 1) và kết hợp với TF-IDF cosine
                bm25_norm = raw_bm25 / (raw_bm25 + 2.5) if raw_bm25 > 0.0 else 0.0
                sim = 0.72 * bm25_norm + 0.28 * tfidf_sim
            else:
                sim = tfidf_sim

            # 3. Boost điểm số nếu khớp chính xác ID kỹ thuật (ví dụ T1059.001) hoặc Rule ID (92211, 60106)
            doc_id_lower = doc_id.lower()
            if doc_id_lower in q_text_lower or doc_id_lower in base_token_set:
                sim += 1.5

            # 4. Boost điểm nếu query nhắc đến tên kỹ thuật hoặc tiêu đề tài liệu
            meta = item.get("metadata", {})
            name_val = str(meta.get("name") or meta.get("title") or "").lower()
            if name_val and name_val in q_text_lower:
                sim += 0.5

            if sim > 0.0:
                record = dict(meta)
                record["score"] = round(float(sim), 4)
                record["document"] = item.get("document", "")
                scored_results.append((sim, record))

        scored_results.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored_results[:n_results]]


class RAGKnowledgeBaseTool:
    """
    Lớp điều khiển Cơ sở tri thức RAG đa tầng cho hệ thống SOC Multi-Agent.
    Hỗ trợ 4 Backends:
      - `numpy_dense`: Dense vector `.npz` lock-free + Hybrid RRF (mặc định trên Python 3.14).
      - `qdrant`: Qdrant vector database (server / `:memory:` / local disk với portalocker fallback).
      - `chromadb`: Persistent ChromaDB (Python < 3.14).
      - `fallback`: Lexical Vector Store thuần Python với Cached BM25 + Bilingual VI<->EN Expansion.
    """

    RRF_K = 60.0

    def __init__(
        self,
        persist_directory: Optional[str] = None,
        force_fallback: bool = False,
        backend: Optional[str] = None,
        embedding_provider: Optional[BaseEmbeddingProvider] = None,
        auto_sync_docs: bool = True,
    ):
        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.root_dir = os.path.dirname(src_dir)

        if persist_directory is None:
            self.persist_directory = os.path.join(self.root_dir, "data", "chromadb")
        else:
            self.persist_directory = persist_directory

        os.makedirs(self.persist_directory, exist_ok=True)
        self.force_fallback = bool(force_fallback)
        self.auto_sync_docs = bool(auto_sync_docs)

        # 1. Luôn khởi tạo FallbackVectorStore làm nhánh Lexical BM25 và tầng cứu cánh tuyệt đối
        fallback_file = os.path.join(self.persist_directory, "fallback_rag_db.json")
        self.fallback_store = FallbackVectorStore(fallback_file)

        # 2. Khởi tạo Embedding Provider (kèm Persistent Disk Cache trong persist_directory)
        self.embedding_provider: BaseEmbeddingProvider = (
            embedding_provider
            if embedding_provider is not None
            else EmbeddingProviderFactory.create(cache_dir=self.persist_directory)
        )

        # 3. Cấu trúc Dense Indices cho numpy_dense / qdrant / chromadb
        self.backend = "fallback"
        self.chroma_client = None
        self.mitre_col = None
        self.wazuh_col = None
        self.threat_col = None
        self.docs_col = None
        self.qdrant_client = None

        self._dense_indices: Dict[str, Dict[str, Any]] = {}
        self._dense_dirty: Dict[str, bool] = {col: True for col in ALL_COLLECTION_NAMES}

        requested_backend = (
            "fallback"
            if self.force_fallback
            else (backend or os.getenv("RAG_BACKEND", "auto")).strip().lower()
        )
        self._init_backend(requested_backend)

        # 4. Đảm bảo nạp đầy đủ tri thức MITRE, Wazuh Rules và 20 OTRF Knowledge Docs
        self._ensure_expanded_seed()

    def _init_backend(self, requested_backend: str):
        """Khởi tạo backend vector store theo cấu hình và tự động fallback an toàn nếu gặp lỗi."""
        if self.force_fallback or requested_backend == "fallback":
            self.backend = "fallback"
            return

        if requested_backend in ("qdrant", "qdrant_memory"):
            if self._try_init_qdrant(in_memory=(requested_backend == "qdrant_memory")):
                self.backend = "qdrant"
                return
            self.backend = "numpy_dense"
            return

        if requested_backend == "chromadb":
            if self._try_init_chromadb():
                self.backend = "chromadb"
                return
            self.backend = "numpy_dense"
            return

        if requested_backend == "numpy_dense":
            self.backend = "numpy_dense"
            return

        # Chế độ "auto":
        # - Nếu có QDRANT_URL explícit -> ưu tiên qdrant
        # - Nếu Python < 3.14 và CHROMADB_AVAILABLE -> dùng chromadb
        # - Mặc định trên Python 3.14 -> dùng numpy_dense (an toàn đa tiến trình, không bị portalocker lock)
        if os.getenv("QDRANT_URL", "").strip() and QDRANT_AVAILABLE:
            if self._try_init_qdrant(in_memory=False):
                self.backend = "qdrant"
                return

        if CHROMADB_AVAILABLE and sys.version_info < (3, 14):
            if self._try_init_chromadb():
                self.backend = "chromadb"
                return

        self.backend = "numpy_dense"

    def _try_init_chromadb(self) -> bool:
        if not CHROMADB_AVAILABLE or chromadb is None:
            return False
        try:
            self.chroma_client = chromadb.PersistentClient(path=self.persist_directory)
            self.mitre_col = self.chroma_client.get_or_create_collection(
                name="mitre_attack",
                metadata={"hnsw:space": "cosine"},
            )
            self.wazuh_col = self.chroma_client.get_or_create_collection(
                name="wazuh_rules",
                metadata={"hnsw:space": "cosine"},
            )
            self.threat_col = self.chroma_client.get_or_create_collection(
                name="threat_feed",
                metadata={"hnsw:space": "cosine"},
            )
            self.docs_col = self.chroma_client.get_or_create_collection(
                name="knowledge_docs",
                metadata={"hnsw:space": "cosine"},
            )
            return True
        except Exception as exc:
            logger.warning("ChromaDB khởi tạo thất bại (%s), chuyển sang numpy_dense.", exc)
            self.chroma_client = None
            return False

    def _try_init_qdrant(self, in_memory: bool = False) -> bool:
        if not QDRANT_AVAILABLE or QdrantClient is None:
            return False
        qdrant_url = os.getenv("QDRANT_URL", "").strip()
        try:
            if in_memory or qdrant_url == ":memory:":
                self.qdrant_client = QdrantClient(":memory:")
            elif qdrant_url:
                self.qdrant_client = QdrantClient(url=qdrant_url, timeout=5.0)
            else:
                qdrant_path = os.path.join(self.persist_directory, "qdrant_store")
                os.makedirs(qdrant_path, exist_ok=True)
                self.qdrant_client = QdrantClient(path=qdrant_path)

            for col_name in ALL_COLLECTION_NAMES:
                if not self.qdrant_client.collection_exists(col_name):
                    self.qdrant_client.create_collection(
                        collection_name=col_name,
                        vectors_config=VectorParams(
                            size=self.embedding_provider.dim,
                            distance=Distance.COSINE,
                        ),
                    )
            return True
        except (RuntimeError, BlockingIOError, Exception) as exc:
            logger.warning(
                "Qdrant local store bị khóa hoặc không khả dụng (%s), tự động fallback sang numpy_dense.",
                exc,
            )
            self.qdrant_client = None
            return False

    def get_backend_info(self) -> Dict[str, Any]:
        """Trả về thông tin chi tiết về Vector Store Backend, Embedding Provider và số lượng bản ghi."""
        return {
            "backend": self.backend,
            "embedding_provider": self.embedding_provider.provider_name,
            "embedding_model": self.embedding_provider.model_name,
            "embedding_dim": self.embedding_provider.dim,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "chromadb_available": CHROMADB_AVAILABLE,
            "qdrant_available": QDRANT_AVAILABLE,
            "persist_directory": self.persist_directory,
            "counts": {
                "mitre_attack": self.count_mitre_techniques(),
                "wazuh_rules": self.count_wazuh_rules(),
                "threat_feed": self.count_threat_feed(),
                "knowledge_docs": self.count_knowledge_docs(),
            },
        }

    @staticmethod
    def _compose_rich_text(item: Dict[str, Any]) -> str:
        meta = item.get("metadata", {})
        meta_parts: List[str] = []
        for k, v in meta.items():
            if k in ("document", "score", "rrf_score"):
                continue
            if isinstance(v, list):
                meta_parts.append(" ".join(str(x) for x in v))
            elif v is not None:
                meta_parts.append(str(v))
        return f"{item.get('document', '')}\n{' '.join(meta_parts)}"

    def _dense_npz_path(self, collection_name: str) -> str:
        return os.path.join(self.persist_directory, f"dense_{collection_name}.npz")

    def _sync_dense_collection(self, collection_name: str, save_to_disk: bool = True):
        """
        Đồng bộ ma trận dense vector chuẩn hóa L2 cho `collection_name` từ `fallback_store`.
        Tận dụng `PersistentEmbeddingCache` để chỉ tính toán vector cho tài liệu mới/thay đổi.
        """
        col = self.fallback_store.collections.get(collection_name, {})
        if not col:
            self._dense_indices[collection_name] = {
                "doc_ids": [],
                "matrix": np.zeros((0, self.embedding_provider.dim), dtype=np.float32),
            }
            self._dense_dirty[collection_name] = False
            return

        doc_ids: List[str] = []
        rich_texts: List[str] = []
        for doc_id, item in col.items():
            doc_ids.append(doc_id)
            rich_texts.append(self._compose_rich_text(item))

        matrix = self.embedding_provider.embed_texts(rich_texts)
        self._dense_indices[collection_name] = {
            "doc_ids": doc_ids,
            "matrix": matrix,
        }
        self._dense_dirty[collection_name] = False

        # Lưu ma trận dense_<collection>.npz xuống đĩa bằng atomic write
        if save_to_disk:
            npz_path = self._dense_npz_path(collection_name)
            tmp_path = f"{npz_path}.{os.getpid()}_{int(time.time() * 1000)}.tmp"
            try:
                with open(tmp_path, "wb") as f:
                    np.savez(
                        f,
                        doc_ids=np.array(doc_ids, dtype=str),
                        matrix=matrix,
                    )
                os.replace(tmp_path, npz_path)
            except Exception as exc:
                logger.debug("Không thể lưu dense matrix %s: %s", npz_path, exc)
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

        # Nếu backend là qdrant, đồng bộ points vào Qdrant collection
        if self.backend == "qdrant" and self.qdrant_client is not None and PointStruct is not None:
            try:
                points = [
                    PointStruct(
                        id=str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{collection_name}:{doc_id}")),
                        vector=matrix[idx].tolist(),
                        payload={"doc_id": doc_id},
                    )
                    for idx, doc_id in enumerate(doc_ids)
                ]
                if points:
                    self.qdrant_client.upsert(collection_name=collection_name, points=points)
            except Exception as exc:
                logger.warning("Qdrant upsert lỗi (%s), chuyển sang numpy_dense.", exc)
                self.backend = "numpy_dense"

    def rebuild_all_dense_indices(self):
        """Tái tạo và lưu toàn bộ ma trận dense `.npz` cho cả 4 collections."""
        self.fallback_store.flush()
        for col_name in ALL_COLLECTION_NAMES:
            self._dense_dirty[col_name] = True
            self._sync_dense_collection(col_name, save_to_disk=True)
        if self.embedding_provider.cache is not None:
            self.embedding_provider.cache.flush()

    def _dense_query_scores(
        self,
        collection_name: str,
        query_text: str,
        top_k: int = 10,
    ) -> List[Tuple[str, float]]:
        """
        Truy vấn nhánh Dense Vector (`qdrant` / `chromadb` / `numpy_dense`)
        và trả về danh sách `[(doc_id, cosine_similarity)]` sắp xếp giảm dần.
        """
        col = self.fallback_store.collections.get(collection_name, {})
        if not col or not query_text:
            return []

        if self._dense_dirty.get(collection_name, True) or collection_name not in self._dense_indices:
            self._sync_dense_collection(collection_name, save_to_disk=True)

        q_vec = self.embedding_provider.embed_query(query_text)
        if float(np.linalg.norm(q_vec)) <= 1e-12:
            return []

        # Nhánh 1: Qdrant
        if self.backend == "qdrant" and self.qdrant_client is not None:
            try:
                res = self.qdrant_client.query_points(
                    collection_name=collection_name,
                    query=q_vec.tolist(),
                    limit=min(top_k, len(col)),
                )
                points = getattr(res, "points", []) or []
                out: List[Tuple[str, float]] = []
                for pt in points:
                    payload = getattr(pt, "payload", {}) or {}
                    did = payload.get("doc_id")
                    if did and did in col:
                        out.append((str(did), float(getattr(pt, "score", 0.0))))
                if out:
                    return out
            except Exception as exc:
                logger.warning("Qdrant query_points lỗi (%s), dùng numpy_dense.", exc)

        # Nhánh 2: ChromaDB
        if self.backend == "chromadb":
            chroma_map = {
                "mitre_attack": self.mitre_col,
                "wazuh_rules": self.wazuh_col,
                "threat_feed": self.threat_col,
                "knowledge_docs": self.docs_col,
            }
            target_col = chroma_map.get(collection_name)
            if target_col is not None:
                try:
                    c_count = target_col.count()
                    if c_count > 0:
                        c_res = self._execute_collection_query(target_col, query_text, min(top_k, c_count))
                        out_c: List[Tuple[str, float]] = []
                        id_field_map = {
                            "mitre_attack": "technique_id",
                            "wazuh_rules": "rule_id",
                            "threat_feed": "doc_id",
                            "knowledge_docs": "doc_id",
                        }
                        id_key = id_field_map.get(collection_name, "id")
                        for item in c_res:
                            did = item.get(id_key) or item.get("id")
                            if did:
                                out_c.append((str(did), float(item.get("score", 0.0))))
                        if out_c:
                            return out_c
                except Exception:
                    pass

        # Nhánh 3: Numpy Dense Exact Cosine Similarity (< 0.2ms)
        dense_data = self._dense_indices.get(collection_name, {})
        doc_ids: List[str] = dense_data.get("doc_ids", [])
        matrix: Optional[np.ndarray] = dense_data.get("matrix")
        if matrix is None or len(doc_ids) == 0 or matrix.shape[0] == 0:
            return []

        scores = matrix @ q_vec
        k = min(top_k, len(doc_ids))
        top_indices = np.argsort(scores)[::-1][:k]
        return [(doc_ids[int(i)], float(scores[int(i)])) for i in top_indices if float(scores[int(i)]) > 0.0]

    def _hybrid_query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Hybrid Retrieval kết hợp Lexical Cached BM25 ($R_{lex}$) và Dense Cosine ($R_{dense}$)
        bằng thuật toán Reciprocal Rank Fusion (RRF, k = 60):
            RRF(d) = w_lex / (60 + rank_lex(d)) + w_dense / (60 + rank_dense(d)) + exact_boost(d)
        """
        col = self.fallback_store.collections.get(collection_name, {})
        if not col or not query_text or not str(query_text).strip():
            return []

        candidate_k = max(12, n_results * 4)

        # 1. Nhánh Lexical (Cached BM25 + Bilingual Expansion)
        lex_results = self.fallback_store.query(
            collection_name,
            query_text,
            n_results=candidate_k,
            use_bm25=True,
            expand_bilingual=True,
        )

        id_field_map = {
            "mitre_attack": "technique_id",
            "wazuh_rules": "rule_id",
            "threat_feed": "doc_id",
            "knowledge_docs": "doc_id",
        }
        id_field = id_field_map.get(collection_name, "id")

        lex_ranks: Dict[str, int] = {}
        lex_scores: Dict[str, float] = {}
        for rank_idx, item in enumerate(lex_results, start=1):
            raw_id = item.get(id_field) or item.get("id")
            if not raw_id:
                continue
            norm_id = self.fallback_store._normalize_doc_id(collection_name, str(raw_id))
            lex_ranks[norm_id] = rank_idx
            lex_scores[norm_id] = float(item.get("score", 0.0))

        # 2. Nhánh Dense Semantic Vector
        dense_pairs = self._dense_query_scores(collection_name, query_text, top_k=candidate_k)
        dense_ranks: Dict[str, int] = {}
        dense_scores: Dict[str, float] = {}
        for rank_idx, (doc_id, d_score) in enumerate(dense_pairs, start=1):
            if d_score < 0.04:
                continue
            dense_ranks[doc_id] = rank_idx
            dense_scores[doc_id] = d_score

        # Hợp nhất tập ứng viên từ cả 2 nhánh
        all_candidate_ids = list(dict.fromkeys(list(lex_ranks.keys()) + list(dense_ranks.keys())))
        if not all_candidate_ids:
            return []

        # Trọng số RRF theo loại Embedding Provider
        if self.embedding_provider.provider_name in ("openai", "ollama"):
            w_lex, w_dense = 0.45, 0.55
        else:
            w_lex, w_dense = 0.65, 0.35

        q_text_lower = query_text.lower()
        q_tokens_set = set(self.fallback_store.tokenize(query_text))
        rrf_k = self.RRF_K

        fused_results: List[Tuple[float, Dict[str, Any]]] = []
        for doc_id in all_candidate_ids:
            entry = col.get(doc_id)
            if not entry:
                continue

            r_lex = lex_ranks.get(doc_id)
            r_dense = dense_ranks.get(doc_id)
            s_lex = lex_scores.get(doc_id, 0.0)
            s_dense = dense_scores.get(doc_id, 0.0)

            rrf_lex = (w_lex / (rrf_k + r_lex)) if r_lex is not None else 0.0
            rrf_dense = (w_dense / (rrf_k + r_dense)) if r_dense is not None else 0.0
            rrf_raw = rrf_lex + rrf_dense

            # Exact ID & Name Boost để đảm bảo tra cứu mã kỹ thuật/Rule ID chính xác luôn đứng Top-1
            exact_boost = 0.0
            doc_id_lower = doc_id.lower()
            if doc_id_lower in q_text_lower or doc_id_lower in q_tokens_set:
                exact_boost += 1.0

            meta = entry.get("metadata", {})
            name_val = str(meta.get("name") or meta.get("title") or "").lower()
            if name_val and name_val in q_text_lower:
                exact_boost += 0.35

            # Chuẩn hóa điểm RRF về thang [0, 1+] tương thích ngưỡng rag_mitre_threshold (0.28)
            rrf_norm = rrf_raw * (rrf_k + 1.0)
            sim_blend = w_lex * min(1.0, s_lex) + w_dense * min(1.0, s_dense)
            final_score = 0.50 * rrf_norm + 0.50 * sim_blend + exact_boost

            if final_score > 0.0:
                record = dict(meta)
                record["score"] = round(float(final_score), 4)
                record["rrf_score"] = round(float(rrf_raw + exact_boost), 6)
                record["document"] = entry.get("document", "")
                fused_results.append((final_score, record))

        fused_results.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in fused_results[:n_results]]

    def query_lexical_only(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 3,
        mode: str = "bm25",
    ) -> List[Dict[str, Any]]:
        """
        Truy vấn chỉ dùng nhánh Lexical phục vụ đánh giá Ablation:
          - `mode="bm25"`: Cached Okapi BM25 + Bilingual VI<->EN Expansion.
          - `mode="legacy_tfidf"`: Raw TF-IDF Cosine gốc không mở rộng từ đồng nghĩa.
        """
        is_legacy = str(mode).strip().lower() in ("legacy_tfidf", "tfidf", "legacy")
        return self.fallback_store.query(
            collection_name,
            query_text,
            n_results=n_results,
            use_bm25=not is_legacy,
            expand_bilingual=not is_legacy,
        )

    def _dispatch_collection_query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 3,
        search_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Điểm điều phối truy vấn thống nhất theo `search_mode` và `self.backend`."""
        resolved_mode = (search_mode or "").strip().lower()
        if resolved_mode in ("legacy_tfidf", "tfidf", "legacy"):
            return self.query_lexical_only(collection_name, query_text, n_results=n_results, mode="legacy_tfidf")
        if resolved_mode in ("bm25", "lexical"):
            return self.query_lexical_only(collection_name, query_text, n_results=n_results, mode="bm25")
        if resolved_mode == "dense_only":
            pairs = self._dense_query_scores(collection_name, query_text, top_k=n_results)
            col = self.fallback_store.collections.get(collection_name, {})
            out: List[Dict[str, Any]] = []
            for did, d_score in pairs:
                entry = col.get(did)
                if entry:
                    rec = dict(entry.get("metadata", {}))
                    rec["score"] = round(float(d_score), 4)
                    rec["document"] = entry.get("document", "")
                    out.append(rec)
            return out

        if self.backend == "fallback" and resolved_mode != "hybrid_rrf":
            return self.fallback_store.query(collection_name, query_text, n_results=n_results)

        return self._hybrid_query(collection_name, query_text, n_results=n_results)

    def add_mitre_technique(
        self,
        technique_id: str,
        name: str,
        tactic: str,
        description: str,
        mitigations: str,
        detection: str,
        defer_save: bool = False,
        protect_core: bool = False,
    ):
        """
        Nạp hoặc cập nhật một kỹ thuật MITRE ATT&CK vào collection `mitre_attack`.
        Chuẩn hóa ID viết hoa (`T1059.001`) và bảo vệ `CORE_PROTECTED_MITRE_IDS` khi `protect_core=True`.
        """
        norm_tid = str(technique_id).strip().upper()
        if not norm_tid:
            return
        if protect_core and norm_tid in CORE_PROTECTED_MITRE_IDS and self.get_mitre_technique(norm_tid) is not None:
            return

        document_text = (
            f"Technique ID: {norm_tid}\n"
            f"Name: {name}\n"
            f"Tactic: {tactic}\n"
            f"Description: {description}\n"
            f"Detection: {detection}\n"
            f"Mitigations: {mitigations}"
        )
        metadata = {
            "technique_id": norm_tid,
            "name": name,
            "tactic": tactic,
            "description": description,
            "mitigations": mitigations,
            "detection": detection,
        }

        self.fallback_store.upsert("mitre_attack", norm_tid, document_text, metadata, defer_save=defer_save)
        self._dense_dirty["mitre_attack"] = True

        if self.backend == "chromadb" and self.mitre_col is not None:
            try:
                self.mitre_col.upsert(
                    ids=[norm_tid],
                    documents=[document_text],
                    metadatas=[metadata],
                )
            except Exception:
                pass

    def add_wazuh_rule(
        self,
        rule_id: str,
        level: int,
        description: str,
        mitre_ids: Union[List[str], str],
        remediation: str,
        defer_save: bool = False,
        protect_core: bool = False,
    ):
        """
        Nạp hoặc cập nhật một quy tắc Wazuh vào collection `wazuh_rules`.
        Bảo vệ `CORE_PROTECTED_WAZUH_RULE_IDS` (ví dụ Rule 92211 SQL Injection) khi `protect_core=True`.
        """
        rule_id_clean = str(rule_id).strip()
        if not rule_id_clean:
            return
        if (
            protect_core
            and rule_id_clean in CORE_PROTECTED_WAZUH_RULE_IDS
            and self.get_wazuh_rule(rule_id_clean) is not None
        ):
            return

        if isinstance(mitre_ids, list):
            mitre_list = [str(m).strip().upper() for m in mitre_ids if str(m).strip()]
        elif isinstance(mitre_ids, str):
            mitre_list = [m.strip().upper() for m in mitre_ids.split(",") if m.strip()]
        else:
            mitre_list = [str(mitre_ids).strip().upper()]

        mitre_str = ", ".join(mitre_list)
        document_text = (
            f"Wazuh Rule ID: {rule_id_clean}\n"
            f"Severity Level: {level}\n"
            f"Description: {description}\n"
            f"MITRE ATT&CK IDs: {mitre_str}\n"
            f"Remediation: {remediation}"
        )

        metadata_for_fallback = {
            "rule_id": rule_id_clean,
            "level": int(level),
            "description": description,
            "mitre_ids": mitre_list,
            "remediation": remediation,
        }

        self.fallback_store.upsert(
            "wazuh_rules",
            rule_id_clean,
            document_text,
            metadata_for_fallback,
            defer_save=defer_save,
        )
        self._dense_dirty["wazuh_rules"] = True

        if self.backend == "chromadb" and self.wazuh_col is not None:
            metadata_for_chroma = {
                "rule_id": rule_id_clean,
                "level": int(level),
                "description": description,
                "mitre_ids": json.dumps(mitre_list),
                "remediation": remediation,
            }
            try:
                self.wazuh_col.upsert(
                    ids=[rule_id_clean],
                    documents=[document_text],
                    metadatas=[metadata_for_chroma],
                )
            except Exception:
                pass

    def add_knowledge_doc(
        self,
        doc_id: str,
        title: str,
        platform: Union[List[str], str] = "Windows",
        tags: Optional[Union[List[str], str]] = None,
        mitre_ids: Optional[Union[List[str], str]] = None,
        tactics: Optional[Union[List[str], str]] = None,
        description: str = "",
        adversary_commands: str = "",
        tools: Optional[Union[List[str], str]] = None,
        notebooks: Optional[Union[List[str], str]] = None,
        source_file: str = "",
        content_hash: str = "",
        defer_save: bool = False,
    ):
        """
        Nạp hoặc cập nhật tài liệu tri thức OTRF Security Dataset / Playbook vào collection `knowledge_docs`.
        Lưu trữ toàn bộ 20 tài liệu YAML (kể cả các tài liệu ánh xạ vào `CORE_PROTECTED_MITRE_IDS`).
        """
        doc_id_clean = str(doc_id).strip()
        if not doc_id_clean:
            return

        def _to_list(val: Any) -> List[str]:
            if val is None:
                return []
            if isinstance(val, list):
                return [str(x).strip() for x in val if str(x).strip()]
            if isinstance(val, str):
                return [x.strip() for x in val.split(",") if x.strip()]
            return [str(val).strip()]

        plat_list = _to_list(platform) or ["Windows"]
        plat_str = ", ".join(plat_list)
        tag_list = _to_list(tags)
        mitre_list = [m.upper() for m in _to_list(mitre_ids)]
        tactic_list = _to_list(tactics)
        tool_list = _to_list(tools)
        notebook_list = _to_list(notebooks)

        document_text = (
            f"Knowledge Doc ID: {doc_id_clean}\n"
            f"Title: {title}\n"
            f"Platform: {plat_str}\n"
            f"Tags: {', '.join(tag_list)}\n"
            f"MITRE ATT&CK IDs: {', '.join(mitre_list)}\n"
            f"Tactics: {', '.join(tactic_list)}\n"
            f"Tools: {', '.join(tool_list)}\n"
            f"Description: {description}\n"
            f"Adversary Commands: {adversary_commands}"
        )

        metadata = {
            "doc_id": doc_id_clean,
            "id": doc_id_clean,
            "title": str(title).strip(),
            "platform": plat_str,
            "platforms": plat_list,
            "tags": tag_list,
            "mitre_ids": mitre_list,
            "tactics": tactic_list,
            "description": str(description).strip(),
            "adversary_commands": str(adversary_commands).strip(),
            "tools": tool_list,
            "notebooks": notebook_list,
            "source_file": str(source_file).strip(),
            "content_hash": str(content_hash).strip(),
        }

        self.fallback_store.upsert(
            "knowledge_docs",
            doc_id_clean,
            document_text,
            metadata,
            defer_save=defer_save,
        )
        self._dense_dirty["knowledge_docs"] = True

        if self.backend == "chromadb" and self.docs_col is not None:
            meta_chroma = {
                "doc_id": doc_id_clean,
                "title": str(title).strip(),
                "platform": plat_str,
                "tags": json.dumps(tag_list),
                "mitre_ids": json.dumps(mitre_list),
                "tactics": json.dumps(tactic_list),
                "description": str(description).strip(),
                "source_file": str(source_file).strip(),
            }
            try:
                self.docs_col.upsert(
                    ids=[doc_id_clean],
                    documents=[document_text],
                    metadatas=[meta_chroma],
                )
            except Exception:
                pass

    @staticmethod
    def _execute_collection_query(collection: Any, query_text: str, k: int) -> List[Dict[str, Any]]:
        """Thực thi truy vấn trên ChromaDB collection và chuẩn hóa kết quả trả về."""
        results = collection.query(query_texts=[query_text], n_results=k)
        output: List[Dict[str, Any]] = []
        if results and "ids" in results and results["ids"]:
            ids = results["ids"][0]
            metas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0] if "distances" in results else []
            docs = results.get("documents", [[]])[0] if "documents" in results else []

            for i in range(len(ids)):
                meta = dict(metas[i]) if i < len(metas) else {}
                dist = distances[i] if i < len(distances) else 0.0
                meta["score"] = round(max(0.0, 1.0 - dist), 4)
                meta["document"] = docs[i] if i < len(docs) else ""
                output.append(meta)
        return output

    def query_mitre_technique(
        self,
        query_text: str,
        n_results: int = 3,
        search_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Tìm kiếm kỹ thuật MITRE ATT&CK phù hợp nhất với ngữ cảnh mô tả hoặc từ khóa."""
        return self._dispatch_collection_query(
            "mitre_attack",
            query_text,
            n_results=n_results,
            search_mode=search_mode,
        )

    def query_wazuh_rule(
        self,
        query_text: str,
        n_results: int = 3,
        search_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Tìm kiếm quy tắc Wazuh Rule và biện pháp remediation phù hợp nhất."""
        results = self._dispatch_collection_query(
            "wazuh_rules",
            query_text,
            n_results=n_results,
            search_mode=search_mode,
        )
        for meta in results:
            raw_mitre = meta.get("mitre_ids")
            if isinstance(raw_mitre, str):
                try:
                    meta["mitre_ids"] = json.loads(raw_mitre)
                except Exception:
                    meta["mitre_ids"] = [raw_mitre]
        return results

    def query_knowledge_docs(
        self,
        query_text: str,
        n_results: int = 3,
        platform: Optional[str] = None,
        search_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Tìm kiếm tài liệu tri thức OTRF Playbooks / Security Datasets trong collection `knowledge_docs`."""
        fetch_k = n_results * 3 if platform else n_results
        results = self._dispatch_collection_query(
            "knowledge_docs",
            query_text,
            n_results=max(fetch_k, 3),
            search_mode=search_mode,
        )
        if platform and str(platform).strip():
            target_plat = str(platform).strip().lower()
            filtered = [
                r for r in results
                if target_plat in str(r.get("platform", "")).lower()
                or any(target_plat == str(p).lower() for p in r.get("platforms", []))
            ]
            return filtered[:n_results]
        return results[:n_results]

    def query_collection(
        self,
        collection: str = "all",
        query_text: str = "",
        n_results: int = 3,
        search_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Điểm truy vấn hợp nhất cho SOC Copilot (`query_rag_mitre`) và các Agent (#10 Mục #6).
        Hỗ trợ `collection` thuộc: `"mitre_attack"`, `"wazuh_rules"`, `"threat_feed"`, `"knowledge_docs"`, `"all"`.
        Mỗi bản ghi trả về đều được gắn trường `"source_collection"`.
        """
        if not query_text or not str(query_text).strip():
            return []

        col_norm = str(collection or "all").strip().lower()
        alias_map = {
            "mitre": "mitre_attack",
            "mitre_attack": "mitre_attack",
            "wazuh": "wazuh_rules",
            "wazuh_rules": "wazuh_rules",
            "rules": "wazuh_rules",
            "threat": "threat_feed",
            "threat_feed": "threat_feed",
            "ioc": "threat_feed",
            "docs": "knowledge_docs",
            "knowledge_docs": "knowledge_docs",
            "otrf": "knowledge_docs",
        }

        if col_norm in alias_map:
            target_col = alias_map[col_norm]
            items = self._dispatch_collection_query(
                target_col,
                query_text,
                n_results=n_results,
                search_mode=search_mode,
            )
            output: List[Dict[str, Any]] = []
            for item in items:
                rec = dict(item)
                rec["source_collection"] = target_col
                output.append(rec)
            return output

        # Truy vấn hợp nhất trên toàn bộ 4 collections ("all")
        combined: List[Dict[str, Any]] = []
        for target_col in ALL_COLLECTION_NAMES:
            if self.fallback_store.count(target_col) == 0:
                continue
            sub_items = self._dispatch_collection_query(
                target_col,
                query_text,
                n_results=n_results,
                search_mode=search_mode,
            )
            for item in sub_items:
                rec = dict(item)
                rec["source_collection"] = target_col
                combined.append(rec)

        combined.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
        return combined[:n_results]

    def get_mitre_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Lấy chi tiết một kỹ thuật MITRE theo ID (không phân biệt hoa/thường: `t1059.001` -> `T1059.001`)."""
        if not technique_id:
            return None
        return self.fallback_store.get("mitre_attack", str(technique_id).strip().upper())

    def get_wazuh_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Lấy chi tiết một quy tắc Wazuh theo ID chính xác."""
        if not rule_id:
            return None
        return self.fallback_store.get("wazuh_rules", str(rule_id).strip())

    def get_knowledge_doc(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Lấy chi tiết một tài liệu OTRF Knowledge Doc theo ID."""
        if not doc_id:
            return None
        return self.fallback_store.get("knowledge_docs", str(doc_id).strip())

    def count_mitre_techniques(self) -> int:
        """Đếm số lượng kỹ thuật MITRE ATT&CK đã lưu."""
        return self.fallback_store.count("mitre_attack")

    def count_wazuh_rules(self) -> int:
        """Đếm số lượng quy tắc Wazuh đã lưu."""
        return self.fallback_store.count("wazuh_rules")

    def count_knowledge_docs(self) -> int:
        """Đếm số lượng tài liệu tri thức OTRF trong collection `knowledge_docs`."""
        return self.fallback_store.count("knowledge_docs")

    def add_threat_feed_item(
        self,
        doc_id: str,
        ioc_type: str,
        value: str,
        description: str,
        severity: str = "HIGH",
        is_malicious: bool = True,
        reputation_score: int = 90,
        mitre_ids: Optional[Union[List[str], str]] = None,
        source: str = "DynamicThreatFeed",
        extra_metadata: Optional[Dict[str, Any]] = None,
        defer_save: bool = False,
    ):
        """Nạp hoặc cập nhật một chỉ báo đe dọa (IoC) vào collection `threat_feed`."""
        doc_id_clean = str(doc_id).strip()
        ioc_type_clean = str(ioc_type).strip().upper()
        value_clean = str(value).strip()

        if isinstance(mitre_ids, list):
            mitre_list = [str(m).strip().upper() for m in mitre_ids if str(m).strip()]
        elif isinstance(mitre_ids, str):
            mitre_list = [m.strip().upper() for m in mitre_ids.split(",") if m.strip()]
        else:
            mitre_list = []

        document_text = (
            f"Indicator ID: {doc_id_clean}\n"
            f"Type: {ioc_type_clean}\n"
            f"Value: {value_clean}\n"
            f"Description: {description}\n"
            f"Severity: {severity}\n"
            f"Source: {source}\n"
            f"MITRE IDs: {', '.join(mitre_list)}"
        )

        metadata_for_fallback = {
            "doc_id": doc_id_clean,
            "ioc_type": ioc_type_clean,
            "value": value_clean,
            "description": description,
            "severity": severity,
            "is_malicious": is_malicious,
            "reputation_score": int(reputation_score),
            "mitre_ids": mitre_list,
            "source": source,
        }
        if extra_metadata and isinstance(extra_metadata, dict):
            metadata_for_fallback.update(extra_metadata)

        self.fallback_store.upsert(
            "threat_feed",
            doc_id_clean,
            document_text,
            metadata_for_fallback,
            defer_save=defer_save,
        )
        self._dense_dirty["threat_feed"] = True

        if self.backend == "chromadb" and self.threat_col is not None:
            metadata_for_chroma = dict(metadata_for_fallback)
            metadata_for_chroma["mitre_ids"] = json.dumps(mitre_list)
            try:
                self.threat_col.upsert(
                    ids=[doc_id_clean],
                    documents=[document_text],
                    metadatas=[metadata_for_chroma],
                )
            except Exception:
                pass

    def update_dynamic_threat_feed(self, feed_items: List[Dict[str, Any]]) -> int:
        """
        Nạp động các IoC mới (IP độc hại, URL mã độc, mã băm malware, kỹ thuật MITRE mới, quy tắc mới)
        vào vector store trong runtime với cơ chế batch save.
        """
        if not feed_items or not isinstance(feed_items, list):
            return 0

        success_count = 0

        for item in feed_items:
            if not isinstance(item, dict):
                continue

            try:
                if "technique_id" in item:
                    self.add_mitre_technique(
                        technique_id=item["technique_id"],
                        name=item.get("name", item["technique_id"]),
                        tactic=item.get("tactic", "Unknown Tactic"),
                        description=item.get("description", ""),
                        mitigations=item.get("mitigations", "N/A"),
                        detection=item.get("detection", "N/A"),
                        defer_save=True,
                    )
                    success_count += 1
                    continue

                if "rule_id" in item:
                    self.add_wazuh_rule(
                        rule_id=str(item["rule_id"]),
                        level=int(item.get("level", 5)),
                        description=item.get("description", ""),
                        mitre_ids=item.get("mitre_ids", []),
                        remediation=item.get("remediation", "N/A"),
                        defer_save=True,
                    )
                    success_count += 1
                    continue

                ioc_type = item.get("ioc_type") or item.get("type", "IOC")
                val = item.get("value") or item.get("indicator") or item.get("ip") or item.get("url") or item.get("hash")
                if not val:
                    continue

                val_str = str(val).strip()
                type_str = str(ioc_type).strip().upper()
                doc_id = str(item.get("id") or f"{type_str}_{val_str}").strip()
                desc = item.get("description") or f"Dynamic threat intelligence for {type_str}: {val_str}"
                severity = item.get("severity", "HIGH")
                is_malicious = bool(item.get("is_malicious", True))
                rep_score = int(item.get("reputation_score", 90))
                mitre_ids = item.get("mitre_ids", [])
                source = item.get("source", "DynamicThreatFeed")

                self.add_threat_feed_item(
                    doc_id=doc_id,
                    ioc_type=type_str,
                    value=val_str,
                    description=desc,
                    severity=severity,
                    is_malicious=is_malicious,
                    reputation_score=rep_score,
                    mitre_ids=mitre_ids,
                    source=source,
                    extra_metadata=item.get("extra_metadata"),
                    defer_save=True,
                )

                try:
                    from src.tools.threat_intel import ThreatIntelTools
                    if type_str in {"IP", "IPV4", "IPV6"} and is_malicious:
                        ThreatIntelTools.KNOWN_MALICIOUS_IPS[val_str] = {
                            "reputation_score": rep_score,
                            "threat_actor": desc,
                            "country": item.get("country", "XX"),
                            "isp": item.get("isp", "Dynamic Feed Provider"),
                            "categories": item.get("categories", ["ThreatFeed", "Malicious"]),
                        }
                    elif type_str == "DOMAIN" and is_malicious:
                        ThreatIntelTools.KNOWN_MALICIOUS_DOMAINS[val_str] = {
                            "reputation_score": rep_score,
                            "threat_actor": desc,
                            "registrar": item.get("registrar", "Unknown Registrar"),
                            "categories": item.get("categories", ["ThreatFeed", "Malicious"]),
                        }
                except Exception:
                    pass

                success_count += 1
            except Exception:
                pass

        if success_count > 0:
            self.fallback_store.flush()
        return success_count

    def query_threat_feed(
        self,
        query_text: str,
        n_results: int = 3,
        search_mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Tìm kiếm chỉ báo IoC / Threat Feed phù hợp nhất với từ khóa truy vấn."""
        results = self._dispatch_collection_query(
            "threat_feed",
            query_text,
            n_results=n_results,
            search_mode=search_mode,
        )
        for meta in results:
            raw_mitre = meta.get("mitre_ids")
            if isinstance(raw_mitre, str):
                try:
                    meta["mitre_ids"] = json.loads(raw_mitre)
                except Exception:
                    meta["mitre_ids"] = [raw_mitre]
        return results

    def count_threat_feed(self) -> int:
        """Đếm số lượng chỉ báo IoC trong threat feed."""
        return self.fallback_store.count("threat_feed")

    def get_threat_feed_item(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Lấy chi tiết một chỉ báo threat feed theo ID."""
        return self.fallback_store.get("threat_feed", doc_id)

    def sync_knowledge_docs(
        self,
        docs_dir: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, int]:
        """
        Đồng bộ toàn bộ 20 tài liệu OTRF Security Datasets (data/knowledge_docs/*.yaml)
        vào collection `knowledge_docs` VÀ bổ sung các kỹ thuật MITRE mới (ngoài `CORE_PROTECTED_MITRE_IDS`)
        vào collection `mitre_attack`.
        Sử dụng `defer_save=True` + `flush()` để chỉ ghi đĩa 1 lần duy nhất.
        """
        target_dir = docs_dir or os.path.join(self.root_dir, "data", "knowledge_docs")
        if not os.path.isdir(target_dir):
            return {
                "docs_synced": 0,
                "mitre_added": 0,
                "total_knowledge_docs": self.count_knowledge_docs(),
                "total_mitre_techniques": self.count_mitre_techniques(),
            }

        valid_exts = (".yaml", ".yml", ".json", ".md")
        doc_files = sorted(f for f in os.listdir(target_dir) if f.lower().endswith(valid_exts))

        docs_synced = 0
        mitre_added = 0

        for fname in doc_files:
            fpath = os.path.join(target_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if not content.strip():
                    continue

                content_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
                parsed_doc = parse_otrf_knowledge_doc(content, fname)
                doc_id = parsed_doc["id"]

                existing_doc = self.get_knowledge_doc(doc_id)
                if force or existing_doc is None or existing_doc.get("content_hash") != content_hash:
                    self.add_knowledge_doc(
                        doc_id=doc_id,
                        title=parsed_doc["title"],
                        platform=parsed_doc["platforms"],
                        tags=parsed_doc["tags"],
                        mitre_ids=parsed_doc["mitre_techniques"],
                        tactics=parsed_doc["tactics"],
                        description=parsed_doc["description"],
                        adversary_commands=parsed_doc["adversary_commands"],
                        tools=parsed_doc["tools"],
                        notebooks=parsed_doc["notebooks"],
                        source_file=fname,
                        content_hash=content_hash,
                        defer_save=True,
                    )
                    docs_synced += 1

                tactic_str = ", ".join(parsed_doc["tactics"]) if parsed_doc["tactics"] else "Execution"
                tools_str = ", ".join(parsed_doc["tools"]) if parsed_doc["tools"] else "N/A"
                for tech_id in parsed_doc["mitre_techniques"]:
                    tid_clean = str(tech_id).strip().upper()
                    if not tid_clean or tid_clean in CORE_PROTECTED_MITRE_IDS:
                        continue
                    if self.get_mitre_technique(tid_clean) is None:
                        detection_text = (
                            f"Monitor OTRF Security Dataset indicators ({doc_id}, Platform: {parsed_doc['platform']}, "
                            f"Tools: {tools_str}) and SIEM telemetry for {parsed_doc['title']}."
                        )
                        if parsed_doc["adversary_commands"]:
                            detection_text += f" Sample adversary commands: {parsed_doc['adversary_commands'][:260]}"
                        self.add_mitre_technique(
                            technique_id=tid_clean,
                            name=f"{parsed_doc['title']} ({doc_id})",
                            tactic=tactic_str,
                            description=parsed_doc["description"],
                            mitigations=(
                                f"Apply least-privilege access controls, audit security telemetry "
                                f"and enforce endpoint/cloud hardening for {tid_clean} ({parsed_doc['title']})."
                            ),
                            detection=detection_text,
                            defer_save=True,
                            protect_core=True,
                        )
                        mitre_added += 1
            except Exception as exc:
                logger.debug("Bỏ qua file knowledge doc lỗi %s: %s", fname, exc)
                continue

        self.fallback_store.flush()
        return {
            "docs_synced": docs_synced,
            "mitre_added": mitre_added,
            "total_knowledge_docs": self.count_knowledge_docs(),
            "total_mitre_techniques": self.count_mitre_techniques(),
        }

    def _ensure_expanded_seed(self):
        """Tự động nạp bộ tri thức mở rộng và 20 tài liệu OTRF YAML nếu chưa đủ."""
        if self.count_mitre_techniques() < 18 or self.count_wazuh_rules() < 15:
            self.seed_expanded_knowledge()
        else:
            # Bảo vệ bất biến cho Rule 92211 (SQL Injection) nếu từng bị ghi đè ngoài ý muốn
            r92211 = self.get_wazuh_rule("92211")
            if r92211 is None or "SQL Injection" not in str(r92211.get("description", "")):
                self.seed_expanded_knowledge()

        if self.auto_sync_docs and self.count_knowledge_docs() < 20:
            default_docs_dir = os.path.join(self.root_dir, "data", "knowledge_docs")
            if os.path.isdir(default_docs_dir):
                self.sync_knowledge_docs(default_docs_dir)

    def seed_expanded_knowledge(self):
        """
        Nạp đầy đủ các kỹ thuật MITRE ATT&CK (bao gồm tập cơ sở và 9 kỹ thuật mở rộng)
        cùng bộ quy tắc Wazuh / Suricata / Linux Rules với cơ chế batch flush (1 lần ghi đĩa).
        """
        baseline_and_expanded_mitre = [
            {
                "technique_id": "T1059.001",
                "name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "description": (
                    "Adversaries may abuse PowerShell commands and scripts for executing malicious code, "
                    "downloading payloads from remote command and control servers, and automating discovery "
                    "or lateral movement. PowerShell is widely used for administrative tasks, making malicious "
                    "usage easy to blend with benign activity. (Kẻ tấn công lạm dụng PowerShell để thực thi "
                    "lệnh độc hại, tải script từ xa qua mạng, thực thi fileless và làm bàn đạp mở rộng tấn công)."
                ),
                "detection": (
                    "Monitor process creation events for powershell.exe with flags like -enc, -EncodedCommand, "
                    "-ExecutionPolicy Bypass, -NoProfile, -WindowStyle Hidden. Monitor Script Block Logging "
                    "(Windows Event ID 4104) for suspicious cmdlets like IEX, DownloadString, Invoke-WebRequest, "
                    "and Start-Process. Enable Antimalware Scan Interface (AMSI)."
                ),
                "mitigations": (
                    "Enforce PowerShell Constrained Language Mode via AppLocker or Windows Defender Application "
                    "Control (WDAC). Restrict PowerShell execution policies across group policies (GPO). Disable "
                    "or uninstall PowerShell version 2.0 to prevent downgrade attacks."
                ),
            },
            {
                "technique_id": "T1078.002",
                "name": "Valid Accounts: Domain Accounts",
                "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
                "description": (
                    "Adversaries may obtain and abuse credentials of existing domain accounts to gain access, "
                    "maintain persistence, elevate privileges, and evade defense mechanisms. Compromised domain "
                    "credentials allow attackers to mimic legitimate domain users and administrators. (Kẻ tấn công "
                    "lừa đảo đánh cắp thông tin tài khoản miền domain, chiếm đoạt mật khẩu quản trị viên để đăng nhập "
                    "và kiểm soát toàn bộ hệ thống)."
                ),
                "detection": (
                    "Audit Windows Security Event ID 4624 (Successful logon) for unusual logon types (Type 3 "
                    "network logon or Type 10 RemoteInteractive), anomalous logon hours, logins from unauthorized "
                    "IP addresses, and sudden access spikes to sensitive servers. Monitor Kerberos Ticket-Granting "
                    "Service requests (Event ID 4769) for abnormal Kerberoasting activity."
                ),
                "mitigations": (
                    "Enforce Multi-Factor Authentication (MFA) for all domain logons and VPN access. Deploy "
                    "Privileged Access Workstations (PAW) and tier-based administration. Enforce strong password "
                    "complexity, implement LAPS (Local Administrator Password Solution), and rotate domain admin "
                    "credentials regularly."
                ),
            },
            {
                "technique_id": "T1046",
                "name": "Network Service Discovery",
                "tactic": "Discovery",
                "description": (
                    "Adversaries may attempt to get a listing of services and open ports running on remote hosts "
                    "through port scanning and service probing. This allows attackers to identify vulnerable "
                    "listening services, management ports like RDP/SSH/SMB, and network topology. (Hành vi quét "
                    "cổng mạng, dò quét cổng dịch vụ mở SYN scan, xác định các cổng dịch vụ khả dụng trên hệ thống "
                    "mạng nội bộ)."
                ),
                "detection": (
                    "Detect rapid connection attempts from a single internal or external host across multiple "
                    "destination IP addresses and ports within a short time window. Analyze Zeek conn.log, "
                    "Suricata/Snort alerts, and firewall connection drops for SYN scan patterns."
                ),
                "mitigations": (
                    "Segment internal network into discrete VLANs with micro-segmentation. Configure host-based "
                    "firewalls to deny inbound traffic by default. Close all unnecessary listening ports and "
                    "disable unneeded services."
                ),
            },
            {
                "technique_id": "T1027",
                "name": "Obfuscated/Encoded Files or Information",
                "tactic": "Defense Evasion",
                "description": (
                    "Adversaries may attempt to make an executable or script difficult to discover or analyze by "
                    "encrypting, encoding, compressing, or otherwise obfuscating its content and command-line "
                    "arguments. Common methods include Base64 encoding, XOR obfuscation, string reversal, and "
                    "variable substitution. (Mã hóa, làm rối chuỗi lệnh và che giấu file thực thi nhằm vượt qua "
                    "phần mềm diệt virus và giải pháp EDR)."
                ),
                "detection": (
                    "Audit process creation command lines for high-entropy strings, Base64 patterns, complex "
                    "concatenation operators, and packed executables. Inspect script executions de-obfuscated "
                    "dynamically by AMSI (Antimalware Scan Interface)."
                ),
                "mitigations": (
                    "Deploy endpoint detection tools supporting behavioral analysis and runtime in-memory "
                    "inspection. Restrict execution of unsigned scripts and binaries using WDAC or AppLocker."
                ),
            },
            {
                "technique_id": "T1053.005",
                "name": "Scheduled Task/Job: Scheduled Task",
                "tactic": "Execution, Persistence, Privilege Escalation",
                "description": (
                    "Adversaries may abuse the Windows Task Scheduler to register scheduled tasks that execute "
                    "malicious binaries, scripts, or payloads at system startup or recurring intervals. (Tạo tác vụ "
                    "lên lịch định kỳ bằng schtasks để duy trì quyền truy cập lâu dài trên hệ thống)."
                ),
                "detection": (
                    "Monitor Windows Security Event ID 4698 (A scheduled task was created), Event ID 4702 "
                    "(Scheduled task updated), and Sysmon Event ID 1 for executions of schtasks.exe with "
                    "parameters /create, /change, or /run."
                ),
                "mitigations": (
                    "Restrict permissions to create and modify scheduled tasks to local and domain administrators "
                    "only. Regularly audit scheduled task entries in C:\\Windows\\System32\\Tasks and registry "
                    "keys under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache."
                ),
            },
            {
                "technique_id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "description": (
                    "Adversaries may communicate using application layer web protocols (HTTP, HTTPS) to disguise "
                    "command and control (C2) traffic, exfiltrate data, and blend in with regular enterprise web "
                    "browsing traffic. (Kênh điều khiển C2 qua giao thức web HTTP/HTTPS)."
                ),
                "detection": (
                    "Analyze web proxy and firewall logs for periodic beaconing intervals, anomalous User-Agent "
                    "strings, long URI queries, and direct connections to newly registered domains (NRDs) or "
                    "dynamic DNS services. Inspect encrypted traffic via SSL/TLS decryption."
                ),
                "mitigations": (
                    "Route all outbound HTTP/HTTPS traffic through an enterprise proxy with SSL inspection. Block "
                    "uncategorized or malicious domains using DNS sinkholing and Threat Intelligence feeds."
                ),
            },
            {
                "technique_id": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "tactic": "Initial Access",
                "description": (
                    "Adversaries may send spearphishing emails containing malicious hyperlinks to lure targeted "
                    "individuals into visiting credential harvesting login pages or downloading weaponized payloads. "
                    "(Hình thức lừa đảo qua email chứa liên kết độc hại, dụ nạn nhân đăng nhập vào trang web giả mạo "
                    "để lấy cắp mật khẩu tài khoản hoặc cài cắm mã độc)."
                ),
                "detection": (
                    "Inspect inbound emails with secure email gateways (SEG) for domain spoofing, URL redirection, "
                    "and brand impersonation. Monitor web browser process invocations initiated from mail client "
                    "processes such as outlook.exe."
                ),
                "mitigations": (
                    "Implement email authentication mechanisms including SPF, DKIM, and DMARC. Deploy web proxy "
                    "URL sandboxing, mandate Multi-Factor Authentication (MFA), and conduct continuous anti-phishing "
                    "user training."
                ),
            },
            {
                "technique_id": "T1021.002",
                "name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "description": (
                    "Adversaries may leverage SMB file sharing and administrative network shares (C$, ADMIN$, IPC$) "
                    "to transfer malicious files, execute commands remotely, and propagate laterally across domain "
                    "workstations. (Lợi dụng chia sẻ tệp tin SMB và admin share để di chuyển ngang trong mạng nội bộ)."
                ),
                "detection": (
                    "Monitor Windows Security Event ID 5140 (A network share object was accessed), Event ID 5145 "
                    "(Detailed network share access), and Sysmon Event ID 3 for outbound TCP port 445 connections "
                    "to internal hosts."
                ),
                "mitigations": (
                    "Disable SMBv1 entirely. Block inbound TCP port 445 between internal workstation subnets using "
                    "host firewalls. Use LAPS to prevent local administrator credential reuse across endpoints."
                ),
            },
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": (
                    "Adversaries may use brute force attacks (including password spraying, credential stuffing, and "
                    "dictionary guessing) to guess passwords and systematically compromise user accounts. (Tấn công "
                    "vét cạn mật khẩu dò tìm thông tin đăng nhập tự động qua SSH, RDP, Web)."
                ),
                "detection": (
                    "Detect a surge of failed authentication attempts in a short timeframe (Windows Event ID 4625, "
                    "Linux sshd authentication failures, Wazuh rule 5710/5712). Monitor Event ID 4740 for multiple "
                    "account lockout occurrences."
                ),
                "mitigations": (
                    "Enforce strict account lockout thresholds after consecutive failed attempts. Mandate complex "
                    "passwords, deploy rate limiting on login interfaces, and enforce Multi-Factor Authentication (MFA)."
                ),
            },
            {
                "technique_id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "description": (
                    "Adversaries may encrypt critical data and documents on local drives and shared network storage, "
                    "interrupting operational workflows and demanding financial ransom for the decryption keys. "
                    "(Mã độc tống tiền ransomware mã hóa tệp tin hàng loạt gây gián đoạn hệ thống)."
                ),
                "detection": (
                    "Detect abnormal high-frequency file modifications and renames with new unknown file extensions. "
                    "Monitor for process executions attempting to delete Volume Shadow Copies (e.g., vssadmin delete "
                    "shadows, wbadmin). Check Sysmon Event 11 for rapid file creation of ransom notes."
                ),
                "mitigations": (
                    "Maintain offline, immutable, and air-gapped backups. Implement EDR anti-ransomware behavioral "
                    "monitoring to automatically terminate rogue encryption processes. Restrict write permissions "
                    "on shared network drives."
                ),
            },
            {
                "technique_id": "T1056.002",
                "name": "Input Capture: GUI Input Capture",
                "tactic": "Credential Access, Collection",
                "description": (
                    "Adversaries may mimic a legitimate dialog box, prompt, or capture graphical user interface "
                    "inputs to obtain credentials from users. This includes prompting fake Windows logon dialogs, "
                    "harvesting credentials via fake Office 365 or portal prompts. (Kẻ tấn công lừa đảo hiển thị "
                    "cửa sổ nhập mật khẩu giả mạo GUI hoặc thu thập thông tin đăng nhập trực tiếp từ giao diện "
                    "người dùng)."
                ),
                "detection": (
                    "Detect unusual processes spawning credential prompt dialogs (e.g., PowerShell invoking Windows "
                    "Forms or WPF credential prompts). Monitor for Credential UI APIs like "
                    "CredUIPromptForWindowsCredentials. Inspect event logs for abnormal user authentication events "
                    "occurring immediately after an untrusted process creation."
                ),
                "mitigations": (
                    "Mandate Multi-Factor Authentication (MFA) with FIDO2/WebAuthn keys. Train users to recognize "
                    "suspicious dialog boxes and never enter domain credentials into unexpected pop-ups. Enforce "
                    "Credential Guard on Windows 10/11 enterprise systems."
                ),
            },
            {
                "technique_id": "T1018",
                "name": "Remote System Discovery",
                "tactic": "Discovery",
                "description": (
                    "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other "
                    "logical identifiers on a network through ICMP ping sweeps, ARP broadcasts, or Active Directory "
                    "computer queries. This reconnaissance enables adversaries to plan lateral movement paths. "
                    "(Kỹ thuật dò quét và lập danh sách các máy chủ hoạt động trong mạng nội bộ thông qua ping sweep "
                    "ICMP hoặc truy vấn Active Directory)."
                ),
                "detection": (
                    "Monitor network traffic and firewall drop/pass logs for sudden high volumes of ICMP Echo "
                    "Requests sent across subnets from a single source host within a brief timeframe. Audit "
                    "command-line executions of net view, ping, arp -a, and Test-Connection in Sysmon Event ID 1."
                ),
                "mitigations": (
                    "Configure internal network firewalls to block unnecessary ICMP sweeps between workstation "
                    "subnets. Implement network segmentation and micro-segmentation to limit visibility across subnets."
                ),
            },
            {
                "technique_id": "T1087",
                "name": "Account Discovery",
                "tactic": "Discovery",
                "description": (
                    "Adversaries may attempt to get a listing of local or domain accounts to determine which "
                    "accounts exist on the system and which have elevated administrative privileges. This includes "
                    "enumerating Active Directory users, domain administrators, and service accounts. (Dò quét và "
                    "thu thập danh sách tài khoản người dùng, tài khoản quản trị miền Domain Admins nhằm phục vụ "
                    "bước leo thang đặc quyền)."
                ),
                "detection": (
                    "Monitor process command lines for tools like net user, net group, dsquery, Get-ADUser, and "
                    "PowerView cmdlets. Monitor Windows Security Event ID 4661 (Handle to an object was requested) "
                    "and Event 4798/4799 for abnormal domain group enumeration."
                ),
                "mitigations": (
                    "Restrict permissions for standard domain users to query sensitive Active Directory objects "
                    "and groups. Enable Active Directory auditing and deploy Honey Accounts (Decoy accounts) to "
                    "detect unauthorized reconnaissance."
                ),
            },
            {
                "technique_id": "T1087.002",
                "name": "Account Discovery: Domain Account",
                "tactic": "Discovery",
                "description": (
                    "Adversaries may attempt to get a listing of domain accounts to identify targeted individuals, "
                    "privileged administrators, and service accounts in the Active Directory environment. (Thu thập "
                    "thông tin tài khoản miền Active Directory để chọn mục tiêu tấn công và leo quyền)."
                ),
                "detection": (
                    "Audit Windows Security Event ID 4672 (Special privileges assigned) and Event ID 4624 for "
                    "unusual administrative logon sessions. Monitor network traffic to Domain Controllers on "
                    "LDAP/LDAPS (ports 389/636) and RPC (port 135/445)."
                ),
                "mitigations": (
                    "Implement Least Privilege Access. Restrict RPC and LDAP queries from non-administrative "
                    "endpoints. Monitor Active Directory replication traffic."
                ),
            },
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": (
                    "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially "
                    "access a network. Weakness in the system can be a software bug, a temporary glitch, or a "
                    "misconfiguration in web applications, databases, or APIs. (Tấn công khai thác lỗ hổng ứng dụng "
                    "web công khai như SQL Injection, RCE, Command Injection, Path Traversal)."
                ),
                "detection": (
                    "Monitor web server access and error logs (Apache, Nginx, IIS) and WAF/Suricata alerts for "
                    "SQL injection payloads (UNION SELECT, OR 1=1), directory traversal sequences (../), and "
                    "anomalous child processes spawned by web server daemons (w3wp.exe, www-data, httpd)."
                ),
                "mitigations": (
                    "Deploy a Web Application Firewall (WAF) in front of public-facing services. Apply regular "
                    "security patches, enforce input validation and parameterized queries, and isolate web tier "
                    "hosts in a strictly segmented DMZ."
                ),
            },
            {
                "technique_id": "T1505.003",
                "name": "Server Software Component: Web Shell",
                "tactic": "Persistence",
                "description": (
                    "Adversaries may backdoor web servers with web shells to establish persistent access to systems. "
                    "A web shell is a malicious file uploaded to a web server directory that enables remote command "
                    "execution over HTTP/HTTPS requests. (Cài cắm mã độc Web Shell PHP, ASPX, JSP lên máy chủ web "
                    "để duy trì quyền điều khiển từ xa)."
                ),
                "detection": (
                    "Monitor File Integrity Monitoring (FIM / Wazuh syscheck) for new or modified files in web "
                    "root directories (/var/www/html, inetpub/wwwroot). Detect web server processes (www-data, "
                    "nginx, apache2, w3wp.exe) spawning OS shells or system utilities (whoami, id, uname, cat)."
                ),
                "mitigations": (
                    "Disable execution permissions on file upload directories. Enforce strict File Integrity "
                    "Monitoring (FIM) and run web server services under minimal non-privileged service accounts."
                ),
            },
            {
                "technique_id": "T1059.004",
                "name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution",
                "description": (
                    "Adversaries may abuse Unix shell commands and bash/sh interpreters to execute arbitrary "
                    "commands, launch reverse shells, or automate post-exploitation tasks on Linux and macOS hosts. "
                    "(Thực thi tập lệnh bash/sh độc hại trên máy chủ Linux)."
                ),
                "detection": (
                    "Monitor auditd (EXECVE, SYSCALL), syslog, and Wazuh agent logs for suspicious /bin/bash or "
                    "/bin/sh invocations, reverse shell one-liners (/dev/tcp, nc -e, bash -i), and cron/daemon "
                    "child processes."
                ),
                "mitigations": (
                    "Restrict shell access for service accounts (/usr/sbin/nologin). Implement SELinux or AppArmor "
                    "mandatory access controls and audit command executions with Linux auditd."
                ),
            },
            {
                "technique_id": "T1548.003",
                "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                "tactic": "Privilege Escalation",
                "description": (
                    "Adversaries may perform sudo caching and/or misconfigured sudoers policies to elevate "
                    "privileges to root on Linux systems without re-authenticating or by exploiting GTFOBins "
                    "binaries allowed via NOPASSWD. (Leo thang đặc quyền trái phép qua lỗ hổng cấu hình sudo "
                    "trên Linux)."
                ),
                "detection": (
                    "Monitor /var/log/auth.log and /var/log/secure (Wazuh rule 5402) for sudo invocations, "
                    "unexpected user-to-root transitions, sudoers file modifications, and failed sudo attempts."
                ),
                "mitigations": (
                    "Audit /etc/sudoers regularly to remove NOPASSWD entries and wildcard command allowances. "
                    "Set timestamp_timeout=0 in sudo configuration and restrict sudo access to authorized admins."
                ),
            },
            {
                "technique_id": "T1003.001",
                "name": "OS Credential Dumping: LSASS Memory",
                "tactic": "Credential Access",
                "description": (
                    "Adversaries may attempt to access credential material stored in the process memory of the "
                    "Local Security Authority Subsystem Service (LSASS) to harvest NTLM hashes and Kerberos tickets. "
                    "(Trích xuất bộ nhớ tiến trình LSASS qua Sysmon Event 10, Mimikatz, ProcDump, comsvcs.dll để "
                    "thu thập thông tin xác thực NTLM/Kerberos)."
                ),
                "detection": (
                    "Monitor Sysmon Event ID 10 (ProcessAccess) targeting lsass.exe with suspicious GrantedAccess "
                    "masks (0x1010, 0x1410, 0x1438, 0x1fffff). Detect executions of procdump.exe, rundll32.exe "
                    "comsvcs.dll MiniDump, and sekurlsa::logonpasswords."
                ),
                "mitigations": (
                    "Enable Windows Defender Credential Guard and LSA Protection (RunAsPPL). Restrict SeDebugPrivilege "
                    "via Group Policy and block untrusted processes from opening handles to lsass.exe."
                ),
            },
            {
                "technique_id": "T1105",
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": (
                    "Adversaries may transfer tools or binary files from an external command and control system "
                    "into a compromised environment to stage secondary utilities and malware binaries. (Tải công cụ "
                    "tấn công, mã độc từ máy chủ C2 bên ngoài vào hệ thống nội bộ bằng certutil, curl, wget, "
                    "bitsadmin)."
                ),
                "detection": (
                    "Monitor process creation and network connection logs for living-off-the-land binaries "
                    "(certutil.exe -urlcache -split -f, bitsadmin /transfer, curl, wget) making outbound HTTP/HTTPS "
                    "requests and writing executable files to temp or public directories."
                ),
                "mitigations": (
                    "Enforce application allowlisting (WDAC/AppLocker) to block unauthorized binaries downloaded "
                    "to user-writable folders. Filter outbound connections at the proxy and firewall layers."
                ),
            },
            {
                "technique_id": "T1490",
                "name": "Inhibit System Recovery",
                "tactic": "Impact",
                "description": (
                    "Adversaries may delete or remove built-in operating system data and turn off recovery features "
                    "to prevent system restoration after a ransomware or destructive attack. (Xóa bản sao lưu hệ "
                    "thống Volume Shadow Copies bằng vssadmin delete shadows, wbadmin, bcdedit để ngăn chặn khôi "
                    "phục dữ liệu sau khi mã hóa Ransomware)."
                ),
                "detection": (
                    "Monitor Sysmon Event ID 1 and Windows Security Event ID 4688 for command lines containing "
                    "vssadmin.exe delete shadows /all /quiet, wmic shadowcopy delete, wbadmin delete catalog, or "
                    "bcdedit /set recoveryenabled no."
                ),
                "mitigations": (
                    "Maintain immutable offline backups isolated from domain credentials. Use EDR behavioral "
                    "prevention rules to block unauthorized invocations of vssadmin.exe, wbadmin.exe, and bcdedit.exe."
                ),
            },
            {
                "technique_id": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": (
                    "Adversaries may steal data by exfiltrating it over an existing command and control channel "
                    "rather than a separate channel. Stolen data is encoded and transmitted within normal C2 "
                    "communications. (Rò rỉ và đánh cắp dữ liệu nhạy cảm ra ngoài qua kênh truyền điều khiển C2)."
                ),
                "detection": (
                    "Analyze network flow telemetry (Zeek conn.log, Suricata eve.json, firewall logs) for large "
                    "outbound byte transfers, persistent long-lived sessions, and high upload-to-download ratios "
                    "to external C2 IP addresses."
                ),
                "mitigations": (
                    "Deploy Data Loss Prevention (DLP) and egress network traffic inspection. Enforce strict "
                    "egress firewall rules and terminate unauthorized outbound sessions."
                ),
            },
            {
                "technique_id": "T1070.001",
                "name": "Indicator Removal: Clear Windows Event Logs",
                "tactic": "Defense Evasion",
                "description": (
                    "Adversaries may clear Windows Event Logs to hide the activity of an intrusion and impede "
                    "forensic investigation. (Xóa nhật ký sự kiện Windows Security/System bằng wevtutil cl, "
                    "Clear-EventLog, phát sinh Event ID 1102 và Event ID 104 nhằm xóa dấu vết điều tra)."
                ),
                "detection": (
                    "Monitor Windows Security Event ID 1102 (The audit log was cleared) and System Event ID 104 "
                    "(The Log file was cleared). Detect command-line executions of wevtutil.exe cl Security, "
                    "wevtutil cl System, or Clear-EventLog."
                ),
                "mitigations": (
                    "Forward all endpoint event logs in real time to a centralized, append-only SIEM (Wazuh/Splunk) "
                    "so local log deletion cannot erase historical forensic telemetry."
                ),
            },
        ]

        for tech in baseline_and_expanded_mitre:
            tid = tech["technique_id"]
            if tid in CORE_PROTECTED_MITRE_IDS or self.get_mitre_technique(tid) is None:
                self.add_mitre_technique(
                    technique_id=tid,
                    name=tech["name"],
                    tactic=tech["tactic"],
                    description=tech["description"],
                    mitigations=tech["mitigations"],
                    detection=tech["detection"],
                    defer_save=True,
                )

        baseline_and_expanded_rules = [
            {
                "rule_id": "60106",
                "level": 8,
                "description": "Windows Event - PowerShell execution with encoded/suspicious command (Phát hiện PowerShell thực thi lệnh mã hóa Base64 hoặc tải script từ xa)",
                "mitre_ids": ["T1059.001", "T1027"],
                "remediation": "Immediately isolate the infected host from the network. Kill the running powershell.exe process and extract full command-line arguments. Review PowerShell Script Block logs (Event ID 4104) to analyze decoded script contents. Scan system memory for injected payloads.",
            },
            {
                "rule_id": "92211",
                "level": 10,
                "description": "Web attack - SQL Injection attempt detected via HTTP query or POST body (Tấn công SQL Injection vào ứng dụng web thông qua tham số HTTP)",
                "mitre_ids": ["T1190"],
                "remediation": "Add attacker IP address to perimeter firewall or WAF ban list immediately. Sanitize and parameterize all SQL queries within the vulnerable web application codebase. Inspect database query logs to verify if data exfiltration or table modification occurred.",
            },
            {
                "rule_id": "5710",
                "level": 5,
                "description": "SSH insecure connection attempt - Unauthorized host or failed login attempt (Đăng nhập SSH thất bại từ địa chỉ không xác thực)",
                "mitre_ids": ["T1110"],
                "remediation": "Check source IP reputation against threat intelligence feeds. Verify whether the attempt was an authorized user typo. If repetitive, trigger Wazuh Active Response to ban source IP for 1 hour.",
            },
            {
                "rule_id": "5715",
                "level": 3,
                "description": "SSH authentication succeeded (Đăng nhập SSH thành công vào hệ thống Linux)",
                "mitre_ids": ["T1078.002", "T1078"],
                "remediation": "Validate source IP and username against approved administrative maintenance rosters. Enforce SSH key-based authentication and disable root password logins over SSH.",
            },
            {
                "rule_id": "60115",
                "level": 10,
                "description": "Windows Event - A scheduled task was created via schtasks or API (Tạo scheduled task mới trên hệ điều hành Windows)",
                "mitre_ids": ["T1053.005"],
                "remediation": "Inspect Windows Security Event 4698 to identify Task Name, Action executable path, and user creator account. If unauthorized, delete the scheduled task immediately using schtasks /delete /tn <TaskName> /f and inspect binary payload.",
            },
            {
                "rule_id": "92215",
                "level": 8,
                "description": "Web attack - Cross-Site Scripting (XSS) attempt detected (Tấn công XSS vào máy chủ web)",
                "mitre_ids": ["T1059.007", "T1190"],
                "remediation": "Sanitize user inputs and enforce context-aware HTML entity encoding. Implement Content Security Policy (CSP) headers on the web server to restrict script execution contexts.",
            },
            {
                "rule_id": "100002",
                "level": 12,
                "description": "Custom Sysmon - Cobalt Strike Beacon / Suspicious process spawned from MS Word (Tiến trình lạ powershell/cmd sinh ra từ Microsoft Word nghi vấn macro độc hại)",
                "mitre_ids": ["T1566.002", "T1059.001"],
                "remediation": "Trigger emergency host network isolation. Dump memory of spawned child process for reverse engineering. Block associated C2 IP and domain on edge firewalls. Invalidate compromised user session tokens and reset Active Directory password.",
            },
            {
                "rule_id": "5501",
                "level": 3,
                "description": "PAM: Login session opened (Phiên đăng nhập người dùng mở trên hệ điều hành)",
                "mitre_ids": ["T1078"],
                "remediation": "Correlate with VPN connection logs and physical badge access records. Monitor user activity for suspicious privilege escalation commands (sudo su, chmod +s).",
            },
            {
                "rule_id": "5502",
                "level": 3,
                "description": "PAM: Login session closed (Phiên đăng nhập người dùng kết thúc)",
                "mitre_ids": ["T1078"],
                "remediation": "Record session duration and calculate baseline behavioral profile for user activity auditing.",
            },
            {
                "rule_id": "5712",
                "level": 10,
                "description": "SSH brute force attempt - Multiple failed logins from same source (Tấn công brute force SSH hàng loạt từ một địa chỉ IP)",
                "mitre_ids": ["T1110"],
                "remediation": "Execute Wazuh Active Response firewall-drop script to block the offending IP address for 24 hours. Enforce fail2ban and mandate MFA for SSH remote access.",
            },
            {
                "rule_id": "60105",
                "level": 5,
                "description": "Windows logon failure - Multiple failed logins for domain account (Đăng nhập thất bại liên tiếp nghi vấn password spraying)",
                "mitre_ids": ["T1110.003"],
                "remediation": "Audit authentication logs for source IP address. If rate exceeds policy threshold, trigger temporary account lockout or block source IP at perimeter firewall.",
            },
            {
                "rule_id": "92213",
                "level": 10,
                "description": "Sysmon - Event 3: Suspicious network connection initiated by PowerShell to external C2 (PowerShell kết nối mạng ra IP máy chủ điều khiển C2 bên ngoài)",
                "mitre_ids": ["T1071.001"],
                "remediation": "Immediately isolate endpoint from network. Terminate the offending PowerShell process. Block external destination IP and port on perimeter firewall and inspect DNS queries.",
            },
            {
                "rule_id": "92218",
                "level": 8,
                "description": "Sysmon - Event 1: Persistence established via schtasks.exe registration (Duy trì quyền truy cập qua Scheduled Task schtasks)",
                "mitre_ids": ["T1053.005"],
                "remediation": "Inspect task action path in Task Scheduler. Delete rogue scheduled task and remove binary payload from disk. Audit registry run keys.",
            },
            {
                "rule_id": "60100",
                "level": 3,
                "description": "Windows logon success - routine user interactive session during business hours (Đăng nhập hợp lệ giờ hành chính - Benign Baseline)",
                "mitre_ids": ["T1078"],
                "remediation": "Routine benign user activity. No remediation action needed.",
            },
            {
                "rule_id": "31103",
                "level": 10,
                "description": "Web Server SQL Injection / URI Attack detected in HTTP request (Phát hiện tấn công SQL Injection hoặc khai thác URI trên máy chủ Web)",
                "mitre_ids": ["T1190"],
                "remediation": "Block offending source IP on WAF and perimeter firewall via Wazuh Active Response. Inspect web server access logs and database queries for unauthorized data extraction. Patch vulnerable web endpoints and enforce parameterized SQL statements.",
            },
            {
                "rule_id": "31168",
                "level": 12,
                "description": "Web Shell execution / Suspicious file upload detected on web server (Phát hiện tải lên và thực thi mã độc Web Shell trên máy chủ Web)",
                "mitre_ids": ["T1505.003", "T1059.004"],
                "remediation": "Quarantine the web server host immediately. Delete the uploaded web shell file and terminate any child bash/sh processes spawned by www-data/nginx/apache. Audit file upload handlers and revoke compromised service credentials.",
            },
            {
                "rule_id": "5402",
                "level": 9,
                "description": "Linux Sudo privilege escalation to root (Người dùng Linux thực thi lệnh sudo leo thang đặc quyền lên root)",
                "mitre_ids": ["T1548.003"],
                "remediation": "Verify if the sudo command execution was authorized. If unauthorized, terminate the user session, revoke sudo privileges in /etc/sudoers, lock the compromised Linux account, and audit root command history.",
            },
            {
                "rule_id": "100501",
                "level": 14,
                "description": "Ransomware Shadow Copy Deletion via vssadmin / wbadmin (Phát hiện hành vi xóa Volume Shadow Copies chuẩn bị mã hóa Ransomware)",
                "mitre_ids": ["T1490", "T1486"],
                "remediation": "Execute immediate emergency host isolation from the network. Kill the vssadmin.exe/wbadmin.exe and parent ransomware processes. Preserve memory dump for forensics and restore affected volumes from offline immutable backups.",
            },
            {
                "rule_id": "201001",
                "level": 11,
                "description": "Suricata NIDS ET EXPLOIT / C2 Traffic Detected (Cảnh báo Suricata phát hiện lưu lượng khai thác lỗ hổng hoặc kết nối máy chủ điều khiển C2)",
                "mitre_ids": ["T1071.001", "T1190"],
                "remediation": "Block external C2 / attacker IP address at perimeter firewall and IPS. Isolate internal source host, capture PCAP network traffic for deep packet inspection, and terminate suspicious outbound processes.",
            },
        ]

        for rule in baseline_and_expanded_rules:
            rid = rule["rule_id"]
            if rid in CORE_PROTECTED_WAZUH_RULE_IDS or self.get_wazuh_rule(rid) is None:
                self.add_wazuh_rule(
                    rule_id=rid,
                    level=rule["level"],
                    description=rule["description"],
                    mitre_ids=rule["mitre_ids"],
                    remediation=rule["remediation"],
                    defer_save=True,
                )

        self.fallback_store.flush()

    def retrieve_incident_knowledge(
        self,
        query_text: str = "",
        mitre_ids: Optional[List[str]] = None,
        rule_ids: Optional[List[str]] = None,
        n_results: int = 3,
        include_knowledge_docs: bool = True,
    ) -> Dict[str, Any]:
        """
        Kết hợp tìm kiếm ngữ nghĩa Hybrid RRF (query_mitre_technique, query_wazuh_rule, query_knowledge_docs)
        VÀ tra cứu chính xác theo mitre_ids / rule_ids.
        Bảo toàn 4 khóa chuẩn (`matched_techniques`, `matched_rules`, `nist_mitigations`, `nist_remediations`)
        và bổ sung khóa thứ 5 `matched_knowledge_docs`.
        """
        matched_techniques: List[Dict[str, Any]] = []
        seen_tech_ids = set()

        matched_rules: List[Dict[str, Any]] = []
        seen_rule_ids = set()

        matched_knowledge_docs: List[Dict[str, Any]] = []
        seen_doc_ids = set()

        # 1. Tra cứu chính xác theo mitre_ids
        if mitre_ids:
            if isinstance(mitre_ids, str):
                mitre_ids = [m.strip() for m in mitre_ids.split(",") if m.strip()]
            for tid in mitre_ids:
                tid_str = str(tid).strip().upper()
                if not tid_str or tid_str in seen_tech_ids:
                    continue
                exact_tech = self.get_mitre_technique(tid_str)
                if exact_tech:
                    record = dict(exact_tech)
                    record.setdefault("score", 1.0)
                    matched_techniques.append(record)
                    seen_tech_ids.add(tid_str)

        # 2. Tra cứu chính xác theo rule_ids
        if rule_ids:
            if isinstance(rule_ids, str):
                rule_ids = [r.strip() for r in rule_ids.split(",") if r.strip()]
            for rid in rule_ids:
                rid_str = str(rid).strip()
                if not rid_str or rid_str in seen_rule_ids:
                    continue
                exact_rule = self.get_wazuh_rule(rid_str)
                if exact_rule:
                    record = dict(exact_rule)
                    record.setdefault("score", 1.0)
                    matched_rules.append(record)
                    seen_rule_ids.add(rid_str)
                    for linked_tid in record.get("mitre_ids", []):
                        linked_tid_str = str(linked_tid).strip().upper()
                        if linked_tid_str and linked_tid_str not in seen_tech_ids:
                            linked_tech = self.get_mitre_technique(linked_tid_str)
                            if linked_tech:
                                tech_rec = dict(linked_tech)
                                tech_rec.setdefault("score", 0.95)
                                matched_techniques.append(tech_rec)
                                seen_tech_ids.add(linked_tid_str)

        # 3. Tìm kiếm ngữ nghĩa theo query_text
        if query_text and str(query_text).strip():
            sem_techs = self.query_mitre_technique(query_text, n_results=n_results)
            for tech in sem_techs:
                tid_str = str(tech.get("technique_id", "")).strip().upper()
                if tid_str and tid_str not in seen_tech_ids:
                    matched_techniques.append(tech)
                    seen_tech_ids.add(tid_str)

            sem_rules = self.query_wazuh_rule(query_text, n_results=n_results)
            for rule in sem_rules:
                rid_str = str(rule.get("rule_id", "")).strip()
                if rid_str and rid_str not in seen_rule_ids:
                    matched_rules.append(rule)
                    seen_rule_ids.add(rid_str)

            if include_knowledge_docs:
                sem_docs = self.query_knowledge_docs(query_text, n_results=n_results)
                for doc in sem_docs:
                    did_str = str(doc.get("doc_id") or doc.get("id") or "").strip()
                    if did_str and did_str not in seen_doc_ids:
                        matched_knowledge_docs.append(doc)
                        seen_doc_ids.add(did_str)

        # Nếu chỉ truyền mitre_ids mà chưa có query_text, vẫn lấy thêm OTRF knowledge_docs khớp mitre_ids
        if include_knowledge_docs and not matched_knowledge_docs and seen_tech_ids:
            doc_query = " ".join(sorted(seen_tech_ids))
            for doc in self.query_knowledge_docs(doc_query, n_results=n_results):
                did_str = str(doc.get("doc_id") or doc.get("id") or "").strip()
                if did_str and did_str not in seen_doc_ids:
                    matched_knowledge_docs.append(doc)
                    seen_doc_ids.add(did_str)

        # 4. Tổng hợp hướng dẫn NIST Mitigations & Remediations (không trùng lặp)
        nist_mitigations: List[str] = []
        for tech in matched_techniques:
            mit = str(tech.get("mitigations", "")).strip()
            if mit and mit not in nist_mitigations:
                nist_mitigations.append(mit)

        nist_remediations: List[str] = []
        for rule in matched_rules:
            rem = str(rule.get("remediation", "")).strip()
            if rem and rem not in nist_remediations:
                nist_remediations.append(rem)

        return {
            "matched_techniques": matched_techniques,
            "matched_rules": matched_rules,
            "nist_mitigations": nist_mitigations,
            "nist_remediations": nist_remediations,
            "matched_knowledge_docs": matched_knowledge_docs,
        }


def _run_cli() -> int:
    parser = argparse.ArgumentParser(
        description="CLI quản trị và kiểm định RAG Knowledge Base (Multi-Backend + Hybrid RRF)."
    )
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Đồng bộ toàn bộ MITRE, Wazuh Rules, 20 OTRF YAML và tái tạo chỉ mục dense .npz.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Chạy kiểm định số lượng bản ghi và chất lượng truy vấn ngữ nghĩa Hybrid RRF.",
    )
    parser.add_argument(
        "--backend",
        type=str,
        default="auto",
        help="Chọn backend vector store (auto|numpy_dense|qdrant|chromadb|fallback).",
    )
    args = parser.parse_args()

    kb = RAGKnowledgeBaseTool(backend=args.backend)

    if args.rebuild_index:
        kb.seed_expanded_knowledge()
        kb.sync_knowledge_docs(force=True)
        kb.rebuild_all_dense_indices()

    info = kb.get_backend_info()
    verification_passed = True
    checks: Dict[str, Any] = {}

    if args.verify:
        counts = info["counts"]
        checks["mitre_count_ok"] = counts["mitre_attack"] >= 40
        checks["wazuh_count_ok"] = counts["wazuh_rules"] >= 19
        checks["knowledge_docs_count_ok"] = counts["knowledge_docs"] >= 20

        q_ps = kb.query_mitre_technique("truy vấn liên quan đến powershell tải script", n_results=3)
        checks["query_powershell_top1"] = q_ps[0]["technique_id"] if q_ps else None
        checks["query_powershell_ok"] = checks["query_powershell_top1"] == "T1059.001"

        q_phish = kb.query_mitre_technique("truy vấn liên quan đến lừa đảo lấy mật khẩu", n_results=3)
        checks["query_phishing_top1"] = q_phish[0]["technique_id"] if q_phish else None
        checks["query_phishing_ok"] = checks["query_phishing_top1"] in ("T1566.002", "T1078.002")

        q_scan = kb.query_mitre_technique("truy vấn quét cổng mạng", n_results=3)
        checks["query_port_scan_top1"] = q_scan[0]["technique_id"] if q_scan else None
        checks["query_port_scan_ok"] = checks["query_port_scan_top1"] == "T1046"

        q_rule = kb.query_wazuh_rule("Wazuh Rule 92211", n_results=3)
        checks["rule_92211_ok"] = bool(
            q_rule
            and q_rule[0]["rule_id"] == "92211"
            and "SQL Injection" in q_rule[0].get("description", "")
        )

        q_docs = kb.query_knowledge_docs("Add-DomainObjectAcl DCSync Active Directory", n_results=3)
        checks["query_otrf_docs_ok"] = bool(q_docs and any("SDWIN-190301125905" in d.get("doc_id", "") for d in q_docs))

        verification_passed = all(
            bool(checks[k])
            for k in (
                "mitre_count_ok",
                "wazuh_count_ok",
                "knowledge_docs_count_ok",
                "query_powershell_ok",
                "query_phishing_ok",
                "query_port_scan_ok",
                "rule_92211_ok",
                "query_otrf_docs_ok",
            )
        )

    output = {
        "backend_info": info,
        "rebuilt": bool(args.rebuild_index),
        "verified": bool(args.verify),
        "verification_passed": verification_passed,
        "checks": checks,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if verification_passed else 1


if __name__ == "__main__":
    sys.exit(_run_cli())
