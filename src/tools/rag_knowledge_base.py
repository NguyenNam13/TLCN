# -*- coding: utf-8 -*-
"""
src/tools/rag_knowledge_base.py
Cơ sở tri thức RAG (Retrieval-Augmented Generation) & Vector Store phục vụ điều tra an ninh mạng.
Quản lý 2 collections chính:
  1. mitre_attack: Kỹ thuật, chiến thuật, cách phát hiện và biện pháp giảm thiểu ATT&CK.
  2. wazuh_rules: Bộ quy tắc Wazuh Detection Ruleset và hướng dẫn khắc phục (Remediation).

Thiết kế linh hoạt:
- Tự động dùng Persistent ChromaDB client nếu thư viện chromadb có sẵn.
- Tự động chuyển sang Fallback Vector Store chuẩn (TF-IDF & Cosine Similarity)
  viết hoàn toàn bằng thư viện chuẩn Python (math, re, collections, json)
  nếu chromadb chưa được cài đặt, đảm bảo không bao giờ lỗi ModuleNotFoundError.
"""

import os
import re
import math
import json
from collections import Counter
from typing import Dict, Any, List, Optional, Union

# Kiểm tra sự sẵn sàng của thư viện chromadb
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except (ImportError, Exception):
    CHROMADB_AVAILABLE = False


class FallbackVectorStore:
    """
    Vector Store thuần Python sử dụng thuật toán TF-IDF và Cosine Similarity.
    Lưu trữ bền vững (Persistent) vào tệp JSON trong thư mục data/chromadb.
    """

    def __init__(self, storage_file: str):
        self.storage_file = storage_file
        self.collections: Dict[str, Dict[str, Dict[str, Any]]] = {
            "mitre_attack": {},
            "wazuh_rules": {}
        }
        self._load()

    def _load(self):
        """Nạp dữ liệu từ file nếu tồn tại."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for col in ("mitre_attack", "wazuh_rules"):
                            if col in data and isinstance(data[col], dict):
                                self.collections[col] = data[col]
            except Exception as e:
                # Nếu file lỗi, khởi tạo rỗng
                pass

    def _save(self):
        """Lưu trữ dữ liệu bền vững ra file JSON."""
        dir_path = os.path.dirname(self.storage_file)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        temp_file = f"{self.storage_file}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(self.collections, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, self.storage_file)

    @staticmethod
    def tokenize(text: str) -> List[str]:
        """Tách từ hỗ trợ tiếng Việt có dấu và các ký tự định danh kỹ thuật (T1059.001, powershell.exe...)."""
        if not text:
            return []
        return re.findall(r'[\w\.\-]+', text.lower(), re.UNICODE)

    def upsert(self, collection_name: str, doc_id: str, document: str, metadata: Dict[str, Any]):
        """Thêm hoặc cập nhật bản ghi trong collection."""
        if collection_name not in self.collections:
            self.collections[collection_name] = {}
        self.collections[collection_name][doc_id] = {
            "id": doc_id,
            "document": document,
            "metadata": metadata
        }
        self._save()

    def get(self, collection_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
        """Lấy bản ghi theo ID."""
        col = self.collections.get(collection_name, {})
        entry = col.get(doc_id)
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
        else:
            self.collections = {"mitre_attack": {}, "wazuh_rules": {}}
        self._save()

    def query(self, collection_name: str, query_text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Truy vấn tìm kiếm ngữ nghĩa theo TF-IDF và Cosine Similarity.
        Kết hợp tính năng trọng số ưu tiên khi khớp ID kỹ thuật hoặc Rule ID.
        """
        col = self.collections.get(collection_name, {})
        if not col:
            return []

        q_tokens = self.tokenize(query_text)
        if not q_tokens:
            return []

        doc_items = list(col.values())
        N = len(doc_items)

        # 1. Thu thập token cho từng document
        doc_token_map: Dict[str, List[str]] = {}
        dfs: Counter = Counter()

        for item in doc_items:
            doc_id = item["id"]
            # Kết hợp document text và metadata để vector hóa phong phú
            meta = item.get("metadata", {})
            meta_str = " ".join(str(v) for v in meta.values())
            full_text = f"{item.get('document', '')} {meta_str}"
            tokens = self.tokenize(full_text)
            doc_token_map[doc_id] = tokens
            dfs.update(set(tokens))

        # 2. Tính IDF (smoothed IDF)
        idfs: Dict[str, float] = {
            t: math.log((1.0 + N) / (1.0 + df)) + 1.0 for t, df in dfs.items()
        }

        # 3. Tính Vector TF-IDF cho Query
        q_tf = Counter(q_tokens)
        q_vec = {t: count * idfs.get(t, 1.0) for t, count in q_tf.items()}
        q_norm = math.sqrt(sum(w ** 2 for w in q_vec.values()))

        if q_norm == 0.0:
            return []

        # 4. Tính Cosine Similarity với từng Document
        scored_results = []
        q_text_lower = query_text.lower()

        for item in doc_items:
            doc_id = item["id"]
            tokens = doc_token_map[doc_id]
            d_tf = Counter(tokens)
            d_vec = {t: count * idfs.get(t, 1.0) for t, count in d_tf.items()}
            d_norm = math.sqrt(sum(w ** 2 for w in d_vec.values()))

            if d_norm == 0.0:
                sim = 0.0
            else:
                dot = sum(q_vec[t] * d_vec.get(t, 0.0) for t in q_vec if t in d_vec)
                sim = dot / (q_norm * d_norm)

            # Boost điểm số nếu có khớp chính xác ID kỹ thuật (ví dụ T1059.001) hoặc Rule ID (ví dụ 92211, 60106)
            doc_id_lower = doc_id.lower()
            if doc_id_lower in q_text_lower or doc_id_lower in q_tokens:
                sim += 1.5

            # Boost điểm nếu query nhắc đến tên hoặc tactic nằm trong metadata
            meta = item.get("metadata", {})
            name_val = str(meta.get("name", "")).lower()
            if name_val and name_val in q_text_lower:
                sim += 0.5

            if sim > 0.0:
                record = dict(meta)
                record["score"] = round(float(sim), 4)
                record["document"] = item.get("document", "")
                scored_results.append((sim, record))

        # 5. Sắp xếp điểm số giảm dần
        scored_results.sort(key=lambda x: x[0], reverse=True)
        top_k = [item[1] for item in scored_results[:n_results]]
        return top_k


class RAGKnowledgeBaseTool:
    """
    Lớp điều khiển Cơ sở tri thức RAG cho Multi-Agent.
    Hỗ trợ Persistent ChromaDB khi có sẵn và Fallback Vector Store chuẩn khi offline.
    """

    def __init__(self, persist_directory: Optional[str] = None, force_fallback: bool = False):
        if persist_directory is None:
            # Mặc định lưu tại TLCN/data/chromadb
            src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            root_dir = os.path.dirname(src_dir)
            self.persist_directory = os.path.join(root_dir, "data", "chromadb")
        else:
            self.persist_directory = persist_directory

        os.makedirs(self.persist_directory, exist_ok=True)
        self.force_fallback = force_fallback

        self.backend = "fallback"
        self.chroma_client = None
        self.mitre_col = None
        self.wazuh_col = None

        # Luôn khởi tạo Fallback store để đồng bộ dữ liệu hoặc làm cứu cánh
        fallback_file = os.path.join(self.persist_directory, "fallback_rag_db.json")
        self.fallback_store = FallbackVectorStore(fallback_file)

        if CHROMADB_AVAILABLE and not self.force_fallback:
            try:
                self.chroma_client = chromadb.PersistentClient(path=self.persist_directory)
                self.mitre_col = self.chroma_client.get_or_create_collection(
                    name="mitre_attack",
                    metadata={"hnsw:space": "cosine"}
                )
                self.wazuh_col = self.chroma_client.get_or_create_collection(
                    name="wazuh_rules",
                    metadata={"hnsw:space": "cosine"}
                )
                self.backend = "chromadb"
            except Exception as e:
                # Nếu ChromaDB gặp trục trặc, tự động fallback
                self.backend = "fallback"

    def add_mitre_technique(
        self,
        technique_id: str,
        name: str,
        tactic: str,
        description: str,
        mitigations: str,
        detection: str
    ):
        """
        Nạp hoặc cập nhật một kỹ thuật MITRE ATT&CK vào collection mitre_attack.
        """
        technique_id = str(technique_id).strip()
        document_text = (
            f"Technique ID: {technique_id}\n"
            f"Name: {name}\n"
            f"Tactic: {tactic}\n"
            f"Description: {description}\n"
            f"Detection: {detection}\n"
            f"Mitigations: {mitigations}"
        )
        metadata = {
            "technique_id": technique_id,
            "name": name,
            "tactic": tactic,
            "description": description,
            "mitigations": mitigations,
            "detection": detection
        }

        # Lưu vào fallback store
        self.fallback_store.upsert("mitre_attack", technique_id, document_text, metadata)

        # Nếu ChromaDB đang kích hoạt, lưu vào collection ChromaDB
        if self.backend == "chromadb" and self.mitre_col is not None:
            try:
                self.mitre_col.upsert(
                    ids=[technique_id],
                    documents=[document_text],
                    metadatas=[metadata]
                )
            except Exception:
                pass

    def add_wazuh_rule(
        self,
        rule_id: str,
        level: int,
        description: str,
        mitre_ids: Union[List[str], str],
        remediation: str
    ):
        """
        Nạp hoặc cập nhật một quy tắc Wazuh vào collection wazuh_rules.
        """
        rule_id = str(rule_id).strip()

        # Chuẩn hóa danh sách mitre_ids
        if isinstance(mitre_ids, list):
            mitre_list = [str(m).strip() for m in mitre_ids if str(m).strip()]
        elif isinstance(mitre_ids, str):
            mitre_list = [m.strip() for m in mitre_ids.split(",") if m.strip()]
        else:
            mitre_list = [str(mitre_ids)]

        mitre_str = ", ".join(mitre_list)
        document_text = (
            f"Wazuh Rule ID: {rule_id}\n"
            f"Severity Level: {level}\n"
            f"Description: {description}\n"
            f"MITRE ATT&CK IDs: {mitre_str}\n"
            f"Remediation: {remediation}"
        )

        metadata_for_fallback = {
            "rule_id": rule_id,
            "level": int(level),
            "description": description,
            "mitre_ids": mitre_list,
            "remediation": remediation
        }

        # Lưu vào fallback store
        self.fallback_store.upsert("wazuh_rules", rule_id, document_text, metadata_for_fallback)

        # ChromaDB metadata không hỗ trợ list trực tiếp nên serialize thành chuỗi JSON
        if self.backend == "chromadb" and self.wazuh_col is not None:
            metadata_for_chroma = {
                "rule_id": rule_id,
                "level": int(level),
                "description": description,
                "mitre_ids": json.dumps(mitre_list),
                "remediation": remediation
            }
            try:
                self.wazuh_col.upsert(
                    ids=[rule_id],
                    documents=[document_text],
                    metadatas=[metadata_for_chroma]
                )
            except Exception:
                pass

    def query_mitre_technique(self, query_text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Tìm kiếm kỹ thuật MITRE ATT&CK phù hợp nhất với ngữ cảnh mô tả hoặc từ khóa.
        """
        if self.backend == "chromadb" and self.mitre_col is not None:
            try:
                count = self.mitre_col.count()
                if count > 0:
                    k = min(n_results, count)
                    results = self.mitre_col.query(query_texts=[query_text], n_results=k)
                    output = []
                    if results and "ids" in results and results["ids"]:
                        ids = results["ids"][0]
                        metas = results.get("metadatas", [[]])[0]
                        distances = results.get("distances", [[]])[0] if "distances" in results else []
                        docs = results.get("documents", [[]])[0] if "documents" in results else []

                        for i, doc_id in enumerate(ids):
                            meta = dict(metas[i]) if i < len(metas) else {}
                            dist = distances[i] if i < len(distances) else 0.0
                            # cosine distance to similarity score
                            score = round(max(0.0, 1.0 - dist), 4)
                            meta["score"] = score
                            meta["document"] = docs[i] if i < len(docs) else ""
                            output.append(meta)
                    if output:
                        return output
            except Exception:
                pass

        # Fallback Vector Store
        return self.fallback_store.query("mitre_attack", query_text, n_results=n_results)

    def query_wazuh_rule(self, query_text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Tìm kiếm quy tắc Wazuh Rule và biện pháp remediation phù hợp nhất.
        """
        if self.backend == "chromadb" and self.wazuh_col is not None:
            try:
                count = self.wazuh_col.count()
                if count > 0:
                    k = min(n_results, count)
                    results = self.wazuh_col.query(query_texts=[query_text], n_results=k)
                    output = []
                    if results and "ids" in results and results["ids"]:
                        ids = results["ids"][0]
                        metas = results.get("metadatas", [[]])[0]
                        distances = results.get("distances", [[]])[0] if "distances" in results else []
                        docs = results.get("documents", [[]])[0] if "documents" in results else []

                        for i, doc_id in enumerate(ids):
                            meta = dict(metas[i]) if i < len(metas) else {}
                            dist = distances[i] if i < len(distances) else 0.0
                            score = round(max(0.0, 1.0 - dist), 4)
                            meta["score"] = score
                            meta["document"] = docs[i] if i < len(docs) else ""
                            # deserialize mitre_ids nếu đang là chuỗi JSON
                            raw_mitre = meta.get("mitre_ids")
                            if isinstance(raw_mitre, str):
                                try:
                                    meta["mitre_ids"] = json.loads(raw_mitre)
                                except Exception:
                                    meta["mitre_ids"] = [raw_mitre]
                            output.append(meta)
                    if output:
                        return output
            except Exception:
                pass

        # Fallback Vector Store
        return self.fallback_store.query("wazuh_rules", query_text, n_results=n_results)

    def get_mitre_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Lấy chi tiết một kỹ thuật MITRE theo ID chính xác."""
        return self.fallback_store.get("mitre_attack", technique_id)

    def get_wazuh_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Lấy chi tiết một quy tắc Wazuh theo ID chính xác."""
        return self.fallback_store.get("wazuh_rules", rule_id)

    def count_mitre_techniques(self) -> int:
        """Đếm số lượng kỹ thuật MITRE ATT&CK đã lưu."""
        return self.fallback_store.count("mitre_attack")

    def count_wazuh_rules(self) -> int:
        """Đếm số lượng quy tắc Wazuh đã lưu."""
        return self.fallback_store.count("wazuh_rules")
