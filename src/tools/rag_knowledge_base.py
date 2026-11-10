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
            "wazuh_rules": {},
            "threat_feed": {}
        }
        self._load()

    def _load(self):
        """Nạp dữ liệu từ file nếu tồn tại."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for col, items in data.items():
                            if isinstance(items, dict):
                                self.collections[col] = items
            except Exception:
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
            self.collections = {"mitre_attack": {}, "wazuh_rules": {}, "threat_feed": {}}
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
        self.threat_col = None

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
                self.threat_col = self.chroma_client.get_or_create_collection(
                    name="threat_feed",
                    metadata={"hnsw:space": "cosine"}
                )
                self.backend = "chromadb"
            except Exception:
                # Nếu ChromaDB gặp trục trặc, tự động fallback
                self.backend = "fallback"

        self._ensure_expanded_seed()

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
                # cosine distance to similarity score
                meta["score"] = round(max(0.0, 1.0 - dist), 4)
                meta["document"] = docs[i] if i < len(docs) else ""
                output.append(meta)
        return output

    def query_mitre_technique(self, query_text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Tìm kiếm kỹ thuật MITRE ATT&CK phù hợp nhất với ngữ cảnh mô tả hoặc từ khóa.
        """
        if self.backend == "chromadb" and self.mitre_col is not None:
            try:
                count = self.mitre_col.count()
                if count > 0:
                    output = self._execute_collection_query(self.mitre_col, query_text, min(n_results, count))
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
                    output = self._execute_collection_query(self.wazuh_col, query_text, min(n_results, count))
                    for meta in output:
                        raw_mitre = meta.get("mitre_ids")
                        if isinstance(raw_mitre, str):
                            try:
                                meta["mitre_ids"] = json.loads(raw_mitre)
                            except Exception:
                                meta["mitre_ids"] = [raw_mitre]
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
        extra_metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Nạp hoặc cập nhật một chỉ báo đe dọa (IoC) vào collection threat_feed.
        """
        doc_id = str(doc_id).strip()
        ioc_type = str(ioc_type).strip().upper()
        value = str(value).strip()

        if isinstance(mitre_ids, list):
            mitre_list = [str(m).strip() for m in mitre_ids if str(m).strip()]
        elif isinstance(mitre_ids, str):
            mitre_list = [m.strip() for m in mitre_ids.split(",") if m.strip()]
        else:
            mitre_list = []

        document_text = (
            f"Indicator ID: {doc_id}\n"
            f"Type: {ioc_type}\n"
            f"Value: {value}\n"
            f"Description: {description}\n"
            f"Severity: {severity}\n"
            f"Source: {source}\n"
            f"MITRE IDs: {', '.join(mitre_list)}"
        )

        metadata_for_fallback = {
            "doc_id": doc_id,
            "ioc_type": ioc_type,
            "value": value,
            "description": description,
            "severity": severity,
            "is_malicious": is_malicious,
            "reputation_score": int(reputation_score),
            "mitre_ids": mitre_list,
            "source": source
        }
        if extra_metadata and isinstance(extra_metadata, dict):
            metadata_for_fallback.update(extra_metadata)

        # Lưu vào fallback store
        self.fallback_store.upsert("threat_feed", doc_id, document_text, metadata_for_fallback)

        # Lưu vào ChromaDB nếu có
        if self.backend == "chromadb" and self.threat_col is not None:
            metadata_for_chroma = dict(metadata_for_fallback)
            metadata_for_chroma["mitre_ids"] = json.dumps(mitre_list)
            try:
                self.threat_col.upsert(
                    ids=[doc_id],
                    documents=[document_text],
                    metadatas=[metadata_for_chroma]
                )
            except Exception:
                pass

    def update_dynamic_threat_feed(self, feed_items: List[Dict[str, Any]]) -> int:
        """
        Nạp động các IoC mới (IP độc hại, URL mã độc, mã băm malware, kỹ thuật MITRE mới, quy tắc mới)
        vào vector store ChromaDB hoặc Fallback Store trong runtime.
        Khắc phục Hạn chế 4: Cập nhật RAG động (Dynamic RAG Threat Feed Update).

        :param feed_items: Danh sách dict chứa thông tin IoC hoặc kỹ thuật MITRE mới.
        :return: Số lượng bản ghi đã được nạp thành công vào cơ sở tri thức.
        """
        if not feed_items or not isinstance(feed_items, list):
            return 0

        success_count = 0

        for item in feed_items:
            if not isinstance(item, dict):
                continue

            try:
                # 1. Kỹ thuật MITRE ATT&CK mới
                if "technique_id" in item:
                    self.add_mitre_technique(
                        technique_id=item["technique_id"],
                        name=item.get("name", item["technique_id"]),
                        tactic=item.get("tactic", "Unknown Tactic"),
                        description=item.get("description", ""),
                        mitigations=item.get("mitigations", "N/A"),
                        detection=item.get("detection", "N/A"),
                    )
                    success_count += 1
                    continue

                # 2. Quy tắc Wazuh / Detection Rule mới
                if "rule_id" in item:
                    self.add_wazuh_rule(
                        rule_id=str(item["rule_id"]),
                        level=int(item.get("level", 5)),
                        description=item.get("description", ""),
                        mitre_ids=item.get("mitre_ids", []),
                        remediation=item.get("remediation", "N/A"),
                    )
                    success_count += 1
                    continue

                # 3. Chỉ báo đe dọa IoC (IP, URL, Hash, Domain...)
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
                    extra_metadata=item.get("extra_metadata")
                )

                # Đồng bộ với ThreatIntelTools in-memory mock/cache nếu là IP/Domain
                try:
                    from src.tools.threat_intel import ThreatIntelTools
                    if type_str in {"IP", "IPV4", "IPV6"} and is_malicious:
                        ThreatIntelTools.KNOWN_MALICIOUS_IPS[val_str] = {
                            "reputation_score": rep_score,
                            "threat_actor": desc,
                            "country": item.get("country", "XX"),
                            "isp": item.get("isp", "Dynamic Feed Provider"),
                            "categories": item.get("categories", ["ThreatFeed", "Malicious"])
                        }
                    elif type_str == "DOMAIN" and is_malicious:
                        ThreatIntelTools.KNOWN_MALICIOUS_DOMAINS[val_str] = {
                            "reputation_score": rep_score,
                            "threat_actor": desc,
                            "registrar": item.get("registrar", "Unknown Registrar"),
                            "categories": item.get("categories", ["ThreatFeed", "Malicious"])
                        }
                except Exception:
                    pass

                success_count += 1
            except Exception:
                pass

        return success_count

    def query_threat_feed(self, query_text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Tìm kiếm chỉ báo IoC / Threat Feed phù hợp nhất với từ khóa truy vấn.
        """
        if self.backend == "chromadb" and self.threat_col is not None:
            try:
                count = self.threat_col.count()
                if count > 0:
                    output = self._execute_collection_query(self.threat_col, query_text, min(n_results, count))
                    for meta in output:
                        raw_mitre = meta.get("mitre_ids")
                        if isinstance(raw_mitre, str):
                            try:
                                meta["mitre_ids"] = json.loads(raw_mitre)
                            except Exception:
                                meta["mitre_ids"] = [raw_mitre]
                    if output:
                        return output
            except Exception:
                pass

        return self.fallback_store.query("threat_feed", query_text, n_results=n_results)

    def count_threat_feed(self) -> int:
        """Đếm số lượng chỉ báo IoC trong threat feed."""
        return self.fallback_store.count("threat_feed")

    def get_threat_feed_item(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Lấy chi tiết một chỉ báo threat feed theo ID."""
        return self.fallback_store.get("threat_feed", doc_id)

    def _ensure_expanded_seed(self):
        """Tự động nạp bộ tri thức mở rộng nếu số lượng kỹ thuật MITRE < 18."""
        if self.count_mitre_techniques() < 18:
            self.seed_expanded_knowledge()

    def seed_expanded_knowledge(self):
        """
        Nạp đầy đủ các kỹ thuật MITRE ATT&CK (bao gồm tập cơ sở và 9 kỹ thuật mở rộng)
        cùng bộ quy tắc Wazuh / Suricata / Linux Rules (nếu chưa có).
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
            # --- 9 Kỹ thuật MITRE ATT&CK mở rộng ---
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
            if self.get_mitre_technique(tech["technique_id"]) is None:
                self.add_mitre_technique(
                    technique_id=tech["technique_id"],
                    name=tech["name"],
                    tactic=tech["tactic"],
                    description=tech["description"],
                    mitigations=tech["mitigations"],
                    detection=tech["detection"],
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
            # --- 5 Quy tắc Wazuh / Suricata / Linux mở rộng ---
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
            if self.get_wazuh_rule(rule["rule_id"]) is None:
                self.add_wazuh_rule(
                    rule_id=rule["rule_id"],
                    level=rule["level"],
                    description=rule["description"],
                    mitre_ids=rule["mitre_ids"],
                    remediation=rule["remediation"],
                )

    def retrieve_incident_knowledge(
        self,
        query_text: str = "",
        mitre_ids: Optional[List[str]] = None,
        rule_ids: Optional[List[str]] = None,
        n_results: int = 3
    ) -> Dict[str, Any]:
        """
        Kết hợp tìm kiếm ngữ nghĩa (query_mitre_technique, query_wazuh_rule) VÀ
        tra cứu chính xác theo mitre_ids / rule_ids (nếu có truyền vào).
        Trả về dictionary chuẩn gồm:
          - matched_techniques: Danh sách kỹ thuật MITRE liên quan (không trùng lặp).
          - matched_rules: Danh sách quy tắc Wazuh liên quan (không trùng lặp).
          - nist_mitigations: Danh sách các hướng dẫn giảm thiểu trích xuất từ MITRE.
          - nist_remediations: Danh sách các hướng dẫn khắc phục trích xuất từ Wazuh Rules.
        """
        matched_techniques: List[Dict[str, Any]] = []
        seen_tech_ids = set()

        matched_rules: List[Dict[str, Any]] = []
        seen_rule_ids = set()

        # 1. Tra cứu chính xác theo mitre_ids
        if mitre_ids:
            if isinstance(mitre_ids, str):
                mitre_ids = [m.strip() for m in mitre_ids.split(",") if m.strip()]
            for tid in mitre_ids:
                tid_str = str(tid).strip()
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
                    # Liên kết tự động các kỹ thuật MITRE từ rule_ids
                    for linked_tid in record.get("mitre_ids", []):
                        linked_tid_str = str(linked_tid).strip()
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
                tid_str = str(tech.get("technique_id", "")).strip()
                if tid_str and tid_str not in seen_tech_ids:
                    matched_techniques.append(tech)
                    seen_tech_ids.add(tid_str)

            sem_rules = self.query_wazuh_rule(query_text, n_results=n_results)
            for rule in sem_rules:
                rid_str = str(rule.get("rule_id", "")).strip()
                if rid_str and rid_str not in seen_rule_ids:
                    matched_rules.append(rule)
                    seen_rule_ids.add(rid_str)

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
        }

