# -*- coding: utf-8 -*-
"""
src/tools/rag_embeddings.py
Module cung cấp Pluggable Embedding Providers (OpenAI-compatible, Ollama, LocalCharNgramDenseProvider)
kèm Persistent Atomic Disk Hash Cache và chuẩn hóa URL Embeddings phục vụ RAG Knowledge Base.

Tương thích hoàn toàn với Python 3.10 - 3.14, hoạt động 100% cả khi có LLM Embedding API
lẫn khi chạy hoàn toàn Offline / Air-gapped (0 external dependency ngoài numpy).
"""

import os
import re
import json
import time
import socket
import hashlib
import logging
from abc import ABC, abstractmethod
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple

import numpy as np

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)


# Danh sách API key giả định / mặc định không dùng để gọi dịch vụ trả phí thực
DUMMY_API_KEYS = {
    "",
    "none",
    "null",
    "dummy",
    "sk-dummy",
    "sk-dummy-key",
    "sk-soc-copilot-dev-dummy-key",
    "sk-xxx",
    "your_api_key",
    "your-api-key",
    "test",
    "test-key",
    "ollama",
    "local",
    "changeme",
}


# Từ điển song ngữ An ninh mạng SOC (VI <-> EN) ~50 cặp thuật ngữ ngôn ngữ tự nhiên cốt lõi
# (KHÔNG chứa mã tài liệu mục tiêu, mã quy tắc Wazuh/EventID hoặc mã kỹ thuật MITRE ATT&CK để tránh rò rỉ dữ liệu)
BILINGUAL_SOC_SYNONYMS: List[Tuple[str, str]] = [
    ("lừa đảo", "phishing spearphishing credential harvesting lure email link"),
    ("spearphishing", "lừa đảo email liên kết độc hại đánh cắp mật khẩu phishing link"),
    ("lấy mật khẩu", "credential harvesting password stealing phishing login dialog domain accounts"),
    ("đánh cắp mật khẩu", "credential dumping lsass memory mimikatz ntlm kerberos password stealing"),
    ("trích xuất bộ nhớ", "memory dump lsass process access procdump comsvcs dumpert credential dumping"),
    ("lsass", "credential dumping memory dump mimikatz procdump dumpert os credential"),
    ("hộp thoại giả mạo", "gui input capture fake dialog credential prompt promptforcredential credui"),
    ("cửa sổ nhập mật khẩu", "gui input capture promptforcredential fake logon dialog"),
    ("quét cổng", "port scan network service discovery syn scan nmap probing"),
    ("dò quét cổng", "port scan network service discovery syn scan listening ports"),
    ("port scan", "quét cổng mạng dò quét dịch vụ mở network service discovery"),
    ("dò quét máy chủ", "remote system discovery ping sweep icmp arp cache host enumeration"),
    ("ping sweep", "dò quét hệ thống từ xa icmp echo remote system discovery"),
    ("arp cache", "arp discovery remote system discovery network neighbors liệt kê bảng arp"),
    ("dò quét tài khoản", "account discovery domain account enumeration net user get-aduser sharpview"),
    ("liệt kê tài khoản", "account discovery domain admin active directory enumeration whoami"),
    ("tài khoản miền", "domain accounts valid accounts active directory logon"),
    ("thực thi powershell", "powershell execution command scripting interpreter encodedcommand iex downloadstring"),
    ("tải script", "powershell downloadstring invoke-webrequest script execution payload"),
    ("lệnh mã hóa", "encodedcommand base64 obfuscated files information powershell encoded"),
    ("làm rối", "obfuscated encoded files information base64 xor string concatenation"),
    ("tác vụ lên lịch", "scheduled task schtasks persistence task scheduler"),
    ("scheduled task", "tác vụ lên lịch định kỳ schtasks duy trì quyền truy cập persistence"),
    ("kết nối c2", "command and control web protocols http https beaconing outbound connection"),
    ("điều khiển từ xa", "command and control c2 channel remote services http listener"),
    ("di chuyển ngang", "lateral movement smb windows admin shares c$ admin$ ipc$ winrm wsman"),
    ("chia sẻ tệp", "smb windows admin shares network share lateral movement"),
    ("winrm", "windows remote management wsman lateral movement invoke-command"),
    ("tấn công vét cạn", "brute force ssh password spraying failed login authentication failure"),
    ("vét cạn mật khẩu", "brute force password guessing ssh rdp failed login authentication failure"),
    ("brute force", "tấn công vét cạn mật khẩu đăng nhập thất bại liên tiếp ssh password guessing"),
    ("mã độc tống tiền", "ransomware data encrypted for impact shadow copy deletion vssadmin wbadmin"),
    ("ransomware", "mã độc tống tiền mã hóa dữ liệu xóa bản sao lưu vssadmin wbadmin"),
    ("xóa bản sao lưu", "inhibit system recovery volume shadow copy deletion vssadmin delete shadows wbadmin bcdedit"),
    ("shadow copy", "inhibit system recovery vssadmin delete shadows ransomware backup deletion"),
    ("tiêm mã sql", "sql injection web attack exploit public-facing application union select"),
    ("sql injection", "tiêm mã sql tấn công ứng dụng web exploit public-facing application"),
    ("khai thác lỗ hổng web", "exploit public-facing application web attack sql injection rce xss"),
    ("web shell", "server software component web shell persistent backdoor php jsp aspx www-data"),
    ("cài cắm web shell", "web shell upload persistence www-data nginx apache w3wp"),
    ("leo thang đặc quyền", "privilege escalation sudo caching sudoers root service modification run keys"),
    ("quyền root", "sudo privilege escalation linux auth.log pam root transition"),
    ("tải công cụ", "ingress tool transfer certutil urlcache bitsadmin curl wget stage payload"),
    ("certutil", "ingress tool transfer download file urlcache split lolbin"),
    ("bitsadmin", "bits jobs ingress tool transfer download persistence"),
    ("rò rỉ dữ liệu", "exfiltration over c2 channel s3 bucket data theft outbound transfer"),
    ("đánh cắp dữ liệu", "exfiltration data from cloud storage s3 sync c2 channel"),
    ("xóa nhật ký", "indicator removal clear windows event logs wevtutil clear-eventlog security audit"),
    ("clear event log", "xóa nhật ký sự kiện wevtutil clear-eventlog indicator removal"),
    ("ntds.dit", "os credential dumping ntds active directory domain controller ntdsutil vssadmin"),
    ("dcsync", "active directory replication dacl modification add-domainobjectacl ds-replication-get-changes directory service replication"),
    ("registry run", "boot or logon autostart execution registry run keys currentversion\\run userinitmprlogonscript"),
    ("s3 bucket", "aws cloud storage exfiltration instance profile metadata ssrf"),
]


def expand_bilingual_query(text: str) -> str:
    """
    Mở rộng câu truy vấn với từ điển song ngữ VI <-> EN cho lĩnh vực SOC/MITRE ATT&CK.
    Giữ nguyên văn bản gốc và nối thêm các thuật ngữ tương đương nếu khớp cụm từ khóa.
    """
    if not text or not text.strip():
        return ""
    lower_text = text.lower()
    expansions: List[str] = []
    for phrase, mapped_terms in BILINGUAL_SOC_SYNONYMS:
        if phrase in lower_text:
            expansions.append(mapped_terms)
    if not expansions:
        return text
    return f"{text} {' '.join(expansions)}"


def expand_bilingual_tokens(tokens: List[str], raw_text: str = "") -> List[str]:
    """
    Mở rộng danh sách token đã tách bằng từ điển song ngữ VI <-> EN.
    """
    if not tokens and not raw_text:
        return []
    combined_lower = (raw_text if raw_text else " ".join(tokens)).lower()
    extra_tokens: List[str] = []
    for phrase, mapped_terms in BILINGUAL_SOC_SYNONYMS:
        if phrase in combined_lower:
            extra_tokens.extend(re.findall(r"[\w\.\-]+", mapped_terms.lower(), re.UNICODE))
    if not extra_tokens:
        return list(tokens)
    return list(tokens) + extra_tokens


def resolve_openai_embeddings_url(explicit_url: Optional[str] = None) -> str:
    """
    Chuẩn hóa URL endpoint cho OpenAI-compatible Embeddings API (#10 Mục #7).
    - Ưu tiên `explicit_url` hoặc biến môi trường `RAG_EMBEDDING_URL`.
    - Nếu không có, đọc `RAG_EMBEDDING_BASE_URL` / `OMNIROUTE_BASE_URL` / `OMNIROUTER_BASE_URL` / `OMNIROUTE_URL`.
    - Loại bỏ các hậu tố `/(?:chat/completions|completions|embeddings|models)/?$` bằng regex
      và nối `/embeddings`.
    Ví dụ:
      - http://localhost:20128/v1/chat/completions -> http://localhost:20128/v1/embeddings
      - https://openrouter.ai/api/v1/chat/completions -> https://openrouter.ai/api/v1/embeddings
      - http://localhost:20128/v1 -> http://localhost:20128/v1/embeddings
      - http://localhost:20128 -> http://localhost:20128/v1/embeddings
    """
    candidate = (
        explicit_url
        or os.getenv("RAG_EMBEDDING_URL")
        or os.getenv("RAG_EMBEDDING_BASE_URL")
        or os.getenv("OMNIROUTE_BASE_URL")
        or os.getenv("OMNIROUTER_BASE_URL")
        or os.getenv("OMNIROUTE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or "http://localhost:20128/v1"
    )
    cleaned = str(candidate).strip().rstrip("/")
    if not cleaned:
        cleaned = "http://localhost:20128/v1"

    # Strip trailing endpoint suffixes if present
    cleaned = re.sub(
        r"/(?:chat/completions|completions|embeddings|models)/?$",
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).rstrip("/")

    # Nếu chỉ có scheme://host[:port] mà chưa có path (ví dụ http://localhost:20128), thêm /v1
    parsed = urlparse(cleaned)
    if parsed.scheme and parsed.netloc and parsed.path in ("", "/"):
        cleaned = f"{cleaned}/v1"

    return f"{cleaned}/embeddings"


def resolve_ollama_embed_urls(ollama_url: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Chuẩn hóa bộ 3 URL cho Ollama Embeddings API (#10 Mục #7).
    Loại bỏ hậu tố `/api/(?:chat|generate|embed|embeddings|tags)/?$` từ `OLLAMA_URL`
    và trả về tuple: `("{base}/api/embed", "{base}/api/embeddings", "{base}/api/tags")`.
    Ví dụ:
      - http://localhost:11434/api/chat -> (
            "http://localhost:11434/api/embed",
            "http://localhost:11434/api/embeddings",
            "http://localhost:11434/api/tags"
        )
    """
    candidate = (
        ollama_url
        or os.getenv("RAG_OLLAMA_URL")
        or os.getenv("OLLAMA_BASE_URL")
        or os.getenv("OLLAMA_URL")
        or "http://localhost:11434"
    )
    cleaned = str(candidate).strip().rstrip("/")
    if not cleaned:
        cleaned = "http://localhost:11434"

    base = re.sub(
        r"/api/(?:chat|generate|embed|embeddings|tags)/?$",
        "",
        cleaned,
        flags=re.IGNORECASE,
    ).rstrip("/")

    if not base:
        base = "http://localhost:11434"

    return (
        f"{base}/api/embed",
        f"{base}/api/embeddings",
        f"{base}/api/tags",
    )


class PersistentEmbeddingCache:
    """
    Bộ nhớ đệm vector embedding bền vững trên đĩa với cơ chế ghi atomic (tmp -> os.replace).
    Lưu trữ dưới dạng:
      - Ma trận numpy `.npz`: `embedding_cache_<provider>_<dim>.npz`
      - Chỉ mục khóa SHA-256 `.json`: `embedding_cache_<provider>_<dim>.json`
    Khóa băm: `sha256(f"{provider_name}:{model_name}:{dim}:{text}")`.
    """

    def __init__(self, cache_dir: str, provider_name: str, model_name: str, dim: int):
        self.cache_dir = cache_dir
        self.provider_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(provider_name))
        self.model_name = str(model_name)
        self.dim = int(dim)
        os.makedirs(self.cache_dir, exist_ok=True)

        base_name = f"embedding_cache_{self.provider_name}_{self.dim}"
        self.npz_path = os.path.join(self.cache_dir, f"{base_name}.npz")
        self.index_path = os.path.join(self.cache_dir, f"{base_name}.json")

        self._vectors: Dict[str, np.ndarray] = {}
        self.hits: int = 0
        self.misses: int = 0
        self._dirty: bool = False
        self._load()

    def make_key(self, text: str) -> str:
        raw = f"{self.provider_name}:{self.model_name}:{self.dim}:{text}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

    def _load(self):
        if not os.path.exists(self.npz_path) or not os.path.exists(self.index_path):
            return
        try:
            with open(self.index_path, "r", encoding="utf-8") as f:
                index_data = json.load(f)
            keys = index_data.get("keys", []) if isinstance(index_data, dict) else []
            if not keys:
                return
            with np.load(self.npz_path, allow_pickle=False) as data:
                if "vectors" not in data:
                    return
                matrix = data["vectors"]
            if matrix.ndim == 2 and matrix.shape[0] == len(keys) and matrix.shape[1] == self.dim:
                for idx, k in enumerate(keys):
                    self._vectors[str(k)] = matrix[idx].astype(np.float32, copy=False)
        except Exception as exc:
            logger.debug("Không thể đọc embedding cache từ %s: %s", self.npz_path, exc)
            self._vectors = {}

    def get(self, text: str) -> Optional[np.ndarray]:
        key = self.make_key(text)
        vec = self._vectors.get(key)
        if vec is not None:
            self.hits += 1
            return vec
        self.misses += 1
        return None

    def put_many(self, texts: List[str], vectors: np.ndarray, flush: bool = True):
        if len(texts) == 0:
            return
        for idx, text in enumerate(texts):
            key = self.make_key(text)
            self._vectors[key] = np.asarray(vectors[idx], dtype=np.float32)
            self._dirty = True
        if flush and self._dirty:
            self.flush()

    def flush(self):
        if not self._dirty:
            return
        os.makedirs(self.cache_dir, exist_ok=True)
        keys = list(self._vectors.keys())
        if keys:
            matrix = np.vstack([self._vectors[k] for k in keys]).astype(np.float32)
        else:
            matrix = np.zeros((0, self.dim), dtype=np.float32)

        pid_suffix = f"{os.getpid()}_{int(time.time() * 1000)}"
        tmp_npz = f"{self.npz_path}.{pid_suffix}.tmp"
        tmp_idx = f"{self.index_path}.{pid_suffix}.tmp"

        try:
            with open(tmp_npz, "wb") as f_npz:
                np.savez(f_npz, vectors=matrix)
            os.replace(tmp_npz, self.npz_path)

            with open(tmp_idx, "w", encoding="utf-8") as f_idx:
                json.dump(
                    {
                        "provider": self.provider_name,
                        "model": self.model_name,
                        "dim": self.dim,
                        "count": len(keys),
                        "keys": keys,
                    },
                    f_idx,
                    ensure_ascii=False,
                )
            os.replace(tmp_idx, self.index_path)
            self._dirty = False
        except Exception as exc:
            logger.debug("Không thể ghi embedding cache xuống đĩa: %s", exc)
            for p in (tmp_npz, tmp_idx):
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass

    def size(self) -> int:
        return len(self._vectors)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "provider": self.provider_name,
            "model": self.model_name,
            "dim": self.dim,
            "cached_entries": len(self._vectors),
            "hits": self.hits,
            "misses": self.misses,
            "npz_path": self.npz_path,
            "index_path": self.index_path,
        }


def normalize_l2(vectors: np.ndarray) -> np.ndarray:
    """Chuẩn hóa L2 cho vector 1D hoặc ma trận 2D kiểu float32."""
    arr = np.asarray(vectors, dtype=np.float32)
    if arr.ndim == 1:
        norm = float(np.linalg.norm(arr))
        if norm > 1e-12:
            return (arr / norm).astype(np.float32)
        return arr
    if arr.ndim == 2:
        if arr.shape[0] == 0:
            return arr
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        safe_norms = np.where(norms > 1e-12, norms, 1.0)
        return (arr / safe_norms).astype(np.float32)
    return arr


class BaseEmbeddingProvider(ABC):
    """
    Lớp cơ sở trừu tượng cho các Embedding Provider trong RAG Knowledge Base.
    Mọi vector đầu ra đều có kiểu `np.float32` và được chuẩn hóa L2 (độ dài đơn vị = 1.0).
    """

    def __init__(
        self,
        provider_name: str,
        model_name: str,
        dim: int,
        cache_dir: Optional[str] = None,
    ):
        self.provider_name = provider_name
        self.model_name = model_name
        self.dim = int(dim)
        self.cache: Optional[PersistentEmbeddingCache] = (
            PersistentEmbeddingCache(cache_dir, provider_name, model_name, self.dim)
            if cache_dir
            else None
        )

    @abstractmethod
    def _compute_embeddings(self, texts: List[str]) -> np.ndarray:
        """Tính toán ma trận embedding `(len(texts), self.dim)` cho các văn bản chưa có trong cache."""
        raise NotImplementedError

    def embed_texts(self, texts: List[str]) -> np.ndarray:
        """
        Sinh ma trận vector embedding chuẩn hóa L2 có kích thước `(len(texts), self.dim)` kiểu `float32`.
        Tự động tận dụng PersistentEmbeddingCache trên đĩa nếu có.
        """
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)

        clean_texts = [str(t or "") for t in texts]
        if self.cache is None:
            raw_mat = self._compute_embeddings(clean_texts)
            return normalize_l2(raw_mat)

        results: List[Optional[np.ndarray]] = [None] * len(clean_texts)
        missing_indices: List[int] = []
        missing_texts: List[str] = []

        for idx, text in enumerate(clean_texts):
            cached_vec = self.cache.get(text)
            if cached_vec is not None:
                results[idx] = cached_vec
            else:
                missing_indices.append(idx)
                missing_texts.append(text)

        if missing_texts:
            computed = normalize_l2(self._compute_embeddings(missing_texts))
            self.cache.put_many(missing_texts, computed, flush=True)
            for local_i, orig_idx in enumerate(missing_indices):
                results[orig_idx] = computed[local_i]

        stacked = np.vstack([r if r is not None else np.zeros((self.dim,), dtype=np.float32) for r in results])
        return stacked.astype(np.float32, copy=False)

    def embed_query(self, text: str) -> np.ndarray:
        """Sinh vector embedding 1 chiều `(self.dim,)` kiểu `float32`, chuẩn hóa L2 cho câu truy vấn."""
        mat = self.embed_texts([str(text or "")])
        if mat.shape[0] == 0:
            return np.zeros((self.dim,), dtype=np.float32)
        return mat[0]


class LocalCharNgramDenseProvider(BaseEmbeddingProvider):
    """
    Bộ sinh Dense Vector ngữ nghĩa cục bộ (`provider_name="local_hash"`, `dim=512`),
    0 phụ thuộc ngoài `numpy`, hoạt động 100% offline/air-gapped.
    Kết hợp:
      1. Mở rộng từ điển đồng nghĩa song ngữ An ninh mạng VI <-> EN (`BILINGUAL_SOC_SYNONYMS`).
      2. Word unigrams, technical identifiers (MITRE ID `T1059.001`, Rule ID `92211`), word bigrams.
      3. Character 3-5 n-grams giúp chịu lỗi chính tả, biến thể hình thái từ và từ ghép kỹ thuật.
      4. Multi-hash signed random projection (CountSketch k=4) chiếu vào không gian dense `float32` L2-normalized.
    """

    _STOPWORDS = {
        "the", "and", "for", "with", "that", "this", "from", "are", "was", "were",
        "have", "has", "had", "not", "but", "can", "may", "will", "into", "over",
        "such", "truy", "vấn", "liên", "quan", "đến", "các", "của", "trong", "cho",
        "được", "hoặc", "nhằm", "bằng", "trên", "một", "những", "khi", "với", "từ",
    }

    def __init__(self, dim: int = 512, cache_dir: Optional[str] = None):
        super().__init__(
            provider_name="local_hash",
            model_name="bilingual-soc-char-ngram-v2",
            dim=dim,
            cache_dir=cache_dir,
        )

    @classmethod
    def _extract_weighted_features(cls, text: str) -> List[Tuple[str, float]]:
        if not text or not text.strip():
            return []

        expanded = expand_bilingual_query(text)
        lower_text = expanded.lower()
        raw_tokens = re.findall(r"[\w\.\-]+", lower_text, re.UNICODE)
        tokens = [t.strip(".-_") for t in raw_tokens if len(t.strip(".-_")) >= 2]
        filtered_tokens = [t for t in tokens if t not in cls._STOPWORDS]
        if not filtered_tokens:
            filtered_tokens = tokens

        features: List[Tuple[str, float]] = []

        # 1. Word unigrams & Technical IDs
        for tok in filtered_tokens:
            if re.match(r"^(?:t\d{4}(?:\.\d{3})?|ta\d{4}|sd(?:win|lin|aws)-\d+|\d{4,6})$", tok):
                features.append((f"id:{tok}", 4.5))
                # Nếu là sub-technique T1059.001 thì thêm cả base technique T1059
                if "." in tok and tok.startswith("t"):
                    features.append((f"base_id:{tok.split('.')[0]}", 2.0))
            else:
                features.append((f"w:{tok}", 2.2))

            # 2. Character 3..5-grams cho từ kỹ thuật / từ dài >= 4 ký tự
            if len(tok) >= 4:
                padded = f"<{tok}>"
                max_len = min(len(padded), 24)
                for n in (3, 4, 5):
                    for i in range(max_len - n + 1):
                        features.append((f"c{n}:{padded[i:i + n]}", 0.55))

        # 3. Word bigrams
        for i in range(min(len(filtered_tokens) - 1, 120)):
            bg = f"bg:{filtered_tokens[i]}_{filtered_tokens[i + 1]}"
            features.append((bg, 1.6))

        return features

    def _embed_single(self, text: str) -> np.ndarray:
        vec = np.zeros((self.dim,), dtype=np.float32)
        features = self._extract_weighted_features(text)
        if not features:
            return vec

        dim = self.dim
        for feat_str, weight in features:
            digest = hashlib.blake2b(feat_str.encode("utf-8", errors="ignore"), digest_size=16).digest()
            # 4 signed projections từ 16-byte digest
            h0 = int.from_bytes(digest[0:4], "little")
            h1 = int.from_bytes(digest[4:8], "little")
            h2 = int.from_bytes(digest[8:12], "little")
            h3 = int.from_bytes(digest[12:16], "little")

            for h in (h0, h1, h2, h3):
                idx = (h >> 1) % dim
                sign = 1.0 if (h & 1) == 0 else -1.0
                vec[idx] += sign * weight

        return normalize_l2(vec)

    def _compute_embeddings(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        rows = [self._embed_single(t) for t in texts]
        return np.vstack(rows).astype(np.float32, copy=False)


class OpenAICompatibleEmbeddingProvider(BaseEmbeddingProvider):
    """
    Embedding Provider tương thích chuẩn OpenAI / OmniRoute / OpenRouter (`/v1/embeddings`).
    Tự động chuẩn hóa URL qua `resolve_openai_embeddings_url()` và hỗ trợ fallback an toàn.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        dim: int = 1536,
        timeout: float = 10.0,
        cache_dir: Optional[str] = None,
    ):
        resolved_model = (
            model_name
            or os.getenv("RAG_EMBEDDING_MODEL")
            or "text-embedding-3-small"
        )
        resolved_dim = int(os.getenv("RAG_EMBEDDING_DIM", str(dim)))
        super().__init__(
            provider_name="openai",
            model_name=resolved_model,
            dim=resolved_dim,
            cache_dir=cache_dir,
        )
        self.api_key = (
            api_key
            or os.getenv("RAG_EMBEDDING_API_KEY")
            or os.getenv("OMNIROUTER_API_KEY")
            or os.getenv("OMNIROUTE_API_KEY")
            or os.getenv("OPENROUTER_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or ""
        ).strip()
        self.endpoint_url = resolve_openai_embeddings_url(base_url)
        self.timeout = float(timeout)
        self._fallback = LocalCharNgramDenseProvider(dim=self.dim, cache_dir=None)

    def has_valid_api_key(self) -> bool:
        return bool(self.api_key) and self.api_key.lower() not in DUMMY_API_KEYS

    def _compute_embeddings(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        if not self.has_valid_api_key() or not HTTPX_AVAILABLE:
            return self._fallback._compute_embeddings(texts)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model_name,
            "input": texts,
        }

        last_err: Optional[Exception] = None
        for attempt in range(2):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(self.endpoint_url, headers=headers, json=payload)
                if resp.status_code in (429, 503) and attempt == 0:
                    time.sleep(0.5)
                    continue
                resp.raise_for_status()
                body = resp.json()
                data_list = body.get("data", [])
                if not isinstance(data_list, list) or len(data_list) != len(texts):
                    raise ValueError("Invalid embeddings response format")
                data_sorted = sorted(
                    data_list,
                    key=lambda item: int(item.get("index", 0)) if isinstance(item, dict) else 0,
                )
                vecs = [np.asarray(item["embedding"], dtype=np.float32) for item in data_sorted]
                mat = np.vstack(vecs).astype(np.float32)
                if mat.shape[1] != self.dim:
                    # Điều chỉnh kích thước nếu server trả về số chiều khác
                    if mat.shape[1] > self.dim:
                        mat = mat[:, : self.dim]
                    else:
                        pad = np.zeros((mat.shape[0], self.dim - mat.shape[1]), dtype=np.float32)
                        mat = np.hstack([mat, pad])
                return normalize_l2(mat)
            except Exception as exc:
                last_err = exc
                if attempt == 0:
                    continue

        logger.warning(
            "OpenAICompatibleEmbeddingProvider (%s) gặp lỗi (%s), chuyển sang LocalCharNgramDenseProvider.",
            self.endpoint_url,
            last_err,
        )
        return self._fallback._compute_embeddings(texts)


class OllamaEmbeddingProvider(BaseEmbeddingProvider):
    """
    Embedding Provider kết nối Ollama cục bộ (`/api/embed`, fallback `/api/embeddings`).
    Tự động chuẩn hóa URL qua `resolve_ollama_embed_urls()`.
    """

    def __init__(
        self,
        ollama_url: Optional[str] = None,
        model_name: Optional[str] = None,
        dim: int = 512,
        timeout: float = 10.0,
        cache_dir: Optional[str] = None,
    ):
        resolved_model = (
            model_name
            or os.getenv("RAG_EMBEDDING_MODEL")
            or "bge-m3"
        )
        super().__init__(
            provider_name="ollama",
            model_name=resolved_model,
            dim=dim,
            cache_dir=cache_dir,
        )
        self.embed_url, self.legacy_embeddings_url, self.tags_url = resolve_ollama_embed_urls(ollama_url)
        self.timeout = float(timeout)
        self._fallback = LocalCharNgramDenseProvider(dim=self.dim, cache_dir=None)

    def is_server_reachable(self, timeout: float = 0.5) -> bool:
        if not HTTPX_AVAILABLE:
            return False
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(self.tags_url)
                return resp.status_code == 200
        except Exception:
            return False

    def _fit_dim(self, mat: np.ndarray) -> np.ndarray:
        if mat.shape[1] == self.dim:
            return mat
        if mat.shape[1] > self.dim:
            return mat[:, : self.dim]
        pad = np.zeros((mat.shape[0], self.dim - mat.shape[1]), dtype=np.float32)
        return np.hstack([mat, pad])

    def _compute_embeddings(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        if not HTTPX_AVAILABLE:
            return self._fallback._compute_embeddings(texts)

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    self.embed_url,
                    json={"model": self.model_name, "input": texts},
                )
                if resp.status_code == 200:
                    body = resp.json()
                    embeddings = body.get("embeddings")
                    if isinstance(embeddings, list) and len(embeddings) == len(texts):
                        mat = np.asarray(embeddings, dtype=np.float32)
                        return normalize_l2(self._fit_dim(mat))

                # Fallback sang endpoint cũ /api/embeddings cho từng văn bản
                vecs: List[np.ndarray] = []
                for t in texts:
                    r_legacy = client.post(
                        self.legacy_embeddings_url,
                        json={"model": self.model_name, "prompt": t},
                    )
                    r_legacy.raise_for_status()
                    emb = r_legacy.json().get("embedding")
                    if not emb:
                        raise ValueError("Missing embedding field from /api/embeddings")
                    vecs.append(np.asarray(emb, dtype=np.float32))
                mat = np.vstack(vecs).astype(np.float32)
                return normalize_l2(self._fit_dim(mat))
        except Exception as exc:
            logger.warning(
                "OllamaEmbeddingProvider (%s) không khả dụng (%s), dùng LocalCharNgramDenseProvider.",
                self.embed_url,
                exc,
            )
            return self._fallback._compute_embeddings(texts)


class EmbeddingProviderFactory:
    """
    Factory khởi tạo Embedding Provider theo chế độ `auto | openai | ollama | local_hash`.
    Ở chế độ `auto`, tự động kiểm tra nhanh không treo mạng và chọn `LocalCharNgramDenseProvider`
    khi chạy offline hoặc chỉ có dummy API key.
    """

    @staticmethod
    def _fast_port_open(url: str, timeout: float = 0.25) -> bool:
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                return False
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    @classmethod
    def create(
        cls,
        mode: Optional[str] = None,
        cache_dir: Optional[str] = None,
        dim: int = 512,
    ) -> BaseEmbeddingProvider:
        resolved_mode = (mode or os.getenv("RAG_EMBEDDING_PROVIDER", "auto")).strip().lower()

        if resolved_mode in ("local_hash", "local", "hash", "offline"):
            return LocalCharNgramDenseProvider(dim=dim, cache_dir=cache_dir)

        if resolved_mode == "openai":
            return OpenAICompatibleEmbeddingProvider(dim=dim, cache_dir=cache_dir)

        if resolved_mode == "ollama":
            return OllamaEmbeddingProvider(dim=dim, cache_dir=cache_dir)

        # Chế độ "auto": chỉ thử kết nối khi người dùng cấu hình rõ RAG_EMBEDDING_URL / RAG_EMBEDDING_BASE_URL và API key hợp lệ
        explicit_emb_key = (
            os.getenv("RAG_EMBEDDING_API_KEY", "").strip()
            or os.getenv("OMNIROUTER_API_KEY", "").strip()
            or os.getenv("OMNIROUTE_API_KEY", "").strip()
            or os.getenv("OPENROUTER_API_KEY", "").strip()
            or os.getenv("OPENAI_API_KEY", "").strip()
        )
        explicit_emb_url = os.getenv("RAG_EMBEDDING_URL", "").strip() or os.getenv("RAG_EMBEDDING_BASE_URL", "").strip()
        if explicit_emb_key and explicit_emb_key.lower() not in DUMMY_API_KEYS and explicit_emb_url:
            target_url = resolve_openai_embeddings_url(explicit_emb_url)
            if cls._fast_port_open(target_url):
                return OpenAICompatibleEmbeddingProvider(
                    api_key=explicit_emb_key,
                    base_url=explicit_emb_url,
                    dim=dim,
                    cache_dir=cache_dir,
                )

        explicit_ollama = os.getenv("RAG_OLLAMA_URL", "").strip()
        if explicit_ollama and cls._fast_port_open(explicit_ollama):
            provider = OllamaEmbeddingProvider(ollama_url=explicit_ollama, dim=dim, cache_dir=cache_dir)
            if provider.is_server_reachable(timeout=0.35):
                return provider

        # Mặc định an toàn, tốc độ cao (<0.2ms), 0 network hang: LocalCharNgramDenseProvider
        return LocalCharNgramDenseProvider(dim=dim, cache_dir=cache_dir)
