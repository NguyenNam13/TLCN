# -*- coding: utf-8 -*-
"""
src/core/config.py
Module quản lý cấu hình tập trung và nạp biến môi trường (.env) cho Hệ thống Multi-Agent SOC.
Thuần Python (không phụ thuộc Streamlit hay bất kỳ module runtime nào khác để tránh circular imports).
"""

import os
import sys
import re
import logging
from pathlib import Path
from typing import Optional, List, Union, Tuple

logger = logging.getLogger("SOCConfig")

# Giá trị mặc định chuẩn (không chứa hardcode IP lab nội bộ)
DEFAULT_MODEL = "AICODE"
DEFAULT_LLM_PROVIDER_MODE = "omnirouter"
DEFAULT_OMNIROUTER_ENDPOINT = "http://localhost:20128/v1/chat/completions"
DEFAULT_OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_OLLAMA_MODEL = "llama3:latest"
DEFAULT_OMNIROUTER_API_KEY = "sk-soc-copilot-dev-dummy-key"

DEFAULT_WAZUH_OVA_IP = "127.0.0.1"
DEFAULT_WAZUH_HOST_IP = "127.0.0.1"
DEFAULT_WEBHOOK_PORT = 8000
DEFAULT_WAZUH_ALLOWED_IPS = "127.0.0.1,localhost"
DEFAULT_WAZUH_MIN_LEVEL = 7
DEFAULT_MAX_BODY_SIZE = 2 * 1024 * 1024  # 2MB
DEFAULT_LLM_TIMEOUT_SECONDS = 15.0
DEFAULT_LLM_MAX_RETRIES = 2

_ENV_KEY_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def get_project_root() -> Path:
    """Trả về đường dẫn thư mục gốc của dự án TLCN."""
    return Path(__file__).resolve().parent.parent.parent


def _should_skip_dotenv() -> bool:
    """Tự động bỏ qua nạp .env trong môi trường pytest/test isolation trừ khi force=True."""
    if os.getenv("PYTEST_CURRENT_TEST"):
        return True
    if "pytest" in sys.modules:
        return True
    if os.getenv("SOC_SKIP_DOTENV") == "1":
        return True
    return False


def _strip_inline_comment(raw_val: str) -> str:
    """Loại bỏ comment '#' ở cuối giá trị chưa bọc dấu nháy."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(raw_val):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or raw_val[idx - 1].isspace():
                return raw_val[:idx].rstrip()
    return raw_val.strip()


def _parse_env_line(line: str) -> Optional[Tuple[str, str]]:
    """Phân tích một dòng trong file .env theo chuẩn KEY=VALUE."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    match = _ENV_KEY_RE.match(stripped)
    if not match:
        return None

    key = match.group(1).strip()
    raw_val = _strip_inline_comment(match.group(2).strip())

    if len(raw_val) >= 2 and (
        (raw_val.startswith('"') and raw_val.endswith('"'))
        or (raw_val.startswith("'") and raw_val.endswith("'"))
    ):
        quote = raw_val[0]
        inner = raw_val[1:-1]
        if quote == '"':
            inner = (
                inner.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace('\\"', '"')
                .replace("\\\\", "\\")
            )
        return key, inner

    return key, raw_val


def _load_env_pure_python(target_path: Path, override: bool = False) -> bool:
    """Parser .env thuần Python làm fallback khi python-dotenv chưa được cài đặt."""
    try:
        content = target_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        logger.warning(f"Không thể đọc tệp môi trường {target_path}: {exc}")
        return False

    for line in content.splitlines():
        parsed = _parse_env_line(line)
        if not parsed:
            continue
        key, value = parsed
        if override:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)
    return True


def load_project_env(
    env_path: Optional[Union[Path, str]] = None,
    force: bool = False,
    override: bool = False,
) -> bool:
    """Nạp biến môi trường từ tệp .env của dự án một cách an toàn.

    Tự động bỏ qua khi đang chạy trong pytest (`PYTEST_CURRENT_TEST` có giá trị,
    `"pytest" in sys.modules`, hoặc `SOC_SKIP_DOTENV == "1"`) trừ khi `force=True`.
    Ưu tiên dùng `python-dotenv` nếu có cài đặt, và luôn có fallback parser thuần Python
    sử dụng `os.environ.setdefault(...)` (hoặc ghi đè nếu `override=True`).
    """
    if not force and _should_skip_dotenv():
        return False

    target_path = Path(env_path) if env_path is not None else (get_project_root() / ".env")
    if not target_path.is_file():
        return False

    try:
        from dotenv import load_dotenv  # type: ignore

        load_dotenv(dotenv_path=target_path, override=override)
        return True
    except ImportError:
        return _load_env_pure_python(target_path, override=override)
    except Exception as exc:
        logger.debug(f"python-dotenv gặp lỗi khi nạp {target_path}, chuyển sang fallback: {exc}")
        return _load_env_pure_python(target_path, override=override)


def _get_nonempty_env(*names: str) -> Optional[str]:
    """Lấy biến môi trường đầu tiên khác None và không rỗng."""
    for name in names:
        val = os.getenv(name)
        if val is not None:
            cleaned = val.strip()
            if cleaned:
                return cleaned
    return None


def _safe_int_env(names: Tuple[str, ...], default: int, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
    raw = _get_nonempty_env(*names)
    if raw is None:
        return default
    try:
        parsed = int(raw)
        if min_val is not None and parsed < min_val:
            return default
        if max_val is not None and parsed > max_val:
            return default
        return parsed
    except (ValueError, TypeError):
        return default


def _safe_float_env(names: Tuple[str, ...], default: float, min_val: Optional[float] = None) -> float:
    raw = _get_nonempty_env(*names)
    if raw is None:
        return default
    try:
        parsed = float(raw)
        if min_val is not None and parsed < min_val:
            return default
        return parsed
    except (ValueError, TypeError):
        return default


# =====================================================================
# CANONICAL ENVIRONMENT GETTERS (CÓ TƯƠNG THÍCH NGƯỢC)
# =====================================================================
def get_wazuh_ova_ip(default: str = DEFAULT_WAZUH_OVA_IP) -> str:
    """Lấy IP máy chủ Wazuh OVA (`WAZUH_OVA_IP`, fallback `WAZUH_MANAGER_IP`)."""
    return _get_nonempty_env("WAZUH_OVA_IP", "WAZUH_MANAGER_IP") or default


def get_wazuh_host_ip(default: str = DEFAULT_WAZUH_HOST_IP) -> str:
    """Lấy IP máy chủ SOC nhận webhook (`WAZUH_HOST_IP`)."""
    return _get_nonempty_env("WAZUH_HOST_IP") or default


def get_webhook_port(default: int = DEFAULT_WEBHOOK_PORT) -> int:
    """Lấy cổng Webhook Receiver (`WEBHOOK_PORT`, fallback `PORT`)."""
    return _safe_int_env(("WEBHOOK_PORT", "PORT"), default=default, min_val=1, max_val=65535)


def get_wazuh_allowed_ips(default: str = DEFAULT_WAZUH_ALLOWED_IPS) -> List[str]:
    """Lấy danh sách IP/CIDR được phép gọi Webhook (`WAZUH_ALLOWED_IPS`)."""
    raw = _get_nonempty_env("WAZUH_ALLOWED_IPS") or default
    ips = [item.strip() for item in raw.split(",") if item.strip()]
    ova_ip = _get_nonempty_env("WAZUH_OVA_IP", "WAZUH_MANAGER_IP")
    if ova_ip and "*" not in ips and ova_ip not in ips:
        ips.append(ova_ip)
    return ips


def get_wazuh_min_level(default: int = DEFAULT_WAZUH_MIN_LEVEL) -> int:
    """Lấy ngưỡng Rule Level tối thiểu tiếp nhận từ Wazuh (`WAZUH_MIN_LEVEL`)."""
    return _safe_int_env(("WAZUH_MIN_LEVEL",), default=default, min_val=0, max_val=15)


def get_max_body_size(default: int = DEFAULT_MAX_BODY_SIZE) -> int:
    """Lấy kích thước payload tối đa của Webhook (`MAX_BODY_SIZE`)."""
    return _safe_int_env(("MAX_BODY_SIZE",), default=default, min_val=1024)


def get_llm_provider_mode(default: str = DEFAULT_LLM_PROVIDER_MODE) -> str:
    """Lấy chế độ LLM provider (`LLM_PROVIDER_MODE`)."""
    val = _get_nonempty_env("LLM_PROVIDER_MODE")
    return val.lower() if val else default


def get_llm_model(default: Optional[str] = None) -> str:
    """Lấy model LLM mặc định (`COPILOT_MODEL`, fallback `OMNIROUTE_MODEL`, `LLM_MODEL`)."""
    return _get_nonempty_env("COPILOT_MODEL", "OMNIROUTE_MODEL", "LLM_MODEL") or default or DEFAULT_MODEL


def get_llm_model_fast(default: Optional[str] = None) -> str:
    """Lấy model tầng nhanh (`LLM_MODEL_FAST`, fallback `OMNIROUTE_FAST_MODEL`)."""
    return _get_nonempty_env("LLM_MODEL_FAST", "OMNIROUTE_FAST_MODEL") or default or DEFAULT_MODEL


def get_llm_model_reasoning(default: Optional[str] = None) -> str:
    """Lấy model tầng suy luận sâu (`LLM_MODEL_REASONING`, fallback `OMNIROUTE_REASONING_MODEL`)."""
    return _get_nonempty_env("LLM_MODEL_REASONING", "OMNIROUTE_REASONING_MODEL") or default or DEFAULT_MODEL


def get_omnirouter_api_key(default: str = DEFAULT_OMNIROUTER_API_KEY) -> str:
    """Lấy API Key cho OmniRouter/OpenRouter (`OMNIROUTER_API_KEY`, fallback `OPENROUTER_API_KEY`)."""
    return _get_nonempty_env("OMNIROUTER_API_KEY", "OPENROUTER_API_KEY") or default


def get_omnirouter_endpoint(
    provider_mode: Optional[str] = None,
    default: Optional[str] = None,
) -> str:
    """Lấy endpoint Chat Completions cho OmniRouter/OpenRouter."""
    explicit = _get_nonempty_env("OMNIROUTE_BASE_URL", "OMNIROUTER_BASE_URL")
    if explicit:
        return explicit
    if default:
        return default
    mode = (provider_mode or get_llm_provider_mode()).lower()
    if mode == "openrouter":
        return DEFAULT_OPENROUTER_ENDPOINT
    return DEFAULT_OMNIROUTER_ENDPOINT


def get_ollama_url(default: str = DEFAULT_OLLAMA_URL) -> str:
    """Lấy URL Local Ollama Chat API (`OLLAMA_URL`)."""
    return _get_nonempty_env("OLLAMA_URL") or default


def get_ollama_model(default: str = DEFAULT_OLLAMA_MODEL) -> str:
    """Lấy tên model Local Ollama (`OLLAMA_MODEL`)."""
    return _get_nonempty_env("OLLAMA_MODEL") or default


def get_llm_timeout(default: float = DEFAULT_LLM_TIMEOUT_SECONDS) -> float:
    """Lấy timeout gọi LLM API theo giây (`LLM_TIMEOUT_SECONDS`)."""
    return _safe_float_env(("LLM_TIMEOUT_SECONDS",), default=default, min_val=0.5)


def get_llm_max_retries(default: int = DEFAULT_LLM_MAX_RETRIES) -> int:
    """Lấy số lần retry tối đa cho HTTP 429/503 (`LLM_MAX_RETRIES`)."""
    return _safe_int_env(("LLM_MAX_RETRIES",), default=default, min_val=0, max_val=10)


def is_parallel_investigation_enabled(default: bool = True) -> bool:
    """Kiểm tra cờ bật chế độ điều tra song song CTI || RCA (`SOC_ENABLE_PARALLEL_INVESTIGATION`)."""
    raw = _get_nonempty_env("SOC_ENABLE_PARALLEL_INVESTIGATION")
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


__all__ = [
    "DEFAULT_MODEL",
    "DEFAULT_LLM_PROVIDER_MODE",
    "DEFAULT_OMNIROUTER_ENDPOINT",
    "DEFAULT_OPENROUTER_ENDPOINT",
    "DEFAULT_OLLAMA_URL",
    "DEFAULT_OLLAMA_MODEL",
    "DEFAULT_OMNIROUTER_API_KEY",
    "DEFAULT_WAZUH_OVA_IP",
    "DEFAULT_WAZUH_HOST_IP",
    "DEFAULT_WEBHOOK_PORT",
    "DEFAULT_WAZUH_ALLOWED_IPS",
    "DEFAULT_WAZUH_MIN_LEVEL",
    "DEFAULT_MAX_BODY_SIZE",
    "DEFAULT_LLM_TIMEOUT_SECONDS",
    "DEFAULT_LLM_MAX_RETRIES",
    "get_project_root",
    "load_project_env",
    "get_wazuh_ova_ip",
    "get_wazuh_host_ip",
    "get_webhook_port",
    "get_wazuh_allowed_ips",
    "get_wazuh_min_level",
    "get_max_body_size",
    "get_llm_provider_mode",
    "get_llm_model",
    "get_llm_model_fast",
    "get_llm_model_reasoning",
    "get_omnirouter_api_key",
    "get_omnirouter_endpoint",
    "get_ollama_url",
    "get_ollama_model",
    "get_llm_timeout",
    "get_llm_max_retries",
    "is_parallel_investigation_enabled",
]
