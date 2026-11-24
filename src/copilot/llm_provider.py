# -*- coding: utf-8 -*-
"""
src/copilot/llm_provider.py
Module cung cấp kết nối LLM Hybrid đa tầng cho SOC AI Copilot.
Hỗ trợ:
1. OmniRouter / OpenRouter Gateway (Cấu hình qua biến môi trường OMNIROUTER_API_KEY)
2. Local Ollama LLM (http://localhost:11434/api/chat)
3. Tier 3 Deterministic CoT Engine: Rule-based Chain-of-Thought tổng hợp tự động từ IncidentState
   khi mất kết nối mạng hoặc API gặp sự cố timeout/lỗi.
"""

import os
import re
import json
import time
import random
import logging
import threading
import contextlib
import contextvars
from enum import Enum
from urllib.parse import urlparse, urlunparse
from typing import Optional, Any, Union, Iterator, Dict, List, Type, Tuple
import requests
from pydantic import BaseModel, ValidationError

from src.core.config import (
    DEFAULT_MODEL as _CFG_DEFAULT_MODEL,
    DEFAULT_OPENROUTER_ENDPOINT as _CFG_DEFAULT_OPENROUTER_ENDPOINT,
    DEFAULT_OMNIROUTER_ENDPOINT as _CFG_DEFAULT_OMNIROUTER_ENDPOINT,
    DEFAULT_OLLAMA_URL as _CFG_DEFAULT_OLLAMA_URL,
    DEFAULT_OLLAMA_MODEL as _CFG_DEFAULT_OLLAMA_MODEL,
    DEFAULT_OMNIROUTER_API_KEY as _CFG_DEFAULT_OMNIROUTER_API_KEY,
    get_llm_provider_mode,
    get_llm_model,
    get_llm_model_fast,
    get_llm_model_reasoning,
    get_omnirouter_endpoint,
    get_omnirouter_api_key,
    get_ollama_url,
    get_ollama_model,
    get_llm_timeout,
    get_llm_max_retries,
    get_wazuh_ova_ip,
    get_webhook_port,
)
from src.core.schemas import LLMHealthStatus, LLMCallTelemetry, LLMCompletionResult

logger = logging.getLogger("HybridLLMProvider")

# Cấu hình mặc định (Đọc an toàn từ config/env, giữ nguyên hằng số tương thích ngược)
DEFAULT_OMNIROUTER_API_KEY = get_omnirouter_api_key(_CFG_DEFAULT_OMNIROUTER_API_KEY)
DEFAULT_OPENROUTER_ENDPOINT = _CFG_DEFAULT_OPENROUTER_ENDPOINT
DEFAULT_OMNIROUTER_ENDPOINT = _CFG_DEFAULT_OMNIROUTER_ENDPOINT
DEFAULT_MODEL = _CFG_DEFAULT_MODEL
DEFAULT_OLLAMA_URL = _CFG_DEFAULT_OLLAMA_URL
DEFAULT_OLLAMA_MODEL = _CFG_DEFAULT_OLLAMA_MODEL

_TELEMETRY_SCOPE: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "hybrid_llm_telemetry_scope", default=None
)


def _iter_clean_lines(response: requests.Response) -> Iterator[str]:
    """Đọc và chuẩn hóa từng dòng văn bản từ luồng phản hồi HTTP streaming."""
    try:
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="ignore")
            line = line.strip()
            if line:
                yield line
    finally:
        response.close()


def _extract_json_str(text: str) -> str:
    """Trích xuất chuỗi JSON thuần từ phản hồi của LLM (loại bỏ markdown fences và văn bản thừa)."""
    if not text:
        return ""
    stripped = text.strip()

    # 1. Bóc tách markdown code fence nếu có (```json ... ``` hoặc ``` ... ```)
    if "```" in stripped:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", stripped, re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            if candidate.startswith(("{", "[")):
                return candidate

    # 2. Tìm khối {...} bao quanh đối tượng JSON
    first_brace = stripped.find("{")
    last_brace = stripped.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        return stripped[first_brace:last_brace + 1]

    # 3. Tìm khối [...] bao quanh danh sách JSON
    first_bracket = stripped.find("[")
    last_bracket = stripped.rfind("]")
    if first_bracket != -1 and last_bracket > first_bracket:
        return stripped[first_bracket:last_bracket + 1]

    return stripped


class HybridLLMProvider:
    """Provider kết nối LLM thông minh hỗ trợ chuyển tầng linh hoạt (Hybrid Failover).

    Thứ tự ưu tiên xử lý:
    1. OmniRouter / OpenRouter API Cloud (Model tiên tiến, phản hồi nhanh).
    2. Local Ollama Server (Môi trường On-Premise/Offline nội bộ).
    3. Tier 3 Deterministic CoT Engine (Rule-based an toàn tuyệt đối, không phụ thuộc ngoại vi).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        model: Optional[str] = None,
        ollama_url: Optional[str] = None,
        ollama_model: Optional[str] = None,
        provider_mode: Optional[str] = None,  # "auto", "omnirouter", "openrouter", "ollama", "deterministic"
        timeout: Optional[float] = None,
        enable_fallback: bool = True,
        fast_model: Optional[str] = None,
        reasoning_model: Optional[str] = None,
        ollama_fast_model: Optional[str] = None,
        ollama_reasoning_model: Optional[str] = None,
        default_temperature: float = 0.2,
        default_max_tokens: int = 1500,
        max_retries: Optional[int] = None,
        retry_base_delay: float = 0.8,
        circuit_breaker_ttl: float = 20.0,
    ):
        resolved_mode = (
            provider_mode if provider_mode is not None else get_llm_provider_mode(default="auto")
        )
        resolved_mode = str(resolved_mode or "auto").strip().lower() or "auto"

        self.provider_mode: str = resolved_mode
        self.api_key: str = api_key or get_omnirouter_api_key(DEFAULT_OMNIROUTER_API_KEY)
        self.endpoint: str = endpoint or get_omnirouter_endpoint(provider_mode=resolved_mode)
        self.model: str = model or get_llm_model(DEFAULT_MODEL)
        self.fast_model: str = fast_model or get_llm_model_fast(self.model)
        self.reasoning_model: str = reasoning_model or get_llm_model_reasoning(self.model)
        self.ollama_url: str = ollama_url or get_ollama_url(DEFAULT_OLLAMA_URL)
        self.ollama_model: str = ollama_model or get_ollama_model(DEFAULT_OLLAMA_MODEL)
        env_ollama_fast = (
            os.getenv("OLLAMA_MODEL_FAST") or os.getenv("OLLAMA_FAST_MODEL") or ""
        ).strip()
        env_ollama_reasoning = (
            os.getenv("OLLAMA_MODEL_REASONING") or os.getenv("OLLAMA_REASONING_MODEL") or ""
        ).strip()
        self.ollama_fast_model: str = ollama_fast_model or env_ollama_fast or self.ollama_model
        self.ollama_reasoning_model: str = (
            ollama_reasoning_model or env_ollama_reasoning or self.ollama_model
        )
        self.default_temperature: float = (
            0.2 if default_temperature is None else float(default_temperature)
        )
        self.default_max_tokens: int = (
            1500 if default_max_tokens is None else int(default_max_tokens)
        )
        self.timeout: float = float(timeout) if timeout is not None else get_llm_timeout(15.0)
        self.enable_fallback: bool = bool(enable_fallback)
        self.max_retries: int = int(max_retries) if max_retries is not None else get_llm_max_retries()
        self.retry_base_delay: float = float(retry_base_delay)
        self.circuit_breaker_ttl: float = float(circuit_breaker_ttl)

        # Trung thực: chưa có lời gọi nào thực thi thành công thì last_used_provider phải là None
        self.last_used_provider: Optional[str] = None
        self.last_error: Optional[str] = None

        # Cache sức khỏe kết nối & trạng thái Circuit Breaker ngắn hạn
        self._last_health_status: Optional[LLMHealthStatus] = None
        self._last_health_checked_at: float = 0.0
        self._health_cache_ttl: float = 30.0
        self._circuit_open_until: Dict[str, float] = {}
        self._circuit_open_reason: Dict[str, str] = {}

        # Telemetry nhẹ theo từng lượt gọi & thread-safe lock
        self.last_telemetry: Optional[LLMCallTelemetry] = None
        self.telemetry_history: List[LLMCallTelemetry] = []
        self._thread_usage: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    @property
    def last_health(self) -> Optional[LLMHealthStatus]:
        return self._last_health_status

    @property
    def last_call_telemetry(self) -> Optional[LLMCallTelemetry]:
        return self.last_telemetry

    @property
    def provider_type(self) -> str:
        """Trả về tên định danh trung thực của provider hiện tại."""
        return self.get_active_provider()

    def get_active_provider(self) -> str:
        """Trả về provider thực tế đã dùng gần nhất hoặc trạng thái xác thực hiện tại."""
        if self.last_used_provider is not None:
            return self.last_used_provider
        if self._last_health_status is not None:
            return self._last_health_status.active_provider
        if self.provider_mode == "deterministic":
            return "deterministic"
        return "none"

    def _is_dummy_key(self) -> bool:
        key_val = (self.api_key or "").strip()
        return (
            not key_val
            or key_val == _CFG_DEFAULT_OMNIROUTER_API_KEY
            or "dummy" in key_val.lower()
            or key_val.lower() in {"changeme", "your-api-key", "none"}
        )

    def resolve_model(
        self,
        provider: Optional[str] = None,
        model_tier: str = "default",
        model_override: Optional[str] = None,
        *,
        provider_name: Optional[str] = None,
    ) -> str:
        """Chọn model tương ứng với provider và tầng suy luận (fast / reasoning / default)."""
        if model_override:
            return model_override
        prov = (provider or provider_name or self.provider_mode or "omnirouter").strip().lower()
        tier = (model_tier or "default").strip().lower()
        if prov == "ollama":
            if tier == "fast":
                return self.ollama_fast_model or self.ollama_model
            if tier == "reasoning":
                return self.ollama_reasoning_model or self.ollama_model
            return self.ollama_model
        if prov == "deterministic":
            return "Deterministic-CoT"
        if tier == "fast":
            return self.fast_model or self.model
        if tier == "reasoning":
            return self.reasoning_model or self.model
        return self.model

    # =========================================================================
    # QUẢN LÝ CẤU HÌNH NÓNG, CIRCUIT BREAKER & HEALTH CHECK THỰC TẾ
    # =========================================================================
    def _reset_circuit_breaker(self, provider_key: Optional[str] = None) -> None:
        with self._lock:
            if provider_key is None:
                self._circuit_open_until.clear()
                self._circuit_open_reason.clear()
            else:
                self._circuit_open_until.pop(provider_key, None)
                self._circuit_open_reason.pop(provider_key, None)

    def _is_circuit_open(self, provider_key: str) -> bool:
        if not self.enable_fallback:
            return False
        with self._lock:
            deadline = self._circuit_open_until.get(provider_key)
            if deadline is None:
                return False
            if time.monotonic() < deadline:
                return True
            self._circuit_open_until.pop(provider_key, None)
            self._circuit_open_reason.pop(provider_key, None)
            return False

    def _trip_circuit_breaker(self, provider_key: str, reason: str = "") -> None:
        if not self.enable_fallback or self.circuit_breaker_ttl <= 0:
            return
        with self._lock:
            self._circuit_open_until[provider_key] = time.monotonic() + self.circuit_breaker_ttl
            if reason:
                self._circuit_open_reason[provider_key] = reason

    @staticmethod
    def _is_connection_error(exc: Exception) -> bool:
        if isinstance(
            exc,
            (requests.ConnectionError, ConnectionRefusedError, requests.Timeout, TimeoutError, OSError),
        ):
            return True
        msg = str(exc).lower()
        return any(
            tok in msg
            for tok in (
                "connection refused",
                "connectionerror",
                "failed to establish",
                "unreachable",
                "timed out",
                "timeout",
                "name or service not known",
                "nodename nor servname",
            )
        )

    def update_config(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        provider_mode: Optional[str] = None,
        fast_model: Optional[str] = None,
        reasoning_model: Optional[str] = None,
        ollama_url: Optional[str] = None,
        ollama_model: Optional[str] = None,
        ollama_fast_model: Optional[str] = None,
        ollama_reasoning_model: Optional[str] = None,
        default_temperature: Optional[float] = None,
        default_max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        enable_fallback: Optional[bool] = None,
        max_retries: Optional[int] = None,
        retry_base_delay: Optional[float] = None,
    ) -> "HybridLLMProvider":
        """Cập nhật nóng cấu hình Gateway/Model và đặt lại trạng thái Circuit Breaker & Health Cache."""
        with self._lock:
            old_model = self.model
            old_ollama_model = self.ollama_model

            if provider_mode is not None and str(provider_mode).strip():
                new_mode = str(provider_mode).strip().lower()
                self.provider_mode = new_mode
                if endpoint is None:
                    if new_mode == "openrouter" and self.endpoint == DEFAULT_OMNIROUTER_ENDPOINT:
                        self.endpoint = DEFAULT_OPENROUTER_ENDPOINT
                    elif new_mode in ("omnirouter", "auto") and self.endpoint == DEFAULT_OPENROUTER_ENDPOINT:
                        self.endpoint = DEFAULT_OMNIROUTER_ENDPOINT

            if endpoint is not None and str(endpoint).strip():
                self.endpoint = str(endpoint).strip()
            if api_key is not None and str(api_key).strip():
                self.api_key = str(api_key).strip()
            if model is not None and str(model).strip():
                self.model = str(model).strip()
                if fast_model is None and self.fast_model == old_model:
                    self.fast_model = self.model
                if reasoning_model is None and self.reasoning_model == old_model:
                    self.reasoning_model = self.model
            if fast_model is not None and str(fast_model).strip():
                self.fast_model = str(fast_model).strip()
            if reasoning_model is not None and str(reasoning_model).strip():
                self.reasoning_model = str(reasoning_model).strip()
            if ollama_url is not None and str(ollama_url).strip():
                self.ollama_url = str(ollama_url).strip()
            if ollama_model is not None and str(ollama_model).strip():
                self.ollama_model = str(ollama_model).strip()
                if ollama_fast_model is None and self.ollama_fast_model == old_ollama_model:
                    self.ollama_fast_model = self.ollama_model
                if ollama_reasoning_model is None and self.ollama_reasoning_model == old_ollama_model:
                    self.ollama_reasoning_model = self.ollama_model
            if ollama_fast_model is not None and str(ollama_fast_model).strip():
                self.ollama_fast_model = str(ollama_fast_model).strip()
            if ollama_reasoning_model is not None and str(ollama_reasoning_model).strip():
                self.ollama_reasoning_model = str(ollama_reasoning_model).strip()
            if default_temperature is not None:
                self.default_temperature = float(default_temperature)
            if default_max_tokens is not None:
                self.default_max_tokens = int(default_max_tokens)
            if timeout is not None:
                self.timeout = float(timeout)
            if enable_fallback is not None:
                self.enable_fallback = bool(enable_fallback)
            if max_retries is not None:
                self.max_retries = max(0, int(max_retries))
            if retry_base_delay is not None:
                self.retry_base_delay = max(0.0, float(retry_base_delay))

            self.last_used_provider = None
            self.last_error = None
            self._last_health_status = None
            self._last_health_checked_at = 0.0
            self._reset_circuit_breaker()
        return self

    reconfigure = update_config

    @staticmethod
    def _derive_models_url(endpoint: str) -> str:
        raw = (endpoint or DEFAULT_OMNIROUTER_ENDPOINT).strip()
        if "/chat/completions" in raw:
            return raw.replace("/chat/completions", "/models")
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return urlunparse((parsed.scheme, parsed.netloc, "/v1/models", "", "", ""))
        return raw.rstrip("/") + "/models"

    @staticmethod
    def _derive_ollama_tags_url(ollama_url: str) -> str:
        raw = (ollama_url or DEFAULT_OLLAMA_URL).strip()
        if "/api/chat" in raw:
            return raw.replace("/api/chat", "/api/tags")
        if "/api/generate" in raw:
            return raw.replace("/api/generate", "/api/tags")
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return urlunparse((parsed.scheme, parsed.netloc, "/api/tags", "", "", ""))
        return raw.rstrip("/") + "/api/tags"

    def _probe_omnirouter(self, probe_timeout: float) -> Tuple[bool, Optional[float], Optional[str]]:
        models_url = self._derive_models_url(self.endpoint)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        t0 = time.perf_counter()
        try:
            resp = requests.get(models_url, headers=headers, timeout=probe_timeout)
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            if resp.status_code == 200:
                self._reset_circuit_breaker("omnirouter")
                return True, latency_ms, None
            if resp.status_code in (404, 405):
                # Một số proxy chỉ mở POST /chat/completions
                post_resp = requests.post(
                    self.endpoint,
                    headers=headers,
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": "ping"}],
                        "max_tokens": 1,
                        "stream": False,
                    },
                    timeout=probe_timeout,
                )
                latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                if post_resp.status_code == 200:
                    self._reset_circuit_breaker("omnirouter")
                    return True, latency_ms, None
                return False, latency_ms, f"HTTP {post_resp.status_code}"
            return False, latency_ms, f"HTTP {resp.status_code}"
        except Exception as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            if self._is_connection_error(exc):
                self._trip_circuit_breaker("omnirouter", str(exc))
            return False, latency_ms, str(exc)

    def _probe_ollama(self, probe_timeout: float) -> Tuple[bool, Optional[float], Optional[str]]:
        tags_url = self._derive_ollama_tags_url(self.ollama_url)
        t0 = time.perf_counter()
        try:
            resp = requests.get(tags_url, timeout=probe_timeout)
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            if resp.status_code == 200:
                self._reset_circuit_breaker("ollama")
                return True, latency_ms, None
            return False, latency_ms, f"HTTP {resp.status_code}"
        except Exception as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            if self._is_connection_error(exc):
                self._trip_circuit_breaker("ollama", str(exc))
            return False, latency_ms, str(exc)

    def check_health(self, force: bool = False, timeout: float = 1.5) -> LLMHealthStatus:
        """Kiểm tra chủ động trạng thái kết nối thực tế tới OmniRouter/OpenRouter và Local Ollama."""
        with self._lock:
            now = time.monotonic()
            if (
                not force
                and self._last_health_status is not None
                and (now - self._last_health_checked_at) < self._health_cache_ttl
            ):
                return self._last_health_status

        if force:
            self._reset_circuit_breaker()

        probe_timeout = max(0.3, min(float(timeout), 3.0))
        dummy_key = self._is_dummy_key()
        mode = self.provider_mode

        if mode == "deterministic":
            status = LLMHealthStatus(
                connected=False,
                active_provider="deterministic",
                configured_mode=mode,
                endpoint="deterministic://local",
                model="Deterministic-CoT",
                latency_ms=0.0,
                using_dummy_key=dummy_key,
                detail="Chế độ Deterministic CoT ngoại tuyến (không kết nối API)",
                error=None,
            )
            with self._lock:
                self._last_health_status = status
                self._last_health_checked_at = time.monotonic()
            return status

        if mode == "ollama":
            ok, lat, err = self._probe_ollama(probe_timeout)
            if ok:
                status = LLMHealthStatus(
                    connected=True,
                    active_provider="ollama",
                    configured_mode=mode,
                    endpoint=self.ollama_url,
                    model=self.ollama_model,
                    latency_ms=lat,
                    using_dummy_key=dummy_key,
                    detail=f"Kết nối Local Ollama thành công ({self.ollama_model})",
                    error=None,
                )
            else:
                active = "deterministic" if self.enable_fallback else "none"
                status = LLMHealthStatus(
                    connected=False,
                    active_provider=active,
                    configured_mode=mode,
                    endpoint=self.ollama_url,
                    model=self.ollama_model,
                    latency_ms=lat,
                    using_dummy_key=dummy_key,
                    detail=(
                        f"Không thể kết nối Local Ollama ({err}); dùng Fallback Deterministic CoT"
                        if self.enable_fallback
                        else f"Không thể kết nối Local Ollama ({err})"
                    ),
                    error=err,
                )
            with self._lock:
                self._last_health_status = status
                self._last_health_checked_at = time.monotonic()
                self.last_error = status.error
            return status

        # Chế độ auto / omnirouter / openrouter
        omni_name = "openrouter" if mode == "openrouter" else "omnirouter"
        omni_ok, omni_lat, omni_err = self._probe_omnirouter(probe_timeout)
        if omni_ok:
            status = LLMHealthStatus(
                connected=True,
                active_provider=omni_name,
                configured_mode=mode,
                endpoint=self.endpoint,
                model=self.model,
                latency_ms=omni_lat,
                using_dummy_key=dummy_key,
                detail=f"Kết nối {omni_name} thành công ({self.model})",
                error=None,
            )
        elif self.enable_fallback:
            ollama_ok, ollama_lat, ollama_err = self._probe_ollama(probe_timeout)
            if ollama_ok:
                status = LLMHealthStatus(
                    connected=True,
                    active_provider="ollama",
                    configured_mode=mode,
                    endpoint=self.ollama_url,
                    model=self.ollama_model,
                    latency_ms=ollama_lat,
                    using_dummy_key=dummy_key,
                    detail=f"{omni_name} ngoại tuyến ({omni_err}); đã chuyển sang Local Ollama ({self.ollama_model})",
                    error=f"{omni_name}: {omni_err}",
                )
            else:
                combined_err = f"OmniRouter: {omni_err} | Ollama: {ollama_err}"
                status = LLMHealthStatus(
                    connected=False,
                    active_provider="deterministic",
                    configured_mode=mode,
                    endpoint=self.endpoint,
                    model=self.model,
                    latency_ms=ollama_lat if ollama_lat is not None else omni_lat,
                    using_dummy_key=dummy_key,
                    detail=f"Mất kết nối LLM Gateway & Ollama; đang dùng Fallback Deterministic CoT",
                    error=combined_err,
                )
        else:
            status = LLMHealthStatus(
                connected=False,
                active_provider="none",
                configured_mode=mode,
                endpoint=self.endpoint,
                model=self.model,
                latency_ms=omni_lat,
                using_dummy_key=dummy_key,
                detail=f"Mất kết nối {omni_name} ({omni_err}) và đã tắt fallback",
                error=f"{omni_name}: {omni_err}",
            )

        with self._lock:
            self._last_health_status = status
            self._last_health_checked_at = time.monotonic()
            self.last_error = status.error
        return status

    def get_connection_status(self, force: bool = False) -> LLMHealthStatus:
        """Lấy trạng thái kết nối hiện có (hoặc probe mới nếu chưa kiểm tra / force=True)."""
        if not force and self._last_health_status is not None:
            return self._last_health_status
        return self.check_health(force=force)

    def ping(self, force: bool = True, timeout: float = 1.5) -> bool:
        """Trả về True nếu có kết nối LLM Gateway/Ollama sống, ngược lại False."""
        return bool(self.check_health(force=force, timeout=timeout).connected)

    # =========================================================================
    # TELEMETRY SCOPE & GHI NHẬN CHỈ SỐ GỌI LLM
    # =========================================================================
    def begin_telemetry_scope(
        self,
        state_or_agent: Optional[Any] = None,
        agent_name_or_node: Optional[str] = None,
        node_or_tier: Optional[str] = None,
        *,
        state: Optional[Any] = None,
        incident_state: Optional[Any] = None,
        agent_name: Optional[str] = None,
        node: Optional[str] = None,
        model_tier: Optional[str] = None,
    ) -> contextvars.Token:
        """Mở scope contextvars để gom telemetry các lượt gọi LLM trong cùng node/agent."""
        if isinstance(state_or_agent, str):
            resolved_state = state if state is not None else incident_state
            resolved_agent = agent_name or state_or_agent or "Unknown"
            resolved_node = node if node is not None else agent_name_or_node
            resolved_tier = model_tier or node_or_tier or "default"
        else:
            resolved_state = (
                state_or_agent
                if state_or_agent is not None
                else (state if state is not None else incident_state)
            )
            resolved_agent = agent_name or agent_name_or_node or "Unknown"
            resolved_node = node if node is not None else node_or_tier
            resolved_tier = model_tier or "default"

        return _TELEMETRY_SCOPE.set(
            {
                "state": resolved_state,
                "agent_name": resolved_agent,
                "node": resolved_node,
                "model_tier": resolved_tier,
                "records": [],
            }
        )

    def end_telemetry_scope(
        self, token: Optional[contextvars.Token] = None
    ) -> List[LLMCallTelemetry]:
        """Đóng scope hiện tại, đồng bộ an toàn vào state (0% double-recording) và trả về danh sách thu thập được."""
        scope = _TELEMETRY_SCOPE.get()
        records = list(scope.get("records", [])) if scope else []
        scoped_state = scope.get("state") if scope else None
        if scoped_state is not None and records:
            for entry in records:
                self._attach_telemetry_to_state(scoped_state, entry)
        if token is not None:
            try:
                _TELEMETRY_SCOPE.reset(token)
            except ValueError:
                _TELEMETRY_SCOPE.set(None)
        else:
            _TELEMETRY_SCOPE.set(None)
        return records

    @contextlib.contextmanager
    def telemetry_scope(
        self,
        state_or_agent: Optional[Any] = None,
        agent_name_or_node: Optional[str] = None,
        node_or_tier: Optional[str] = None,
        *,
        state: Optional[Any] = None,
        incident_state: Optional[Any] = None,
        agent_name: Optional[str] = None,
        node: Optional[str] = None,
        model_tier: Optional[str] = None,
    ) -> Iterator[List[LLMCallTelemetry]]:
        """Context manager mở và đóng ContextVar telemetry scope tự động."""
        token = self.begin_telemetry_scope(
            state_or_agent,
            agent_name_or_node,
            node_or_tier,
            state=state,
            incident_state=incident_state,
            agent_name=agent_name,
            node=node,
            model_tier=model_tier,
        )
        scope = _TELEMETRY_SCOPE.get()
        records_ref: List[LLMCallTelemetry] = scope["records"] if scope is not None else []
        try:
            yield records_ref
        finally:
            self.end_telemetry_scope(token)

    @staticmethod
    def _attach_telemetry_to_state(target_state: Any, entry: LLMCallTelemetry) -> None:
        if target_state is None:
            return
        try:
            if hasattr(target_state, "record_llm_telemetry"):
                target_state.record_llm_telemetry(entry)
            elif hasattr(target_state, "llm_telemetry") and isinstance(
                target_state.llm_telemetry, list
            ):
                if not any(
                    getattr(x, "call_id", None) == entry.call_id
                    for x in target_state.llm_telemetry
                ):
                    target_state.llm_telemetry.append(entry)
        except Exception as exc:
            logger.debug(f"Could not attach telemetry to incident_state: {exc}")

    @staticmethod
    def _estimate_tokens(text: Optional[str]) -> int:
        if not text:
            return 0
        return max(1, len(str(text)) // 4)

    def _record_telemetry(
        self,
        *,
        provider_used: str,
        model: str,
        latency_ms: float,
        prompt_text: str = "",
        completion_text: str = "",
        usage: Optional[Dict[str, Any]] = None,
        model_tier: str = "default",
        agent_name: Optional[str] = None,
        node: Optional[str] = None,
        structured_attempts: int = 1,
        schema_valid: bool = True,
        schema_name: Optional[str] = None,
        tool_calls_count: int = 0,
        success: bool = True,
        fallback_reason: Optional[str] = None,
        incident_state: Optional[Any] = None,
    ) -> LLMCallTelemetry:
        scope = _TELEMETRY_SCOPE.get()
        eff_agent = agent_name or (scope.get("agent_name") if scope else None) or "Unknown"
        eff_node = node or (scope.get("node") if scope else None)
        eff_tier = (
            model_tier
            if (model_tier and model_tier != "default")
            else ((scope.get("model_tier") if scope else None) or model_tier or "default")
        )

        usage_dict = usage or {}
        prompt_tokens = int(usage_dict.get("prompt_tokens") or 0)
        completion_tokens = int(usage_dict.get("completion_tokens") or 0)
        total_tokens = int(usage_dict.get("total_tokens") or 0)
        estimated = bool(usage_dict.get("usage_estimated", False))
        if prompt_tokens == 0 and completion_tokens == 0 and (prompt_text or completion_text):
            prompt_tokens = self._estimate_tokens(prompt_text) if prompt_text else 1
            completion_tokens = self._estimate_tokens(completion_text) if completion_text else 0
            total_tokens = prompt_tokens + completion_tokens
            estimated = True
        elif total_tokens == 0:
            total_tokens = prompt_tokens + completion_tokens

        entry = LLMCallTelemetry(
            agent_name=eff_agent,
            node=eff_node,
            model_tier=eff_tier,
            provider_used=provider_used,
            model=model,
            latency_ms=round(max(0.0, float(latency_ms)), 2),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            usage_estimated=estimated,
            structured_attempts=max(0, int(structured_attempts)),
            self_corrected=structured_attempts > 1,
            schema_valid=schema_valid,
            schema_name=schema_name,
            tool_calls_count=max(0, int(tool_calls_count)),
            success=success,
            fallback_reason=fallback_reason,
        )

        with self._lock:
            self.last_telemetry = entry
            self.telemetry_history.append(entry)
            if len(self.telemetry_history) > 500:
                self.telemetry_history = self.telemetry_history[-500:]

        if scope is not None:
            scope["records"].append(entry)

        target_state = (
            incident_state
            if incident_state is not None
            else (scope.get("state") if scope is not None else None)
        )
        if target_state is not None:
            self._attach_telemetry_to_state(target_state, entry)

        return entry

    def get_telemetry(self) -> List[LLMCallTelemetry]:
        with self._lock:
            return list(self.telemetry_history)

    def get_telemetry_summary(self) -> Dict[str, Any]:
        with self._lock:
            records = list(self.telemetry_history)
        total = len(records)
        if total == 0:
            return {
                "total_calls": 0,
                "live_calls": 0,
                "fallback_calls": 0,
                "self_correction_calls": 0,
                "tool_calls_total": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "avg_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
                "providers": {},
                "last_provider": self.get_active_provider(),
            }
        providers: Dict[str, int] = {}
        for r in records:
            providers[r.provider_used] = providers.get(r.provider_used, 0) + 1
        sorted_lat = sorted(r.latency_ms for r in records)
        p95_idx = min(len(sorted_lat) - 1, max(0, int(round(0.95 * (len(sorted_lat) - 1)))))
        return {
            "total_calls": total,
            "live_calls": sum(
                1
                for r in records
                if r.provider_used not in {"deterministic", "skipped_tiered"} and r.success
            ),
            "fallback_calls": sum(
                1
                for r in records
                if r.fallback_reason is not None or r.provider_used == "deterministic"
            ),
            "self_correction_calls": sum(1 for r in records if r.self_corrected),
            "tool_calls_total": sum(r.tool_calls_count for r in records),
            "prompt_tokens": sum(r.prompt_tokens for r in records),
            "completion_tokens": sum(r.completion_tokens for r in records),
            "total_tokens": sum(r.total_tokens for r in records),
            "avg_latency_ms": round(sum(r.latency_ms for r in records) / total, 2),
            "p95_latency_ms": round(sorted_lat[p95_idx], 2),
            "providers": providers,
            "last_provider": records[-1].provider_used,
        }

    # =========================================================================
    # TẠO PHẢN HỒI TEXT & STREAMING (HYBRID FAILOVER)
    # =========================================================================
    @staticmethod
    def _extract_prompt_from_messages(
        prompt: Optional[str], messages: Optional[List[Dict[str, Any]]]
    ) -> str:
        if prompt:
            return prompt
        if not messages:
            return ""
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "user" and msg.get("content"):
                return str(msg.get("content", ""))
        return "\n".join(
            str(m.get("content", ""))
            for m in messages
            if isinstance(m, dict) and m.get("content")
        )

    def generate_response(
        self,
        prompt: Optional[str] = "",
        system_prompt: Optional[str] = None,
        stream: bool = False,
        incident_state: Optional[Any] = None,
        response_format: Optional[Dict[str, Any]] = None,
        *,
        messages: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        model_tier: str = "default",
        model_override: Optional[str] = None,
        agent_name: Optional[str] = None,
        _record_telemetry: bool = True,
    ) -> Union[str, Iterator[str]]:
        """Tạo phản hồi từ LLM hoặc Fallback Engine."""
        raw_prompt = prompt or ""
        effective_prompt = self._extract_prompt_from_messages(raw_prompt, messages)
        telemetry_prompt_text = (
            "\n".join(
                str(m.get("content", ""))
                for m in messages
                if isinstance(m, dict) and m.get("content")
            )
            if messages
            else effective_prompt
        )
        if raw_prompt and messages and raw_prompt not in telemetry_prompt_text:
            telemetry_prompt_text = f"{telemetry_prompt_text}\n{raw_prompt}".strip()

        system_prompt = system_prompt or (
            "Bạn là Trợ lý SOC, chuyên gia an ninh mạng cấp cao phục vụ phân tích điều tra số "
            "(DFIR) và hỗ trợ chuyên viên SOC ra quyết định phản ứng sự cố."
        )
        t_start = time.perf_counter()
        tid = threading.get_ident()
        with self._lock:
            self._thread_usage.pop(tid, None)

        def _finalize(
            result: Union[str, Iterator[str]],
            used_provider: str,
            used_model: str,
            fb_reason: Optional[str] = None,
        ) -> Union[str, Iterator[str]]:
            with self._lock:
                self.last_used_provider = used_provider
                usage = self._thread_usage.pop(tid, {}) if _record_telemetry else {}
            if _record_telemetry:
                elapsed_ms = (time.perf_counter() - t_start) * 1000.0
                completion_preview = result if isinstance(result, str) else ""
                self._record_telemetry(
                    provider_used=used_provider,
                    model=used_model,
                    latency_ms=elapsed_ms,
                    prompt_text=telemetry_prompt_text or effective_prompt,
                    completion_text=completion_preview,
                    usage=usage,
                    model_tier=model_tier,
                    agent_name=agent_name,
                    success=True,
                    fallback_reason=fb_reason,
                    incident_state=incident_state,
                )
            return result

        # 1. Chế độ cưỡng bức Deterministic
        if self.provider_mode == "deterministic":
            res = self._deterministic_cot_generate(
                prompt=effective_prompt,
                system_prompt=system_prompt,
                stream=stream,
                incident_state=incident_state,
                response_format=response_format,
            )
            return _finalize(res, "deterministic", "Deterministic-CoT")

        # 2. Chế độ cưỡng bức Ollama
        if self.provider_mode == "ollama":
            ollama_mdl = self.resolve_model("ollama", model_tier=model_tier, model_override=model_override)
            try:
                if self._is_circuit_open("ollama"):
                    raise requests.ConnectionError(
                        self._circuit_open_reason.get("ollama", "Ollama circuit breaker open")
                    )
                res = self._call_ollama(
                    raw_prompt,
                    system_prompt,
                    stream=stream,
                    response_format=response_format,
                    model_override=ollama_mdl,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout,
                )
                with self._lock:
                    self.last_error = None
                return _finalize(res, "ollama", ollama_mdl)
            except Exception as e:
                if self._is_connection_error(e):
                    self._trip_circuit_breaker("ollama", str(e))
                with self._lock:
                    self.last_error = f"Ollama: {e}"
                logger.warning(f"Ollama provider failed: {e}")
                if self.enable_fallback:
                    res = self._deterministic_cot_generate(
                        effective_prompt,
                        system_prompt,
                        stream=stream,
                        incident_state=incident_state,
                        response_format=response_format,
                    )
                    return _finalize(res, "deterministic", "Deterministic-CoT", fb_reason=f"Ollama: {e}")
                with self._lock:
                    self.last_used_provider = None
                raise

        # 3. Chế độ cưỡng bức hoặc tự động OpenRouter/OmniRouter
        if self.provider_mode in ("auto", "omnirouter", "openrouter"):
            primary_name = "openrouter" if self.provider_mode == "openrouter" else "omnirouter"
            primary_mdl = self.resolve_model(primary_name, model_tier=model_tier, model_override=model_override)
            primary_err: Optional[Exception] = None
            try:
                if self._is_circuit_open("omnirouter"):
                    raise requests.ConnectionError(
                        self._circuit_open_reason.get("omnirouter", "OmniRouter circuit breaker open")
                    )
                res = self._call_openrouter(
                    raw_prompt,
                    system_prompt,
                    stream=stream,
                    response_format=response_format,
                    model_override=primary_mdl,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout,
                )
                with self._lock:
                    self.last_error = None
                return _finalize(res, primary_name, primary_mdl)
            except Exception as e:
                primary_err = e
                if self._is_connection_error(e):
                    self._trip_circuit_breaker("omnirouter", str(e))
                with self._lock:
                    self.last_error = f"OmniRouter error: {e}"
                logger.warning(f"OpenRouter/OmniRouter call failed: {e}")
                if not self.enable_fallback:
                    with self._lock:
                        self.last_used_provider = None
                    raise

            # Thử chuyển tiếp sang Local Ollama
            ollama_mdl = self.resolve_model("ollama", model_tier=model_tier, model_override=model_override)
            ollama_err: Optional[Exception] = None
            try:
                if self._is_circuit_open("ollama"):
                    raise requests.ConnectionError(
                        self._circuit_open_reason.get("ollama", "Ollama circuit breaker open")
                    )
                logger.info("Falling back to Local Ollama...")
                res = self._call_ollama(
                    raw_prompt,
                    system_prompt,
                    stream=stream,
                    response_format=response_format,
                    model_override=ollama_mdl,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout,
                )
                return _finalize(
                    res,
                    "ollama",
                    ollama_mdl,
                    fb_reason=f"{primary_name}: {primary_err}",
                )
            except Exception as oe:
                ollama_err = oe
                if self._is_connection_error(oe):
                    self._trip_circuit_breaker("ollama", str(oe))
                combined_err = f"OmniRouter: {primary_err} | Ollama: {ollama_err}"
                with self._lock:
                    self.last_error = combined_err
                logger.warning(f"Local Ollama also failed: {ollama_err}")

            # Chuyển về Tier 3 Deterministic CoT Engine
            logger.info("Falling back to Tier 3 Deterministic CoT Engine...")
            res = self._deterministic_cot_generate(
                effective_prompt,
                system_prompt,
                stream=stream,
                incident_state=incident_state,
                response_format=response_format,
            )
            return _finalize(
                res,
                "deterministic",
                "Deterministic-CoT",
                fb_reason=f"OmniRouter: {primary_err} | Ollama: {ollama_err}",
            )

        # Mặc định fallback
        res = self._deterministic_cot_generate(
            effective_prompt,
            system_prompt,
            stream=stream,
            incident_state=incident_state,
            response_format=response_format,
        )
        return _finalize(
            res,
            "deterministic",
            "Deterministic-CoT",
            fb_reason=f"Unsupported provider_mode: {self.provider_mode}",
        )

    def stream_response(
        self,
        prompt: Optional[str] = "",
        system_prompt: Optional[str] = None,
        incident_state: Optional[Any] = None,
        response_format: Optional[Dict[str, Any]] = None,
        *,
        messages: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        model_tier: str = "default",
        model_override: Optional[str] = None,
        agent_name: Optional[str] = None,
    ) -> Iterator[str]:
        """Phương thức tiện ích để stream phản hồi từng phần (Token Chunk Generator)."""
        res = self.generate_response(
            prompt=prompt,
            system_prompt=system_prompt,
            stream=True,
            incident_state=incident_state,
            response_format=response_format,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            model_tier=model_tier,
            model_override=model_override,
            agent_name=agent_name,
        )
        if isinstance(res, str):
            yield res
        else:
            yield from res

    # =========================================================================
    # OPENAI-COMPATIBLE TOOL CALLING (CHAT COMPLETION)
    # =========================================================================
    @staticmethod
    def _normalize_tool_calls(raw_tool_calls: Any) -> List[Dict[str, Any]]:
        """Chuẩn hóa danh sách tool_calls từ OpenAI/OmniRouter hoặc Ollama."""
        if not isinstance(raw_tool_calls, list):
            return []
        normalized: List[Dict[str, Any]] = []
        for idx, tc in enumerate(raw_tool_calls):
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            name = fn.get("name") or tc.get("name") or ""
            if not name:
                continue
            raw_args = fn.get("arguments") if "arguments" in fn else tc.get("arguments", "{}")
            if raw_args is None:
                norm_args: Any = "{}"
            elif isinstance(raw_args, (str, dict)):
                norm_args = raw_args
            else:
                norm_args = json.dumps(raw_args, ensure_ascii=False)
            call_id = tc.get("id") or f"call_{idx + 1}"
            normalized.append(
                {
                    "id": str(call_id),
                    "type": str(tc.get("type") or "function"),
                    "function": {
                        "name": str(name),
                        "arguments": norm_args,
                    },
                }
            )
        return normalized

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        *,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        response_format: Optional[Dict[str, Any]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        model_tier: str = "default",
        model_override: Optional[str] = None,
        incident_state: Optional[Any] = None,
        agent_name: Optional[str] = None,
    ) -> LLMCompletionResult:
        """Gọi Chat Completion hỗ trợ OpenAI-compatible Tool Calling và fallback an toàn."""
        t_start = time.perf_counter()
        default_sys = (
            "Bạn là Trợ lý SOC, chuyên gia an ninh mạng cấp cao phục vụ phân tích điều tra số "
            "(DFIR) và hỗ trợ chuyên viên SOC ra quyết định phản ứng sự cố."
        )
        normalized_messages = self._build_messages("", default_sys, messages)
        last_user_prompt = self._extract_prompt_from_messages("", normalized_messages)
        prompt_text_for_est = "\n".join(
            str(m.get("content", ""))
            for m in normalized_messages
            if isinstance(m, dict) and m.get("content")
        )

        def _build_result(
            content: str,
            tool_calls: List[Dict[str, Any]],
            finish_reason: Optional[str],
            used_provider: str,
            used_model: str,
            usage: Optional[Dict[str, Any]] = None,
            fb_reason: Optional[str] = None,
        ) -> LLMCompletionResult:
            with self._lock:
                self.last_used_provider = used_provider
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            comp_preview = content or (
                json.dumps(tool_calls, ensure_ascii=False) if tool_calls else ""
            )
            telemetry = self._record_telemetry(
                provider_used=used_provider,
                model=used_model,
                latency_ms=elapsed_ms,
                prompt_text=prompt_text_for_est or last_user_prompt,
                completion_text=comp_preview,
                usage=usage,
                model_tier=model_tier,
                agent_name=agent_name,
                tool_calls_count=len(tool_calls),
                success=True,
                fallback_reason=fb_reason,
                incident_state=incident_state,
            )
            return LLMCompletionResult(
                content=content or "",
                tool_calls=tool_calls,
                finish_reason=finish_reason,
                provider_used=used_provider,
                model=used_model,
                telemetry=telemetry,
            )

        # 1. Chế độ cưỡng bức Deterministic
        if self.provider_mode == "deterministic":
            det_res = self._deterministic_cot_generate(
                prompt=last_user_prompt,
                system_prompt=default_sys,
                stream=False,
                incident_state=incident_state,
                response_format=response_format,
            )
            det_text = det_res if isinstance(det_res, str) else "".join(list(det_res))
            return _build_result(
                content=det_text,
                tool_calls=[],
                finish_reason="stop",
                used_provider="deterministic",
                used_model="Deterministic-CoT",
            )

        # 2. Chế độ cưỡng bức Ollama
        if self.provider_mode == "ollama":
            ollama_mdl = self.resolve_model(
                "ollama", model_tier=model_tier, model_override=model_override
            )
            try:
                if self._is_circuit_open("ollama"):
                    raise requests.ConnectionError(
                        self._circuit_open_reason.get("ollama", "Ollama circuit breaker open")
                    )
                content, t_calls, fin_reason, usage, tools_fb = self._call_ollama_chat_completion(
                    messages=normalized_messages,
                    model_override=ollama_mdl,
                    tools=tools,
                    response_format=response_format,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout,
                )
                with self._lock:
                    self.last_error = None
                return _build_result(
                    content=content,
                    tool_calls=t_calls,
                    finish_reason=fin_reason,
                    used_provider="ollama",
                    used_model=ollama_mdl,
                    usage=usage,
                    fb_reason=tools_fb,
                )
            except Exception as e:
                if self._is_connection_error(e):
                    self._trip_circuit_breaker("ollama", str(e))
                with self._lock:
                    self.last_error = f"Ollama: {e}"
                logger.warning(f"Ollama chat_completion failed: {e}")
                if self.enable_fallback:
                    det_res = self._deterministic_cot_generate(
                        prompt=last_user_prompt,
                        system_prompt=default_sys,
                        stream=False,
                        incident_state=incident_state,
                        response_format=response_format,
                    )
                    det_text = det_res if isinstance(det_res, str) else "".join(list(det_res))
                    return _build_result(
                        content=det_text,
                        tool_calls=[],
                        finish_reason="stop",
                        used_provider="deterministic",
                        used_model="Deterministic-CoT",
                        fb_reason=f"Ollama: {e}",
                    )
                with self._lock:
                    self.last_used_provider = None
                raise

        # 3. Chế độ auto / omnirouter / openrouter
        if self.provider_mode in ("auto", "omnirouter", "openrouter"):
            primary_name = "openrouter" if self.provider_mode == "openrouter" else "omnirouter"
            primary_mdl = self.resolve_model(
                primary_name, model_tier=model_tier, model_override=model_override
            )
            primary_err: Optional[Exception] = None
            try:
                if self._is_circuit_open("omnirouter"):
                    raise requests.ConnectionError(
                        self._circuit_open_reason.get(
                            "omnirouter", "OmniRouter circuit breaker open"
                        )
                    )
                content, t_calls, fin_reason, usage, tools_fb = (
                    self._call_openrouter_chat_completion(
                        messages=normalized_messages,
                        model_override=primary_mdl,
                        tools=tools,
                        tool_choice=tool_choice,
                        response_format=response_format,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        timeout=timeout,
                    )
                )
                with self._lock:
                    self.last_error = None
                return _build_result(
                    content=content,
                    tool_calls=t_calls,
                    finish_reason=fin_reason,
                    used_provider=primary_name,
                    used_model=primary_mdl,
                    usage=usage,
                    fb_reason=tools_fb,
                )
            except Exception as e:
                primary_err = e
                if self._is_connection_error(e):
                    self._trip_circuit_breaker("omnirouter", str(e))
                with self._lock:
                    self.last_error = f"OmniRouter error: {e}"
                logger.warning(f"OmniRouter/OpenRouter chat_completion failed: {e}")
                if not self.enable_fallback:
                    with self._lock:
                        self.last_used_provider = None
                    raise

            # Failover sang Local Ollama
            ollama_mdl = self.resolve_model(
                "ollama", model_tier=model_tier, model_override=model_override
            )
            ollama_err: Optional[Exception] = None
            try:
                if self._is_circuit_open("ollama"):
                    raise requests.ConnectionError(
                        self._circuit_open_reason.get("ollama", "Ollama circuit breaker open")
                    )
                content, t_calls, fin_reason, usage, tools_fb = self._call_ollama_chat_completion(
                    messages=normalized_messages,
                    model_override=ollama_mdl,
                    tools=tools,
                    response_format=response_format,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout,
                )
                fb_msg = tools_fb or f"{primary_name}: {primary_err}"
                return _build_result(
                    content=content,
                    tool_calls=t_calls,
                    finish_reason=fin_reason,
                    used_provider="ollama",
                    used_model=ollama_mdl,
                    usage=usage,
                    fb_reason=fb_msg,
                )
            except Exception as oe:
                ollama_err = oe
                if self._is_connection_error(oe):
                    self._trip_circuit_breaker("ollama", str(oe))
                combined_err = f"OmniRouter: {primary_err} | Ollama: {ollama_err}"
                with self._lock:
                    self.last_error = combined_err
                logger.warning(f"Local Ollama chat_completion also failed: {ollama_err}")

            # Failover về Tier 3 Deterministic
            det_res = self._deterministic_cot_generate(
                prompt=last_user_prompt,
                system_prompt=default_sys,
                stream=False,
                incident_state=incident_state,
                response_format=response_format,
            )
            det_text = det_res if isinstance(det_res, str) else "".join(list(det_res))
            return _build_result(
                content=det_text,
                tool_calls=[],
                finish_reason="stop",
                used_provider="deterministic",
                used_model="Deterministic-CoT",
                fb_reason=f"OmniRouter: {primary_err} | Ollama: {ollama_err}",
            )

        det_res = self._deterministic_cot_generate(
            prompt=last_user_prompt,
            system_prompt=default_sys,
            stream=False,
            incident_state=incident_state,
            response_format=response_format,
        )
        det_text = det_res if isinstance(det_res, str) else "".join(list(det_res))
        return _build_result(
            content=det_text,
            tool_calls=[],
            finish_reason="stop",
            used_provider="deterministic",
            used_model="Deterministic-CoT",
            fb_reason=f"Unsupported provider_mode: {self.provider_mode}",
        )

    # =========================================================================
    # STRUCTURED OUTPUT & JSON MODE ENGINE (PYDANTIC V2)
    # =========================================================================
    @staticmethod
    def _serialize_structured_obj(obj: Any) -> str:
        if obj is None:
            return "{}"
        if hasattr(obj, "model_dump_json") and callable(obj.model_dump_json):
            try:
                return obj.model_dump_json()
            except Exception:
                pass
        try:
            return json.dumps(obj, default=str, ensure_ascii=False)
        except Exception:
            return str(obj)

    def generate_structured_output(
        self,
        prompt: str,
        schema_class: Any,
        system_prompt: Optional[str] = None,
        incident_state: Optional[Any] = None,
        *,
        messages: Optional[List[Dict[str, Any]]] = None,
        model_tier: str = "default",
        model_override: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
        agent_name: Optional[str] = None,
    ) -> Any:
        """Tạo phản hồi chuẩn hóa theo định dạng Structured Output (JSON Mode) và xác thực qua schema_class."""
        t_start = time.perf_counter()
        schema_name = getattr(schema_class, "__name__", str(schema_class))
        tid = threading.get_ident()

        def _record_struct_telemetry(
            *,
            provider_used: str,
            model: str,
            attempts: int,
            schema_valid: bool,
            fb_reason: Optional[str],
            prompt_text: str,
            completion_text: str,
            usage_acc: Optional[Dict[str, int]] = None,
        ) -> None:
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            self._record_telemetry(
                provider_used=provider_used,
                model=model,
                latency_ms=elapsed_ms,
                prompt_text=prompt_text,
                completion_text=completion_text,
                usage=usage_acc,
                model_tier=model_tier,
                agent_name=agent_name,
                structured_attempts=attempts,
                schema_valid=schema_valid,
                schema_name=schema_name,
                success=True,
                fallback_reason=fb_reason,
                incident_state=incident_state,
            )

        # 1. Chế độ cưỡng bức Deterministic
        if self.provider_mode == "deterministic":
            with self._lock:
                self.last_used_provider = "deterministic"
            out = self._build_default_structured_output(schema_class, incident_state)
            _record_struct_telemetry(
                provider_used="deterministic",
                model="Deterministic-CoT",
                attempts=1,
                schema_valid=True,
                fb_reason="provider_mode=deterministic",
                prompt_text=prompt,
                completion_text=self._serialize_structured_obj(out),
            )
            return out

        # 2. Xây dựng prompt kèm chỉ dẫn schema
        sys_prompt = system_prompt or (
            "Bạn là Trợ lý SOC, chuyên gia an ninh mạng cấp cao phục vụ phân tích điều tra số "
            "(DFIR) và hỗ trợ chuyên viên SOC ra quyết định phản ứng sự cố. "
            "Bạn PHẢI chỉ phản hồi DUY NHẤT một chuỗi JSON hợp lệ tuân thủ cấu trúc schema "
            "được yêu cầu, không kèm bất kỳ lời dẫn hay văn bản giải thích nào ngoài JSON."
        )

        schema_json_str = ""
        if hasattr(schema_class, "model_json_schema"):
            try:
                schema_json_str = json.dumps(
                    schema_class.model_json_schema(), ensure_ascii=False, indent=2
                )
            except Exception as e:
                logger.debug(f"Could not dump model_json_schema: {e}")

        prompt_with_schema = prompt
        if schema_json_str:
            prompt_with_schema = (
                f"{prompt}\n\n"
                f"[YÊU CẦU ĐỊNH DẠNG JSON SCHEMA]:\n"
                f"Phản hồi PHẢI tuân thủ 100% theo JSON Schema sau:\n"
                f"{schema_json_str}"
            )

        usage_acc: Dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        def _accumulate_usage() -> None:
            with self._lock:
                u = self._thread_usage.pop(tid, {})
            for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
                usage_acc[k] += int(u.get(k) or 0)

        # 3. Gọi LLM lần 1 với response_format={"type": "json_object"}
        raw_text: Optional[str] = None
        try:
            raw_res = self.generate_response(
                prompt=prompt_with_schema,
                system_prompt=sys_prompt,
                stream=False,
                incident_state=incident_state,
                response_format={"type": "json_object"},
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                model_tier=model_tier,
                model_override=model_override,
                agent_name=agent_name,
                _record_telemetry=False,
            )
            _accumulate_usage()
            if self.last_used_provider == "deterministic":
                out = self._build_default_structured_output(schema_class, incident_state)
                _record_struct_telemetry(
                    provider_used="deterministic",
                    model="Deterministic-CoT",
                    attempts=1,
                    schema_valid=True,
                    fb_reason=self.last_error or "fallback_to_deterministic",
                    prompt_text=prompt_with_schema,
                    completion_text=self._serialize_structured_obj(out),
                )
                return out
            raw_text = raw_res if isinstance(raw_res, str) else "".join(list(raw_res))
        except Exception as llm_err:
            logger.warning(f"LLM call failed during generate_structured_output: {llm_err}")
            if self.enable_fallback:
                with self._lock:
                    self.last_used_provider = "deterministic"
                out = self._build_default_structured_output(schema_class, incident_state)
                _record_struct_telemetry(
                    provider_used="deterministic",
                    model="Deterministic-CoT",
                    attempts=1,
                    schema_valid=False,
                    fb_reason=str(llm_err),
                    prompt_text=prompt_with_schema,
                    completion_text=self._serialize_structured_obj(out),
                )
                return out
            raise

        used_prov = self.last_used_provider or "omnirouter"
        used_mdl = self.resolve_model(
            used_prov, model_tier=model_tier, model_override=model_override
        )

        # 4. Xác thực dữ liệu trả về lần 1
        first_err: Optional[Exception] = None
        try:
            parsed = self._parse_and_validate(schema_class, raw_text)
            _record_struct_telemetry(
                provider_used=used_prov,
                model=used_mdl,
                attempts=1,
                schema_valid=True,
                fb_reason=self.last_error if used_prov == "ollama" else None,
                prompt_text=prompt_with_schema,
                completion_text=raw_text or "",
                usage_acc=usage_acc,
            )
            return parsed
        except (ValidationError, json.JSONDecodeError, ValueError, Exception) as val_err:
            first_err = val_err
            logger.warning(
                f"JSON validation failed for schema {schema_name}: {val_err}. "
                f"Initiating Self-Correction loop..."
            )

        # 5. Kích hoạt cơ chế Self-Correction (gửi lại 1 lần prompt yêu cầu sửa JSON)
        correction_prompt = (
            f"Dữ liệu JSON bạn vừa tạo không hợp lệ hoặc không khớp với schema yêu cầu.\n"
            f"Chi tiết lỗi phát sinh: {first_err}\n"
            f"Dữ liệu phản hồi bị lỗi trước đó:\n```\n{raw_text}\n```\n\n"
            f"Hãy sửa lại và CHỈ trả về duy nhất một chuỗi JSON hợp lệ tuân thủ cấu trúc schema sau:\n"
            f"{schema_json_str if schema_json_str else str(schema_class)}\n\n"
            f"Yêu cầu nghiệp vụ ban đầu: {prompt}"
        )

        try:
            corrected_res = self.generate_response(
                prompt=correction_prompt,
                system_prompt=sys_prompt,
                stream=False,
                incident_state=incident_state,
                response_format={"type": "json_object"},
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                model_tier=model_tier,
                model_override=model_override,
                agent_name=agent_name,
                _record_telemetry=False,
            )
            _accumulate_usage()
            if self.last_used_provider == "deterministic":
                out = self._build_default_structured_output(schema_class, incident_state)
                _record_struct_telemetry(
                    provider_used="deterministic",
                    model="Deterministic-CoT",
                    attempts=2,
                    schema_valid=False,
                    fb_reason=self.last_error or str(first_err),
                    prompt_text=prompt_with_schema,
                    completion_text=raw_text or self._serialize_structured_obj(out),
                    usage_acc=usage_acc,
                )
                return out

            corrected_text = (
                corrected_res if isinstance(corrected_res, str) else "".join(list(corrected_res))
            )
            parsed = self._parse_and_validate(schema_class, corrected_text)
            used_prov2 = self.last_used_provider or used_prov
            used_mdl2 = self.resolve_model(
                used_prov2, model_tier=model_tier, model_override=model_override
            )
            _record_struct_telemetry(
                provider_used=used_prov2,
                model=used_mdl2,
                attempts=2,
                schema_valid=True,
                fb_reason=self.last_error if used_prov2 == "ollama" else None,
                prompt_text=prompt_with_schema + "\n" + correction_prompt,
                completion_text=(raw_text or "") + "\n" + corrected_text,
                usage_acc=usage_acc,
            )
            return parsed
        except Exception as corr_err:
            logger.warning(f"Self-correction failed for {schema_name}: {corr_err}.")
            if self.enable_fallback:
                logger.info("Falling back to deterministic structured output generator...")
                with self._lock:
                    self.last_used_provider = "deterministic"
                out = self._build_default_structured_output(schema_class, incident_state)
                _record_struct_telemetry(
                    provider_used="deterministic",
                    model="Deterministic-CoT",
                    attempts=2,
                    schema_valid=False,
                    fb_reason=f"self_correction_failed: {corr_err}",
                    prompt_text=prompt_with_schema,
                    completion_text=raw_text or self._serialize_structured_obj(out),
                    usage_acc=usage_acc,
                )
                return out
            raise

    def _parse_and_validate(self, schema_class: Any, raw_text: str) -> Any:
        """Parse và validate chuỗi JSON theo schema_class."""
        clean_json = _extract_json_str(raw_text)
        if not clean_json:
            raise ValueError("Không tìm thấy nội dung JSON hợp lệ trong chuỗi phản hồi.")

        # Trường hợp schema_class là dict hoặc Dict
        if (
            schema_class is dict
            or schema_class == Dict[str, Any]
            or (isinstance(schema_class, type) and issubclass(schema_class, dict))
        ):
            return json.loads(clean_json)

        # Trường hợp Pydantic v2 model_validate_json
        if hasattr(schema_class, "model_validate_json"):
            return schema_class.model_validate_json(clean_json)

        # Trường hợp Pydantic v1 / fallback model_validate
        if hasattr(schema_class, "model_validate"):
            parsed_dict = json.loads(clean_json)
            return schema_class.model_validate(parsed_dict)

        # Trường hợp callable thông thường
        parsed_dict = json.loads(clean_json)
        if callable(schema_class):
            if isinstance(parsed_dict, dict):
                return schema_class(**parsed_dict)
            return schema_class(parsed_dict)

        return parsed_dict

    def _build_default_structured_output(
        self,
        schema_class: Any,
        incident_state: Optional[Any] = None,
    ) -> Any:
        """Tạo đối tượng fallback hợp lệ theo schema_class từ IncidentState hoặc khởi tạo mặc định an toàn."""
        # 1. Trường hợp schema_class là dict hoặc Dict
        if (
            schema_class is dict
            or schema_class == Dict[str, Any]
            or (isinstance(schema_class, type) and issubclass(schema_class, dict))
        ):
            inc_id = (
                getattr(incident_state, "incident_id", "INC-LOCAL")
                if incident_state
                else "INC-LOCAL"
            )
            status = getattr(incident_state, "status", None)
            status_val = status.value if hasattr(status, "value") else str(status or "NEW")
            triage = getattr(incident_state, "triage_result", None)
            sev = getattr(triage, "severity", None)
            sev_val = sev.value if hasattr(sev, "value") else str(sev or "MEDIUM")
            return {
                "incident_id": inc_id,
                "status": status_val,
                "severity": sev_val,
                "is_incident": True,
                "mode": "deterministic_fallback",
                "summary": "Deterministic fallback structured output",
                "attack_type": getattr(incident_state, "attack_type", "Chưa phân loại")
                if incident_state
                else "Chưa phân loại",
            }

        # 2. Xử lý các model nghiệp vụ SOC cốt lõi
        name = getattr(schema_class, "__name__", "")
        if name == "TriageOutput":
            if incident_state and getattr(incident_state, "triage_result", None):
                return incident_state.triage_result
            try:
                from src.core.schemas import TriageOutput, SeverityLevel, AttackCategory

                sev = getattr(incident_state, "severity", None) or SeverityLevel.MEDIUM
                att_cat = getattr(incident_state, "attack_category", None)
                if not isinstance(att_cat, AttackCategory):
                    att_cat = AttackCategory.UNKNOWN
                return TriageOutput(
                    is_incident=True,
                    confidence_score=0.85,
                    severity=sev,
                    summary=f"Phân loại tự động từ Deterministic CoT Fallback cho sự cố {getattr(incident_state, 'incident_id', 'INC-LOCAL')}.",
                    rule_or_model="Deterministic-CoT-Fallback",
                    attack_category=att_cat,
                    attack_type=getattr(incident_state, "attack_type", "Phát hiện bất thường SOC"),
                    primary_mitre_tactics=[],
                )
            except Exception as e:
                logger.debug(f"Direct TriageOutput fallback construction failed: {e}")

        elif name == "RootCauseAnalysis":
            if incident_state and getattr(incident_state, "rca_result", None):
                return incident_state.rca_result
            try:
                from src.core.schemas import RootCauseAnalysis

                return RootCauseAnalysis(
                    initial_access_vector="Deterministic Rule Correlation",
                    attack_timeline=["Tiếp nhận cảnh báo", "Kích hoạt phân tích dự phòng"],
                    process_tree=[],
                    high_fidelity_tree=[],
                    mitre_tactics=[],
                    root_cause_summary=f"Phân tích nguyên nhân gốc rễ dự phòng tự động cho sự cố {getattr(incident_state, 'incident_id', 'INC-LOCAL')}.",
                    confirmed_attack_type=getattr(incident_state, "attack_type", None),
                )
            except Exception as e:
                logger.debug(f"Direct RootCauseAnalysis fallback construction failed: {e}")

        elif name == "ThreatIntelEnrichment":
            if incident_state and getattr(incident_state, "threat_intel", None):
                return incident_state.threat_intel
            try:
                from src.core.schemas import ThreatIntelEnrichment

                return ThreatIntelEnrichment(
                    extracted_iocs=[],
                    related_threat_actors=[],
                    mitre_techniques=[],
                    enrichment_summary="Thông tin CTI dự phòng tự động từ bộ quy tắc cục bộ.",
                )
            except Exception as e:
                logger.debug(f"Direct ThreatIntelEnrichment fallback construction failed: {e}")

        elif name == "IncidentReport":
            if incident_state and getattr(incident_state, "final_report", None):
                return incident_state.final_report
            try:
                from src.core.schemas import IncidentReport

                inc_id = (
                    getattr(incident_state, "incident_id", "INC-LOCAL")
                    if incident_state
                    else "INC-LOCAL"
                )
                return IncidentReport(
                    report_id=f"REP-{inc_id}",
                    incident_title=f"Báo cáo điều tra sự cố {inc_id}",
                    executive_summary=f"Báo cáo tóm lược điều hành cho sự cố {inc_id} được tổng hợp bởi Fallback Engine.",
                    detailed_findings="Không có kết nối LLM ngoại vi. Toàn bộ phát hiện dựa trên quy tắc suy luận nội bộ.",
                    mitre_attack_matrix_mapping=[],
                    ioc_table=[],
                    action_plan=getattr(incident_state, "recommended_actions", [])
                    if incident_state
                    else [],
                )
            except Exception as e:
                logger.debug(f"Direct IncidentReport fallback construction failed: {e}")

        elif name == "RecommendedAction":
            try:
                from src.core.schemas import RecommendedAction, ActionType

                return RecommendedAction(
                    action_type=ActionType.ISOLATE_HOST,
                    target=getattr(incident_state, "incident_id", "HOST-01")
                    if incident_state
                    else "HOST-01",
                    description="Hành động ngăn chặn mặc định từ Fallback Engine.",
                    priority=1,
                    require_human_approval=True,
                )
            except Exception as e:
                logger.debug(f"Direct RecommendedAction fallback construction failed: {e}")

        # 3. Pydantic Model tổng quát (BaseModel)
        if isinstance(schema_class, type) and issubclass(schema_class, BaseModel):
            return self._create_default_pydantic_instance(schema_class, incident_state)

        # 4. Khởi tạo mặc định nếu callable
        if callable(schema_class):
            try:
                return schema_class()
            except Exception:
                pass

        return {}

    def _create_default_pydantic_instance(
        self,
        model_cls: Type[BaseModel],
        incident_state: Optional[Any] = None,
    ) -> Any:
        """Tạo đối tượng Pydantic mặc định hợp lệ không để xảy ra ngoại lệ."""
        # Thử khởi tạo trực tiếp không tham số
        try:
            return model_cls()
        except Exception:
            pass

        # Xây dựng dummy_data cho từng trường bắt buộc
        dummy_data: Dict[str, Any] = {}
        if hasattr(model_cls, "model_fields"):
            for field_name, field_info in model_cls.model_fields.items():
                if not field_info.is_required():
                    continue
                dummy_data[field_name] = self._resolve_default_field_value(
                    field_info, field_name, incident_state
                )

        try:
            return model_cls(**dummy_data)
        except Exception:
            # Dùng model_construct để đảm bảo 100% không văng ValidationError
            if hasattr(model_cls, "model_construct"):
                return model_cls.model_construct(**dummy_data)
            return dummy_data

    def _resolve_default_field_value(
        self,
        field_info: Any,
        field_name: str,
        incident_state: Optional[Any] = None,
    ) -> Any:
        """Sinh giá trị mặc định hợp lệ cho một trường schema Pydantic."""
        ann = field_info.annotation

        # Nếu incident_state có thuộc tính tương ứng
        if incident_state and hasattr(incident_state, field_name):
            val = getattr(incident_state, field_name)
            if val is not None:
                return val

        origin = getattr(ann, "__origin__", None)
        args = getattr(ann, "__args__", ())

        # Optional hoặc Union
        if origin is Union:
            if type(None) in args:
                return None
            non_none = [a for a in args if a is not type(None)]
            if non_none:
                ann = non_none[0]
                origin = getattr(ann, "__origin__", None)
                args = getattr(ann, "__args__", ())

        # List / Sequence
        if origin in (list, List) or ann in (list, List):
            return []

        # Dict / Mapping
        if origin in (dict, Dict) or ann in (dict, Dict):
            return {}

        # Kiểu cơ bản
        if ann is str:
            if "id" in field_name.lower():
                return (
                    getattr(incident_state, "incident_id", "DEFAULT-ID")
                    if incident_state
                    else "DEFAULT-ID"
                )
            return f"default_{field_name}"
        if ann is int:
            return 1
        if ann is float:
            return 0.5
        if ann is bool:
            return True

        # Enum
        if isinstance(ann, type) and issubclass(ann, Enum):
            members = list(ann)
            return members[0] if members else "DEFAULT"

        # Nested BaseModel
        if isinstance(ann, type) and issubclass(ann, BaseModel):
            return self._create_default_pydantic_instance(ann, incident_state)

        return None

    # =========================================================================
    # GIAO TIẾP OPENROUTER / OMNIROUTER REST API
    # =========================================================================
    @staticmethod
    def _build_messages(
        prompt: str,
        system_prompt: str,
        messages: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        if not messages:
            built_default: List[Dict[str, Any]] = []
            if system_prompt:
                built_default.append({"role": "system", "content": system_prompt})
            built_default.append({"role": "user", "content": prompt or ""})
            return built_default
        built: List[Dict[str, Any]] = []
        has_sys = any(m.get("role") == "system" for m in messages if isinstance(m, dict))
        if not has_sys and system_prompt:
            built.append({"role": "system", "content": system_prompt})
        for m in messages:
            if not isinstance(m, dict) or not m.get("role"):
                continue
            item: Dict[str, Any] = {
                "role": m["role"],
                "content": "" if m.get("content") is None else m["content"],
            }
            for extra_key in ("tool_calls", "tool_call_id", "name"):
                if extra_key in m and m[extra_key] is not None:
                    item[extra_key] = m[extra_key]
            built.append(item)
        if prompt and not (
            built and built[-1].get("role") == "user" and built[-1].get("content") == prompt
        ):
            built.append({"role": "user", "content": prompt})
        return built

    def _compute_retry_delay(self, response: requests.Response, attempt: int) -> float:
        retry_after = None
        headers = getattr(response, "headers", None)
        if isinstance(headers, dict) or hasattr(headers, "get"):
            try:
                retry_after = headers.get("Retry-After") or headers.get("retry-after")
            except Exception:
                retry_after = None
        if retry_after is not None and isinstance(retry_after, (int, float, str)):
            try:
                return min(8.0, max(0.0, float(retry_after)))
            except (TypeError, ValueError):
                pass
        jitter = random.uniform(0.0, 0.25)
        return min(8.0, self.retry_base_delay * (2 ** attempt) + jitter)

    def _post_with_retry(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json_payload: Dict[str, Any],
        timeout: float,
        stream: bool,
        provider_label: str,
        allow_status_codes: Tuple[int, ...] = (200,),
    ) -> requests.Response:
        """Gửi POST với exponential backoff CHỈ cho HTTP 429/503; không retry 500 hay ConnectionError."""
        attempts = max(1, 1 + self.max_retries)
        for attempt in range(attempts):
            post_kwargs: Dict[str, Any] = {
                "json": json_payload,
                "timeout": timeout,
                "stream": stream,
            }
            if headers is not None:
                post_kwargs["headers"] = headers

            response = requests.post(url, **post_kwargs)

            if response.status_code in allow_status_codes:
                return response

            if response.status_code in (429, 503) and attempt < attempts - 1:
                delay = self._compute_retry_delay(response, attempt)
                logger.warning(
                    f"{provider_label} returned HTTP {response.status_code}, retrying in {delay:.2f}s..."
                )
                time.sleep(delay)
                continue

            raise requests.RequestException(
                f"{provider_label} API returned error code {response.status_code}: {response.text}"
            )

        raise requests.RequestException(f"{provider_label} API failed after {attempts} attempts")

    @staticmethod
    def _extract_openai_usage(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        usage = data.get("usage")
        if not isinstance(usage, dict):
            return None
        p_tok = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
        c_tok = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
        t_tok = int(usage.get("total_tokens") or (p_tok + c_tok))
        if p_tok == 0 and c_tok == 0 and t_tok == 0:
            return None
        return {
            "prompt_tokens": p_tok,
            "completion_tokens": c_tok,
            "total_tokens": t_tok if t_tok > 0 else (p_tok + c_tok),
            "usage_estimated": False,
        }

    @staticmethod
    def _extract_ollama_usage(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        usage_obj = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        prompt_cnt = int(data.get("prompt_eval_count") or usage_obj.get("prompt_tokens") or 0)
        comp_cnt = int(data.get("eval_count") or usage_obj.get("completion_tokens") or 0)
        total_cnt = int(usage_obj.get("total_tokens") or (prompt_cnt + comp_cnt))
        if prompt_cnt == 0 and comp_cnt == 0 and total_cnt == 0:
            return None
        return {
            "prompt_tokens": prompt_cnt,
            "completion_tokens": comp_cnt,
            "total_tokens": total_cnt if total_cnt > 0 else (prompt_cnt + comp_cnt),
            "usage_estimated": False,
        }

    def _call_openrouter(
        self,
        prompt: str,
        system_prompt: str,
        stream: bool = False,
        response_format: Optional[Dict[str, Any]] = None,
        *,
        model_override: Optional[str] = None,
        messages: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Union[str, Iterator[str]]:
        """Gửi yêu cầu Chat Completions chuẩn OpenAI qua OpenRouter/OmniRouter."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://tlcn-soc.local",
            "X-Title": "TLCN Tro Ly SOC",
        }

        eff_temp = self.default_temperature if temperature is None else float(temperature)
        eff_max_tok = self.default_max_tokens if max_tokens is None else int(max_tokens)

        payload: Dict[str, Any] = {
            "model": model_override or self.model,
            "messages": self._build_messages(prompt, system_prompt, messages),
            "stream": stream,
            "temperature": eff_temp,
            "max_tokens": eff_max_tok,
        }

        if response_format is not None:
            payload["response_format"] = response_format

        response = self._post_with_retry(
            self.endpoint,
            headers=headers,
            json_payload=payload,
            timeout=self.timeout if timeout is None else float(timeout),
            stream=stream,
            provider_label="OmniRouter",
        )

        if not stream:
            data = response.json()
            parsed_usage = self._extract_openai_usage(data)
            if parsed_usage is not None:
                with self._lock:
                    self._thread_usage[threading.get_ident()] = parsed_usage
            choices = data.get("choices", [])
            if not choices:
                raise ValueError("OmniRouter response missing 'choices'")
            return choices[0].get("message", {}).get("content", "") or ""

        # Xử lý SSE Streaming
        return self._stream_sse_chunks(response)

    def _call_openrouter_chat_completion(
        self,
        *,
        messages: List[Dict[str, Any]],
        model_override: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        response_format: Optional[Dict[str, Any]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[str, List[Dict[str, Any]], Optional[str], Optional[Dict[str, Any]], Optional[str]]:
        """Gửi Chat Completion có hỗ trợ tools tới OmniRouter/OpenRouter; tự retry không tools khi HTTP 400."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://tlcn-soc.local",
            "X-Title": "TLCN Tro Ly SOC",
        }
        eff_temp = self.default_temperature if temperature is None else float(temperature)
        eff_max_tok = self.default_max_tokens if max_tokens is None else int(max_tokens)
        eff_timeout = self.timeout if timeout is None else float(timeout)

        payload: Dict[str, Any] = {
            "model": model_override or self.model,
            "messages": messages,
            "stream": False,
            "temperature": eff_temp,
            "max_tokens": eff_max_tok,
        }
        if response_format is not None:
            payload["response_format"] = response_format
        if tools:
            payload["tools"] = tools
            if tool_choice is not None:
                payload["tool_choice"] = tool_choice

        tools_fb_reason: Optional[str] = None
        allow_codes = (200, 400) if tools else (200,)
        response = self._post_with_retry(
            self.endpoint,
            headers=headers,
            json_payload=payload,
            timeout=eff_timeout,
            stream=False,
            provider_label="OmniRouter",
            allow_status_codes=allow_codes,
        )

        if response.status_code == 400 and tools:
            logger.warning(
                "OmniRouter returned HTTP 400 with tools payload; retrying once without tools..."
            )
            retry_payload = dict(payload)
            retry_payload.pop("tools", None)
            retry_payload.pop("tool_choice", None)
            tools_fb_reason = "tools_unsupported"
            response = self._post_with_retry(
                self.endpoint,
                headers=headers,
                json_payload=retry_payload,
                timeout=eff_timeout,
                stream=False,
                provider_label="OmniRouter",
                allow_status_codes=(200,),
            )

        data = response.json()
        parsed_usage = self._extract_openai_usage(data)
        choices = data.get("choices", [])
        if not choices:
            raise ValueError("OmniRouter response missing 'choices'")
        first_choice = choices[0] if isinstance(choices[0], dict) else {}
        msg = first_choice.get("message", {}) if isinstance(first_choice.get("message"), dict) else {}
        content = msg.get("content") or ""
        norm_tools = self._normalize_tool_calls(msg.get("tool_calls"))
        finish_reason = first_choice.get("finish_reason")
        if finish_reason is None and norm_tools:
            finish_reason = "tool_calls"
        return str(content), norm_tools, finish_reason, parsed_usage, tools_fb_reason

    def _stream_sse_chunks(self, response: requests.Response) -> Iterator[str]:
        """Trích xuất delta content từ luồng Server-Sent Events (SSE)."""
        for line in _iter_clean_lines(response):
            if line.startswith("data:"):
                raw_data = line[5:].strip()
                if raw_data == "[DONE]":
                    break
                try:
                    chunk_json = json.loads(raw_data)
                    delta = chunk_json.get("choices", [{}])[0].get("delta", {})
                    content = delta.get("content")
                    if content:
                        yield content
                except json.JSONDecodeError:
                    continue

    # =========================================================================
    # GIAO TIẾP LOCAL OLLAMA REST API
    # =========================================================================
    def _call_ollama(
        self,
        prompt: str,
        system_prompt: str,
        stream: bool = False,
        response_format: Optional[Dict[str, Any]] = None,
        *,
        model_override: Optional[str] = None,
        messages: Optional[List[Dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Union[str, Iterator[str]]:
        """Gửi yêu cầu Chat Completion tới Local Ollama Instance."""
        eff_temp = self.default_temperature if temperature is None else float(temperature)
        eff_max_tok = self.default_max_tokens if max_tokens is None else int(max_tokens)

        payload: Dict[str, Any] = {
            "model": model_override or self.ollama_model,
            "messages": self._build_messages(prompt, system_prompt, messages),
            "stream": stream,
            "options": {
                "temperature": eff_temp,
                "num_predict": eff_max_tok,
            },
        }

        if response_format is not None:
            if isinstance(response_format, dict):
                fmt_type = response_format.get("type", "")
                if fmt_type in ("json_object", "json") or "json" in str(fmt_type).lower():
                    payload["format"] = "json"
                elif "json_schema" in response_format:
                    schema_data = response_format.get("json_schema", {}).get("schema")
                    payload["format"] = schema_data if schema_data else "json"
                else:
                    payload["format"] = "json"
            elif isinstance(response_format, str) and "json" in response_format.lower():
                payload["format"] = "json"

        response = self._post_with_retry(
            self.ollama_url,
            headers=None,
            json_payload=payload,
            timeout=self.timeout if timeout is None else float(timeout),
            stream=stream,
            provider_label="Ollama",
        )

        if not stream:
            data = response.json()
            parsed_usage = self._extract_ollama_usage(data)
            if parsed_usage is not None:
                with self._lock:
                    self._thread_usage[threading.get_ident()] = parsed_usage
            return data.get("message", {}).get("content", "") or ""

        return self._stream_ollama_ndjson(response)

    def _call_ollama_chat_completion(
        self,
        *,
        messages: List[Dict[str, Any]],
        model_override: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        response_format: Optional[Dict[str, Any]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[str, List[Dict[str, Any]], Optional[str], Optional[Dict[str, Any]], Optional[str]]:
        """Gửi Chat Completion có hỗ trợ tools tới Local Ollama; tự retry không tools khi HTTP 400."""
        eff_temp = self.default_temperature if temperature is None else float(temperature)
        eff_max_tok = self.default_max_tokens if max_tokens is None else int(max_tokens)
        eff_timeout = self.timeout if timeout is None else float(timeout)

        payload: Dict[str, Any] = {
            "model": model_override or self.ollama_model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": eff_temp,
                "num_predict": eff_max_tok,
            },
        }
        if tools:
            payload["tools"] = tools
        if response_format is not None:
            payload["format"] = "json"

        tools_fb_reason: Optional[str] = None
        allow_codes = (200, 400) if tools else (200,)
        response = self._post_with_retry(
            self.ollama_url,
            headers=None,
            json_payload=payload,
            timeout=eff_timeout,
            stream=False,
            provider_label="Ollama",
            allow_status_codes=allow_codes,
        )

        if response.status_code == 400 and tools:
            logger.warning(
                "Ollama returned HTTP 400 with tools payload; retrying once without tools..."
            )
            retry_payload = dict(payload)
            retry_payload.pop("tools", None)
            tools_fb_reason = "tools_unsupported"
            response = self._post_with_retry(
                self.ollama_url,
                headers=None,
                json_payload=retry_payload,
                timeout=eff_timeout,
                stream=False,
                provider_label="Ollama",
                allow_status_codes=(200,),
            )

        data = response.json()
        parsed_usage = self._extract_ollama_usage(data)
        msg = data.get("message", {}) if isinstance(data.get("message"), dict) else {}
        content = msg.get("content") or ""
        norm_tools = self._normalize_tool_calls(msg.get("tool_calls"))
        finish_reason = data.get("done_reason") or ("tool_calls" if norm_tools else "stop")
        return str(content), norm_tools, finish_reason, parsed_usage, tools_fb_reason

    def _stream_ollama_ndjson(self, response: requests.Response) -> Iterator[str]:
        """Trích xuất message content từ newline-delimited JSON stream của Ollama."""
        for line in _iter_clean_lines(response):
            try:
                item = json.loads(line)
                content = item.get("message", {}).get("content", "")
                if content:
                    yield content
                if item.get("done", False):
                    break
            except json.JSONDecodeError:
                continue

    # =========================================================================
    # TIER 3: DETERMINISTIC CHAIN-OF-THOUGHT (CoT) ENGINE
    # =========================================================================
    def _deterministic_cot_generate(
        self,
        prompt: str,
        system_prompt: str,
        stream: bool = False,
        incident_state: Optional[Any] = None,
        response_format: Optional[Dict[str, Any]] = None,
    ) -> Union[str, Iterator[str]]:
        """Tự động suy luận và sinh báo cáo CoT chuẩn quy trình SOC từ IncidentState."""
        if response_format and isinstance(response_format, dict) and "json" in str(response_format).lower():
            # Hỗ trợ sinh JSON chuẩn nếu được yêu cầu
            inc_id = getattr(incident_state, "incident_id", "INC-LOCAL") if incident_state else "INC-LOCAL"
            status = getattr(incident_state, "status", None)
            status_val = status.value if hasattr(status, "value") else str(status or "NEW")
            triage = getattr(incident_state, "triage_result", None)
            sev = getattr(triage, "severity", None)
            sev_val = sev.value if hasattr(sev, "value") else str(sev or "MEDIUM")
            summary = getattr(triage, "summary", "Phát hiện sự cố từ Deterministic Fallback Engine") if triage else "Phát hiện sự cố từ Deterministic Fallback Engine"
            attack_type = getattr(incident_state, "attack_type", "Chưa phân loại") if incident_state else "Chưa phân loại"

            json_payload = {
                "incident_id": inc_id,
                "status": status_val,
                "severity": sev_val,
                "is_incident": True,
                "attack_type": attack_type,
                "summary": summary,
                "mode": "deterministic_fallback",
            }
            text = json.dumps(json_payload, ensure_ascii=False, indent=2)
        else:
            text = self._build_deterministic_text(prompt, incident_state)

        if not stream:
            return text

        # Trả về iterator chia theo từ để giả lập stream mượt mà
        def _chunk_generator():
            words = text.split(" ")
            for i, word in enumerate(words):
                yield word + (" " if i < len(words) - 1 else "")

        return _chunk_generator()

    def _build_deterministic_text(self, prompt: str, state: Optional[Any]) -> str:
        """Xây dựng nội dung phản hồi suy luận logic không cần LLM."""
        prompt_lower = prompt.lower()
        if "yêu cầu của chuyên viên soc" in prompt_lower:
            user_part = prompt_lower.split("yêu cầu của chuyên viên soc")[-1]
        else:
            user_part = prompt_lower

        is_ioc = "(lookup_ioc)" in prompt_lower or any(k in user_part for k in ["ioc", "ip", "hash", "domain", "virustotal", "cti", "độc hại"])
        is_summary = "(executive_summary)" in prompt_lower or any(k in user_part for k in ["tóm tắt", "summary", "tổng quan", "executive", "báo cáo"])
        is_rca = "(explain_rca)" in prompt_lower or any(k in user_part for k in ["rca", "nguyên nhân", "root cause", "tiến trình", "process tree", "tại sao"])
        is_action = any(k in user_part for k in ["hành động", "action", "phản ứng", "containment"])

        # 1. Thu thập thông tin từ IncidentState nếu có
        inc_id = getattr(state, "incident_id", "INC-UNKNOWN") if state else "INC-LOCAL"
        status = getattr(state, "status", None)
        status_val = status.value if hasattr(status, "value") else str(status or "UNKNOWN")
        attack_type = getattr(state, "attack_type", None) or "Chưa phân loại"

        triage = getattr(state, "triage_result", None)
        severity = getattr(triage, "severity", None)
        severity_val = severity.value if hasattr(severity, "value") else str(severity or "Chưa phân loại")
        triage_summary = getattr(triage, "summary", "Chưa có phát hiện bất thường") if triage else "Chưa có phát hiện bất thường"

        rca = getattr(state, "rca_result", None)
        threat_intel = getattr(state, "threat_intel", None)
        actions = getattr(state, "recommended_actions", []) or []

        # Kiểm tra nếu ở Live mode nhưng chưa nhận được bất kỳ log nào
        has_logs = bool(getattr(state, "raw_logs", None) or getattr(state, "parsed_events", None))
        is_live_empty = (not has_logs) and ("LIVE" in str(inc_id).upper() or status_val in ("IncidentStatus.NEW", "NEW"))

        if is_live_empty and not (triage or rca or threat_intel):
            wazuh_ip = get_wazuh_ova_ip()
            webhook_port = get_webhook_port()
            return (
                f"### [Deterministic CoT] Trạng thái Trực tiếp Wazuh OVA: Chưa nhận được Cảnh báo\n\n"
                f"- **Mã phiên sự cố:** `{inc_id}`\n"
                f"- **Trạng thái:** `Đang trực tuyến (Live Webhook Mode)`\n"
                f"- **Nhật ký nhận được:** `0 log`\n\n"
                f"ℹ️ **Hệ thống đang túc trực tại endpoint `:{webhook_port}/api/v1/wazuh-alert` nhưng máy chủ Wazuh OVA ({wazuh_ip}) chưa gửi bất kỳ cảnh báo nào sang.**\n\n"
                f"**Cách thực hiện tiếp theo:**\n"
                f"1. Tạo sự kiện an ninh trên Agent Wazuh để Wazuh Manager quét và tự động đẩy cảnh báo qua Webhook.\n"
                f"2. Hoặc nếu muốn kiểm thử quy trình điều tra ngay, hãy chọn **'📁 2. Kịch bản kiểm nghiệm mẫu (Offline Replay Datasets)'** ở menu bên trái."
            )

        # 2. Xử lý trường hợp tra cứu IoC / Tình báo CTI
        if is_ioc:
            iocs = (getattr(threat_intel, "extracted_iocs", None) or getattr(threat_intel, "indicators", [])) if threat_intel else []
            if iocs:
                ioc_lines = []
                for item in iocs[:5]:
                    ioc_type = getattr(item, "ioc_type", "IoC")
                    ioc_type_val = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
                    val = getattr(item, "value", "")
                    score = getattr(item, "reputation_score", 85)
                    mal = "ĐỘC HẠI" if getattr(item, "is_malicious", True) else "Bình thường"
                    ioc_lines.append(f"- **[{ioc_type_val}]** `{val}` | Điểm độc hại: **{score}/100** ({mal})")
                return (
                    f"### [Deterministic CoT] Tra cứu Chỉ số Tình báo Mối đe dọa (CTI & IoC)\n\n"
                    f"Hệ thống đã thu thập và đối soát các chỉ số IoC của sự cố **{inc_id}**:\n\n"
                    + "\n".join(ioc_lines)
                    + "\n\n**Khuyến nghị phản ứng:** Chặn lập tức các IP/Domain trên Gateway Firewall và phong tỏa Hash trên toàn bộ Endpoint EDR."
                )
            else:
                return (
                    f"### [Deterministic CoT] Tra cứu Chỉ số Tình báo Mối đe dọa (CTI & IoC) - {inc_id}\n\n"
                    f"ℹ️ **Không phát hiện IoC độc hại:** Sự cố hiện tại chưa ghi nhận địa chỉ IP, Domain hay Hash tệp độc hại nào cần xử lý."
                )

        # 3. Xử lý trường hợp hỏi Tóm tắt sự cố
        if is_summary:
            if not triage:
                return (
                    f"### [Deterministic CoT] Tóm tắt Sự cố ({inc_id})\n\n"
                    f"- **Mức độ nghiêm trọng:** `Chưa phân loại`\n"
                    f"- **Trạng thái xử lý:** `{status_val}`\n"
                    f"- **Tình trạng:** Sự cố mới được tiếp nhận và chưa chạy qua bước phân loại sơ bộ (Triage Agent).\n\n"
                    f"**Đề xuất hành động:** Vui lòng nhấn **'🚀 Chạy Hết'** để hệ thống Multi-Agent thực thi phân tích."
                )

            pending_count = len([a for a in actions if getattr(a, "is_approved", None) is None])
            approved_count = len([a for a in actions if getattr(a, "is_approved", False) is True])

            return (
                f"### [Deterministic CoT] Tóm tắt Sự cố ({inc_id})\n\n"
                f"- **Mức độ nghiêm trọng:** `{severity_val}`\n"
                f"- **Trạng thái xử lý:** `{status_val}`\n"
                f"- **Loại hình tấn công:** {attack_type}\n"
                f"- **Tóm tắt phát hiện:** {triage_summary}\n\n"
                f"**Tình trạng hành động ứng phó:**\n"
                f"- Đã duyệt: **{approved_count}** hành động\n"
                f"- Đang chờ thẩm định HITL: **{pending_count}** hành động\n\n"
                f"**Đề xuất hành động tiếp theo:** Chuyên viên SOC cần hoàn tất thẩm định các hành động ngăn chặn để đưa sự cố về trạng thái `CONTAINED`."
            )

        # 4. Xử lý trường hợp hỏi về Root Cause / Cây tiến trình / RCA
        if is_rca:
            if not rca:
                return (
                    f"### [Deterministic CoT] Phân tích Nguyên nhân Gốc rễ (RCA) - {inc_id}\n\n"
                    f"⚠️ **Chưa có dữ liệu RCA:** Sự cố `{inc_id}` hiện chưa hoàn tất phân tích nguyên nhân gốc rễ hoặc chưa có log tiến trình Sysmon.\n\n"
                    f"**Chỉ dẫn:** Vui lòng nhấn nút **'🚀 Chạy Hết'** hoặc **'⏭️ Từng bước'** trên thanh thao tác bên trái để kích hoạt các Agent phân tích cây tiến trình và chuỗi tấn công."
                )

            initial_vector = getattr(rca, "initial_access_vector", "Chưa xác định")
            rca_summary = getattr(rca, "root_cause_summary", "Chưa có tóm tắt nguyên nhân gốc rễ")
            tactics = getattr(rca, "mitre_tactics", [])
            process_tree = getattr(rca, "process_tree", []) or []

            tree_str = ""
            if process_tree:
                tree_str = "\n".join([
                    f"  - [{p.process_id}] {p.process_name} (Lệnh: `{p.command_line[:60]}...`)"
                    f"{' [MÃ ĐỘC GỐC]' if getattr(p, 'is_malicious_origin', False) else ''}"
                    for p in process_tree[:5]
                ])
            else:
                tree_str = "  - Không phát hiện tiến trình độc hại nào trong cây tiến trình."

            return (
                f"### [Deterministic CoT] Phân tích Nguyên nhân Gốc rễ (RCA) - {inc_id}\n\n"
                f"**1. Phương thức xâm nhập ban đầu (Initial Access):**\n"
                f"- Nhận diện: **{initial_vector}**\n\n"
                f"**2. Cây tiến trình điều tra (Process Lineage):**\n"
                f"{tree_str}\n\n"
                f"**3. Suy luận kỹ thuật (Root Cause Summary):**\n"
                f"{rca_summary}\n\n"
                f"**4. Chiến thuật MITRE ATT&CK liên quan:**\n"
                f"- {', '.join(tactics) if isinstance(tactics, list) and tactics else 'Chưa có'}\n\n"
                f"**5. Đánh giá chuyên viên:** Tiến trình gốc cần được giám sát và xử lý theo quy trình ứng phó sự cố."
            )

        # 5. Phản hồi thông tin hành động / kế hoạch ứng phó
        if is_action:
            if actions:
                action_items = []
                for act in actions:
                    act_id = getattr(act, "action_id", "ACT-XXX")
                    act_type = getattr(act, "action_type", "")
                    act_type_val = act_type.value if hasattr(act_type, "value") else str(act_type)
                    target = getattr(act, "target", "")
                    appr = getattr(act, "is_approved", None)
                    status_badge = "ĐÃ DUYỆT" if appr is True else ("TỪ CHỐI" if appr is False else "CHỜ DUYỆT")
                    action_items.append(f"- **{act_id}**: `{act_type_val}` đối tượng `{target}` -> [{status_badge}]")
                action_str = "\n".join(action_items)
            else:
                action_str = "- Không có hành động nào được ghi nhận."

            return (
                f"### [Deterministic CoT] Danh mục Hành động Ứng phó ({inc_id})\n\n"
                f"{action_str}\n\n"
                f"Chuyên viên có thể nhập: `duyệt [Mã Action]` hoặc `duyệt tất cả` để Trợ lý SOC thực thi."
            )

        # 6. Mặc định phản hồi tổng quan phân tích SOC
        if not triage:
            return (
                f"### [Deterministic CoT] Tổng quan Sự cố - {inc_id}\n\n"
                f"- **Trạng thái:** `{status_val}`\n"
                f"- **Tình trạng:** Sự cố mới tiếp nhận, chưa có kết quả phân loại từ các Agent.\n"
                f"- **Chỉ dẫn:** Nhấn **'🚀 Chạy Hết'** trên menu bên trái để kích hoạt tiến trình điều tra tự động."
            )

        return (
            f"### [Deterministic CoT] Phân tích Hỗ trợ Điều tra - {inc_id}\n\n"
            f"- **Trạng thái:** `{status_val}` | **Mức độ:** `{severity_val}`\n"
            f"- **Tóm lược:** {triage_summary}\n"
            f"- **Chỉ dẫn:** Chuyên viên có thể hỏi sâu về:\n"
            f"  1. *Nguyên nhân gốc rễ và cây tiến trình (RCA)*\n"
            f"  2. *Danh mục IoC độc hại và độ nguy hiểm (CTI)*\n"
            f"  3. *Tóm tắt sự cố*\n"
            f"  4. *Phê duyệt hoặc từ chối hành động ứng phó (HITL Approve/Reject)*"
        )


def begin_telemetry_scope(
    state_or_agent: Optional[Any] = None,
    agent_name_or_node: Optional[str] = None,
    node_or_tier: Optional[str] = None,
    *,
    state: Optional[Any] = None,
    incident_state: Optional[Any] = None,
    agent_name: Optional[str] = None,
    node: Optional[str] = None,
    model_tier: Optional[str] = None,
) -> contextvars.Token:
    """Module-level helper mở ContextVar telemetry scope."""
    if isinstance(state_or_agent, str):
        resolved_state = state if state is not None else incident_state
        resolved_agent = agent_name or state_or_agent or "Unknown"
        resolved_node = node if node is not None else agent_name_or_node
        resolved_tier = model_tier or node_or_tier or "default"
    else:
        resolved_state = (
            state_or_agent
            if state_or_agent is not None
            else (state if state is not None else incident_state)
        )
        resolved_agent = agent_name or agent_name_or_node or "Unknown"
        resolved_node = node if node is not None else node_or_tier
        resolved_tier = model_tier or "default"

    return _TELEMETRY_SCOPE.set(
        {
            "state": resolved_state,
            "agent_name": resolved_agent,
            "node": resolved_node,
            "model_tier": resolved_tier,
            "records": [],
        }
    )


def end_telemetry_scope(
    token: Optional[contextvars.Token] = None,
) -> List[LLMCallTelemetry]:
    """Module-level helper đóng ContextVar telemetry scope và trả về danh sách records."""
    scope = _TELEMETRY_SCOPE.get()
    records = list(scope.get("records", [])) if scope else []
    scoped_state = scope.get("state") if scope else None
    if scoped_state is not None and records:
        for entry in records:
            HybridLLMProvider._attach_telemetry_to_state(scoped_state, entry)
    if token is not None:
        try:
            _TELEMETRY_SCOPE.reset(token)
        except ValueError:
            _TELEMETRY_SCOPE.set(None)
    else:
        _TELEMETRY_SCOPE.set(None)
    return records


@contextlib.contextmanager
def telemetry_scope(
    state_or_agent: Optional[Any] = None,
    agent_name_or_node: Optional[str] = None,
    node_or_tier: Optional[str] = None,
    *,
    state: Optional[Any] = None,
    incident_state: Optional[Any] = None,
    agent_name: Optional[str] = None,
    node: Optional[str] = None,
    model_tier: Optional[str] = None,
) -> Iterator[List[LLMCallTelemetry]]:
    """Module-level contextmanager cho ContextVar telemetry scope."""
    token = begin_telemetry_scope(
        state_or_agent,
        agent_name_or_node,
        node_or_tier,
        state=state,
        incident_state=incident_state,
        agent_name=agent_name,
        node=node,
        model_tier=model_tier,
    )
    scope = _TELEMETRY_SCOPE.get()
    records_ref: List[LLMCallTelemetry] = scope["records"] if scope is not None else []
    try:
        yield records_ref
    finally:
        end_telemetry_scope(token)

