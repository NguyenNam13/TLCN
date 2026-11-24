# -*- coding: utf-8 -*-
"""
src/agents/llm_utils.py
Tiện ích dùng chung để gọi LLM structured output một cách an toàn cho cả 6 Agent.
Tương thích ngược với các MockLLMProvider tối giản (chỉ có `generate_response`) trong unit tests.
Hàm không bao giờ raise exception.
"""

import inspect
from typing import Any, Optional, Tuple


def _supported_kwargs(func: Any, candidates: dict) -> dict:
    """Lọc các keyword args mà `func` thực sự hỗ trợ (theo inspect.signature)."""
    try:
        params = inspect.signature(func).parameters
    except (TypeError, ValueError):
        return {}
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return dict(candidates)
    return {k: v for k, v in candidates.items() if k in params}


def invoke_structured_llm(
    llm_provider: Any,
    prompt: str,
    schema_class: Any,
    system_prompt: Optional[str] = None,
    incident_state: Optional[Any] = None,
    *,
    model_tier: str = "default",
    temperature: float = 0.1,
    max_tokens: int = 1500,
    timeout: Optional[float] = None,
    agent_name: Optional[str] = None,
) -> Tuple[Optional[Any], bool, Optional[str]]:
    """
    Gọi LLM structured output một cách an toàn.

    Returns:
        (structured_obj, used_real_llm, info)
        - llm_provider None            -> (None, False, "no_llm_provider")
        - provider có generate_structured_output -> (obj, used_real_llm, None)
        - provider chỉ có generate_response (mock) -> (None, True, raw_text)
        - lỗi bất kỳ                   -> (None, False, "error:<ExceptionType>")
    """
    if llm_provider is None:
        return None, False, "no_llm_provider"

    try:
        structured_fn = getattr(llm_provider, "generate_structured_output", None)
        if callable(structured_fn):
            kwargs = _supported_kwargs(
                structured_fn,
                {
                    "system_prompt": system_prompt,
                    "incident_state": incident_state,
                    "model_tier": model_tier,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "timeout": timeout,
                    "agent_name": agent_name,
                },
            )
            obj = structured_fn(prompt, schema_class, **kwargs)
            used_real_llm = getattr(llm_provider, "last_used_provider", None) not in (
                None,
                "deterministic",
                "none",
            )
            return obj, used_real_llm, None

        response_fn = getattr(llm_provider, "generate_response", None)
        if callable(response_fn):
            kwargs = _supported_kwargs(
                response_fn,
                {"system_prompt": system_prompt},
            )
            raw_text = response_fn(prompt, **kwargs)
            return None, True, raw_text if isinstance(raw_text, str) else str(raw_text)

        return None, False, "unsupported_llm_provider"
    except Exception as e:  # noqa: BLE001 - tuyệt đối không để lỗi LLM làm sập Agent
        return None, False, f"error:{type(e).__name__}"
