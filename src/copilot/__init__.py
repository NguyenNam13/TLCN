# -*- coding: utf-8 -*-
"""
src/copilot/__init__.py
Gói SOC AI Copilot Engine & LLM Provider cho đề tài TLCN-NAM.
Cung cấp khả năng tương tác tự nhiên 2 chiều giữa chuyên viên SOC và hệ thống Multi-Agent,
hỗ trợ bóc tách ngữ cảnh, suy luận điều tra (RCA, IoC, Tóm lược điều hành) và điều khiển HITL.
"""

from src.copilot.llm_provider import HybridLLMProvider
from src.copilot.engine import SOCCopilotEngine, CopilotIntent, CopilotResponse

__all__ = [
    "HybridLLMProvider",
    "SOCCopilotEngine",
    "CopilotIntent",
    "CopilotResponse",
]
