# -*- coding: utf-8 -*-
"""
src/copilot/copilot_engine.py
Module alias tương thích cho SOCCopilotEngine, định tuyến trực tiếp tới src/copilot/engine.py.
"""

from src.copilot.engine import (
    SOCCopilotEngine,
    CopilotIntent,
    CopilotResponse,
    logger,
)

__all__ = [
    "SOCCopilotEngine",
    "CopilotIntent",
    "CopilotResponse",
    "logger",
]
