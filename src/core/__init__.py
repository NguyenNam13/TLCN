# -*- coding: utf-8 -*-
"""
src/core
Gói cốt lõi của hệ thống SOC Multi-Agent Orchestration.
Chứa các thành phần quản lý trạng thái, schemas, bộ điều phối StateGraph Orchestrator
và cơ chế Người Trong Vòng Lặp (HITL) nâng cao.
"""

from src.core.schemas import (
    SeverityLevel,
    IncidentStatus,
    ActionType,
    RawLogInput,
    ParsedEvent,
    TriageOutput,
    IoCItem,
    ThreatIntelEnrichment,
    ProcessNode,
    RootCauseAnalysis,
    RecommendedAction,
    IncidentReport,
    WazuhAlert,
)
from src.core.state import (
    IncidentState,
    StateTransition,
    IncidentStateDict,
)
from src.core.orchestrator import (
    StateGraphOrchestrator,
    create_full_soc_pipeline,
    START,
    END,
)
from src.core.hitl_manager import (
    DecisionType,
    HITLDecision,
    HITLManager,
    HITLSessionStore,
)
from src.core.incident_store import IncidentStore

__all__ = [
    # Schemas
    "SeverityLevel",
    "IncidentStatus",
    "ActionType",
    "RawLogInput",
    "ParsedEvent",
    "TriageOutput",
    "IoCItem",
    "ThreatIntelEnrichment",
    "ProcessNode",
    "RootCauseAnalysis",
    "RecommendedAction",
    "IncidentReport",
    "WazuhAlert",
    # State
    "IncidentState",
    "StateTransition",
    "IncidentStateDict",
    "IncidentStore",
    # Orchestrator
    "StateGraphOrchestrator",
    "create_full_soc_pipeline",
    "START",
    "END",
    # HITL
    "DecisionType",
    "HITLDecision",
    "HITLManager",
    "HITLSessionStore",
]

