# -*- coding: utf-8 -*-
"""
src/eval/schemas.py
Pydantic v2 schemas for the Phase 4 (P2) LLM Evaluation & Benchmark Harness.

Covers:
- Benchmark splits (In-Distribution vs OOD Unseen vs Adversarial Injection)
- Ground-truth labels and benchmark case containers
- Ablation configuration profiles (`DEFAULT_ABLATION_CONFIGS`)
- Deterministic entity grounding audit results (`GroundingAuditResult`)
- Per-case evaluation outcomes (`CaseEvalResult`) and aggregated summaries (`BenchmarkSummary`)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from src.core.schemas import (
    ActionType,
    AttackCategory,
    LLMCallTelemetry,
    ParsedEvent,
    RawLogInput,
    SeverityLevel,
)


class BenchmarkSplit(str, Enum):
    """Five stratified benchmark splits separating ID, OOD, and Adversarial cases."""

    WAZUH_KNOWN = "wazuh_known"
    MORDOR_PUBLIC = "mordor_public"
    LOGHUB_PUBLIC = "loghub_public"
    OOD_UNSEEN = "ood_unseen"
    ADVERSARIAL_INJECTION = "adversarial_injection"


class GroundTruthLabel(BaseModel):
    """Reference ground-truth annotations for a single benchmark incident/event."""

    is_incident: bool
    expected_severity: SeverityLevel
    expected_attack_category: AttackCategory
    expected_mitre_ids: List[str] = Field(default_factory=list)
    expected_patient_zero_process: Optional[str] = None
    expected_initial_access_keywords: List[str] = Field(default_factory=list)
    expected_action_types: List[ActionType] = Field(default_factory=list)
    is_adversarial_injection: bool = False
    injection_language: Literal["none", "en", "vi", "mixed_obfuscated"] = "none"


class BenchmarkCase(BaseModel):
    """Normalized benchmark test case consumable by the evaluation harness."""

    case_id: str
    split: BenchmarkSplit
    title: str
    source_ref: str
    raw_logs: List[RawLogInput] = Field(default_factory=list)
    parsed_events: Optional[List[ParsedEvent]] = None
    ground_truth: GroundTruthLabel
    is_in_distribution: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvalConfig(BaseModel):
    """Ablation / baseline evaluation configuration matching pipeline switches."""

    config_id: str
    label: str
    llm_enabled: bool = True
    enable_tiered_routing: bool = True
    enable_parallel_ensemble: bool = True
    enable_rag: bool = True
    enable_security_guard: bool = True
    provider_mode: str = "deterministic"
    fast_model: Optional[str] = None
    reasoning_model: Optional[str] = None
    temperature: float = 0.0
    price_per_1m_input_usd: float = 0.15
    price_per_1m_output_usd: float = 0.60


DEFAULT_ABLATION_CONFIGS: Dict[str, EvalConfig] = {
    "rule_only": EvalConfig(
        config_id="rule_only",
        label="Config A: Rule-Only Baseline",
        llm_enabled=False,
        enable_tiered_routing=False,
        enable_parallel_ensemble=False,
        enable_rag=False,
        enable_security_guard=False,
        provider_mode="deterministic",
    ),
    "pure_llm": EvalConfig(
        config_id="pure_llm",
        label="Config B: Pure LLM (No Tiering / Ensemble / RAG / Guard)",
        llm_enabled=True,
        enable_tiered_routing=False,
        enable_parallel_ensemble=False,
        enable_rag=False,
        enable_security_guard=False,
        provider_mode="deterministic",
    ),
    "hybrid_no_rag": EvalConfig(
        config_id="hybrid_no_rag",
        label="Config C: Hybrid Multi-Agent without RAG",
        llm_enabled=True,
        enable_tiered_routing=True,
        enable_parallel_ensemble=True,
        enable_rag=False,
        enable_security_guard=True,
        provider_mode="deterministic",
    ),
    "hybrid_full": EvalConfig(
        config_id="hybrid_full",
        label="Config D: Hybrid Multi-Agent + RAG + SecurityGuard (Proposed)",
        llm_enabled=True,
        enable_tiered_routing=True,
        enable_parallel_ensemble=True,
        enable_rag=True,
        enable_security_guard=True,
        provider_mode="deterministic",
    ),
}


class GroundingAuditResult(BaseModel):
    """Deterministic zero-LLM-judge grounding and hallucination audit result."""

    total_cited_entities: int = 0
    verified_entities: int = 0
    ungrounded_entities: List[Dict[str, str]] = Field(default_factory=list)
    forbidden_fabrications: List[str] = Field(default_factory=list)
    grounding_rate: float = 1.0
    has_hallucination: bool = False


class CaseEvalResult(BaseModel):
    """Per-case execution outcome, telemetry, grounding, and adversarial metrics."""

    case_id: str
    split: BenchmarkSplit
    config_id: str
    is_in_distribution: bool = True
    ground_truth: GroundTruthLabel

    # Detection & Classification predictions
    predicted_is_incident: bool = False
    predicted_severity: Optional[SeverityLevel] = None
    predicted_attack_category: Optional[AttackCategory] = None
    predicted_mitre_ids: List[str] = Field(default_factory=list)
    predicted_action_types: List[ActionType] = Field(default_factory=list)
    predicted_patient_zero: Optional[str] = None
    predicted_initial_access: Optional[str] = None
    incident_status: Optional[str] = None
    confidence_score: Optional[float] = None
    fast_path_short_circuited: bool = False

    # LLM Telemetry & Schema Compliance (deduped by call_id)
    telemetry: List[LLMCallTelemetry] = Field(default_factory=list)
    llm_calls_count: int = 0
    live_llm_calls_count: int = 0
    structured_calls_count: int = 0
    first_pass_valid_calls: int = 0
    retried_calls: int = 0
    self_corrected_calls: int = 0
    final_schema_valid_calls: int = 0
    first_pass_valid_rate: float = 0.0
    self_correction_recovery_rate: float = 0.0
    final_schema_compliance_rate: float = 0.0

    # Token, Cost & Latency
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    node_latencies_ms: Dict[str, float] = Field(default_factory=dict)

    # Grounding & Adversarial Outcomes
    grounding_audit: GroundingAuditResult = Field(default_factory=GroundingAuditResult)
    flipped_to_benign: bool = False
    severity_downgraded: bool = False
    auto_approved_by_injection: bool = False
    guard_triggered: bool = False
    guard_reasons: List[str] = Field(default_factory=list)

    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BenchmarkSummary(BaseModel):
    """Aggregated thesis-grade evaluation summary for one EvalConfig."""

    run_id: str
    config_id: str
    label: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_cases: int = 0
    splits_evaluated: List[str] = Field(default_factory=list)

    # Detection Performance
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0
    fpr: float = 0.0
    fprr_siem: float = 0.0
    fprr_vs_rule: Optional[float] = None
    attack_category_macro_f1: float = 0.0
    severity_exact_accuracy: float = 0.0
    severity_within_one_accuracy: float = 0.0

    # MITRE ATT&CK Mapping Quality
    mitre_exact_micro_f1: float = 0.0
    mitre_exact_macro_f1: float = 0.0
    mitre_base_micro_f1: float = 0.0
    mitre_base_macro_f1: float = 0.0

    # Schema Compliance & Telemetry
    llm_calls_count: int = 0
    live_llm_calls_count: int = 0
    structured_calls_count: int = 0
    first_pass_valid_rate: float = 0.0
    self_correction_recovery_rate: float = 0.0
    final_schema_compliance_rate: float = 0.0
    fast_path_short_circuit_rate: float = 0.0

    # Token, Cost & Latency
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    avg_tokens_per_incident: float = 0.0
    token_savings_vs_pure_llm_pct: Optional[float] = None
    total_cost_usd: float = 0.0
    cost_per_incident_usd: float = 0.0
    cost_per_1000_alerts_usd: float = 0.0
    mean_latency_ms: float = 0.0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    mean_node_latencies_ms: Dict[str, float] = Field(default_factory=dict)

    # Grounding & Hallucination
    total_cited_entities: int = 0
    verified_entities: int = 0
    entity_grounding_rate: float = 1.0
    hallucinated_cases_count: int = 0
    case_hallucination_rate: float = 0.0

    # Adversarial Security
    adversarial_total: int = 0
    adversarial_flipped_count: int = 0
    adversarial_asr: float = 0.0
    adversarial_asr_by_language: Dict[str, float] = Field(default_factory=dict)
    adversarial_guard_triggered_count: int = 0
    injection_block_rate: float = 0.0
    guard_false_positive_count: int = 0
    guard_false_positive_rate: float = 0.0

    # Breakdowns, Statistical Significance & Provenance
    per_split: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    id_vs_ood_summary: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    mcnemar_tests: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    bootstrap_ci_95: Dict[str, Tuple[float, float]] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
