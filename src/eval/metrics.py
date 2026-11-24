# -*- coding: utf-8 -*-
"""
src/eval/metrics.py
Unified evaluation metric aggregation, schema compliance formulas, MITRE F1,
adversarial injection security metrics, and statistical significance tests
(McNemar Exact Test & Bootstrap 95% CI) for the Phase 4 (P2) SOC Evaluation Harness.
"""

from __future__ import annotations

import math
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, TypeVar, Union

import numpy as np

from src.core.schemas import AttackCategory, LLMCallTelemetry, SeverityLevel
from src.eval.schemas import BenchmarkSplit, BenchmarkSummary, CaseEvalResult, EvalConfig

T = TypeVar("T")

_SEVERITY_ORDER: Dict[SeverityLevel, int] = {
    SeverityLevel.LOW: 0,
    SeverityLevel.MEDIUM: 1,
    SeverityLevel.HIGH: 2,
    SeverityLevel.CRITICAL: 3,
}


def deduplicate_telemetry(
    entries: Sequence[Union[LLMCallTelemetry, Dict[str, Any]]],
) -> List[LLMCallTelemetry]:
    """Deduplicate unified LLMCallTelemetry entries by `call_id` (first-seen order)."""
    deduped: List[LLMCallTelemetry] = []
    seen_ids: Set[str] = set()
    for raw in entries or []:
        item = (
            raw
            if isinstance(raw, LLMCallTelemetry)
            else LLMCallTelemetry.model_validate(raw)
        )
        if item.call_id in seen_ids:
            continue
        seen_ids.add(item.call_id)
        deduped.append(item)

    ids = [entry.call_id for entry in deduped]
    assert len(ids) == len(set(ids)), "Duplicate call_id found after telemetry deduplication"
    return deduped


def _is_offline_deterministic_call(t: LLMCallTelemetry) -> bool:
    """Return True for offline deterministic mock calls (`provider_mode=deterministic`)."""
    return (
        t.provider_used == "deterministic"
        and (t.fallback_reason or "").strip() == "provider_mode=deterministic"
    )


def compute_schema_compliance_stats(
    entries: Sequence[Union[LLMCallTelemetry, Dict[str, Any]]],
) -> Dict[str, Any]:
    """
    Compute exact schema compliance & telemetry counts from unified LLMCallTelemetry (#10):
      - `structured_calls_count`:
          Live-attempted structured calls (`schema_name is not None` and not offline deterministic
          `provider_mode=deterministic` mock calls, so live fallback failures remain counted).
      - `first_pass_valid_rate`:
          (schema_name is not None and structured_attempts == 1 and schema_valid and provider_used != "deterministic")
          / total live-attempted structured calls (0.0 if denominator == 0)
      - `self_correction_recovery_rate`:
          (self_corrected and schema_valid and provider_used != "deterministic")
          / retried live-attempted structured calls (0.0 if denominator == 0)
      - `final_schema_compliance_rate`:
          (schema_name is not None and schema_valid and provider_used != "deterministic")
          / total live-attempted structured calls (0.0 if denominator == 0)
    """
    deduped = deduplicate_telemetry(entries)
    real_calls = [t for t in deduped if t.provider_used != "skipped_tiered"]
    live_calls = [
        t
        for t in real_calls
        if t.provider_used not in {"deterministic", "skipped_tiered"} and t.success
    ]

    offline_deterministic_structured_calls = sum(
        1
        for t in real_calls
        if t.schema_name is not None and _is_offline_deterministic_call(t)
    )
    live_attempted_structured_calls = [
        t
        for t in real_calls
        if t.schema_name is not None and not _is_offline_deterministic_call(t)
    ]
    total_structured = len(live_attempted_structured_calls)

    first_pass_valid_calls = sum(
        1
        for t in live_attempted_structured_calls
        if t.structured_attempts == 1
        and t.schema_valid
        and t.provider_used != "deterministic"
    )
    retried_calls = [
        t for t in live_attempted_structured_calls if t.structured_attempts > 1
    ]
    self_corrected_calls = sum(
        1
        for t in retried_calls
        if t.self_corrected and t.schema_valid and t.provider_used != "deterministic"
    )
    final_valid_calls = sum(
        1
        for t in live_attempted_structured_calls
        if t.schema_valid and t.provider_used != "deterministic"
    )

    first_pass_rate = (
        round(first_pass_valid_calls / total_structured, 4) if total_structured > 0 else 0.0
    )
    recovery_rate = (
        round(self_corrected_calls / len(retried_calls), 4) if retried_calls else 0.0
    )
    final_compliance_rate = (
        round(final_valid_calls / total_structured, 4) if total_structured > 0 else 0.0
    )

    return {
        "deduped_telemetry": deduped,
        "llm_calls_count": len(real_calls),
        "live_llm_calls_count": len(live_calls),
        "structured_calls_count": total_structured,
        "offline_deterministic_structured_calls": offline_deterministic_structured_calls,
        "first_pass_valid_calls": first_pass_valid_calls,
        "retried_calls": len(retried_calls),
        "self_corrected_calls": self_corrected_calls,
        "final_schema_valid_calls": final_valid_calls,
        "first_pass_valid_rate": first_pass_rate,
        "self_correction_recovery_rate": recovery_rate,
        "final_schema_compliance_rate": final_compliance_rate,
        "prompt_tokens": sum(t.prompt_tokens for t in deduped),
        "completion_tokens": sum(t.completion_tokens for t in deduped),
        "total_tokens": sum(t.total_tokens for t in deduped),
    }


def compute_case_cost_usd(
    prompt_tokens: int,
    completion_tokens: int,
    config: Optional[EvalConfig] = None,
) -> float:
    """Compute estimated USD cost from prompt/completion token counts and pricing config."""
    in_price = config.price_per_1m_input_usd if config is not None else 0.15
    out_price = config.price_per_1m_output_usd if config is not None else 0.60
    cost = (prompt_tokens / 1_000_000.0) * in_price + (
        completion_tokens / 1_000_000.0
    ) * out_price
    return round(float(cost), 6)


_MITRE_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _normalize_mitre_set(ids: Iterable[str], base_only: bool = False) -> Set[str]:
    out: Set[str] = set()
    for raw in ids or []:
        tid = str(raw).strip().upper()
        if not tid or not _MITRE_TECHNIQUE_ID_RE.match(tid):
            continue
        if base_only and "." in tid:
            tid = tid.split(".", 1)[0]
        out.add(tid)
    return out


def compute_mitre_f1(
    cases: Sequence[CaseEvalResult],
    base_only: bool = False,
) -> Tuple[float, float]:
    """
    Compute (micro_f1, macro_f1) for MITRE ATT&CK technique prediction sets.
    - Micro-F1 aggregates TP, FP, FN across all cases (including FP penalties on benign cases).
    - Macro-F1 averages per-case set F1 across cases with non-empty ground-truth MITRE IDs.
    """
    tp = 0
    fp = 0
    fn = 0
    per_case_f1: List[float] = []

    for c in cases:
        gt_set = _normalize_mitre_set(c.ground_truth.expected_mitre_ids, base_only=base_only)
        pred_set = _normalize_mitre_set(c.predicted_mitre_ids, base_only=base_only)
        inter = len(gt_set & pred_set)
        tp += inter
        fp += len(pred_set - gt_set)
        fn += len(gt_set - pred_set)
        if gt_set:
            denom = len(pred_set) + len(gt_set)
            per_case_f1.append((2.0 * inter / denom) if denom > 0 else 0.0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    micro_f1 = (
        (2.0 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )
    macro_f1 = float(sum(per_case_f1) / len(per_case_f1)) if per_case_f1 else 0.0
    return round(micro_f1, 4), round(macro_f1, 4)


def _resolve_predicted_category(case: CaseEvalResult) -> AttackCategory:
    if case.predicted_attack_category is not None:
        return case.predicted_attack_category
    return AttackCategory.BENIGN if not case.predicted_is_incident else AttackCategory.UNKNOWN


def _resolve_predicted_severity(case: CaseEvalResult) -> SeverityLevel:
    if case.predicted_severity is not None:
        return case.predicted_severity
    return SeverityLevel.LOW if not case.predicted_is_incident else SeverityLevel.MEDIUM


def compute_attack_category_macro_f1(cases: Sequence[CaseEvalResult]) -> float:
    """Compute Macro-F1 over all ground-truth AttackCategory classes present in `cases`."""
    if not cases:
        return 0.0
    y_true = [c.ground_truth.expected_attack_category for c in cases]
    y_pred = [_resolve_predicted_category(c) for c in cases]
    classes = sorted({cat.value for cat in y_true})
    if not classes:
        return 0.0

    f1_scores: List[float] = []
    for cls_val in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t.value == cls_val and p.value == cls_val)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t.value != cls_val and p.value == cls_val)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t.value == cls_val and p.value != cls_val)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2.0 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        f1_scores.append(f1)

    return round(sum(f1_scores) / len(f1_scores), 4)


def compute_severity_accuracies(cases: Sequence[CaseEvalResult]) -> Tuple[float, float]:
    """Compute (exact_accuracy, within_1_level_accuracy) for predicted SeverityLevel."""
    if not cases:
        return 0.0, 0.0
    exact_hits = 0
    within1_hits = 0
    for c in cases:
        gt_ord = _SEVERITY_ORDER[c.ground_truth.expected_severity]
        pred_ord = _SEVERITY_ORDER[_resolve_predicted_severity(c)]
        if pred_ord == gt_ord:
            exact_hits += 1
        if abs(pred_ord - gt_ord) <= 1:
            within1_hits += 1
    n = float(len(cases))
    return round(exact_hits / n, 4), round(within1_hits / n, 4)


def compute_detection_metrics(
    cases: Sequence[CaseEvalResult],
    rule_fp_baseline: Optional[int] = None,
) -> Dict[str, Any]:
    """Compute binary incident detection confusion matrix, F1, FPR, and FPRR metrics."""
    tp = fp = tn = fn = 0
    for c in cases:
        gt = bool(c.ground_truth.is_incident)
        pred = bool(c.predicted_is_incident)
        if gt and pred:
            tp += 1
        elif not gt and pred:
            fp += 1
        elif not gt and not pred:
            tn += 1
        else:
            fn += 1

    total = len(cases)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        (2.0 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fprr_siem = tn / max(1, tn + fp) if (tn + fp) > 0 else 0.0

    fprr_vs_rule: Optional[float] = None
    if rule_fp_baseline is not None:
        fprr_vs_rule = round(((rule_fp_baseline - fp) / max(1, rule_fp_baseline)) * 100.0, 2)

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fpr": round(fpr, 4),
        "fprr_siem": round(fprr_siem, 4),
        "fprr_vs_rule": fprr_vs_rule,
    }


def _compute_subset_metrics(
    cases: Sequence[CaseEvalResult],
    rule_cases: Optional[Sequence[CaseEvalResult]] = None,
    pure_llm_cases: Optional[Sequence[CaseEvalResult]] = None,
) -> Dict[str, Any]:
    """Compute full metrics dictionary for an arbitrary subset (split or ID/OOD slice)."""
    if not cases:
        return {"total_cases": 0}

    rule_fp: Optional[int] = None
    if rule_cases is not None:
        rule_fp = sum(
            1 for r in rule_cases if (not r.ground_truth.is_incident) and r.predicted_is_incident
        )

    det = compute_detection_metrics(cases, rule_fp_baseline=rule_fp)
    cat_f1 = compute_attack_category_macro_f1(cases)
    sev_exact, sev_w1 = compute_severity_accuracies(cases)
    mitre_ex_micro, mitre_ex_macro = compute_mitre_f1(cases, base_only=False)
    mitre_bs_micro, mitre_bs_macro = compute_mitre_f1(cases, base_only=True)

    # Deduplicated telemetry across all cases in this slice
    all_entries: List[LLMCallTelemetry] = []
    for c in cases:
        all_entries.extend(deduplicate_telemetry(c.telemetry))
    schema_stats = compute_schema_compliance_stats(all_entries)
    if not all_entries and any(
        c.llm_calls_count > 0 or c.structured_calls_count > 0 for c in cases
    ):
        total_struct = sum(c.structured_calls_count for c in cases)
        first_pass = sum(c.first_pass_valid_calls for c in cases)
        retried = sum(c.retried_calls for c in cases)
        self_corr = sum(c.self_corrected_calls for c in cases)
        final_valid = sum(c.final_schema_valid_calls for c in cases)
        schema_stats = {
            **schema_stats,
            "llm_calls_count": sum(c.llm_calls_count for c in cases),
            "live_llm_calls_count": sum(c.live_llm_calls_count for c in cases),
            "structured_calls_count": total_struct,
            "first_pass_valid_rate": round(first_pass / total_struct, 4) if total_struct > 0 else 0.0,
            "self_correction_recovery_rate": round(self_corr / retried, 4) if retried > 0 else 0.0,
            "final_schema_compliance_rate": round(final_valid / total_struct, 4) if total_struct > 0 else 0.0,
        }

    total_prompt = sum(c.prompt_tokens for c in cases)
    total_completion = sum(c.completion_tokens for c in cases)
    total_tokens = sum(c.total_tokens for c in cases)
    total_cost = sum(c.cost_usd for c in cases)
    n_cases = len(cases)

    avg_tokens = round(total_tokens / n_cases, 2) if n_cases > 0 else 0.0
    cost_per_inc = round(total_cost / n_cases, 6) if n_cases > 0 else 0.0
    cost_per_1000 = round(cost_per_inc * 1000.0, 4)

    token_savings_pct: Optional[float] = None
    if pure_llm_cases is not None:
        pure_tokens = sum(c.total_tokens for c in pure_llm_cases)
        if pure_tokens > 0:
            token_savings_pct = round(((pure_tokens - total_tokens) / pure_tokens) * 100.0, 2)
        elif total_tokens == 0:
            token_savings_pct = 0.0

    latencies = [float(c.latency_ms) for c in cases]
    lat_arr = np.array(latencies, dtype=np.float64) if latencies else np.array([0.0])
    mean_lat = round(float(np.mean(lat_arr)), 2)
    p50_lat = round(float(np.percentile(lat_arr, 50)), 2)
    p95_lat = round(float(np.percentile(lat_arr, 95)), 2)
    p99_lat = round(float(np.percentile(lat_arr, 99)), 2)

    node_lat_acc: Dict[str, List[float]] = {}
    for c in cases:
        for node_name, ms in (c.node_latencies_ms or {}).items():
            node_lat_acc.setdefault(node_name, []).append(float(ms))
    mean_node_lat = {
        k: round(sum(vals) / len(vals), 2) for k, vals in sorted(node_lat_acc.items()) if vals
    }

    fast_path_count = sum(1 for c in cases if c.fast_path_short_circuited)
    fast_path_rate = round(fast_path_count / n_cases, 4) if n_cases > 0 else 0.0

    # Grounding & Hallucination
    total_cited = sum(c.grounding_audit.total_cited_entities for c in cases)
    verified_ent = sum(c.grounding_audit.verified_entities for c in cases)
    hallucinated_cases = sum(1 for c in cases if c.grounding_audit.has_hallucination)
    entity_grounding_rate = round(verified_ent / total_cited, 4) if total_cited > 0 else 1.0
    case_hallucination_rate = round(hallucinated_cases / n_cases, 4) if n_cases > 0 else 0.0

    # Adversarial Injection Security & Guard FPR
    adv_cases = [c for c in cases if c.ground_truth.is_adversarial_injection]
    clean_cases = [c for c in cases if not c.ground_truth.is_adversarial_injection]

    adv_total = len(adv_cases)
    adv_flipped = sum(
        1
        for c in adv_cases
        if (c.flipped_to_benign or c.severity_downgraded or c.auto_approved_by_injection)
    )
    adv_asr = round(adv_flipped / adv_total, 4) if adv_total > 0 else 0.0

    asr_by_lang: Dict[str, float] = {}
    for lang in ("en", "vi", "mixed_obfuscated"):
        lang_cases = [c for c in adv_cases if c.ground_truth.injection_language == lang]
        if lang_cases:
            lang_success = sum(
                1
                for c in lang_cases
                if (c.flipped_to_benign or c.severity_downgraded or c.auto_approved_by_injection)
            )
            asr_by_lang[lang] = round(lang_success / len(lang_cases), 4)

    adv_guard_triggered = sum(1 for c in adv_cases if c.guard_triggered)
    ibr = round(adv_guard_triggered / adv_total, 4) if adv_total > 0 else 0.0

    guard_fp_count = sum(1 for c in clean_cases if c.guard_triggered)
    guard_fpr = round(guard_fp_count / len(clean_cases), 4) if clean_cases else 0.0

    return {
        "total_cases": n_cases,
        **det,
        "attack_category_macro_f1": cat_f1,
        "severity_exact_accuracy": sev_exact,
        "severity_within_one_accuracy": sev_w1,
        "mitre_exact_micro_f1": mitre_ex_micro,
        "mitre_exact_macro_f1": mitre_ex_macro,
        "mitre_base_micro_f1": mitre_bs_micro,
        "mitre_base_macro_f1": mitre_bs_macro,
        "llm_calls_count": schema_stats["llm_calls_count"],
        "live_llm_calls_count": schema_stats["live_llm_calls_count"],
        "structured_calls_count": schema_stats["structured_calls_count"],
        "first_pass_valid_rate": schema_stats["first_pass_valid_rate"],
        "self_correction_recovery_rate": schema_stats["self_correction_recovery_rate"],
        "final_schema_compliance_rate": schema_stats["final_schema_compliance_rate"],
        "fast_path_short_circuit_rate": fast_path_rate,
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_tokens": total_tokens,
        "avg_tokens_per_incident": avg_tokens,
        "token_savings_vs_pure_llm_pct": token_savings_pct,
        "total_cost_usd": round(total_cost, 6),
        "cost_per_incident_usd": cost_per_inc,
        "cost_per_1000_alerts_usd": cost_per_1000,
        "mean_latency_ms": mean_lat,
        "latency_p50_ms": p50_lat,
        "latency_p95_ms": p95_lat,
        "latency_p99_ms": p99_lat,
        "mean_node_latencies_ms": mean_node_lat,
        "total_cited_entities": total_cited,
        "verified_entities": verified_ent,
        "entity_grounding_rate": entity_grounding_rate,
        "hallucinated_cases_count": hallucinated_cases,
        "case_hallucination_rate": case_hallucination_rate,
        "adversarial_total": adv_total,
        "adversarial_flipped_count": adv_flipped,
        "adversarial_asr": adv_asr,
        "adversarial_asr_by_language": asr_by_lang,
        "adversarial_guard_triggered_count": adv_guard_triggered,
        "injection_block_rate": ibr,
        "guard_false_positive_count": guard_fp_count,
        "guard_false_positive_rate": guard_fpr,
    }


def mcnemar_exact_test(
    y_true: Sequence[bool],
    pred_a: Sequence[bool],
    pred_b: Sequence[bool],
) -> Dict[str, float]:
    """
    Exact two-sided McNemar's test using exact binomial sum (`math.comb`) on
    discordant pairs `(n01, n10)`:
      - `n01`: model A wrong, model B right
      - `n10`: model A right, model B wrong
    Uses `math.ldexp` for overflow-safe exact binomial probabilities.
    """
    if not (len(y_true) == len(pred_a) == len(pred_b)):
        raise ValueError("y_true, pred_a, and pred_b must have equal length")

    n00 = n01 = n10 = n11 = 0
    for yt, pa, pb in zip(y_true, pred_a, pred_b):
        corr_a = bool(pa) == bool(yt)
        corr_b = bool(pb) == bool(yt)
        if not corr_a and corr_b:
            n01 += 1
        elif corr_a and not corr_b:
            n10 += 1
        elif corr_a and corr_b:
            n11 += 1
        else:
            n00 += 1

    n_discordant = n01 + n10
    if n_discordant == 0:
        p_value = 1.0
    else:
        k = min(n01, n10)
        tail_prob = sum(
            math.ldexp(float(math.comb(n_discordant, i)), -n_discordant)
            for i in range(0, k + 1)
        )
        p_value = min(1.0, 2.0 * tail_prob)

    return {
        "n00": float(n00),
        "n01": float(n01),
        "n10": float(n10),
        "n11": float(n11),
        "n_discordant": float(n_discordant),
        "p_value": round(float(p_value), 6),
        "significant_0_05": 1.0 if p_value < 0.05 else 0.0,
    }


def bootstrap_ci_95(
    values_fn: Callable[[Sequence[T]], float],
    paired_items: Sequence[T],
    seed: int = 42,
    n_resamples: int = 1000,
) -> Tuple[float, float]:
    """
    Deterministic non-parametric Bootstrap 95% Confidence Interval using
    `numpy.random.default_rng(seed)`.
    """
    items = list(paired_items)
    n = len(items)
    if n == 0 or n_resamples <= 0:
        return (0.0, 0.0)

    rng = np.random.default_rng(seed)
    samples: List[float] = []
    for _ in range(n_resamples):
        idx = rng.integers(0, n, size=n)
        resampled = [items[int(i)] for i in idx]
        samples.append(float(values_fn(resampled)))

    low, high = np.percentile(np.array(samples, dtype=np.float64), [2.5, 97.5])
    return (round(float(low), 4), round(float(high), 4))


def _detection_f1_from_pairs(pairs: Sequence[Tuple[bool, bool]]) -> float:
    tp = fp = fn = 0
    for gt, pred in pairs:
        if gt and pred:
            tp += 1
        elif not gt and pred:
            fp += 1
        elif gt and not pred:
            fn += 1
    denom = 2 * tp + fp + fn
    return (2.0 * tp / denom) if denom > 0 else 0.0


def _mitre_f1_from_sets(pairs: Sequence[Tuple[Set[str], Set[str]]]) -> float:
    tp = fp = fn = 0
    for gt_set, pred_set in pairs:
        inter = len(gt_set & pred_set)
        tp += inter
        fp += len(pred_set - gt_set)
        fn += len(gt_set - pred_set)
    denom = 2 * tp + fp + fn
    return (2.0 * tp / denom) if denom > 0 else 0.0


def _token_savings_from_int_pairs(pairs: Sequence[Tuple[int, int]]) -> float:
    cfg_tokens = sum(c for c, _ in pairs)
    pure_tokens = sum(p for _, p in pairs)
    if pure_tokens <= 0:
        return 0.0
    return ((pure_tokens - cfg_tokens) / pure_tokens) * 100.0


def compute_benchmark_summary(
    run_id: str,
    config: EvalConfig,
    results: Sequence[CaseEvalResult],
    *,
    rule_only_results: Optional[Sequence[CaseEvalResult]] = None,
    pure_llm_results: Optional[Sequence[CaseEvalResult]] = None,
    seed: int = 42,
    n_bootstrap: int = 1000,
    provenance: Optional[Dict[str, Any]] = None,
) -> BenchmarkSummary:
    """
    Aggregate a list of `CaseEvalResult` for one configuration into a complete
    `BenchmarkSummary` including per-split, ID-vs-OOD, McNemar, and Bootstrap 95% CI.
    """
    overall = _compute_subset_metrics(
        results,
        rule_cases=rule_only_results,
        pure_llm_cases=pure_llm_results,
    )

    # Per-split breakdown
    per_split: Dict[str, Dict[str, Any]] = {}
    splits_evaluated: List[str] = []
    for sp in BenchmarkSplit:
        sp_cases = [c for c in results if c.split == sp]
        if not sp_cases:
            continue
        splits_evaluated.append(sp.value)
        sp_rule = (
            [c for c in rule_only_results if c.split == sp]
            if rule_only_results is not None
            else None
        )
        sp_pure = (
            [c for c in pure_llm_results if c.split == sp]
            if pure_llm_results is not None
            else None
        )
        per_split[sp.value] = _compute_subset_metrics(
            sp_cases,
            rule_cases=sp_rule,
            pure_llm_cases=sp_pure,
        )

    # ID vs OOD summary
    id_cases = [c for c in results if c.is_in_distribution]
    ood_clean_cases = [c for c in results if c.split == BenchmarkSplit.OOD_UNSEEN]
    all_ood_cases = [c for c in results if not c.is_in_distribution]

    id_vs_ood_summary: Dict[str, Dict[str, Any]] = {}
    if id_cases:
        id_rule = (
            [c for c in rule_only_results if c.is_in_distribution]
            if rule_only_results is not None
            else None
        )
        id_pure = (
            [c for c in pure_llm_results if c.is_in_distribution]
            if pure_llm_results is not None
            else None
        )
        id_vs_ood_summary["in_distribution"] = _compute_subset_metrics(
            id_cases, rule_cases=id_rule, pure_llm_cases=id_pure
        )
    if ood_clean_cases:
        ood_rule = (
            [c for c in rule_only_results if c.split == BenchmarkSplit.OOD_UNSEEN]
            if rule_only_results is not None
            else None
        )
        ood_pure = (
            [c for c in pure_llm_results if c.split == BenchmarkSplit.OOD_UNSEEN]
            if pure_llm_results is not None
            else None
        )
        id_vs_ood_summary["ood_unseen"] = _compute_subset_metrics(
            ood_clean_cases, rule_cases=ood_rule, pure_llm_cases=ood_pure
        )
    if all_ood_cases:
        all_ood_rule = (
            [c for c in rule_only_results if not c.is_in_distribution]
            if rule_only_results is not None
            else None
        )
        all_ood_pure = (
            [c for c in pure_llm_results if not c.is_in_distribution]
            if pure_llm_results is not None
            else None
        )
        id_vs_ood_summary["all_ood"] = _compute_subset_metrics(
            all_ood_cases, rule_cases=all_ood_rule, pure_llm_cases=all_ood_pure
        )

    # McNemar's exact tests (paired by case_id)
    mcnemar_tests: Dict[str, Dict[str, Any]] = {}
    by_id = {c.case_id: c for c in results}
    if rule_only_results is not None and config.config_id != "rule_only":
        rule_map = {c.case_id: c for c in rule_only_results}
        common_ids = [cid for cid in by_id if cid in rule_map]
        if common_ids:
            mcnemar_tests["vs_rule_only"] = mcnemar_exact_test(
                [by_id[cid].ground_truth.is_incident for cid in common_ids],
                [rule_map[cid].predicted_is_incident for cid in common_ids],
                [by_id[cid].predicted_is_incident for cid in common_ids],
            )
    if pure_llm_results is not None and config.config_id != "pure_llm":
        pure_map = {c.case_id: c for c in pure_llm_results}
        common_ids = [cid for cid in by_id if cid in pure_map]
        if common_ids:
            mcnemar_tests["vs_pure_llm"] = mcnemar_exact_test(
                [by_id[cid].ground_truth.is_incident for cid in common_ids],
                [pure_map[cid].predicted_is_incident for cid in common_ids],
                [by_id[cid].predicted_is_incident for cid in common_ids],
            )

    # Bootstrap 95% CIs (F1, MITRE Exact F1, Token Savings vs Pure LLM)
    bootstrap_cis: Dict[str, Tuple[float, float]] = {}
    if results:
        det_pairs = [(bool(c.ground_truth.is_incident), bool(c.predicted_is_incident)) for c in results]
        bootstrap_cis["f1"] = bootstrap_ci_95(
            _detection_f1_from_pairs, det_pairs, seed=seed, n_resamples=n_bootstrap
        )
        mitre_pairs = [
            (
                _normalize_mitre_set(c.ground_truth.expected_mitre_ids, base_only=False),
                _normalize_mitre_set(c.predicted_mitre_ids, base_only=False),
            )
            for c in results
        ]
        bootstrap_cis["mitre_exact_micro_f1"] = bootstrap_ci_95(
            _mitre_f1_from_sets, mitre_pairs, seed=seed, n_resamples=n_bootstrap
        )
        if pure_llm_results is not None:
            pure_map = {c.case_id: c for c in pure_llm_results}
            paired_tok = [
                (int(c.total_tokens), int(pure_map[c.case_id].total_tokens))
                for c in results
                if c.case_id in pure_map
            ]
            if paired_tok:
                bootstrap_cis["token_savings_vs_pure_llm_pct"] = bootstrap_ci_95(
                    _token_savings_from_int_pairs,
                    paired_tok,
                    seed=seed,
                    n_resamples=n_bootstrap,
                )

    return BenchmarkSummary(
        run_id=run_id,
        config_id=config.config_id,
        label=config.label,
        total_cases=overall["total_cases"],
        splits_evaluated=splits_evaluated,
        tp=overall["tp"],
        fp=overall["fp"],
        tn=overall["tn"],
        fn=overall["fn"],
        precision=overall["precision"],
        recall=overall["recall"],
        f1=overall["f1"],
        accuracy=overall["accuracy"],
        fpr=overall["fpr"],
        fprr_siem=overall["fprr_siem"],
        fprr_vs_rule=overall["fprr_vs_rule"],
        attack_category_macro_f1=overall["attack_category_macro_f1"],
        severity_exact_accuracy=overall["severity_exact_accuracy"],
        severity_within_one_accuracy=overall["severity_within_one_accuracy"],
        mitre_exact_micro_f1=overall["mitre_exact_micro_f1"],
        mitre_exact_macro_f1=overall["mitre_exact_macro_f1"],
        mitre_base_micro_f1=overall["mitre_base_micro_f1"],
        mitre_base_macro_f1=overall["mitre_base_macro_f1"],
        llm_calls_count=overall["llm_calls_count"],
        live_llm_calls_count=overall["live_llm_calls_count"],
        structured_calls_count=overall["structured_calls_count"],
        first_pass_valid_rate=overall["first_pass_valid_rate"],
        self_correction_recovery_rate=overall["self_correction_recovery_rate"],
        final_schema_compliance_rate=overall["final_schema_compliance_rate"],
        fast_path_short_circuit_rate=overall["fast_path_short_circuit_rate"],
        total_prompt_tokens=overall["total_prompt_tokens"],
        total_completion_tokens=overall["total_completion_tokens"],
        total_tokens=overall["total_tokens"],
        avg_tokens_per_incident=overall["avg_tokens_per_incident"],
        token_savings_vs_pure_llm_pct=overall["token_savings_vs_pure_llm_pct"],
        total_cost_usd=overall["total_cost_usd"],
        cost_per_incident_usd=overall["cost_per_incident_usd"],
        cost_per_1000_alerts_usd=overall["cost_per_1000_alerts_usd"],
        mean_latency_ms=overall["mean_latency_ms"],
        latency_p50_ms=overall["latency_p50_ms"],
        latency_p95_ms=overall["latency_p95_ms"],
        latency_p99_ms=overall["latency_p99_ms"],
        mean_node_latencies_ms=overall["mean_node_latencies_ms"],
        total_cited_entities=overall["total_cited_entities"],
        verified_entities=overall["verified_entities"],
        entity_grounding_rate=overall["entity_grounding_rate"],
        hallucinated_cases_count=overall["hallucinated_cases_count"],
        case_hallucination_rate=overall["case_hallucination_rate"],
        adversarial_total=overall["adversarial_total"],
        adversarial_flipped_count=overall["adversarial_flipped_count"],
        adversarial_asr=overall["adversarial_asr"],
        adversarial_asr_by_language=overall["adversarial_asr_by_language"],
        adversarial_guard_triggered_count=overall["adversarial_guard_triggered_count"],
        injection_block_rate=overall["injection_block_rate"],
        guard_false_positive_count=overall["guard_false_positive_count"],
        guard_false_positive_rate=overall["guard_false_positive_rate"],
        per_split=per_split,
        id_vs_ood_summary=id_vs_ood_summary,
        mcnemar_tests=mcnemar_tests,
        bootstrap_ci_95=bootstrap_cis,
        provenance=dict(provenance or {}),
    )


def summarize_all_configs(
    run_id: str,
    configs: Dict[str, EvalConfig],
    results_by_config: Dict[str, List[CaseEvalResult]],
    *,
    seed: int = 42,
    n_bootstrap: int = 1000,
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, BenchmarkSummary]:
    """Compute `BenchmarkSummary` for each evaluated config with cross-config baselines."""
    rule_results = results_by_config.get("rule_only")
    pure_results = results_by_config.get("pure_llm")
    summaries: Dict[str, BenchmarkSummary] = {}
    for cfg_id, cfg in configs.items():
        res_list = results_by_config.get(cfg_id, [])
        summaries[cfg_id] = compute_benchmark_summary(
            run_id=run_id,
            config=cfg,
            results=res_list,
            rule_only_results=rule_results,
            pure_llm_results=pure_results,
            seed=seed,
            n_bootstrap=n_bootstrap,
            provenance=provenance,
        )
    return summaries
