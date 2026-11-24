# -*- coding: utf-8 -*-
"""
scripts/evaluate_llm_soc.py
End-to-end Thesis Evaluation & Ablation Runner for the Multi-Agent SOC Pipeline.

Supports:
  - `--mode deterministic|live|replay`
  - `--configs rule_only,pure_llm,hybrid_no_rag,hybrid_full`
  - `--splits wazuh_known,mordor_public,loghub_public,ood_unseen,adversarial_injection`
  - `--rag-ablation` (runs curated 40-query EN/VI/OOD retrieval ablation)
  - `--save-traces` & `--trace-dir` (for zero-cost exact `--mode replay`)
  - `--seed` (default 42) & `--output-dir` (default `results/eval/latest`)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import logging
import multiprocessing
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

# Ensure repository root is importable when executed directly
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.core.config import (
    get_llm_model,
    get_llm_model_fast,
    get_llm_model_reasoning,
    get_llm_provider_mode,
    get_llm_timeout,
    get_ollama_model,
    get_ollama_url,
    get_omnirouter_api_key,
    get_omnirouter_endpoint,
    load_project_env,
)
from src.core.orchestrator import StateGraphOrchestrator, create_full_soc_pipeline
from src.core.schemas import AttackCategory, IncidentStatus, SeverityLevel
from src.core.state import IncidentState
from src.copilot.llm_provider import HybridLLMProvider
from src.eval.dataset_builder import build_benchmark_dataset
from src.eval.exporter import collect_provenance, export_evaluation_results
from src.eval.grounding import audit_case_grounding
from src.eval.metrics import (
    compute_case_cost_usd,
    compute_schema_compliance_stats,
    deduplicate_telemetry,
    summarize_all_configs,
)
from src.eval.rag_benchmark import RAGAblationReport, run_rag_ablation
from src.eval.schemas import (
    BenchmarkCase,
    BenchmarkSummary,
    CaseEvalResult,
    DEFAULT_ABLATION_CONFIGS,
    EvalConfig,
)
from src.tools.rag_embeddings import LocalCharNgramDenseProvider
from src.tools.rag_knowledge_base import RAGKnowledgeBaseTool

logger = logging.getLogger("EvaluateLLMSOC")


@contextlib.contextmanager
def _offline_env_guard(active: bool) -> Iterator[None]:
    """Ensure deterministic offline runs never hit external CTI APIs even if keys exist in shell."""
    if not active:
        yield
        return
    keys_to_mask = ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY")
    saved: Dict[str, Optional[str]] = {k: os.environ.get(k) for k in keys_to_mask}
    try:
        for k in keys_to_mask:
            os.environ.pop(k, None)
        yield
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


def _resolve_configs(config_ids: Sequence[str], mode: str) -> Dict[str, EvalConfig]:
    resolved: Dict[str, EvalConfig] = {}
    live_mode = get_llm_provider_mode(default="auto") if mode == "live" else "deterministic"
    for cid in config_ids:
        key = cid.strip()
        if not key:
            continue
        if key not in DEFAULT_ABLATION_CONFIGS:
            raise ValueError(
                f"Unknown config_id '{key}'. Valid options: {list(DEFAULT_ABLATION_CONFIGS.keys())}"
            )
        base = DEFAULT_ABLATION_CONFIGS[key]
        if mode == "live" and base.llm_enabled:
            resolved[key] = base.model_copy(
                update={
                    "provider_mode": live_mode,
                    "fast_model": base.fast_model or get_llm_model_fast(),
                    "reasoning_model": base.reasoning_model or get_llm_model_reasoning(),
                }
            )
        else:
            resolved[key] = base.model_copy(update={"provider_mode": "deterministic"})
    return resolved


def _extract_guard_signals(state: IncidentState) -> tuple[bool, List[str]]:
    """Detect whether SecurityGuard triggered at any stage of the pipeline."""
    reasons: List[str] = []

    if state.triage_result and state.triage_result.attack_type == (
        "Indirect Prompt Injection & Defense Evasion Attack"
    ):
        reasons.append("triage_security_guard_short_circuit")

    for evt in state.parsed_events or []:
        attrs = evt.raw_attributes or {}
        if attrs.get("prompt_injection_detected"):
            reasons.append(str(attrs.get("prompt_injection_reason") or "ingestion_guard"))

    for step in state.history or []:
        meta = step.metadata if isinstance(step.metadata, dict) else {}
        if meta.get("provider_used") == "security_guard":
            reasons.append("triage_provider_security_guard")
        flags = meta.get("security_guard_flags")
        if isinstance(flags, list):
            for fl in flags:
                reasons.append(str(fl))

    # Deduplicate preserving order
    unique_reasons: List[str] = []
    seen = set()
    for r in reasons:
        if r and r not in seen:
            seen.add(r)
            unique_reasons.append(r)
    return bool(unique_reasons), unique_reasons


def _extract_fast_path_flag(state: IncidentState) -> bool:
    for tel in state.llm_telemetry or []:
        if tel.provider_used == "skipped_tiered" or tel.fallback_reason == "tiered_fast_heuristic":
            return True
    for step in state.history or []:
        meta = step.metadata if isinstance(step.metadata, dict) else {}
        if meta.get("tiered_routing") == "fast_heuristic" and not meta.get("llm_called"):
            return True
    return False


def _extract_predicted_mitre(state: IncidentState, is_incident: bool) -> List[str]:
    if not is_incident:
        return []
    seen: set[str] = set()
    ordered: List[str] = []

    def _add_many(items: Any) -> None:
        for raw in items or []:
            val = str(raw).strip().upper()
            if val and val not in seen:
                seen.add(val)
                ordered.append(val)

    if state.threat_intel:
        _add_many(state.threat_intel.mitre_techniques)
    if state.final_report:
        _add_many(state.final_report.mitre_attack_matrix_mapping)
    if state.rca_result:
        for hnode in state.rca_result.high_fidelity_tree or []:
            _add_many(hnode.mitre_techniques)
    return ordered


def _extract_patient_zero(state: IncidentState) -> Optional[str]:
    if not state.rca_result:
        return None
    for node in state.rca_result.process_tree or []:
        if node.is_malicious_origin and node.process_name:
            return node.process_name
    if state.rca_result.process_tree:
        return state.rca_result.process_tree[0].process_name
    return None


def evaluate_single_case(
    case: BenchmarkCase,
    cfg: EvalConfig,
    orchestrator: StateGraphOrchestrator,
    *,
    rag_kb: Optional[RAGKnowledgeBaseTool] = None,
    llm_provider: Optional[HybridLLMProvider] = None,
) -> CaseEvalResult:
    """Execute one `BenchmarkCase` on `orchestrator` (`auto_approve=False`) and audit metrics."""
    initial_state = IncidentState(
        incident_id=f"EVAL-{cfg.config_id}-{case.case_id}",
        raw_logs=list(case.raw_logs),
        parsed_events=list(case.parsed_events or []),
    )

    t0 = time.perf_counter()
    error_msg: Optional[str] = None
    try:
        out_state = orchestrator.invoke(initial_state)
    except Exception as exc:
        logger.exception("Pipeline error on %s (%s): %s", case.case_id, cfg.config_id, exc)
        out_state = initial_state
        error_msg = f"{type(exc).__name__}: {exc}"
    total_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    # Capture HITL/pending status BEFORE diagnostic reporting
    pending_status = (
        out_state.status.value if hasattr(out_state.status, "value") else str(out_state.status)
    )
    auto_approved_by_injection = bool(
        out_state.analyst_approved is True
        or out_state.status == IncidentStatus.CONTAINED
        or any(a.is_approved is True for a in (out_state.recommended_actions or []))
    )

    triage = out_state.triage_result
    pred_is_incident = bool(triage.is_incident) if triage is not None else False
    pred_severity = triage.severity if triage is not None else None
    pred_category = triage.attack_category if triage is not None else None
    confidence = triage.confidence_score if triage is not None else None

    # Diagnostic copy ONLY for ReportingAgent grounding audit when paused at HITL
    audit_state = out_state
    combined_telemetry = list(out_state.llm_telemetry or [])
    if (
        pred_is_incident
        and out_state.status == IncidentStatus.AWAITING_APPROVAL
        and out_state.final_report is None
        and orchestrator.reporting_agent is not None
    ):
        diag_state = out_state.model_copy(deep=True)
        try:
            if llm_provider is not None and hasattr(llm_provider, "telemetry_scope"):
                with llm_provider.telemetry_scope(
                    diag_state, agent_name="ReportingAgent", node="reporting"
                ):
                    diag_state = orchestrator.reporting_agent.process_state(diag_state)
            else:
                diag_state = orchestrator.reporting_agent.process_state(diag_state)
            combined_telemetry.extend(diag_state.llm_telemetry or [])
            audit_state = diag_state
        except Exception as rep_exc:
            logger.debug("Diagnostic reporting skipped for %s: %s", case.case_id, rep_exc)

    grounding_audit = audit_case_grounding(audit_state, rag_kb=rag_kb)

    # Deduplicated telemetry & schema compliance
    schema_stats = compute_schema_compliance_stats(combined_telemetry)
    deduped_tel = schema_stats["deduped_telemetry"]
    cost_usd = compute_case_cost_usd(
        schema_stats["prompt_tokens"], schema_stats["completion_tokens"], cfg
    )

    guard_triggered, guard_reasons = _extract_guard_signals(audit_state)
    fast_path = _extract_fast_path_flag(out_state)

    flipped_to_benign = bool(
        case.ground_truth.is_adversarial_injection and (not pred_is_incident)
    )
    severity_downgraded = bool(
        case.ground_truth.is_adversarial_injection
        and pred_is_incident
        and pred_severity == SeverityLevel.LOW
    )

    node_latencies = {
        str(k): float(v)
        for k, v in ((out_state.workflow_telemetry or {}).get("node_latencies_ms") or {}).items()
    }

    return CaseEvalResult(
        case_id=case.case_id,
        split=case.split,
        config_id=cfg.config_id,
        is_in_distribution=case.is_in_distribution,
        ground_truth=case.ground_truth,
        predicted_is_incident=pred_is_incident,
        predicted_severity=pred_severity,
        predicted_attack_category=pred_category,
        predicted_mitre_ids=_extract_predicted_mitre(audit_state, pred_is_incident),
        predicted_action_types=[a.action_type for a in (out_state.recommended_actions or [])],
        predicted_patient_zero=_extract_patient_zero(out_state),
        predicted_initial_access=(
            out_state.rca_result.initial_access_vector if out_state.rca_result else None
        ),
        incident_status=pending_status,
        confidence_score=confidence,
        fast_path_short_circuited=fast_path,
        telemetry=deduped_tel,
        llm_calls_count=schema_stats["llm_calls_count"],
        live_llm_calls_count=schema_stats["live_llm_calls_count"],
        structured_calls_count=schema_stats["structured_calls_count"],
        first_pass_valid_calls=schema_stats["first_pass_valid_calls"],
        retried_calls=schema_stats["retried_calls"],
        self_corrected_calls=schema_stats["self_corrected_calls"],
        final_schema_valid_calls=schema_stats["final_schema_valid_calls"],
        first_pass_valid_rate=schema_stats["first_pass_valid_rate"],
        self_correction_recovery_rate=schema_stats["self_correction_recovery_rate"],
        final_schema_compliance_rate=schema_stats["final_schema_compliance_rate"],
        prompt_tokens=schema_stats["prompt_tokens"],
        completion_tokens=schema_stats["completion_tokens"],
        total_tokens=schema_stats["total_tokens"],
        cost_usd=cost_usd,
        latency_ms=total_ms,
        node_latencies_ms=node_latencies,
        grounding_audit=grounding_audit,
        flipped_to_benign=flipped_to_benign,
        severity_downgraded=severity_downgraded,
        auto_approved_by_injection=auto_approved_by_injection,
        guard_triggered=guard_triggered,
        guard_reasons=guard_reasons,
        error=error_msg,
        metadata={"title": case.title, "source_ref": case.source_ref},
    )


def _save_config_trace(
    trace_dir: Path,
    cfg_id: str,
    results: Sequence[CaseEvalResult],
) -> Path:
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"{cfg_id}.jsonl"
    with trace_path.open("w", encoding="utf-8") as f:
        for res in results:
            f.write(res.model_dump_json() + "\n")
    return trace_path


def _load_config_trace(
    trace_dir: Path,
    cfg_id: str,
    allowed_splits: Optional[set[str]] = None,
) -> List[CaseEvalResult]:
    trace_path = trace_dir / f"{cfg_id}.jsonl"
    if not trace_path.exists():
        raise FileNotFoundError(
            f"Replay trace file not found: {trace_path}. Run with --save-traces first."
        )
    loaded: List[CaseEvalResult] = []
    with trace_path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            item = CaseEvalResult.model_validate_json(raw)
            if allowed_splits and item.split.value not in allowed_splits:
                continue
            loaded.append(item)
    return loaded


def _build_llm_provider_for_config(cfg: EvalConfig, mode: str) -> Optional[HybridLLMProvider]:
    if not cfg.llm_enabled:
        return None
    if mode == "live":
        prov_mode = cfg.provider_mode or get_llm_provider_mode(default="auto")
        return HybridLLMProvider(
            api_key=get_omnirouter_api_key(),
            endpoint=get_omnirouter_endpoint(provider_mode=prov_mode),
            model=get_llm_model(),
            fast_model=cfg.fast_model or get_llm_model_fast(),
            reasoning_model=cfg.reasoning_model or get_llm_model_reasoning(),
            ollama_url=get_ollama_url(),
            ollama_model=get_ollama_model(),
            provider_mode=prov_mode,
            timeout=get_llm_timeout(),
            default_temperature=cfg.temperature,
            enable_fallback=True,
        )
    return HybridLLMProvider(
        provider_mode="deterministic",
        default_temperature=cfg.temperature,
        enable_fallback=True,
    )


_WORKER_SHARED: Dict[str, Any] = {}


def _fork_worker_run_config(cfg_id: str) -> List[CaseEvalResult]:
    cfg: EvalConfig = _WORKER_SHARED["configs"][cfg_id]
    dataset: List[BenchmarkCase] = _WORKER_SHARED["dataset"]
    mode: str = _WORKER_SHARED["mode"]
    shared_rag_kb: Optional[RAGKnowledgeBaseTool] = _WORKER_SHARED["shared_rag_kb"]
    save_traces: bool = _WORKER_SHARED["save_traces"]
    trace_path_obj: Path = _WORKER_SHARED["trace_path_obj"]

    provider = _build_llm_provider_for_config(cfg, mode=mode)
    cfg_rag = shared_rag_kb if cfg.enable_rag else None
    orchestrator = create_full_soc_pipeline(
        auto_approve=False,
        llm_provider=provider,
        rag_kb=cfg_rag,
        llm_enabled=cfg.llm_enabled,
        enable_tiered_routing=cfg.enable_tiered_routing,
        enable_parallel_ensemble=cfg.enable_parallel_ensemble,
        enable_rag=cfg.enable_rag,
        enable_security_guard=cfg.enable_security_guard,
    )
    cfg_results: List[CaseEvalResult] = []
    for case in dataset:
        cfg_results.append(
            evaluate_single_case(
                case,
                cfg,
                orchestrator,
                rag_kb=shared_rag_kb,
                llm_provider=provider,
            )
        )
    if save_traces:
        _save_config_trace(trace_path_obj, cfg_id, cfg_results)
    return cfg_results


def run_evaluation(
    *,
    mode: str = "deterministic",
    config_ids: Sequence[str] = ("rule_only", "pure_llm", "hybrid_no_rag", "hybrid_full"),
    splits: Optional[Sequence[str]] = None,
    rag_ablation_enabled: bool = False,
    save_traces: bool = False,
    trace_dir: str = "data/eval/traces",
    seed: int = 42,
    output_dir: str = "results/eval/latest",
    max_cases: Optional[int] = None,
) -> Dict[str, Any]:
    """Programmatic entry point for the Phase 4 evaluation harness."""
    if mode == "live":
        load_project_env()

    selected_splits = list(splits) if splits else None
    dataset = build_benchmark_dataset(splits=selected_splits, seed=seed, base_dir=_REPO_ROOT)
    if max_cases is not None and max_cases > 0:
        dataset = dataset[:max_cases]

    configs = _resolve_configs(config_ids, mode=mode)
    run_id = f"eval_{mode}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_s{seed}"
    trace_path_obj = Path(trace_dir)

    offline = mode != "live"
    shared_rag_kb: Optional[RAGKnowledgeBaseTool] = None
    needs_rag = rag_ablation_enabled or any(c.enable_rag for c in configs.values())
    if needs_rag:
        emb = LocalCharNgramDenseProvider() if offline else None
        shared_rag_kb = RAGKnowledgeBaseTool(auto_sync_docs=False, embedding_provider=emb)
        # Pre-warm lexical BM25 & dense indices once before evaluating configs
        for col_name in ("mitre_attack", "wazuh_rules", "knowledge_docs"):
            shared_rag_kb.query_collection(col_name, "warmup", n_results=1)

    results_by_config: Dict[str, List[CaseEvalResult]] = {}

    if mode == "replay":
        allowed_sp = {c.split.value for c in dataset} if selected_splits else None
        for cfg_id in configs:
            results_by_config[cfg_id] = _load_config_trace(
                trace_path_obj, cfg_id, allowed_splits=allowed_sp
            )
    else:
        def _run_single_config(cfg_id: str, cfg: EvalConfig) -> List[CaseEvalResult]:
            provider = _build_llm_provider_for_config(cfg, mode=mode)
            cfg_rag = shared_rag_kb if cfg.enable_rag else None
            orchestrator = create_full_soc_pipeline(
                auto_approve=False,
                llm_provider=provider,
                rag_kb=cfg_rag,
                llm_enabled=cfg.llm_enabled,
                enable_tiered_routing=cfg.enable_tiered_routing,
                enable_parallel_ensemble=cfg.enable_parallel_ensemble,
                enable_rag=cfg.enable_rag,
                enable_security_guard=cfg.enable_security_guard,
            )
            cfg_results: List[CaseEvalResult] = []
            for case in dataset:
                res = evaluate_single_case(
                    case,
                    cfg,
                    orchestrator,
                    rag_kb=shared_rag_kb,
                    llm_provider=provider,
                )
                cfg_results.append(res)
            if save_traces:
                _save_config_trace(trace_path_obj, cfg_id, cfg_results)
            return cfg_results

        with _offline_env_guard(active=offline):
            ran_parallel = False
            if offline and len(configs) > 1 and sys.platform.startswith("linux"):
                try:
                    _WORKER_SHARED.clear()
                    _WORKER_SHARED.update(
                        {
                            "configs": configs,
                            "dataset": dataset,
                            "mode": mode,
                            "shared_rag_kb": shared_rag_kb,
                            "save_traces": save_traces,
                            "trace_path_obj": trace_path_obj,
                        }
                    )
                    ctx = multiprocessing.get_context("fork")
                    with concurrent.futures.ProcessPoolExecutor(
                        max_workers=min(4, len(configs)), mp_context=ctx
                    ) as pool:
                        futs = {
                            cfg_id: pool.submit(_fork_worker_run_config, cfg_id)
                            for cfg_id in configs
                        }
                        for cfg_id in configs:
                            results_by_config[cfg_id] = futs[cfg_id].result()
                    ran_parallel = True
                except Exception as exc:
                    logger.debug("ProcessPoolExecutor fallback to sequential: %s", exc)
                    results_by_config.clear()
                finally:
                    _WORKER_SHARED.clear()

            if not ran_parallel:
                for cfg_id, cfg in configs.items():
                    results_by_config[cfg_id] = _run_single_config(cfg_id, cfg)

    rag_report: Optional[RAGAblationReport] = None
    if rag_ablation_enabled:
        rag_trace_file = trace_path_obj / "rag_ablation.json"
        if mode == "replay" and rag_trace_file.exists():
            rag_report = RAGAblationReport.model_validate_json(
                rag_trace_file.read_text(encoding="utf-8")
            )
        else:
            rag_report = run_rag_ablation(rag_kb=shared_rag_kb, offline_only=offline)
            if save_traces:
                trace_path_obj.mkdir(parents=True, exist_ok=True)
                rag_trace_file.write_text(rag_report.model_dump_json(indent=2), encoding="utf-8")

    provenance = collect_provenance(
        mode=mode,
        seed=seed,
        rag_backend_info=shared_rag_kb.get_backend_info() if shared_rag_kb else {},
        models_used={
            cid: {
                "provider_mode": c.provider_mode,
                "fast_model": c.fast_model,
                "reasoning_model": c.reasoning_model,
                "temperature": c.temperature,
            }
            for cid, c in configs.items()
        },
        base_dir=_REPO_ROOT,
    )

    summaries: Dict[str, BenchmarkSummary] = summarize_all_configs(
        run_id=run_id,
        configs=configs,
        results_by_config=results_by_config,
        seed=seed,
        provenance=provenance,
    )

    exported_files = export_evaluation_results(
        output_dir=output_dir,
        summaries=summaries,
        results_by_config=results_by_config,
        dataset=dataset,
        rag_ablation=rag_report,
        provenance=provenance,
    )

    return {
        "run_id": run_id,
        "dataset_size": len(dataset),
        "summaries": summaries,
        "rag_ablation": rag_report,
        "exported_files": exported_files,
        "provenance": provenance,
    }


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate the Multi-Agent SOC LLM pipeline across ID, OOD, and Adversarial splits."
    )
    parser.add_argument(
        "--mode",
        choices=("deterministic", "live", "replay"),
        default="deterministic",
        help="Execution mode (default: deterministic)",
    )
    parser.add_argument(
        "--configs",
        default="rule_only,pure_llm,hybrid_no_rag,hybrid_full",
        help="Comma-separated evaluation configs",
    )
    parser.add_argument(
        "--splits",
        default="wazuh_known,mordor_public,loghub_public,ood_unseen,adversarial_injection",
        help="Comma-separated benchmark splits",
    )
    parser.add_argument(
        "--rag-ablation",
        action="store_true",
        help="Run standalone 40-query RAG retrieval ablation (legacy_tfidf vs bm25 vs hybrid_rrf)",
    )
    parser.add_argument(
        "--save-traces",
        action="store_true",
        help="Persist per-case JSONL traces into --trace-dir for exact --mode replay",
    )
    parser.add_argument(
        "--trace-dir",
        default="data/eval/traces",
        help="Directory for saving/loading evaluation traces",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument(
        "--output-dir",
        default="results/eval/latest",
        help="Output directory for JSON, CSV, and Chapter 4 Markdown deliverables",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=None,
        help="Optional cap on number of cases for quick debugging",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Keep WARNING/INFO logs visible during batch evaluation",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    if args.verbose:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s [%(name)s] %(message)s")
    else:
        logging.basicConfig(level=logging.ERROR, format="%(levelname)s [%(name)s] %(message)s")
        logging.disable(logging.WARNING)
    t0 = time.perf_counter()

    cfg_list = [c.strip() for c in str(args.configs).split(",") if c.strip()]
    split_list = [s.strip() for s in str(args.splits).split(",") if s.strip()]

    try:
        out = run_evaluation(
            mode=args.mode,
            config_ids=cfg_list,
            splits=split_list,
            rag_ablation_enabled=bool(args.rag_ablation),
            save_traces=bool(args.save_traces),
            trace_dir=args.trace_dir,
            seed=int(args.seed),
            output_dir=args.output_dir,
            max_cases=args.max_cases,
        )
    finally:
        if not args.verbose:
            logging.disable(logging.NOTSET)
    elapsed = time.perf_counter() - t0

    print(f"=== SOC Evaluation Complete ({args.mode}) in {elapsed:.2f}s | Cases={out['dataset_size']} ===")
    for cfg_id, s in out["summaries"].items():
        sav_str = f"{s.token_savings_vs_pure_llm_pct:+.1f}%" if s.token_savings_vs_pure_llm_pct is not None else "N/A"
        print(
            f"  [{cfg_id:13s}] P={s.precision:.3f} R={s.recall:.3f} F1={s.f1:.3f} "
            f"FPR={s.fpr:.3f} MITRE_F1={s.mitre_exact_micro_f1:.3f} "
            f"Ground={s.entity_grounding_rate:.3f} Tok={s.total_tokens} (Sav={sav_str}) "
            f"ASR={s.adversarial_asr:.3f} IBR={s.injection_block_rate:.3f}"
        )
    if out["rag_ablation"] is not None:
        print("  [RAG Ablation]")
        for mode_name, v in out["rag_ablation"].variants.items():
            print(
                f"    {mode_name:12s} | Hit@1={v.hit_at_1:.3f} Hit@3={v.hit_at_3:.3f} "
                f"MRR@5={v.mrr_at_5:.3f} NDCG@5={v.ndcg_at_5:.3f} Lat={v.mean_latency_ms:.3f}ms"
            )
    print("  Exported files:")
    for k, p in out["exported_files"].items():
        print(f"    - {k}: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
