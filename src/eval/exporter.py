# -*- coding: utf-8 -*-
"""
src/eval/exporter.py
Exports all 5 thesis-grade evaluation deliverables into `output_dir`:
  1. `raw_results.json` (provenance, summaries, RAG ablation, per-case results)
  2. `summary_comparison.csv`
  3. `per_split_breakdown.csv`
  4. `rag_ablation.csv`
  5. `thesis_report_chapter4.md` (Bilingual VI-EN report with Tables 4.1 -> 4.6)
"""

from __future__ import annotations

import csv
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from src.eval.rag_benchmark import RAGAblationReport
from src.eval.schemas import BenchmarkCase, BenchmarkSplit, BenchmarkSummary, CaseEvalResult


def collect_provenance(
    *,
    mode: str,
    seed: int,
    rag_backend_info: Optional[Dict[str, Any]] = None,
    models_used: Optional[Dict[str, Any]] = None,
    base_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Collect reproducible execution provenance (git SHA, Python, RAG backend, models, seed)."""
    repo_root = base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    git_sha = "unknown"
    try:
        git_sha = (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=repo_root,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            .decode("utf-8", errors="ignore")
            .strip()
            or "unknown"
        )
    except Exception:
        git_sha = "unknown"

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "mode": mode,
        "seed": seed,
        "rag_backend_info": rag_backend_info or {},
        "models": models_used or {},
    }


def _fmt_pct(val: Optional[float], already_percent: bool = False) -> str:
    if val is None:
        return "N/A"
    pct = float(val) if already_percent else float(val) * 100.0
    return f"{pct:.2f}%"


def _fmt_f(val: Optional[float], digits: int = 4) -> str:
    if val is None:
        return "N/A"
    return f"{float(val):.{digits}f}"


def _write_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def _export_summary_comparison_csv(
    path: Path,
    summaries: Dict[str, BenchmarkSummary],
) -> None:
    fieldnames = [
        "config_id",
        "label",
        "total_cases",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "f1",
        "accuracy",
        "fpr",
        "fprr_siem",
        "fprr_vs_rule",
        "attack_category_macro_f1",
        "severity_exact_accuracy",
        "severity_within_one_accuracy",
        "mitre_exact_micro_f1",
        "mitre_exact_macro_f1",
        "mitre_base_micro_f1",
        "mitre_base_macro_f1",
        "llm_calls_count",
        "live_llm_calls_count",
        "structured_calls_count",
        "first_pass_valid_rate",
        "self_correction_recovery_rate",
        "final_schema_compliance_rate",
        "fast_path_short_circuit_rate",
        "total_prompt_tokens",
        "total_completion_tokens",
        "total_tokens",
        "avg_tokens_per_incident",
        "token_savings_vs_pure_llm_pct",
        "total_cost_usd",
        "cost_per_incident_usd",
        "cost_per_1000_alerts_usd",
        "mean_latency_ms",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
        "entity_grounding_rate",
        "case_hallucination_rate",
        "adversarial_total",
        "adversarial_flipped_count",
        "adversarial_asr",
        "injection_block_rate",
        "guard_false_positive_count",
        "guard_false_positive_rate",
    ]
    rows: List[Dict[str, Any]] = []
    for summary in summaries.values():
        dump = summary.model_dump()
        rows.append({k: dump.get(k) for k in fieldnames})
    _write_csv(path, fieldnames, rows)


def _export_per_split_csv(
    path: Path,
    summaries: Dict[str, BenchmarkSummary],
) -> None:
    fieldnames = [
        "config_id",
        "split",
        "is_in_distribution",
        "total_cases",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "f1",
        "accuracy",
        "fpr",
        "fprr_siem",
        "fprr_vs_rule",
        "attack_category_macro_f1",
        "severity_exact_accuracy",
        "mitre_exact_micro_f1",
        "mitre_base_micro_f1",
        "entity_grounding_rate",
        "case_hallucination_rate",
        "total_tokens",
        "avg_tokens_per_incident",
        "token_savings_vs_pure_llm_pct",
        "mean_latency_ms",
        "latency_p50_ms",
        "latency_p95_ms",
        "adversarial_asr",
        "injection_block_rate",
        "guard_false_positive_rate",
    ]
    id_splits = {
        BenchmarkSplit.WAZUH_KNOWN.value,
        BenchmarkSplit.MORDOR_PUBLIC.value,
        BenchmarkSplit.LOGHUB_PUBLIC.value,
    }
    rows: List[Dict[str, Any]] = []
    for cfg_id, summary in summaries.items():
        for sp_name, sp_metrics in summary.per_split.items():
            row = {"config_id": cfg_id, "split": sp_name, "is_in_distribution": sp_name in id_splits}
            row.update(sp_metrics)
            rows.append(row)
    _write_csv(path, fieldnames, rows)


def _export_rag_ablation_csv(
    path: Path,
    rag_ablation: Optional[RAGAblationReport],
) -> None:
    fieldnames = [
        "mode",
        "total_queries",
        "hit_at_1",
        "hit_at_3",
        "mrr_at_5",
        "ndcg_at_5",
        "mean_latency_ms",
        "en_hit_at_1",
        "en_hit_at_3",
        "en_mrr_at_5",
        "vi_hit_at_1",
        "vi_hit_at_3",
        "vi_mrr_at_5",
        "ood_hit_at_1",
        "ood_hit_at_3",
        "ood_mrr_at_5",
    ]
    rows: List[Dict[str, Any]] = []
    if rag_ablation is not None:
        for mode, v in rag_ablation.variants.items():
            en = v.by_language.get("en", {})
            vi = v.by_language.get("vi", {})
            ood = v.by_language.get("ood_log", {})
            rows.append(
                {
                    "mode": mode,
                    "total_queries": v.total_queries,
                    "hit_at_1": v.hit_at_1,
                    "hit_at_3": v.hit_at_3,
                    "mrr_at_5": v.mrr_at_5,
                    "ndcg_at_5": v.ndcg_at_5,
                    "mean_latency_ms": v.mean_latency_ms,
                    "en_hit_at_1": en.get("hit_at_1", ""),
                    "en_hit_at_3": en.get("hit_at_3", ""),
                    "en_mrr_at_5": en.get("mrr_at_5", ""),
                    "vi_hit_at_1": vi.get("hit_at_1", ""),
                    "vi_hit_at_3": vi.get("hit_at_3", ""),
                    "vi_mrr_at_5": vi.get("mrr_at_5", ""),
                    "ood_hit_at_1": ood.get("hit_at_1", ""),
                    "ood_hit_at_3": ood.get("hit_at_3", ""),
                    "ood_mrr_at_5": ood.get("mrr_at_5", ""),
                }
            )
    _write_csv(path, fieldnames, rows)


def _render_thesis_markdown(
    summaries: Dict[str, BenchmarkSummary],
    dataset: Sequence[BenchmarkCase],
    rag_ablation: Optional[RAGAblationReport],
    provenance: Dict[str, Any],
) -> str:
    """Render bilingual Vietnamese-English Markdown report with Tables 4.1 -> 4.6."""
    lines: List[str] = []
    lines.append("# Báo cáo Đánh giá Thực nghiệm Hệ thống Multi-Agent SOC (Chapter 4 & 5 Evaluation Report)")
    lines.append("")
    lines.append("## Thông tin Tái lập Thực nghiệm (Reproducibility & Provenance)")
    lines.append(f"- **Timestamp (UTC)**: `{provenance.get('timestamp_utc', 'N/A')}`")
    lines.append(f"- **Execution Mode**: `{provenance.get('mode', 'N/A')}` | **Seed**: `{provenance.get('seed', 42)}` | **Git SHA**: `{provenance.get('git_sha', 'unknown')}`")
    lines.append(f"- **Python**: `{provenance.get('python_version', 'N/A')}`")
    rag_info = provenance.get("rag_backend_info") or {}
    if rag_info:
        lines.append(
            f"- **RAG Engine**: backend=`{rag_info.get('backend', 'N/A')}`, "
            f"embedding=`{rag_info.get('embedding_provider', 'N/A')}` (`{rag_info.get('embedding_model', 'N/A')}`)"
        )
    lines.append("")

    # === BẢNG 4.1: DATASET COMPOSITION ===
    lines.append("## Bảng 4.1 — Thành phần Bộ dữ liệu Đánh giá Phân tầng (Table 4.1: Stratified Benchmark Dataset Composition)")
    lines.append("")
    lines.append("| Split | Distribution | Total | Incidents (TP Target) | Benign (TN Target) | Primary Focus |")
    lines.append("|---|---|---:|---:|---:|---|")
    split_descriptions = {
        BenchmarkSplit.WAZUH_KNOWN.value: "Wazuh SIEM scenarios + alert-fatigue benign events",
        BenchmarkSplit.MORDOR_PUBLIC.value: "Mordor/OTRF attack episodes + background benign windows",
        BenchmarkSplit.LOGHUB_PUBLIC.value: "OpenSSH, Linux, Apache operational & attack bursts",
        BenchmarkSplit.OOD_UNSEEN.value: "Unseen LOLBins, non-enc obfuscation, Cloud/AD chains & hard benign confounders",
        BenchmarkSplit.ADVERSARIAL_INJECTION.value: "EN / VI / Mixed-Obfuscated Indirect Prompt Injection payloads",
    }
    total_all = total_pos = total_neg = 0
    for sp in BenchmarkSplit:
        sp_cases = [c for c in dataset if c.split == sp]
        if not sp_cases:
            continue
        n_pos = sum(1 for c in sp_cases if c.ground_truth.is_incident)
        n_neg = len(sp_cases) - n_pos
        dist_lbl = "In-Distribution (ID)" if sp_cases[0].is_in_distribution else "Out-of-Distribution (OOD)"
        total_all += len(sp_cases)
        total_pos += n_pos
        total_neg += n_neg
        lines.append(
            f"| `{sp.value}` | {dist_lbl} | {len(sp_cases)} | {n_pos} | {n_neg} | {split_descriptions[sp.value]} |"
        )
    lines.append(f"| **Total** | **ID + OOD + Adversarial** | **{total_all}** | **{total_pos}** | **{total_neg}** | **Full 5-Split Evaluation Suite** |")
    lines.append("")

    # === BẢNG 4.2: DETECTION & FPRR (ID vs OOD + McNemar + 95% CI) ===
    lines.append("## Bảng 4.2 — Hiệu năng Phát hiện Sự cố & Giảm Báo động Giả ID vs OOD (Table 4.2: Detection Performance, FPRR & Statistical Significance)")
    lines.append("")
    lines.append("| Config | Precision | Recall | F1 (95% CI) | FPR | FPRR (SIEM) | FPRR vs Rule | ID F1 | OOD Unseen F1 | Cat Macro-F1 | Sev Exact / ±1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for cfg_id, s in summaries.items():
        f1_ci = s.bootstrap_ci_95.get("f1")
        f1_ci_str = f"{s.f1:.4f} [{f1_ci[0]:.3f}, {f1_ci[1]:.3f}]" if f1_ci else f"{s.f1:.4f}"
        id_f1 = s.id_vs_ood_summary.get("in_distribution", {}).get("f1")
        ood_f1 = s.id_vs_ood_summary.get("ood_unseen", {}).get("f1")
        fprr_rule_str = f"{s.fprr_vs_rule:+.2f}%" if s.fprr_vs_rule is not None else "Baseline"
        lines.append(
            f"| `{cfg_id}` | {_fmt_f(s.precision)} | {_fmt_f(s.recall)} | {f1_ci_str} | "
            f"{_fmt_pct(s.fpr)} | {_fmt_pct(s.fprr_siem)} | {fprr_rule_str} | "
            f"{_fmt_f(id_f1)} | {_fmt_f(ood_f1)} | {_fmt_f(s.attack_category_macro_f1)} | "
            f"{_fmt_pct(s.severity_exact_accuracy)} / {_fmt_pct(s.severity_within_one_accuracy)} |"
        )
    lines.append("")
    lines.append("### Kiểm định Thống kê McNemar's Exact Test (Statistical Significance)")
    lines.append("| Comparison | Discordant Pairs (n01 / n10) | Exact p-value | Significant (p < 0.05) |")
    lines.append("|---|---|---:|---|")
    any_mcnemar = False
    for cfg_id, s in summaries.items():
        for cmp_name, m_res in s.mcnemar_tests.items():
            any_mcnemar = True
            n01 = int(m_res.get("n01", 0))
            n10 = int(m_res.get("n10", 0))
            pval = float(m_res.get("p_value", 1.0))
            sig = "Yes" if m_res.get("significant_0_05", 0.0) >= 1.0 else "No"
            lines.append(f"| `{cfg_id}` {cmp_name} | {n01} / {n10} | {pval:.6f} | {sig} |")
    if not any_mcnemar:
        lines.append("| N/A | - | - | - |")
    lines.append("")

    # === BẢNG 4.3: RAG ABLATION & MITRE ATT&CK F1 ===
    lines.append("## Bảng 4.3 — Đánh giá Mở rộng Truy xuất RAG & Ánh xạ MITRE ATT&CK (Table 4.3: RAG Retrieval Ablation & MITRE ATT&CK F1)")
    lines.append("")
    lines.append("### 4.3a — Standalone RAG Retrieval Ablation (40 EN / VI / OOD Behavioral Queries)")
    lines.append("| Retrieval Mode | Queries | Hit@1 | Hit@3 | MRR@5 | NDCG@5 | VI Hit@1 | OOD Hit@1 | Mean Latency (ms) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    if rag_ablation is not None and rag_ablation.variants:
        for mode, v in rag_ablation.variants.items():
            vi_h1 = v.by_language.get("vi", {}).get("hit_at_1")
            ood_h1 = v.by_language.get("ood_log", {}).get("hit_at_1")
            lines.append(
                f"| `{mode}` | {v.total_queries} | {_fmt_f(v.hit_at_1)} | {_fmt_f(v.hit_at_3)} | "
                f"{_fmt_f(v.mrr_at_5)} | {_fmt_f(v.ndcg_at_5)} | {_fmt_f(vi_h1)} | {_fmt_f(ood_h1)} | "
                f"{v.mean_latency_ms:.3f} |"
            )
    else:
        lines.append("| (Not run — pass `--rag-ablation`) | 0 | - | - | - | - | - | - | - |")
    lines.append("")
    lines.append("### 4.3b — End-to-End Pipeline MITRE ATT&CK Mapping Quality")
    lines.append("| Config | Exact Micro-F1 (95% CI) | Exact Macro-F1 | Base-Technique Micro-F1 | Base-Technique Macro-F1 |")
    lines.append("|---|---:|---:|---:|---:|")
    for cfg_id, s in summaries.items():
        m_ci = s.bootstrap_ci_95.get("mitre_exact_micro_f1")
        m_ci_str = f"{s.mitre_exact_micro_f1:.4f} [{m_ci[0]:.3f}, {m_ci[1]:.3f}]" if m_ci else f"{s.mitre_exact_micro_f1:.4f}"
        lines.append(
            f"| `{cfg_id}` | {m_ci_str} | {_fmt_f(s.mitre_exact_macro_f1)} | "
            f"{_fmt_f(s.mitre_base_micro_f1)} | {_fmt_f(s.mitre_base_macro_f1)} |"
        )
    lines.append("")

    # === BẢNG 4.4: GROUNDING & SCHEMA COMPLIANCE ===
    lines.append("## Bảng 4.4 — Độ Trung thực Thực thể & Tuân thủ Schema JSON (Table 4.4: Entity Grounding & Schema Compliance)")
    lines.append("")
    lines.append("| Config | Cited Entities | Verified | Entity Grounding Rate | Case Hallucination Rate | Structured Calls | First-Pass Valid | Self-Correction Recovery | Final Schema Compliance |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for cfg_id, s in summaries.items():
        if s.structured_calls_count == 0:
            schema_na = (
                "N/A (offline)"
                if (s.llm_calls_count > 0 and s.live_llm_calls_count == 0)
                else "N/A"
            )
            first_pass_str = schema_na
            recovery_str = schema_na
            final_compliance_str = schema_na
        else:
            first_pass_str = _fmt_pct(s.first_pass_valid_rate)
            recovery_str = _fmt_pct(s.self_correction_recovery_rate)
            final_compliance_str = _fmt_pct(s.final_schema_compliance_rate)
        lines.append(
            f"| `{cfg_id}` | {s.total_cited_entities} | {s.verified_entities} | "
            f"{_fmt_pct(s.entity_grounding_rate)} | {_fmt_pct(s.case_hallucination_rate)} | "
            f"{s.structured_calls_count} | {first_pass_str} | "
            f"{recovery_str} | {final_compliance_str} |"
        )
    lines.append("")

    # === BẢNG 4.5: TOKEN SAVINGS, COST & LATENCY ===
    lines.append("## Bảng 4.5 — Hiệu quả Tiết kiệm Token, Chi phí & Độ trễ Thực thi (Table 4.5: Token Savings, Cost & Latency Percentiles)")
    lines.append("")
    lines.append("| Config | Fast-Path Rate | Total Tokens | Avg Tokens/Case | Token Savings vs Pure LLM (95% CI) | Cost/Case (USD) | Cost/1K Alerts (USD) | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for cfg_id, s in summaries.items():
        sav = s.token_savings_vs_pure_llm_pct
        sav_ci = s.bootstrap_ci_95.get("token_savings_vs_pure_llm_pct")
        if sav is None:
            sav_str = "N/A"
        elif sav_ci is not None:
            sav_str = f"{sav:+.2f}% [{sav_ci[0]:+.1f}%, {sav_ci[1]:+.1f}%]"
        else:
            sav_str = f"{sav:+.2f}%"
        lines.append(
            f"| `{cfg_id}` | {_fmt_pct(s.fast_path_short_circuit_rate)} | {s.total_tokens:,} | "
            f"{s.avg_tokens_per_incident:.1f} | {sav_str} | ${s.cost_per_incident_usd:.5f} | "
            f"${s.cost_per_1000_alerts_usd:.3f} | {s.mean_latency_ms:.1f} | {s.latency_p50_ms:.1f} | "
            f"{s.latency_p95_ms:.1f} | {s.latency_p99_ms:.1f} |"
        )
    lines.append("")

    # === BẢNG 4.6: ADVERSARIAL PROMPT INJECTION DEFENSE ===
    lines.append("## Bảng 4.6 — Phòng vệ Tấn công Indirect Prompt Injection EN/VI (Table 4.6: Adversarial Prompt Injection Security Before vs After SecurityGuard)")
    lines.append("")
    lines.append("| Config | SecurityGuard | Adv Cases | ASR Overall | ASR (EN) | ASR (VI) | ASR (Mixed/Obf) | Injection Block Rate (IBR) | Guard False Positive Rate |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    guard_enabled_map = {
        "rule_only": "Disabled",
        "pure_llm": "Disabled (Before)",
        "hybrid_no_rag": "Enabled (After)",
        "hybrid_full": "Enabled (After)",
    }
    for cfg_id, s in summaries.items():
        g_lbl = guard_enabled_map.get(cfg_id, "Configured")
        en_asr = s.adversarial_asr_by_language.get("en")
        vi_asr = s.adversarial_asr_by_language.get("vi")
        mx_asr = s.adversarial_asr_by_language.get("mixed_obfuscated")
        lines.append(
            f"| `{cfg_id}` | {g_lbl} | {s.adversarial_total} | {_fmt_pct(s.adversarial_asr)} | "
            f"{_fmt_pct(en_asr)} | {_fmt_pct(vi_asr)} | {_fmt_pct(mx_asr)} | "
            f"{_fmt_pct(s.injection_block_rate)} | {_fmt_pct(s.guard_false_positive_rate)} |"
        )
    lines.append("")
    return "\n".join(lines)


def export_evaluation_results(
    output_dir: str,
    *,
    summaries: Dict[str, BenchmarkSummary],
    results_by_config: Dict[str, List[CaseEvalResult]],
    dataset: Sequence[BenchmarkCase],
    rag_ablation: Optional[RAGAblationReport] = None,
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """
    Write all 5 thesis deliverables into `output_dir` and return their absolute file paths.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    prov = dict(provenance or {})

    # 1. raw_results.json
    raw_json_path = out_path / "raw_results.json"
    raw_payload = {
        "provenance": prov,
        "summaries": {k: v.model_dump(mode="json") for k, v in summaries.items()},
        "rag_ablation": rag_ablation.model_dump(mode="json") if rag_ablation is not None else None,
        "cases": {
            cfg_id: [c.model_dump(mode="json") for c in res_list]
            for cfg_id, res_list in results_by_config.items()
        },
    }
    with raw_json_path.open("w", encoding="utf-8") as f:
        json.dump(raw_payload, f, ensure_ascii=False, indent=2)

    # 2. summary_comparison.csv
    summary_csv_path = out_path / "summary_comparison.csv"
    _export_summary_comparison_csv(summary_csv_path, summaries)

    # 3. per_split_breakdown.csv
    split_csv_path = out_path / "per_split_breakdown.csv"
    _export_per_split_csv(split_csv_path, summaries)

    # 4. rag_ablation.csv
    rag_csv_path = out_path / "rag_ablation.csv"
    _export_rag_ablation_csv(rag_csv_path, rag_ablation)

    # 5. thesis_report_chapter4.md
    report_md_path = out_path / "thesis_report_chapter4.md"
    md_text = _render_thesis_markdown(summaries, dataset, rag_ablation, prov)
    report_md_path.write_text(md_text, encoding="utf-8")

    return {
        "raw_results_json": str(raw_json_path),
        "summary_comparison_csv": str(summary_csv_path),
        "per_split_breakdown_csv": str(split_csv_path),
        "rag_ablation_csv": str(rag_csv_path),
        "thesis_report_chapter4_md": str(report_md_path),
    }
