# -*- coding: utf-8 -*-
"""
src/eval/__init__.py
Evaluation & Benchmark Harness package for the Multi-Agent SOC pipeline.

Exports:
- Schemas & configs: `BenchmarkSplit`, `GroundTruthLabel`, `BenchmarkCase`,
  `EvalConfig`, `DEFAULT_ABLATION_CONFIGS`, `GroundingAuditResult`,
  `CaseEvalResult`, `BenchmarkSummary`
- Dataset builder: `build_benchmark_dataset`
- Grounding auditor: `audit_case_grounding`
"""

from src.eval.schemas import (
    BenchmarkCase,
    BenchmarkSplit,
    BenchmarkSummary,
    CaseEvalResult,
    DEFAULT_ABLATION_CONFIGS,
    EvalConfig,
    GroundTruthLabel,
    GroundingAuditResult,
)
from src.eval.dataset_builder import build_benchmark_dataset
from src.eval.grounding import audit_case_grounding

__all__ = [
    "BenchmarkSplit",
    "GroundTruthLabel",
    "BenchmarkCase",
    "EvalConfig",
    "DEFAULT_ABLATION_CONFIGS",
    "GroundingAuditResult",
    "CaseEvalResult",
    "BenchmarkSummary",
    "build_benchmark_dataset",
    "audit_case_grounding",
]
