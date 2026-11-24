# Báo cáo Đánh giá Thực nghiệm Hệ thống Multi-Agent SOC (Chapter 4 & 5 Evaluation Report)

## Thông tin Tái lập Thực nghiệm (Reproducibility & Provenance)
- **Timestamp (UTC)**: `2026-11-24T04:19:54.664155+00:00`
- **Execution Mode**: `deterministic` | **Seed**: `42` | **Git SHA**: `7ce2b62`
- **Python**: `3.14.9`
- **RAG Engine**: backend=`numpy_dense`, embedding=`local_hash` (`bilingual-soc-char-ngram-v2`)

## Bảng 4.1 — Thành phần Bộ dữ liệu Đánh giá Phân tầng (Table 4.1: Stratified Benchmark Dataset Composition)

| Split | Distribution | Total | Incidents (TP Target) | Benign (TN Target) | Primary Focus |
|---|---|---:|---:|---:|---|
| `wazuh_known` | In-Distribution (ID) | 16 | 3 | 13 | Wazuh SIEM scenarios + alert-fatigue benign events |
| `mordor_public` | In-Distribution (ID) | 22 | 11 | 11 | Mordor/OTRF attack episodes + background benign windows |
| `loghub_public` | In-Distribution (ID) | 18 | 9 | 9 | OpenSSH, Linux, Apache operational & attack bursts |
| `ood_unseen` | Out-of-Distribution (OOD) | 40 | 22 | 18 | Unseen LOLBins, non-enc obfuscation, Cloud/AD chains & hard benign confounders |
| `adversarial_injection` | Out-of-Distribution (OOD) | 30 | 30 | 0 | EN / VI / Mixed-Obfuscated Indirect Prompt Injection payloads |
| **Total** | **ID + OOD + Adversarial** | **126** | **75** | **51** | **Full 5-Split Evaluation Suite** |

## Bảng 4.2 — Hiệu năng Phát hiện Sự cố & Giảm Báo động Giả ID vs OOD (Table 4.2: Detection Performance, FPRR & Statistical Significance)

| Config | Precision | Recall | F1 (95% CI) | FPR | FPRR (SIEM) | FPRR vs Rule | ID F1 | OOD Unseen F1 | Cat Macro-F1 | Sev Exact / ±1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `rule_only` | 0.9661 | 0.7600 | 0.8507 [0.773, 0.908] | 3.92% | 96.08% | +0.00% | 1.0000 | 0.2857 | 0.8007 | 68.25% / 81.75% |
| `pure_llm` | 0.9857 | 0.9200 | 0.9517 [0.913, 0.981] | 1.96% | 98.04% | +50.00% | 1.0000 | 0.8205 | 0.8151 | 67.46% / 87.30% |
| `hybrid_no_rag` | 0.9718 | 0.9200 | 0.9452 [0.902, 0.978] | 3.92% | 96.08% | +0.00% | 1.0000 | 0.8000 | 0.8149 | 65.08% / 86.51% |
| `hybrid_full` | 0.9718 | 0.9200 | 0.9452 [0.902, 0.978] | 3.92% | 96.08% | +0.00% | 1.0000 | 0.8000 | 0.8149 | 65.08% / 86.51% |

### Kiểm định Thống kê McNemar's Exact Test (Statistical Significance)
| Comparison | Discordant Pairs (n01 / n10) | Exact p-value | Significant (p < 0.05) |
|---|---|---:|---|
| `rule_only` vs_pure_llm | 0 / 13 | 0.000244 | Yes |
| `pure_llm` vs_rule_only | 13 / 0 | 0.000244 | Yes |
| `hybrid_no_rag` vs_rule_only | 12 / 0 | 0.000488 | Yes |
| `hybrid_no_rag` vs_pure_llm | 0 / 1 | 1.000000 | No |
| `hybrid_full` vs_rule_only | 12 / 0 | 0.000488 | Yes |
| `hybrid_full` vs_pure_llm | 0 / 1 | 1.000000 | No |

## Bảng 4.3 — Đánh giá Mở rộng Truy xuất RAG & Ánh xạ MITRE ATT&CK (Table 4.3: RAG Retrieval Ablation & MITRE ATT&CK F1)

### 4.3a — Standalone RAG Retrieval Ablation (40 EN / VI / OOD Behavioral Queries)
| Retrieval Mode | Queries | Hit@1 | Hit@3 | MRR@5 | NDCG@5 | VI Hit@1 | OOD Hit@1 | Mean Latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `legacy_tfidf` | 40 | 0.9000 | 1.0000 | 0.9500 | 0.9499 | 0.8462 | 0.8333 | 0.084 |
| `bm25` | 40 | 0.9500 | 1.0000 | 0.9750 | 0.9607 | 1.0000 | 0.8333 | 0.211 |
| `hybrid_rrf` | 40 | 0.9750 | 1.0000 | 0.9875 | 0.9743 | 1.0000 | 0.9167 | 1.014 |

### 4.3b — End-to-End Pipeline MITRE ATT&CK Mapping Quality
| Config | Exact Micro-F1 (95% CI) | Exact Macro-F1 | Base-Technique Micro-F1 | Base-Technique Macro-F1 |
|---|---:|---:|---:|---:|
| `rule_only` | 0.5388 [0.454, 0.608] | 0.4124 | 0.5628 | 0.4329 |
| `pure_llm` | 0.5301 [0.446, 0.601] | 0.4124 | 0.5532 | 0.4329 |
| `hybrid_no_rag` | 0.5259 [0.442, 0.596] | 0.4124 | 0.5485 | 0.4329 |
| `hybrid_full` | 0.5234 [0.443, 0.596] | 0.4169 | 0.5620 | 0.4552 |

## Bảng 4.4 — Độ Trung thực Thực thể & Tuân thủ Schema JSON (Table 4.4: Entity Grounding & Schema Compliance)

| Config | Cited Entities | Verified | Entity Grounding Rate | Case Hallucination Rate | Structured Calls | First-Pass Valid | Self-Correction Recovery | Final Schema Compliance |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `rule_only` | 536 | 536 | 100.00% | 0.00% | 0 | N/A | N/A | N/A |
| `pure_llm` | 534 | 534 | 100.00% | 0.00% | 0 | N/A (offline) | N/A (offline) | N/A (offline) |
| `hybrid_no_rag` | 627 | 627 | 100.00% | 0.00% | 0 | N/A (offline) | N/A (offline) | N/A (offline) |
| `hybrid_full` | 639 | 639 | 100.00% | 0.00% | 0 | N/A (offline) | N/A (offline) | N/A (offline) |

## Bảng 4.5 — Hiệu quả Tiết kiệm Token, Chi phí & Độ trễ Thực thi (Table 4.5: Token Savings, Cost & Latency Percentiles)

| Config | Fast-Path Rate | Total Tokens | Avg Tokens/Case | Token Savings vs Pure LLM (95% CI) | Cost/Case (USD) | Cost/1K Alerts (USD) | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `rule_only` | 0.00% | 0 | 0.0 | +100.00% [+100.0%, +100.0%] | $0.00000 | $0.000 | 16.1 | 12.1 | 35.0 | 43.7 |
| `pure_llm` | 0.00% | 339,466 | 2694.2 | +0.00% [+0.0%, +0.0%] | $0.00050 | $0.499 | 18.4 | 19.3 | 34.6 | 44.7 |
| `hybrid_no_rag` | 10.32% | 357,072 | 2833.9 | -5.19% [-8.2%, -2.2%] | $0.00051 | $0.507 | 31.1 | 27.2 | 79.1 | 163.0 |
| `hybrid_full` | 10.32% | 386,955 | 3071.1 | -13.99% [-17.2%, -11.1%] | $0.00054 | $0.543 | 43.3 | 43.0 | 108.7 | 200.9 |

## Bảng 4.6 — Phòng vệ Tấn công Indirect Prompt Injection EN/VI (Table 4.6: Adversarial Prompt Injection Security Before vs After SecurityGuard)

| Config | SecurityGuard | Adv Cases | ASR Overall | ASR (EN) | ASR (VI) | ASR (Mixed/Obf) | Injection Block Rate (IBR) | Guard False Positive Rate |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `rule_only` | Disabled | 30 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| `pure_llm` | Disabled (Before) | 30 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| `hybrid_no_rag` | Enabled (After) | 30 | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0.00% |
| `hybrid_full` | Enabled (After) | 30 | 0.00% | 0.00% | 0.00% | 0.00% | 100.00% | 0.00% |
