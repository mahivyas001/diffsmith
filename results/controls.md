No tested feature shows within-instance signal distinguishable from chance under the agent-disjoint control (all 95% CIs include 0.5); Baseline A's standard-split 0.625 largely reflects agent formatting.

# Phase 3c Control Experiments & Sensitivity Diagnostics

## 1. Summary Verdict

> **Verdict:** No tested feature shows within-instance signal distinguishable from chance under the agent-disjoint control (all 95% CIs include 0.5); Baseline A's standard-split 0.625 largely reflects agent formatting.

## 2. Pre-Registered Success Bar Wording Rewrite & Loophole Analysis

- **Corrected Criterion 3 Definition:** Requires the **95% confidence interval lower bound** under the agent-disjoint control to strictly exceed `0.50` (`Control (i) CI lower bound > 0.50`).
- **Loophole Explanation:** The previous wording (`Control (i) mean within-instance AUC > 0.50`) was a statistical loophole because a mean AUC slightly above 0.50 with a 95% confidence interval encompassing 0.50 (e.g. H2 Control (i) combined AUC `0.480 [0.386-0.576]`) is completely indistinguishable from random noise (0.50). Requiring `CI lower bound > 0.50` ensures statistically significant discrimination.
- **Stage 3b Record:** The Stage 3b result remains strictly recorded as `bar NOT met` (Val within-instance AUC = `0.505`, Test 95% CI = `[0.409, 0.592]`).

## 3. Agent-Disjoint Control (3-Fold Submission-Group CV Respecting Repo Split)

> **Method & Variance Note:** Mean-of-folds test within-instance AUC and pooled test within-instance AUC differ (e.g., Baseline A3: `0.580` mean-of-folds vs `0.500 [0.406-0.611]` pooled). Each fold evaluates within-instance AUC on only ~8 multi-label test instances (24 test multi-label instances total across 3 folds), making per-fold estimates small and noisy. Furthermore, pooling predictions across 3 models trained on different submission subsets introduces calibration shifts in score scale. Crucially, under both metrics, all 95% confidence intervals encompass 0.50.

| Model | Val Within-Inst AUC (Mean) | Test Within-Inst AUC (Mean) | Test Per-Fold AUCs | Test Combined AUC (95% CI) |
|---|---|---|---|---|
| **H2** | 0.487 | 0.487 | [0.410, 0.515, 0.537] | 0.480 [0.386-0.576] |
| **H3** | 0.527 | 0.473 | [0.404, 0.504, 0.513] | 0.489 [0.391-0.586] |
| **Baseline A** | 0.495 | 0.501 | [0.557, 0.607, 0.340] | 0.514 [0.411-0.615] |
| **Baseline E** | 0.562 | 0.578 | [0.608, 0.696, 0.431] | 0.582 [0.467-0.684] |
| **Baseline A2** | 0.504 | 0.517 | [0.543, 0.576, 0.433] | 0.546 [0.454-0.629] |
| **Baseline A3** | 0.555 | 0.580 | [0.622, 0.554, 0.562] | 0.500 [0.406-0.611] |

## 4. Body-Only & Touched-Paths Text Baselines (A2 & A3)

| Baseline Model | Feature Extraction Description | Standard Split Test Within-AUC (95% CI) | Agent-Disjoint 3-Fold Test Within-AUC |
|---|---|---|---|
| **Baseline A2 (Body-Only Code Lines)** | TF-IDF on added/removed code lines only (headers & unchanged context stripped) | 0.559 [0.464-0.644] | 0.517 |
| **Baseline A3 (Touched Paths Only)** | TF-IDF on touched file paths only (diff code stripped) | 0.630 [0.567-0.692] | 0.580 |

## 5. Tie Diagnostics

### Test Instance Feature Variance (% of Test Instances with >1 Distinct Value Across Candidate Patches)

| Feature Name | Varying Instances / Total (n=32) | Percentage |
|---|---|---|
| `fraction_touched_named` | 15/32 | 46.9% |
| `any_named_untouched` | 1/32 | 3.1% |
| `issue_identifier_overlap_frac` | 31/32 | 96.9% |
| `literal_hardcoding_count` | 25/32 | 78.1% |
| `has_literal_hardcoding` | 25/32 | 78.1% |
| `special_casing_count` | 3/32 | 9.4% |
| `has_special_casing` | 3/32 | 9.4% |
| `swallowed_exception_count` | 4/32 | 12.5% |
| `has_swallowed_exception` | 4/32 | 12.5% |
| `test_tampering_count` | 1/32 | 3.1% |
| `has_test_tampering` | 1/32 | 3.1% |
| `suppression_marker_count` | 1/32 | 3.1% |
| `has_suppression_marker` | 1/32 | 3.1% |
| `scope_creep_count` | 25/32 | 78.1% |
| `scope_creep_fraction` | 24/32 | 75.0% |

### H2 Model Within-Instance Pairwise Prediction Ties
- **Total Positive-Negative Candidate Patch Pairs (Test Set):** `1105`
- **Tied Pairs (Identical H2 Probability P(p+) == P(p-)):** `138` (12.5%)

## 6. Sign Check (Direction Fixed on Train Only)

| Feature Name | Train Learned Coef (Global Correlation) | Val Within-Instance AUC | Test Within-Instance AUC | Separate Direction Interpretation (Train vs Within-Instance) |
|---|---|---|---|---|
| `scope_creep_count` | `-0.1232` | `0.472` | `0.417` | Train correlation: negative coef (-0.1232, more scope creep -> lower train resolved rate) | Within-instance direction: Val AUC 0.472 / Test AUC 0.417 (< 0.50, patches with MORE scope creep rank HIGHER within an instance) |
| `fraction_touched_named` | `+0.4599` | `0.480` | `0.461` | Train correlation: positive coef (+0.4599, higher fraction touched named -> higher train resolved rate) | Within-instance direction: Val AUC 0.480 / Test AUC 0.461 (< 0.50, patches touching higher fraction of named files rank LOWER within an instance) |