# Phase 2 Baseline Evaluation Results

**Note:** The test split consists of 32 distinct instances across 3 held-out repositories (`matplotlib/matplotlib`, `pydata/xarray`, `mwaskom/seaborn`). Within-instance AUC is computed across test instances with both resolved and unresolved candidate patches (n=24).

## Baseline Feature Definitions

- **(A) Patch TF-IDF + LogReg**: TF-IDF unigrams and bigrams extracted from patch diff text (`patch` column; max 5,000 features).
- **(B) Issue TF-IDF LogReg**: TF-IDF unigrams and bigrams extracted from problem statement text (`problem_statement` column; max 5,000 features).
- **(C) Repo-Prior Baseline**: Repository-level historical resolution rates computed on the training split.
- **(D) Patch-Size Features LogReg**: 5 scalar patch size metrics (`lines_added`, `lines_removed`, `total_lines_changed`, `files_touched`, `hunks_count`), standardized via `StandardScaler`.
- **(E) Combined A+B+D LogReg**: Concatenation of features from Baseline A, Baseline B, and Baseline D.

**Feature Confirmation:** Neither `well_formed` nor `malformed_reason` are used as input features in any baseline model. `well_formed` is used strictly as an evaluation filtering mask, and `malformed_reason` is diagnostic metadata.

## Baseline Results Table (Test Set)

### Subset 1: All Test Rows

| Baseline Model | Within-Inst AUC (95% CI) [Primary] | Global ROC-AUC (95% CI) | PR-AUC (95% CI) | Prec @ 5% FPR | FP / 100 @ 80% Rec |
|---|---|---|---|---|---|
| (A) Patch TF-IDF + LogReg | 0.625 [0.540-0.704] | 0.613 [0.515-0.708] | 0.366 [0.223-0.531] | 42.4% | 44.0 |
| (B) Issue TF-IDF LogReg | 0.500 [0.500-0.500] | 0.685 [0.555-0.799] | 0.450 [0.315-0.623] | 38.7% | 38.4 |
| (D) Patch-Size Features LogReg | 0.511 [0.432-0.586] | 0.593 [0.507-0.681] | 0.383 [0.223-0.567] | 51.3% | 50.9 |
| (E) Combined A+B+D LogReg | 0.675 [0.579-0.769] | 0.721 [0.650-0.800] | 0.444 [0.330-0.575] | 45.7% | 33.6 |

*Note: Baseline (C) Repo-Prior Baseline is removed from the main table because test repos are unseen, making repo prior a constant prediction. It is retained in results/baselines.json with a note.*

### Subset 2: Well-Formed Test Rows Only (`well_formed=1`)

| Baseline Model | Within-Inst AUC (95% CI) [Primary] | Global ROC-AUC (95% CI) | PR-AUC (95% CI) | Prec @ 5% FPR | FP / 100 @ 80% Rec |
|---|---|---|---|---|---|
| (A) Patch TF-IDF + LogReg | 0.617 [0.525-0.703] | 0.611 [0.512-0.718] | 0.375 [0.242-0.559] | 43.8% | 43.5 |
| (B) Issue TF-IDF LogReg | 0.500 [0.500-0.500] | 0.684 [0.546-0.798] | 0.458 [0.320-0.620] | 40.0% | 37.8 |
| (D) Patch-Size Features LogReg | 0.505 [0.415-0.593] | 0.591 [0.497-0.675] | 0.392 [0.248-0.570] | 52.6% | 50.3 |
| (E) Combined A+B+D LogReg | 0.665 [0.562-0.757] | 0.717 [0.643-0.794] | 0.450 [0.329-0.588] | 47.1% | 33.5 |

## Validation Split Results (SymPy - Within-Instance AUC)

| Baseline Model | Within-Inst AUC (95% CI) | Valid Instances (n) |
|---|---|---|
| (A) Patch TF-IDF + LogReg | 0.591 [0.520-0.661] | 50 |
| (B) Issue TF-IDF LogReg | 0.500 [0.500-0.500] | 50 |
| (C) Repo-Prior Baseline | 0.500 [0.500-0.500] | 50 |
| (D) Patch-Size Features LogReg | 0.538 [0.462-0.615] | 50 |
| (E) Combined A+B+D LogReg | 0.660 [0.596-0.726] | 50 |

## Generalizability Validation Checks (Baseline A - Patch TF-IDF)
- **Leave-One-Repo-Out (LORO) Mean ROC-AUC:** `0.592`
- **Instance-Disjoint Leave-One-Submission-Out (LOSO) Mean ROC-AUC:** `0.492`
- **Leaky LOSO (shared instances):** `0.897` (kept for historical record)