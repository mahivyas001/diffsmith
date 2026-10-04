# Phase 2 Baseline Evaluation Results

**Note:** The test split consists of 32 distinct instances across 3 held-out repositories (`matplotlib/matplotlib`, `pydata/xarray`, `mwaskom/seaborn`).

## Baseline Results Table (Test Set)

### Subset 1: All Test Rows

| Baseline Model | ROC-AUC (95% CI) | PR-AUC (95% CI) | Prec @ 5% FPR | FP / 100 @ 80% Rec |
|---|---|---|---|---|
| (A) Patch TF-IDF + LogReg | 0.613 [0.515-0.708] | 0.366 [0.223-0.531] | 42.4% | 44.0 |
| (B) Issue TF-IDF LogReg | 0.685 [0.555-0.799] | 0.450 [0.315-0.623] | 38.7% | 38.4 |
| (C) Repo-Prior Baseline | 0.500 [0.500-0.500] | 0.285 [0.190-0.391] | 0.0% | 60.4 |
| (D) Patch-Size Features LogReg | 0.593 [0.507-0.681] | 0.383 [0.223-0.567] | 51.3% | 50.9 |
| (E) Combined A+B+D LogReg | 0.721 [0.650-0.800] | 0.444 [0.330-0.575] | 45.7% | 33.6 |

### Subset 2: Well-Formed Test Rows Only (`well_formed=1`)

| Baseline Model | ROC-AUC (95% CI) | PR-AUC (95% CI) | Prec @ 5% FPR | FP / 100 @ 80% Rec |
|---|---|---|---|---|
| (A) Patch TF-IDF + LogReg | 0.611 [0.512-0.718] | 0.375 [0.242-0.559] | 43.8% | 43.5 |
| (B) Issue TF-IDF LogReg | 0.684 [0.546-0.798] | 0.458 [0.320-0.620] | 40.0% | 37.8 |
| (C) Repo-Prior Baseline | 0.500 [0.500-0.500] | 0.295 [0.191-0.405] | 0.0% | 59.9 |
| (D) Patch-Size Features LogReg | 0.591 [0.497-0.675] | 0.392 [0.248-0.570] | 52.6% | 50.3 |
| (E) Combined A+B+D LogReg | 0.717 [0.643-0.794] | 0.450 [0.329-0.588] | 47.1% | 33.5 |

## Generalizability Validation Checks (Baseline A - Patch TF-IDF)
- **Leave-One-Repo-Out (LORO) Mean ROC-AUC:** `0.592`
- **Leave-One-Submission-Out (LOSO) Mean ROC-AUC:** `0.897`