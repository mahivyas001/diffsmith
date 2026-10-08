# diffsmith Data Pipeline & Held-Out Set Documentation

## 1. SWE-bench Lite Dataset & Leak-Proof Repo Splits

The dataset source is `princeton-nlp/SWE-bench_Lite` (300 instances across 12 distinct repositories).
To prevent cross-repository data leakage between training and evaluation, splits are partitioned strictly by whole repository (`repo` column). No repository is shared between splits.

### Split Manifest Summary (`data/splits/*.json`)

| Split | Instances | Repos | Repositories Included |
|---|---|---|---|
| **Train** | 191 | 8 | `django/django`, `scikit-learn/scikit-learn`, `pytest-dev/pytest`, `sphinx-doc/sphinx`, `astropy/astropy`, `psf/requests`, `pylint-dev/pylint`, `pallets/flask` |
| **Val** | 77 | 1 | `sympy/sympy` |
| **Test** | 32 | 3 | `matplotlib/matplotlib`, `pydata/xarray`, `mwaskom/seaborn` |

---

## 2. Real Agent Held-Out Evaluation Dataset (`data/heldout/heldout.csv`)

### Data Source & Pipeline
- **Source:** `swe-bench/experiments`
- **Resolution Labels:** Retrieved from GitHub `evaluation/lite/<submission>/results/results.json` (`resolved` list).
- **Model Patches:** Fetched from the public S3 bucket `swe-bench-submissions` at `lite/<submission>/all_preds.jsonl` (anonymous HTTPS).

### Submissions & Row Counts
- **Submissions Used:** 18 submissions (2 skipped: `20250114_Isoform` and `20250609_KGCompass` due to predictions file 404).
- **Total Labeled Patches:** 5,123 labeled patches (181 empty patches excluded).
- **Overall Resolution Stats:** 1,696 resolved, 3,427 unresolved; positive rate **33.1%** (per-submission resolve rates range from **3.0% to 57.8%**).
- **Split Distribution (Grouped by Repo from `data/splits`):**
  - **Train repos:** 3,290 rows
  - **Val repo (`sympy/sympy`):** 1,297 rows
  - **Test repos (`matplotlib`, `xarray`, `seaborn`):** 536 rows (covering 32 distinct instances)
- **Patch Application Breakdown:**
  - Applied info exists for 2,066 rows: 1,715 applied cleanly, 1,257 applied-but-failed, 458 resolved.
  - 3,057 rows have no applied info.

---

## 3. Limitations & Evaluation Considerations

- **Issue Overlap:** Only 299 distinct issues are repeated across agent submissions. Cross-validation must group by `instance_id`.
- **Incomplete Application Metadata:** "Applied" info is missing for ~60% of rows.
- **Repository Skew:** Heavy repository distribution skew toward `django/django` (1,970 rows) and `sympy/sympy` (1,297 rows).
- **Shortcut & Fingerprint Risks:** Potential risks of agent-style formatting fingerprints and issue-difficulty shortcuts.
- **Unresolved Semantics:** "Unresolved" indicates test suite failure, not necessarily a "shallow fix".


---

## 4. Key Phase 2b Evaluation Findings

- **Issue Difficulty Explains Most of the Label:** Baseline B (Issue TF-IDF) achieves a strong global ROC-AUC (~0.685) because issue problem statements allow predicting overall issue difficulty. However, its Within-Instance AUC is exactly `0.500` because issue text is identical for all candidate patches of a given issue, so it cannot distinguish resolved patches from unresolved patches for the same issue.
- **LOSO was Leaky:** The original Leave-One-Submission-Out (LOSO) cross-validation shared `instance_id`s between training and held-out folds, yielding an artificially inflated mean AUC of `0.897`. The corrected instance-disjoint LOSO (excluding all instances in the test fold from training) yields a mean AUC of `0.492`, confirming that sharing issue instances creates severe data leakage.
- **Test Set Constraints (32 Instances):** The held-out test split comprises 32 distinct instances across 3 unseen repositories (`matplotlib`, `xarray`, `seaborn`). 24 of these instances contain both resolved and unresolved patches necessary for within-instance evaluation.
- **Confidence Intervals Overlap:** Bootstrap 95% confidence intervals overlap heavily across baseline models (e.g., Baseline A within-instance AUC `0.625 [0.540-0.704]` vs Combined E `0.675 [0.579-0.769]`), indicating that baselines cannot be strictly ranked with statistical significance on this test set size.
