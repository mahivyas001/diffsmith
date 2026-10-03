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

## 2. Investigation of `https://github.com/swe-bench/experiments` (`evaluation/lite/`)

- **Total Lite Submissions:** 84 submission directories.
- **Directory Structure (Sample Submissions):**
  - `20240402_sweagent_gpt4`: `logo.png`, `metadata.yaml`, `README.md`, `figures/`, `results/end_condition.json`, `results/end_condition_resolved.json`, `results/file_f1.json`, `results/patch_stats.json`, `results/resolved_by_repo.json`, `results/resolved_by_time.json`, `results/results.json`
  - `20240530_autocoderover-v20240408`: `logo.jpg`, `metadata.yaml`, `README.md`, `results/file_f1.json`, `results/patch_stats.json`, `results/resolved_by_repo.json`, `results/resolved_by_time.json`, `results/results.json`
  - `20240604_CodeR`: `metadata.yaml`, `README.md`, `figs/`, `results/file_f1.json`, `results/patch_stats.json`, `results/resolved_by_repo.json`, `results/resolved_by_time.json`, `results/results.json`
- **Predictions File:** **NOT FOUND** (no prediction files such as `all_preds.jsonl` or patch text files are present).
- **Results File:** `results/results.json`
- **First 300 characters of `20240402_sweagent_gpt4/results/results.json`:**
  ```json
  {
    "no_generation": [
      "sympy__sympy-13146",
      "django__django-12284",
      "pytest-dev__pytest-5103",
      "sympy__sympy-20442",
      "django__django-15851",
      "sphinx-doc__sphinx-10451",
      "django__django-13964",
      "pytest-dev__pytest-7168",
      "sphinx-doc__sphinx-8721",
      "django__dja
  ```

---

## 3. Dataset Clarifications

- **`SWE-bench/SWE-smith`:** 59,026 synthetic bug injection task instances (columns: `instance_id`, `patch`, `FAIL_TO_PASS`, `PASS_TO_PASS`, `image_name`, `repo`, `problem_statement`). It contains task definitions, not model predictions or model resolution labels.
