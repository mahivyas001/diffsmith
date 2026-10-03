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

## 2. Investigation of `https://github.com/swe-bench/experiments`

We inspected all 84 submission directories under `evaluation/lite/` in `https://github.com/swe-bench/experiments` (e.g., `20240402_sweagent_gpt4`, `20240530_autocoderover-v20240408`, `20240604_CodeR`).

### Findings
- **Paths inspected:** `evaluation/lite/{submission}/results/results.json`, `patch_stats.json`, `metadata.yaml`
- **File format:** `results.json` contains JSON objects listing `instance_id` strings under keys `resolved`, `applied`, `no_generation`, `install_fail`, etc.
- **Result:** **NONE FOUND**. The `swe-bench/experiments` repository stores evaluation metadata and lists of resolved instance IDs, but **does NOT store the actual model-generated code patches or diff text**.

---

## 3. Proposed Options for Held-Out Evaluation

1. **Option A (Synthetic Corruptions for Held-Out Set):** Generate synthetic negative patches (`source="synthetic"`) for the 32 held-out test instances using the 6 corruption strategies.
2. **Option B (Hugging Face `SWE-bench/SWE-smith` Trajectories):** Stream/download model-generated patch strings and unit-test execution labels directly from `SWE-bench/SWE-smith`.
3. **Option C (Agent Release Logs):** Download prediction `.jsonl` files from model agent releases (e.g., SWE-agent, Aider).
