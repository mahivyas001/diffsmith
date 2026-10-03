# RULES.md — Standing Rules for diffsmith Development

These rules apply for every phase of this project. No exceptions.

---

## 1. Verification Gate

**Every phase ends with `python scripts/verify.py` and the real output is
pasted verbatim into the PHASE SUMMARY. Never say a phase is "complete"
without that output.**

```powershell
python scripts/verify.py        # standard
python scripts/verify.py --smoke  # when training changes were made
```

---

## 2. Phase Summary Requirements

Every PHASE SUMMARY must include **all** of the following (no omissions):

| Field | Example |
|---|---|
| Commit hash | `abc1234` |
| Push confirmation | `pushed to origin/main` |
| Test counts | `passed=12 failed=0 skipped=0` |
| Python version | `3.14.4` |
| Transformers version | `5.17.0` |
| Key metrics (if training ran) | `train_loss=0.73  wall_time=68.9s  6.1s/step` |
| Red flags | any FAIL lines from verify.py |

---

## 3. Secrets, Checkpoints, and Data

- **Never commit** model weights, checkpoints (`models/checkpoint*/`), or large
  data files (`data/`). These are gitignored.
- **Never commit** `.env` files or API keys.
- Training output goes to `models/diffsmith-core-v1/` (gitignored).

---

## 4. Metric Honesty

**Never report metrics that were not computed by a running script.**

- Loss values must come from actual training output.
- Accuracy/F1 must come from actual evaluation output.
- Wall times must come from `scripts/verify.py --smoke` or trainer logs.
- Do not fabricate, estimate, or carry over numbers from previous runs.

---

## 5. Package Management

- **Always use `python -m pip`** for installs. Never bare `pip`.
- If a package has no Python 3.14 wheel, **say so explicitly** and propose
  setting up a Python 3.12 venv. Do not silently work around it.

---

## 6. Cost Constraint

**Everything stays free.** No paid APIs, no paid compute, no paid services.
Free tiers (Hugging Face Hub, GitHub Actions, Google Colab) are allowed.

---

## 7. Module Layout

All code lives in `src/diffsmith/`. The documented way to run the pipeline is:

```powershell
# Data generation
python -m diffsmith.data_loader

# Training (full)
python -m diffsmith.model_architecture

# Training (smoke test — 50 samples, 1 epoch)
python -m diffsmith.model_architecture --smoke

# Audit
python -m diffsmith.cli --issue demo/sample_issue.txt --diff demo/sample_patch.diff
# or via entry point:
diffsmith --issue demo/sample_issue.txt --diff demo/sample_patch.diff
```

---

## 8. Commit Message Convention

```
<type>(<scope>): <summary>

Types: feat | fix | chore | docs | refactor | test | ci
```

Examples:
- `feat(phase-1): add heuristic AST scanner`
- `chore: automated verification, pre-commit, CI, rules`
- `fix(training): correct path resolution for DATA_CSV`
