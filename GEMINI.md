# diffsmith — Project Rules for Antigravity

These rules are always active for this workspace.

## Verification Gate

Every phase ends with `python scripts/verify.py` and the **real output** is pasted verbatim into the PHASE SUMMARY. Never declare a phase "complete" without it.

```powershell
python scripts/verify.py           # all phases
python scripts/verify.py --smoke   # when training code changed
```

## Phase Summary Requirements

Every PHASE SUMMARY must include **all** of:
- Commit hash and push confirmation
- `python scripts/verify.py` output (verbatim, not paraphrased)
- Test counts: `passed=N failed=0 skipped=0`
- Python version and transformers version
- Key metrics if training ran: `train_loss`, `wall_time`, `s/step`
- All FAIL lines from verify.py (zero FAILs = OK to proceed)

## Code Location

All source code lives in `src/diffsmith/`. The canonical commands are:

```powershell
python -m diffsmith.data_loader                     # generate training CSV
python -m diffsmith.model_architecture              # full training
python -m diffsmith.model_architecture --smoke      # 50-sample smoke test
diffsmith --issue <f> --diff <f>                    # run audit
```

## Package Management

- Always `python -m pip` — never bare `pip`.
- If a package has no Python 3.14 wheel, say so and propose a 3.12 venv. Never silently work around it.

## Metric Honesty

Never report metrics not computed by a running script. Loss, accuracy, F1, wall time — all must come from actual script output, not estimates or prior runs.

## Secrets and Large Files

Never commit: model weights, checkpoints (`models/`), data files (`data/`), `.env`, API keys. All are gitignored.

## Everything Stays Free

No paid APIs, paid compute, or paid services. Free tiers allowed (HF Hub, GitHub Actions, Google Colab).
