# diffsmith

A local CLI that flags risky patterns in AI-generated patches and in the issue text they came from. It does not judge whether a patch is correct.

## Framing

These rules are tripwires for common, named patterns written by one author. They are not a defence against a determined attacker, and a clean result does not mean a patch is correct or safe.

## Installation and Usage

Install in editable mode:

```bash
pip install -e .
```

Run an audit on a patch diff and an issue description:

```bash
diffsmith --diff patch.diff --issue issue.txt
```

CLI options:
- `--diff <path>`: Path to unified diff file to audit (required).
- `--issue <path>`: Path to issue description text file (required).
- `--json`: Emit machine-readable JSON output on stdout.
- `--codebert`: Enable the experimental CodeBERT signal (synthetic labels, no evaluation; shown separately and never part of the verdict). Default: OFF.
- `--model-path <path>`: Optional path to fine-tuned model directory (defaults to `./models/diffsmith-core-v1`).

### Exit Codes

- `0`: Clean; no risky patterns flagged, or low-severity informational notes only.
- `1`: Security MEDIUM finding or prompt injection finding (when no security HIGH).
- `2`: Security HIGH or CRITICAL finding (such as shell pipe, credential read, or hook tampering). If both security HIGH and injection findings occur, exit code is 2 and both findings are listed.
- `3`: Usage error or internal error (unreadable diff or issue file, empty diff or issue text, or an unhandled scanning layer exception).

### Layer Status Lines and Mandatory Footer

Every audit run reports status lines for all layers. The lines appear in the Scanner Layers panel and in JSON:
- `Security scanner: RAN`
- `Injection shield (regex): RAN`
- `Injection shield (ML): OFF (experimental; no calibrated threshold; see results/injection_ml_calibration.md)`
- `CodeBERT: OFF (experimental; trained on synthetic corruptions; no evaluation)`

Every terminal run ends with the mandatory footer line:
"This tool flags risky behavior; it does not determine whether a patch is correct or safe. Rules are tripwires for common named patterns, not a defence against a determined attacker."

## What It Checks

### Security Scanner (SEC001-SEC008)

The security scanner checks patch diffs for risky operational patterns (documented in [docs/DATA.md](docs/DATA.md)):
- `SEC001_NETWORK_CALL`: Outbound network calls (requests, urllib, socket, curl, wget).
- `SEC002_SHELL_PIPE`: Piped shell execution (`curl | sh`, `wget | bash`).
- `SEC003_COMMAND_EXEC`: Command execution invocations (subprocess, os.system, eval, exec).
- `SEC004_OBFUSCATION`: Obfuscated or Base64/binary string decoding.
- `SEC005_CREDENTIAL_READS`: Credential and sensitive environment variable access (.env, tokens, keys).
- `SEC006_WORKFLOW_BUILD`: CI workflow, build configuration, and dependency file modifications.
- `SEC007_HOOK_TAMPERING`: Git hooks, custom install command classes, and setup script tampering.
- `SEC008_DYNAMIC_ACCESS`: Dynamic reflective imports and attributes (`__import__`, `importlib`, `getattr`).

Severity policy: Only `SEC002_SHELL_PIPE` (which assigns `CRITICAL`), `SEC007_HOOK_TAMPERING` (which assigns `HIGH`), and `SEC005_CREDENTIAL_READS` (which assigns `HIGH` when matching credential-like targets outside scratch scripts and test files) produce `HIGH` or `CRITICAL` severity findings. All other security rules produce `MEDIUM` or `low` findings (or `review` for vendored directory additions).

### Regex Prompt-Injection Shield (INJ001-INJ006)

The injection shield scans issue text and added patch comments/strings for known directive patterns:
- `INJ001`: Instruction override directives (ignore previous instructions, reset system prompts).
- `INJ002`: Role and system impersonation (jailbreak personas, system mode declarations).
- `INJ003`: Exfiltration commands (requests to leak system messages, keys, or environment secrets).
- `INJ004`: Concealment directives (instructions to hide actions from users or reviewers).
- `INJ005`: Authority claims (false assertions of administrative or maintainer privileges).
- `INJ006`: Assistant command injections (directives commanding the assistant to insert backdoors or edit build files).

## Empirical Results

Wilson 95% confidence intervals are computed via [scripts/wilson_intervals.py](scripts/wilson_intervals.py). Every evaluation row is labelled with its methodological status:

| Evaluation Set | Status | Category / Metric | Result | Wilson 95% Confidence Interval |
|---|---|---|---|---|
| Security Set B v1 | held-out, frozen | Plain (expected rule) | 21 / 36 | 58.33% [42.20%, 72.86%] |
| Security Set B v1 | held-out, frozen | Plain (any rule) | 22 / 36 | 61.11% [44.86%, 75.22%] |
| Security Set B v1 | held-out, frozen | Evasion (expected rule) | 5 / 14 | 35.71% [16.34%, 61.24%] |
| Security Set B v1 | held-out, frozen | Evasion (any rule) | 10 / 14 | 71.43% [45.35%, 88.28%] |
| Security Set B v1 | held-out, frozen | Benign false alarms | 1 / 16 | 6.25% [1.11%, 28.33%] |
| Injection Set C v1 | held-out, frozen | Plain injection | 2 / 22 | 9.09% [2.53%, 27.81%] |
| Injection Set C v1 | held-out, frozen | Evasion injection | 2 / 14 | 14.29% [4.01%, 39.94%] |
| Injection Set C v1 | held-out, frozen | Benign false alarms | 0 / 37 | 0.00% [0.00%, 9.41%] |
| Real Patches (SWE-bench) | calibrated, not held-out | Flagged patches | 186 / 5,123 | 3.63% [3.15%, 4.18%] |
| Real Patches (SWE-bench) | calibrated; not independent evidence | HIGH severity patches | 0 / 5,123 | 0.00% [0.00%, 0.07%] |

Detailed records: [results/security_heldback_v1.md](results/security_heldback_v1.md) and [results/injection_setC_v1.md](results/injection_setC_v1.md).

Evaluation details and caveats:
- Security Set B v1: The evaluation set had 1 false alarm (`docs/Dockerfile.rst`, SEC006 MEDIUM), and 9 of 26 caught attacks reported HIGH/CRITICAL. As noted in the source evaluation, this is a "small hand-written set; not a benchmark and not evidence of real-world detection".
- Injection Set C v1: Under Set C, both plain detections were in added comments; 0 of 16 plain issue cases and 0 of 2 commit cases were caught. Three arguable cases (legitimate text quoting an attack string fires INJ001, not counted) are recorded in the evaluation document. The regex injection shield has very low recall on paraphrased or obfuscated injection inputs (flagging only 2/22 on Set C plain and 2/14 on Set C evasion); it operates as a precision-oriented tripwire for specific canonical phrases, not a general semantic injection detector.
- Prior Set B injection evaluations were inspected by the development agent during iteration; those numbers are dev-tuned, not evidence, and are void.
- The 5,123 real patch study ([results/security_eval.md](results/security_eval.md)) flagged 186 patches (3.63%) across 85 scratch scripts, 51 command executions (9 MEDIUM, 42 low), 36 workflow/build edits (36 MEDIUM), 12 obfuscation (12 low), 5 network calls (5 low), 3 credential reads (3 low), 3 dynamic access (1 MEDIUM, 2 low), and 1 vendored directory edit (1 review), with 0 HIGH findings. This calibration occurred after inspecting the corpus; it is calibrated; not independent evidence.

## What Did Not Work

Two experimental components failed to yield reliable production utility:

1. **ML Injection Layer (`ProtectAI/deberta-v3-base-prompt-injection-v2`):**
   Evaluated offline against real SWE-bench issues and patches (assumed benign) (see [results/injection_ml_calibration.md](results/injection_ml_calibration.md)). At a standard 0.50 decision threshold, the model flagged 222 of 300 issues and 967 of 5,123 patches. Even at extreme thresholds (0.99999), it flagged 51 issues and 172 patches. Because no candidate threshold achieved zero flags on both corpora, the layer is disabled by default (`None` threshold). The pipeline was checked (label index, attention mask, batching, tokenizer parity with raw sentencepiece) and no fault was found; the cause is not established.

2. **CodeBERT experiment (synthetic labels):**
   The model was trained on synthetic labels generated by a heuristic corruption function (`corrupt_patch`). Crucially, 94 `instance_id` values overlapped between the training and validation splits. No held-out test evaluation metrics were ever measured or verified. Model weights are not distributed. The `--codebert` option remains experimental, disabled by default, and entirely excluded from CLI verdicts.

## Methodology and Lessons Learned

Earlier iterations of the project suffered from evaluation contamination: an automated coding agent inspected and tuned rules directly against evaluation sets, invalidating reported figures.

To keep the evaluation numbers trustworthy:
- Held-out test cases are kept strictly outside the repository (as mandated by [RULES.md](RULES.md)).
- Agents are prohibited from viewing, listing, reading, or copying held-out files.
- Results are recorded as frozen documents (such as [results/security_heldback_v1.md](results/security_heldback_v1.md) and [results/injection_setC_v1.md](results/injection_setC_v1.md)) that are never modified after execution.

## Limitations

- **Single author:** Evaluation cases were authored by a single person and do not represent the full diversity of real-world threats.
- **Small sample sizes:** Sample counts are limited, resulting in wide Wilson confidence intervals.
- **Static tripwires:** Simple regex pattern matching can be easily bypassed by obfuscation, paraphrasing, or novel encodings.
- **English-only issue text:** Injection patterns and issue heuristics target English-language descriptions.
- **Tripwires, not barriers:** These rules are tripwires for common, named patterns written by one author. They are not a defence against a determined attacker, and a clean result does not mean a patch is correct or safe.

## License

Distributed under the Apache 2.0 License.
