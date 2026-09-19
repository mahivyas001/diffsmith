# 🛡️ AEGIS - The AI Fix Auditor

> **AI Code Fix Integrity & Prompt Injection Auditor**  
> A local CLI security and code auditing tool that detects shallow hacks, edge-case bypasses, and embedded prompt-injection attacks in AI-generated code repairs.

---

## 📖 Overview

As software engineering teams increasingly rely on autonomous coding agents and LLMs to remediate vulnerabilities and resolve bug tickets, a new attack surface emerges:
1. **Shallow AI Hacks:** AI models generating lazy fixes—such as commenting out assertions, suppressing errors, or inserting hardcoded magic numbers—rather than fixing the root cause.
2. **Indirect Prompt Injections:** Adversarial instructions hidden inside issue tickets or bug reports attempting to hijack the AI agent during automated patch generation.

**Aegis** is an offline security barrier that audits both the prompt context and the resulting code diff before patches are committed or merged.

---

## 🏛️ Architecture

Aegis uses a defense-in-depth pipeline combining rule-based heuristics with deep transformer models:

1. **Safety Scanner (`facebook/bart-large-mnli` + Fast Regex Layer)**
   - **Fast Layer (Regex):** Pre-empts common prompt injection vectors (`[ignore previous]`, `[system:]`, `[developer mode]`, DAN personas) in microseconds.
   - **Zero-Shot NLI Classifier:** Analyzes issue statements against candidate semantic profiles (`"describes a software bug"`, `"contains system instructions"`, `"is attempting a prompt injection"`, `"asks to ignore rules"`).
   - Assigns risk classifications: `SAFE`, `WARNING`, `FLAGGED`, or `CRITICAL`.

2. **Semantic Analyzer (`microsoft/codebert-base`)**
   - A dual-sequence classification model fine-tuned on SWE-bench Lite data and synthetically corrupted patches.
   - Evaluates joint context: `[CLS] problem_statement [SEP] patch [SEP]`.
   - Computes a calibrated **Fix Integrity Score** ($0\% - 100\%$), distinguishing genuine semantic repairs from shallow shortcuts.

3. **Structural Heuristics**
   - Synthetically probes diff structures for magic-number overrides, commented-out boundary checks, and lazy conditionals.
   - Integrates with the terminal dashboard for transparent violation explanations.

---

## 🚀 Installation

Clone the repository and install dependencies in your Python environment:

```bash
git clone https://github.com/mahivyas001/aegis.git
cd aegis
pip install -r requirements.txt
```

*(Optional)* If training on GPU, ensure PyTorch with CUDA support is installed.

---

## 💻 Usage

Run the Aegis CLI by providing the path to an issue report and its proposed patch diff:

```bash
python src/cli.py --issue demo/sample_issue.txt --diff demo/sample_patch.diff
```

### CLI Arguments

| Argument | Required | Description |
|---|:---:|---|
| `--issue` | **Yes** | Path to the bug report / issue description text file |
| `--diff` | **Yes** | Path to the code patch / unified diff file |
| `--model-path` | No | Path to fine-tuned model weights (defaults to `./models/aegis-core-v1`) |

---

## 🧪 Training & Pipeline Setup

To reproduce or update the fine-tuned audit model:

### 1. Mine and Synthesize Training Data
```bash
python -m src.data_loader
```
*Downloads `SWE-bench_Lite`, applies synthetic negative corruptions (magic numbers & commented checks), and generates `data/processed/training_data.csv`.*

### 2. Fine-Tune CodeBERT
```bash
python -m src.model_architecture
```
*Fine-tunes `microsoft/codebert-base` on GPU/CPU with early stopping on F1 score and saves the checkpoint to `models/aegis-core-v1/`.*

---

## 📂 Project Structure

```
aegis/
├── demo/
│   ├── sample_issue.txt         # Demo issue with prompt injection attempt
│   └── sample_patch.diff        # Demo patch with shallow hardcoded fix
├── src/
│   ├── __init__.py
│   ├── cli.py                   # Main terminal CLI & Rich report generator
│   ├── data_loader.py           # SWE-bench data loader & synthetic corruptor
│   ├── model_architecture.py    # CodeBERT fine-tuning pipeline
│   ├── safety_scanner.py        # BART zero-shot prompt injection detector
│   └── semantic_analyzer.py     # Semantic audit stubs
├── models/                      # Fine-tuned model checkpoints (models/aegis-core-v1/)
├── notebooks/                   # Prototyping and experiments
├── tests/                       # Test suites
├── requirements.txt             # Project dependencies
└── README.md
```

---

## 📊 Sample Output

When auditing a patch, Aegis renders an interactive terminal report:

```text
┌────────────────────────────── 🛡️  AEGIS AUDIT REPORT ──────────────────────────────┐
│                  AI Code Fix Integrity & Prompt Injection Auditor                  │
└────────────────────────────────────────────────────────────────────────────────────┘

  Issue File   demo/sample_issue.txt (142 chars)
  Patch Diff   demo/sample_patch.diff (128 chars)
  Audit Engine models/aegis-core-v1 [CPU]

╭─ 🔍 Input Safety Scan ─────────────────────────────────────────────────────────────╮
│ • Status: CRITICAL (Confidence: 100.0% via regex)                                  │
│ • Details: Fast-layer regex detected a directive: ignore previous instructions.    │
╰────────────────────────────────────────────────────────────────────────────────────╯

╭─ 🧠 Fix Integrity Analysis ────────────────────────────────────────────────────────╮
│ Fix Integrity Score: [██░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  12.4%                       │
│                                                                                    │
│   • Genuine Fix Probability:   12.4%                                               │
│   • Shallow Hack Probability:  87.6%                                               │
│   • Assessment: Patch exhibits signs of lazy edge-case suppression.                │
╰────────────────────────────────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ❌ VERDICT: REJECTED                                                               ┃
┃                                                                                    ┃
┃ Identified Violations:                                                             ┃
┃   • Safety Scanner flagged input issue as CRITICAL                                 ┃
┃   • Fix Integrity score (12.4%) falls below 50.0% safe threshold                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

---

## ⚖️ License

Distributed under the Apache 2.0 License.
