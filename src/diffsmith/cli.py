# cli.py -- Entry point for the diffsmith command-line interface.

import argparse
import json
import os
import sys
from typing import Any

# Enable UTF-8 for console output on Windows to prevent charmap UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is on sys.path regardless of how script is invoked
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from diffsmith.safety import scan_patch, scan_patch_comments, scan_text

console = Console()

DEFAULT_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "diffsmith-core-v1")
ALT_LOCAL_MODEL_DIR = os.path.abspath("./models/diffsmith-core-v1")

MANDATORY_FOOTER = (
    "This tool flags risky behavior; it does not determine whether a patch is correct or safe. "
    "Rules are tripwires for common named patterns, not a defence against a determined attacker."
)


# ---------------------------------------------------------------------------
# Custom Argument Parser (Exit code 3 on usage errors)
# ---------------------------------------------------------------------------
class DiffsmithArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that exits with code 3 on usage errors instead of 2."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(3)


# ---------------------------------------------------------------------------
# Local Model Verification & Loader
# ---------------------------------------------------------------------------
def resolve_model_path(custom_path: str | None = None) -> str:
    """
    Resolve and validate the local model directory.
    Checks custom path first, then ./models/diffsmith-core-v1 and project-root equivalent.
    """
    candidates = []
    if custom_path:
        candidates.append(os.path.abspath(custom_path))
    candidates.append(ALT_LOCAL_MODEL_DIR)
    candidates.append(DEFAULT_MODEL_DIR)

    for path in candidates:
        if os.path.isdir(path):
            has_config = os.path.exists(os.path.join(path, "config.json"))
            has_weights = any(
                os.path.exists(os.path.join(path, f))
                for f in ["pytorch_model.bin", "model.safetensors"]
            )
            if has_config and has_weights:
                return path

    return ""


def load_local_model(model_path: str):
    """
    Load the fine-tuned CodeBERT model and tokenizer strictly from local disk.
    """
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_path,
        num_labels=2,
        local_files_only=True,
    )
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = model.to(device)
    model.eval()
    return tokenizer, model, device


# ---------------------------------------------------------------------------
# Visual Component Helpers
# ---------------------------------------------------------------------------
def make_progress_bar(percentage: float, width: int = 30) -> str:
    """Create a formatted ASCII progress bar with color styling."""
    filled_len = int(round(width * (percentage / 100.0)))
    filled_len = max(0, min(width, filled_len))
    empty_len = width - filled_len
    bar = "█" * filled_len + "░" * empty_len

    if percentage >= 75:
        color = "green"
    elif percentage >= 50:
        color = "yellow"
    else:
        color = "red"

    return f"[{color}]{bar}[/{color}] [bold {color}]{percentage:5.1f}%[/bold {color}]"


# ---------------------------------------------------------------------------
# De-duplication and Verdict Determination
# ---------------------------------------------------------------------------
def deduplicate_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """
    De-duplicate findings by (rule_id, file, line, evidence).
    Returns (unique_findings, duplicates_collapsed).
    """
    seen: set[tuple[Any, ...]] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = (
            f.get("rule_id"),
            f.get("file"),
            f.get("line"),
            f.get("evidence"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    collapsed = len(findings) - len(unique)
    return unique, collapsed


def determine_verdict(findings: list[dict[str, Any]]) -> tuple[str, int]:
    """
    Determine the verdict and exit code from findings, case-insensitively:
      - no findings: exit 0
      - only LOW/REVIEW-level security findings: exit 0
      - security MEDIUM: exit 1
      - security HIGH or CRITICAL: exit 2
      - any injection-shield finding (any severity), and no security HIGH: exit 1
      - both security HIGH and injection findings: exit 2 and list both
    """
    if not findings:
        return "No risky patterns flagged.", 0

    has_security_high = False
    has_security_medium = False
    has_security_low_or_review = False
    has_injection = False

    for f in findings:
        rule_id = str(f.get("rule_id", "")).upper()
        severity = str(f.get("severity", "")).upper()

        if rule_id.startswith("INJ"):
            has_injection = True
        else:
            if severity in ("HIGH", "CRITICAL"):
                has_security_high = True
            elif severity == "MEDIUM":
                has_security_medium = True
            elif severity in ("LOW", "REVIEW"):
                has_security_low_or_review = True

    if has_security_high and has_injection:
        return (
            "Do not merge without manual review. "
            "Human should review: possible prompt-injection content in the issue or patch text.",
            2,
        )
    if has_security_high:
        return "Do not merge without manual review.", 2
    if has_injection:
        if has_security_medium:
            return (
                "Review recommended: risky behavior flagged. "
                "Human should review: possible prompt-injection content in the issue or patch text.",
                1,
            )
        return (
            "Human should review: possible prompt-injection content in the issue or patch text.",
            1,
        )
    if has_security_medium:
        return "Review recommended: risky behavior flagged.", 1
    if has_security_low_or_review:
        return "Low-severity notes only; listed below.", 0

    return "No risky patterns flagged.", 0


def _handle_error(reason: str, json_mode: bool = False) -> int:
    """Handle internal error, print message, and exit with code 3."""
    if json_mode:
        err_payload = {
            "verdict": f"ERROR: {reason}",
            "exit_code": 3,
            "layers": {
                "Security scanner": "NOT RUN (error)",
                "Injection shield (regex)": "NOT RUN (error)",
                "Injection shield (ML)": "OFF (experimental; no calibrated threshold; see results/injection_ml_calibration.md)",
                "CodeBERT": "OFF (experimental; trained on synthetic corruptions; no evaluation)",
            },
            "findings": [],
            "duplicates_collapsed": 0,
            "experimental": {},
            "footer": MANDATORY_FOOTER,
        }
        sys.stdout.write(json.dumps(err_payload, indent=2) + "\n")
        sys.stderr.write(f"ERROR: {reason}\n")
    else:
        console.print(f"[bold red]ERROR:[/bold red] {reason}")
    return 3


# ---------------------------------------------------------------------------
# Audit Pipeline
# ---------------------------------------------------------------------------
def run_audit(
    diff_path: str,
    issue_path: str,
    model_path: str | None = None,
    json_mode: bool = False,
    use_codebert: bool = False,
) -> int:
    """
    Execute full diffsmith audit on an issue description and code patch.
    """
    # -- File Validations ---------------------------------------------------
    if not os.path.isfile(issue_path):
        return _handle_error(f"Issue file not found: {issue_path}", json_mode)

    try:
        with open(issue_path, encoding="utf-8") as f:
            issue_text = f.read()
    except Exception as e:
        return _handle_error(f"Could not read issue file '{issue_path}': {e}", json_mode)

    if not issue_text.strip():
        return _handle_error(f"Issue file is empty: {issue_path}", json_mode)

    if not os.path.isfile(diff_path):
        return _handle_error(f"Diff file not found: {diff_path}", json_mode)

    try:
        with open(diff_path, "rb") as f:
            diff_bytes = f.read()
        if b"\x00" in diff_bytes:
            return _handle_error(f"Diff file is non-text (binary): {diff_path}", json_mode)
        diff_text = diff_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return _handle_error(f"Diff file is non-text or not valid UTF-8: {e}", json_mode)
    except Exception as e:
        return _handle_error(f"Could not read diff file '{diff_path}': {e}", json_mode)

    if not diff_text.strip():
        return _handle_error(f"Diff file is empty: {diff_path}", json_mode)

    # -- Layer Execution ----------------------------------------------------
    raw_findings: list[dict[str, Any]] = []

    # 1. Security scanner
    try:
        sec_findings = scan_patch(diff_text)
        if sec_findings:
            raw_findings.extend(sec_findings)
    except Exception as e:
        return _handle_error(f"Security scanner layer failed: {e}", json_mode)

    # 2. Regex injection shield on issue text
    try:
        inj_issue_findings = scan_text(issue_text, source="issue")
        if inj_issue_findings:
            raw_findings.extend(inj_issue_findings)
    except Exception as e:
        return _handle_error(f"Injection shield (regex) on issue text failed: {e}", json_mode)

    # 3. Regex injection shield on added patch comments/strings
    try:
        inj_comment_findings = scan_patch_comments(diff_text)
        if inj_comment_findings:
            raw_findings.extend(inj_comment_findings)
    except Exception as e:
        return _handle_error(f"Injection shield (regex) on patch comments failed: {e}", json_mode)

    # -- De-duplicate Findings ----------------------------------------------
    unique_findings, collapsed = deduplicate_findings(raw_findings)

    # -- Verdict Decision ---------------------------------------------------
    verdict, exit_code = determine_verdict(unique_findings)

    # -- CodeBERT (Optional Experimental Signal) ----------------------------
    codebert_status = "OFF (experimental; trained on synthetic corruptions; no evaluation)"
    experimental_data: dict[str, Any] = {}
    p_genuine: float | None = None
    p_shallow: float | None = None

    if use_codebert:
        resolved_path = resolve_model_path(model_path)
        if not resolved_path:
            reason = f"no local weights found at {model_path or './models/diffsmith-core-v1'}"
            codebert_status = f"NOT RUN ({reason})"
            experimental_data["codebert"] = {"status": codebert_status}
        else:
            try:
                import torch
                from diffsmith.model_architecture import truncate_issue_and_patch

                tokenizer, model, device = load_local_model(resolved_path)
                trunc_issue, trunc_diff = truncate_issue_and_patch(
                    issue_text, diff_text, tokenizer, max_length=256
                )
                inputs = tokenizer(
                    trunc_issue,
                    trunc_diff,
                    truncation=True,
                    padding=True,
                    max_length=256,
                    return_tensors="pt",
                )
                inputs = {k: v.to(device) for k, v in inputs.items()}
                with torch.no_grad():
                    outputs = model(**inputs)
                    probabilities = torch.softmax(outputs.logits, dim=-1)[0]

                p_genuine = round(float(probabilities[0].item()), 4)
                p_shallow = round(float(probabilities[1].item()), 4)
                codebert_status = "RAN"
                experimental_data["codebert"] = {
                    "status": "RAN",
                    "p_genuine": p_genuine,
                    "p_shallow": p_shallow,
                }
            except Exception as e:
                codebert_status = f"NOT RUN (inference error: {e})"
                experimental_data["codebert"] = {"status": codebert_status}

    # -- Layer Statuses -----------------------------------------------------
    layers = {
        "Security scanner": "RAN",
        "Injection shield (regex)": "RAN",
        "Injection shield (ML)": "OFF (experimental; no calibrated threshold; see results/injection_ml_calibration.md)",
        "CodeBERT": codebert_status,
    }

    # -- Presentation -------------------------------------------------------
    if json_mode:
        payload = {
            "verdict": verdict,
            "exit_code": exit_code,
            "layers": layers,
            "findings": unique_findings,
            "duplicates_collapsed": collapsed,
            "experimental": experimental_data,
            "footer": MANDATORY_FOOTER,
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return exit_code

    # Rich Text UI
    console.print()
    console.print(
        Panel(
            Text("🛡️  DIFFSMITH AUDIT REPORT", style="bold white on blue", justify="center"),
            subtitle="[dim]flags risky patterns; not a correctness check[/dim]",
            box=box.DOUBLE_EDGE,
            border_style="blue",
        )
    )

    # Layer Status Panel
    status_lines = [f"• {name}: [bold]{st}[/bold]" for name, st in layers.items()]
    console.print(
        Panel(
            "\n".join(status_lines),
            title="⚙️ Scanner Layers",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # Collapsed Duplicates Note
    console.print(f"[dim]{collapsed} duplicate findings collapsed[/dim]")
    console.print()

    # Findings Display
    if unique_findings:
        table = Table(title="Flagged Patterns", box=box.SIMPLE, show_edge=True)
        table.add_column("Rule ID", style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Location", style="yellow")
        table.add_column("Evidence", style="white")

        for f in unique_findings:
            sev = str(f.get("severity", "UNKNOWN")).upper()
            color = "red" if sev in ("HIGH", "CRITICAL") else ("yellow" if sev == "MEDIUM" else "blue")
            loc = f"{f.get('file', 'issue')}:{f.get('line', '-')}"
            table.add_row(
                f.get("rule_id", "UNKNOWN"),
                f"[{color}]{sev}[/{color}]",
                loc,
                str(f.get("evidence", ""))[:120],
            )
        console.print(table)
        console.print()

    # Experimental Signal Heading (if requested)
    if use_codebert:
        exp_lines = [f"• Status: {codebert_status}"]
        if p_genuine is not None and p_shallow is not None:
            exp_lines.append(f"• Genuine Probability: {p_genuine * 100:.1f}%")
            exp_lines.append(f"• Shallow Probability: {p_shallow * 100:.1f}%")
        console.print(
            Panel(
                "\n".join(exp_lines),
                title="🔬 Experimental signal (not part of the verdict)",
                border_style="dim",
                box=box.ROUNDED,
            )
        )

    # Final Verdict Panel
    if exit_code == 0:
        verdict_color = "green"
        prefix = "✅ VERDICT:"
    elif exit_code == 1:
        verdict_color = "yellow"
        prefix = "⚠️ VERDICT:"
    else:
        verdict_color = "red"
        prefix = "❌ VERDICT:"

    verdict_panel = Panel(
        Text(f"{prefix} {verdict}", style=f"bold {verdict_color}", justify="center"),
        border_style=verdict_color,
        box=box.HEAVY,
    )
    console.print(verdict_panel)
    console.print()

    # Mandatory Footer
    console.print(f"[dim]{MANDATORY_FOOTER}[/dim]", soft_wrap=True)
    console.print()

    return exit_code


# ---------------------------------------------------------------------------
# Entry Point & Argument Parsing
# ---------------------------------------------------------------------------
def main():
    parser = DiffsmithArgumentParser(
        prog="diffsmith",
        description="diffsmith: flags risky patterns in AI-generated patches; it does not judge correctness",
    )
    parser.add_argument(
        "--diff",
        required=True,
        help="Path to the code patch / diff file to audit.",
    )
    parser.add_argument(
        "--issue",
        required=True,
        help="Path to the issue description text file.",
    )
    parser.add_argument(
        "--model-path",
        default=None,
        help="Optional custom path to fine-tuned model directory (defaults to ./models/diffsmith-core-v1).",
    )
    parser.add_argument(
        "--json",
        dest="json_mode",
        action="store_true",
        help="Emit machine-readable JSON output on stdout.",
    )
    parser.add_argument(
        "--codebert",
        dest="use_codebert",
        action="store_true",
        help="Enable experimental CodeBERT fix integrity layer (default: OFF).",
    )

    args = parser.parse_args()
    exit_code = run_audit(
        diff_path=args.diff,
        issue_path=args.issue,
        model_path=args.model_path,
        json_mode=args.json_mode,
        use_codebert=args.use_codebert,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
