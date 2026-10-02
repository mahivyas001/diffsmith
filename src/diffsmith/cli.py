# cli.py — Entry point for the diffsmith command-line interface.

import os
import sys
import argparse
from typing import Optional, Tuple

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

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

DEFAULT_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "diffsmith-core-v1")
ALT_LOCAL_MODEL_DIR = os.path.abspath("./models/diffsmith-core-v1")
LEGACY_MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "aegis-core-v1")
ALT_LEGACY_MODEL_DIR = os.path.abspath("./models/aegis-core-v1")



# ─────────────────────────────────────────────
# Local Model Verification & Loader
# ─────────────────────────────────────────────
def resolve_model_path(custom_path: Optional[str] = None) -> str:
    """
    Resolve and validate the local model directory.
    Checks custom path, ./models/diffsmith-core-v1, and legacy fallback paths.
    """
    candidates = []
    if custom_path:
        candidates.append(os.path.abspath(custom_path))
    candidates.append(ALT_LOCAL_MODEL_DIR)
    candidates.append(DEFAULT_MODEL_DIR)
    candidates.append(ALT_LEGACY_MODEL_DIR)
    candidates.append(LEGACY_MODEL_DIR)

    for path in candidates:
        if os.path.isdir(path):
            # Verify basic HuggingFace model artifacts exist
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
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

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
    except Exception as e:
        console.print(
            Panel(
                f"[bold red]Failed to load local model from:[/bold red] {model_path}\n"
                f"[dim]Details: {str(e)}[/dim]",
                title="❌ Model Load Error",
                border_style="red",
            )
        )
        sys.exit(1)



# ─────────────────────────────────────────────
# Visual Component Helpers
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
# Audit Pipeline
# ─────────────────────────────────────────────
def run_audit(diff_path: str, issue_path: str, model_path: Optional[str] = None) -> int:
    """
    Execute full diffsmith audit on an issue description and code patch.
    Returns exit code (0 for APPROVED, 1 for REJECTED / ERROR).
    """
    # ── File Validations ───────────────────────────────────────────────────
    if not os.path.isfile(issue_path):
        console.print(
            Panel(
                f"[bold red]Issue file not found:[/bold red] {issue_path}\n"
                "Please provide a valid path to the issue text file.",
                title="❌ File Error",
                border_style="red",
            )
        )
        return 1

    if not os.path.isfile(diff_path):
        console.print(
            Panel(
                f"[bold red]Diff file not found:[/bold red] {diff_path}\n"
                "Please provide a valid path to the code patch / diff file.",
                title="❌ File Error",
                border_style="red",
            )
        )
        return 1

    with open(issue_path, "r", encoding="utf-8", errors="replace") as f:
        issue_text = f.read().strip()

    with open(diff_path, "r", encoding="utf-8", errors="replace") as f:
        diff_text = f.read().strip()

    if not issue_text:
        console.print(Panel("[bold red]Issue file is empty.[/bold red]", title="❌ File Error", border_style="red"))
        return 1

    if not diff_text:
        console.print(Panel("[bold red]Diff file is empty.[/bold red]", title="❌ File Error", border_style="red"))
        return 1

    # ── Model Resolution ───────────────────────────────────────────────────
    resolved_path = resolve_model_path(model_path)
    if not resolved_path:
        console.print(
            Panel(
                "[bold red]No fine-tuned model found at local path:[/bold red] ./models/diffsmith-core-v1\n\n"
                "[yellow]Please run the training pipeline first to build the local model:[/yellow]\n\n"
                "    [bold cyan]python -m src.data_loader[/bold cyan]\n"
                "    [bold cyan]python -m src.model_architecture[/bold cyan]\n\n"
                "[dim]diffsmith requires our locally fine-tuned CodeBERT model to perform semantic audits.[/dim]",
                title="⚠ Model Missing",
                border_style="yellow",
                expand=False,
            )
        )
        return 1

    # ── Step 1: Safety Scan ────────────────────────────────────────────────
    try:
        from diffsmith.safety_scanner import scan_text
    except ImportError:
        from src.safety_scanner import scan_text

    with console.status("[bold cyan]Step 1/2: Running Safety Scanner on Issue...", spinner="dots"):
        safety_result = scan_text(issue_text)

    safety_status = safety_result.get("status", "WARNING")
    safety_confidence = safety_result.get("confidence", 0.0)
    safety_reason = safety_result.get("reason", "No reason provided.")
    safety_layer = safety_result.get("layer", "unknown")

    # Global risk flag for dangerous instructions
    is_safety_flagged = safety_status in ("CRITICAL", "FLAGGED")

    # ── Step 2: Semantic Analysis ──────────────────────────────────────────
    import torch

    with console.status(f"[bold cyan]Step 2/2: Loading {os.path.basename(resolved_path)} & Auditing Patch...", spinner="dots"):
        tokenizer, model, device = load_local_model(resolved_path)

        inputs = tokenizer(
            issue_text,
            diff_text,
            truncation=True,
            padding="max_length",
            max_length=256,
            return_tensors="pt",
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)[0]

        # Label 0 = Genuine, Label 1 = Shallow/Fake
        p_genuine = float(probabilities[0].item())
        p_shallow = float(probabilities[1].item())
        integrity_score = round(p_genuine * 100.0, 2)

    # ── Verdict Decision ───────────────────────────────────────────────────
    rejection_reasons = []
    if is_safety_flagged:
        rejection_reasons.append(f"Safety Scanner flagged input issue as [bold]{safety_status}[/bold]")
    if integrity_score < 50.0:
        rejection_reasons.append(
            f"Fix Integrity score ([bold]{integrity_score}%[/bold]) falls below 50.0% safe threshold"
        )

    is_approved = (not is_safety_flagged) and (integrity_score >= 50.0)

    # ── Rich UI Report Presentation ────────────────────────────────────────
    console.print()
    # Main Header
    console.print(
        Panel(
            Text("🛡️  DIFFSMITH AUDIT REPORT", style="bold white on blue", justify="center"),
            subtitle="[dim]an evidence-based auditor for AI-generated patches[/dim]",
            box=box.DOUBLE_EDGE,
            border_style="blue",
        )
    )

    # Target Metadata Table
    meta_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    meta_table.add_column("Key", style="bold cyan")
    meta_table.add_column("Value", style="white")
    meta_table.add_row("Issue File", f"{os.path.abspath(issue_path)} ({len(issue_text)} chars)")
    meta_table.add_row("Patch Diff", f"{os.path.abspath(diff_path)} ({len(diff_text.splitlines())} lines)")
    meta_table.add_row("Audit Engine", f"{resolved_path} [{device.upper()}]")
    console.print(meta_table)
    console.print()

    # Section 1: Safety Scanner
    safety_color = "green" if safety_status == "SAFE" else ("yellow" if safety_status == "WARNING" else "red")
    safety_badge = f"[bold {safety_color}]{safety_status}[/bold {safety_color}]"

    safety_content = (
        f"• Status: {safety_badge} (Confidence: [bold]{safety_confidence * 100:.1f}%[/bold] via [dim]{safety_layer}[/dim])\n"
        f"• Details: [dim]{safety_reason}[/dim]"
    )
    console.print(
        Panel(
            safety_content,
            title="🔍 Input Safety Scan",
            border_style=safety_color,
            box=box.ROUNDED,
        )
    )

    # Section 2: Fix Integrity Analysis
    meter_bar = make_progress_bar(integrity_score)
    integrity_color = "green" if integrity_score >= 50.0 else "red"

    integrity_content = (
        f"Fix Integrity Score: {meter_bar}\n\n"
        f"  • Genuine Fix Probability:  [bold green]{p_genuine * 100:5.1f}%[/bold green]\n"
        f"  • Shallow Hack Probability: [bold red]{p_shallow * 100:5.1f}%[/bold red]\n"
        f"  • Assessment: [italic {integrity_color}]"
        f"{'Patch demonstrates genuine semantic repair logic.' if integrity_score >= 50.0 else 'Patch exhibits signs of lazy edge-case suppression or magic-number hacks.'}"
        f"[/italic {integrity_color}]"
    )
    console.print(
        Panel(
            integrity_content,
            title="🧠 Fix Integrity Analysis",
            border_style=integrity_color,
            box=box.ROUNDED,
        )
    )

    # Section 3: Final Verdict
    if is_approved:
        verdict_panel = Panel(
            Text("✅ VERDICT: APPROVED\nAll safety tests passed. Code patch meets integrity standards.",
                 style="bold green", justify="center"),
            border_style="green",
            box=box.HEAVY,
        )
        exit_code = 0
    else:
        reasons_bullet = "\n".join(f"  • {r}" for r in rejection_reasons)
        verdict_text = (
            f"[bold red]❌ VERDICT: REJECTED[/bold red]\n\n"
            f"[bold yellow]Identified Violations:[/bold yellow]\n{reasons_bullet}"
        )
        verdict_panel = Panel(
            verdict_text,
            border_style="red",
            box=box.HEAVY,
        )
        exit_code = 1

    console.print(verdict_panel)
    console.print()
    return exit_code


# ─────────────────────────────────────────────
# Entry Point & Argument Parsing
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="diffsmith",
        description="diffsmith: an evidence-based auditor for AI-generated patches",
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

    args = parser.parse_args()
    exit_code = run_audit(args.diff, args.issue, args.model_path)
    sys.exit(exit_code)



if __name__ == "__main__":
    main()
