"""
scripts/verify.py — Automated verification for diffsmith.

Usage:
    python scripts/verify.py           # run all checks
    python scripts/verify.py --smoke   # also run the training smoke test
"""

import argparse
import os
import re
import subprocess
import sys

# Windows: reconfigure stdout to UTF-8 so the script is safe in any console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── helpers ──────────────────────────────────────────────────────────────────

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run(cmd: list[str], *, capture: bool = True, cwd: str = REPO_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        cwd=cwd,
    )


results: list[tuple[str, bool, str]] = []  # (label, passed, detail)


def check(label: str, passed: bool, detail: str = "") -> bool:
    status = "PASS" if passed else "FAIL"
    suffix = f"  [{detail}]" if detail else ""
    print(f"  {status}  {label}{suffix}")
    results.append((label, passed, detail))
    return passed


# ── checks ────────────────────────────────────────────────────────────────────

def check_git() -> None:
    print("\n── git ──────────────────────────────────────────────────────────────")

    # Working tree clean
    r = run([sys.executable, "-c",
             "import subprocess, sys; r=subprocess.run(['git','status','--porcelain'],capture_output=True,text=True); sys.stdout.write(r.stdout)"])
    dirty = r.stdout.strip()
    check("working tree clean", not dirty, dirty[:80] if dirty else "")

    # Branch not ahead of origin
    r = run(["git", "rev-list", "--count", "@{u}..HEAD"])
    ahead = r.stdout.strip() if r.returncode == 0 else "?"
    check("not ahead of origin/main", ahead == "0", f"ahead={ahead}")

    # No untracked junk files (allow .pytest_cache, __pycache__, .ruff_cache)
    r = run(["git", "ls-files", "--others", "--exclude-standard"])
    untracked = [
        f.strip() for f in r.stdout.splitlines()
        if f.strip()
        and not f.strip().startswith((".pytest_cache", "__pycache__", ".ruff_cache"))
        and not f.strip().endswith(".pyc")
    ]
    check("no untracked junk files", not untracked,
          ", ".join(untracked[:5]) if untracked else "")


def check_environment() -> None:
    print("\n── environment ──────────────────────────────────────────────────────")

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    check("python version", True, py_ver)

    try:
        import transformers  # noqa: PLC0415
        tf_ver = transformers.__version__
        check("transformers importable", True, tf_ver)
    except ImportError as e:
        check("transformers importable", False, str(e))

    try:
        import diffsmith  # noqa: PLC0415
        check("diffsmith importable", True, getattr(diffsmith, "__version__", "ok"))
    except ImportError as e:
        check("diffsmith importable", False, str(e))


def check_no_aegis() -> None:
    print("\n── aegis / duplicate checks ─────────────────────────────────────────")

    r = run(["git", "grep", "-i", "aegis"])
    check("git grep -i aegis returns nothing", r.returncode != 0,
          r.stdout.strip()[:120] if r.returncode == 0 else "")

    # No duplicated module names under src/
    r = run(["git", "ls-files", "src"])
    files = r.stdout.splitlines()
    basenames = [os.path.basename(f) for f in files if f.endswith(".py")]
    from collections import Counter  # noqa: PLC0415
    dupes = [n for n, c in Counter(basenames).items() if c > 1]
    check("no duplicated module names under src/", not dupes,
          ", ".join(dupes) if dupes else "")


def check_ruff() -> None:
    print("\n── ruff ─────────────────────────────────────────────────────────────")

    r = run([sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"])
    passed = r.returncode == 0
    detail = ""
    if not passed:
        lines = (r.stdout + r.stderr).strip().splitlines()
        detail = "; ".join(lines[:3])
    check("ruff check src tests scripts", passed, detail)


def check_pytest() -> None:
    print("\n── pytest ───────────────────────────────────────────────────────────")

    r = run([sys.executable, "-m", "pytest", "-v", "--tb=short"])
    output = r.stdout + r.stderr

    # Parse summary line e.g. "12 passed in 11.88s" or "1 failed, 11 passed"
    summary_match = re.search(
        r"(\d+) passed(?:, (\d+) failed)?(?:, (\d+) warning)?(?:, (\d+) skipped)?",
        output,
    )
    failed_match = re.search(r"(\d+) failed", output)
    skipped_match = re.search(r"(\d+) skipped", output)

    passed_count = int(summary_match.group(1)) if summary_match else 0
    failed_count = int(failed_match.group(1)) if failed_match else 0
    skipped_count = int(skipped_match.group(1)) if skipped_match else 0

    overall_passed = r.returncode == 0 and failed_count == 0
    detail = f"passed={passed_count} failed={failed_count} skipped={skipped_count}"

    if skipped_count > 0:
        # Any skipped test is a FAIL — every test we register is expected to run
        overall_passed = False
        detail += " (skipped tests are unexpected)"

    check("pytest", overall_passed, detail)

    # Print the last few lines of pytest output for visibility
    tail = output.strip().splitlines()[-8:]
    for line in tail:
        print(f"       {line}")


def check_smoke() -> None:
    print("\n── smoke test (--smoke flag) ────────────────────────────────────────")

    r = run([sys.executable, "-m", "diffsmith.model_architecture", "--smoke"])
    output = r.stdout + r.stderr

    # Extract loss and wall time from output
    loss_match = re.search(r"'train_loss':\s*'?([0-9.]+)", output)
    time_match = re.search(r"Total wall time:\s*([0-9.]+)s", output)

    if loss_match:
        loss = float(loss_match.group(1))
        check("smoke loss < 1.5 (model initialised)", loss < 1.5, f"train_loss={loss:.4f}")
    else:
        check("smoke loss captured", False, "loss not found in output")

    if time_match:
        secs = float(time_match.group(1))
        check("smoke wall time", True, f"{secs:.1f}s")
    else:
        check("smoke wall time captured", False, "wall time not found in output")

    # Print last 15 lines for visibility
    for line in output.strip().splitlines()[-15:]:
        print(f"       {line}")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="diffsmith automated verification")
    parser.add_argument("--smoke", action="store_true",
                        help="Also run the training smoke test.")
    args = parser.parse_args()

    print("=" * 70)
    print("diffsmith — automated verification")
    print("=" * 70)

    check_git()
    check_environment()
    check_no_aegis()
    check_ruff()
    check_pytest()

    if args.smoke:
        check_smoke()

    # ── overall result ────────────────────────────────────────────────────────
    total = len(results)
    n_pass = sum(1 for _, p, _ in results if p)
    n_fail = total - n_pass

    print("\n" + "=" * 70)
    if n_fail == 0:
        print(f"OVERALL  PASS  ({n_pass}/{total} checks passed)")
    else:
        print(f"OVERALL  FAIL  ({n_pass}/{total} checks passed, {n_fail} failing)")
        for label, passed, detail in results:
            if not passed:
                print(f"  FAIL  {label}  [{detail}]")
    print("=" * 70)

    sys.exit(0 if n_fail == 0 else 1)


if __name__ == "__main__":
    main()
