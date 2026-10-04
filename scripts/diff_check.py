"""Cheap, offline well-formedness check for unified diffs (no repo needed).

This is a PROXY for "would `git apply` even parse this": it checks structure,
not whether the patch applies to the actual code. Use it to separate
malformed patches from plausible ones when the `applied` info is missing.

    from diffsmith-style import: scripts/diff_check.py -> check_diff(patch)
    python scripts/diff_check.py        # annotates data/heldout/heldout.csv
"""
import csv
import os
import re
import sys
from collections import Counter

# Some agents emit "diff --git a/x b/x--- a/x" (missing newline). The SWE-bench
# harness accepted these (resolved patches exist), so repair before checking.
GLUED_HEADER_RE = re.compile(r"^(diff --git a/\S+ b/\S+)(--- )", re.MULTILINE)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def check_diff(patch):
    """Return (well_formed: bool, reason: str). reason is 'ok' when valid."""
    if not patch or not patch.strip():
        return False, "empty"
    patch = GLUED_HEADER_RE.sub(r"\1\n\2", patch)
    lines = patch.split("\n")  # not splitlines(): it also splits on \x0c etc.
    if lines and lines[-1] == "":     # drop the artifact of a final newline
        lines.pop()
    has_old = any(ln.startswith("--- ") for ln in lines)
    has_new = any(ln.startswith("+++ ") for ln in lines)
    if not (has_old and has_new):
        return False, "missing_file_headers"
    i, n, hunks = 0, len(lines), 0
    while i < n:
        m = HUNK_RE.match(lines[i])
        if not m:
            i += 1
            continue
        hunks += 1
        old_left = int(m.group(2)) if m.group(2) is not None else 1
        new_left = int(m.group(4)) if m.group(4) is not None else 1
        i += 1
        while i < n and (old_left > 0 or new_left > 0):
            ln = lines[i]
            if ln.startswith("\\"):          # "\ No newline at end of file"
                i += 1
                continue
            if ln.startswith("+"):
                new_left -= 1
            elif ln.startswith("-"):
                old_left -= 1
            elif ln.startswith(" ") or ln == "":
                old_left -= 1
                new_left -= 1
            else:
                return False, "bad_line_in_hunk"
            i += 1
        if old_left != 0 or new_left != 0:
            return False, "truncated_or_miscounted_hunk"
    if hunks == 0:
        return False, "no_hunks"
    return True, "ok"


def main():
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    src = os.path.join(ROOT, "data", "heldout", "heldout.csv")
    dst = os.path.join(ROOT, "data", "heldout", "heldout_checked.csv")
    if not os.path.exists(src):
        sys.exit(f"ERROR: {src} not found. Run scripts/build_heldout.py first.")
    with open(src, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        ok, why = check_diff(r["patch"])
        r["well_formed"], r["malformed_reason"] = int(ok), why
    with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"rows: {len(rows)}  well-formed: {sum(r['well_formed'] for r in rows)}")
    print("reasons:", dict(Counter(r["malformed_reason"] for r in rows)))
    print("\nresolved rate by well_formed:")
    for wf in (1, 0):
        sub = [r for r in rows if r["well_formed"] == wf]
        if sub:
            res = sum(int(r["resolved"]) for r in sub)
            print(f"  well_formed={wf}: {len(sub)} rows, {res} resolved "
                  f"({res / len(sub):.1%})")
    known = [r for r in rows if r.get("applied") not in ("", None)]
    if known:
        print("\nagreement with real 'applied' info (rows where it exists):")
        tab = Counter((r["applied"], r["well_formed"]) for r in known)
        for (a, wf), c in sorted(tab.items()):
            print(f"  applied={a}  well_formed={wf}: {c}")
    print(f"\nwrote {dst}")


if __name__ == "__main__":
    main()
