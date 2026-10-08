"""
src/diffsmith/heuristics/swallowed_exceptions.py — Rule 5: Swallowed Exceptions
"""

import re
from diffsmith.heuristics.utils import extract_diff_lines

SINGLE_SWALLOW_RE = re.compile(
    r"^\s*except(?:\s+Exception|\s+BaseException)?\s*:\s*(?:pass|return\b|continue\b)",
    re.IGNORECASE,
)

EXCEPT_LINE_RE = re.compile(
    r"^\s*except(?:\s+Exception|\s+BaseException)?\s*:\s*(?:#.*)?$",
    re.IGNORECASE,
)
PASS_LINE_RE = re.compile(
    r"^\s*(?:pass|return(?:\s+None|\s+False|\s*)|continue)\s*(?:#.*)?$",
    re.IGNORECASE,
)


def evaluate_swallowed_exceptions(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Detect added bare `except:` or `except Exception: pass` patterns.
    Returns:
        findings: list of finding dicts
        features: {
            "swallowed_exception_count": float,
            "has_swallowed_exception": float,
        }
    """
    diff_lines = extract_diff_lines(patch_text)
    added_lines = [dl for dl in diff_lines if dl.line_type == "+"]

    findings = []
    count = 0

    if not added_lines:
        return [], {
            "swallowed_exception_count": 0.0,
            "has_swallowed_exception": 0.0,
        }

    i = 0
    while i < len(added_lines):
        dl = added_lines[i]
        code = dl.content

        if SINGLE_SWALLOW_RE.search(code):
            count += 1
            findings.append({
                "rule_id": "swallowed_exceptions",
                "severity": "high",
                "file": dl.file_path,
                "line": dl.line_no,
                "evidence": f"Added single-line swallowed exception: {code.strip()[:60]}",
            })
            i += 1
            continue

        if EXCEPT_LINE_RE.search(code) and i + 1 < len(added_lines):
            next_dl = added_lines[i + 1]
            if next_dl.file_path == dl.file_path and PASS_LINE_RE.search(next_dl.content):
                count += 1
                findings.append({
                    "rule_id": "swallowed_exceptions",
                    "severity": "high",
                    "file": dl.file_path,
                    "line": dl.line_no,
                    "evidence": f"Added multi-line swallowed exception: {code.strip()} -> {next_dl.content.strip()}",
                })
                i += 2
                continue

        i += 1

    return findings, {
        "swallowed_exception_count": float(count),
        "has_swallowed_exception": 1.0 if count > 0 else 0.0,
    }
