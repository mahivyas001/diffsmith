"""
src/diffsmith/heuristics/suppression_markers.py — Rule 7: Suppression Markers
"""

import re
from diffsmith.heuristics.utils import extract_diff_lines

SUPPRESSION_PATTERNS = [
    (re.compile(r"#\s*type:\s*ignore\b", re.IGNORECASE), "# type: ignore"),
    (re.compile(r"#\s*noqa\b", re.IGNORECASE), "# noqa"),
    (re.compile(r"#\s*pragma:\s*no\s*cover\b", re.IGNORECASE), "pragma: no cover"),
    (re.compile(r"#\s*fmt:\s*skip\b", re.IGNORECASE), "fmt: skip"),
    (re.compile(r"#\s*pylint:\s*disable=", re.IGNORECASE), "pylint: disable"),
    (re.compile(r"#\s*nosec\b", re.IGNORECASE), "# nosec"),
]


def evaluate_suppression_markers(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Detect added linter, type-checker, or test coverage suppression markers.
    Returns:
        findings: list of finding dicts
        features: {
            "suppression_marker_count": float,
            "has_suppression_marker": float,
        }
    """
    diff_lines = extract_diff_lines(patch_text)
    added_lines = [dl for dl in diff_lines if dl.line_type == "+"]

    findings = []
    count = 0

    if not added_lines:
        return [], {
            "suppression_marker_count": 0.0,
            "has_suppression_marker": 0.0,
        }

    for dl in added_lines:
        code = dl.content
        for pat, label in SUPPRESSION_PATTERNS:
            if pat.search(code):
                count += 1
                findings.append({
                    "rule_id": "suppression_markers",
                    "severity": "medium",
                    "file": dl.file_path,
                    "line": dl.line_no,
                    "evidence": f"Added suppression marker ({label}): {code.strip()[:60]}",
                })
                break

    return findings, {
        "suppression_marker_count": float(count),
        "has_suppression_marker": 1.0 if count > 0 else 0.0,
    }
