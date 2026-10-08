"""
src/diffsmith/heuristics/special_casing.py — Rule 4: Special Casing
"""

import re
from diffsmith.heuristics.utils import extract_diff_lines

SPECIAL_CASE_PATTERNS = [
    re.compile(r"^\s*(?:if|elif)\s+[\w\.\_\(\)\[\]]+\s*==\s*['\"]?[a-zA-Z0-9_\-\.]+['\"]?\s*:\s*return\b", re.IGNORECASE),
    re.compile(r"^\s*(?:if|elif)\s+[\w\.\_]+\s+(?:is|==)\s+None\s*:\s*return\s+['\"]?[a-zA-Z0-9_\-\.]+['\"]?", re.IGNORECASE),
    re.compile(r"^\s*(?:if|elif)\s+[\w\.\_]+\s+in\s+\[.*\]\s*:\s*return\b", re.IGNORECASE),
]

IF_EQ_RE = re.compile(r"^\s*(?:if|elif)\s+[\w\.\_\(\)\[\]]+\s*==\s*['\"]?[a-zA-Z0-9_\-\.]+['\"]?\s*:\s*$", re.IGNORECASE)
RETURN_RE = re.compile(r"^\s*return\s+['\"]?[a-zA-Z0-9_\-\.]+['\"]?\s*$", re.IGNORECASE)


def evaluate_special_casing(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Detect added special-casing return branches (`if x == <literal>: return <literal>`).
    Returns:
        findings: list of finding dicts
        features: {
            "special_casing_count": float,
            "has_special_casing": float,
        }
    """
    diff_lines = extract_diff_lines(patch_text)
    added_lines = [dl for dl in diff_lines if dl.line_type == "+"]

    findings = []
    count = 0

    if not added_lines:
        return [], {
            "special_casing_count": 0.0,
            "has_special_casing": 0.0,
        }

    i = 0
    while i < len(added_lines):
        dl = added_lines[i]
        code = dl.content

        if any(pat.search(code) for pat in SPECIAL_CASE_PATTERNS):
            count += 1
            findings.append({
                "rule_id": "special_casing",
                "severity": "high",
                "file": dl.file_path,
                "line": dl.line_no,
                "evidence": f"Added single-line special casing: {code.strip()[:60]}",
            })
            i += 1
            continue

        if IF_EQ_RE.search(code) and i + 1 < len(added_lines):
            next_dl = added_lines[i + 1]
            if next_dl.file_path == dl.file_path and RETURN_RE.search(next_dl.content):
                count += 1
                findings.append({
                    "rule_id": "special_casing",
                    "severity": "high",
                    "file": dl.file_path,
                    "line": dl.line_no,
                    "evidence": f"Added multi-line special casing: {code.strip()} -> {next_dl.content.strip()}",
                })
                i += 2
                continue

        i += 1

    return findings, {
        "special_casing_count": float(count),
        "has_special_casing": 1.0 if count > 0 else 0.0,
    }
