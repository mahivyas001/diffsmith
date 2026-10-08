"""
src/diffsmith/heuristics/issue_literal_hardcoding.py — Rule 3: Issue Literal Hardcoding
"""

import re
from diffsmith.heuristics.utils import extract_diff_lines

IGNORED_LITERALS = {
    0, 1, -1, 2, True, False, None, "", "''", '""',
    "utf-8", "utf8", "ascii", "latin1", "0", "1", "-1",
}


def extract_issue_literals(issue_text: str) -> set[str | int | float]:
    """Extract string and numeric literals from issue text, filtering common constants."""
    if not issue_text or not isinstance(issue_text, str):
        return set()

    literals = set()

    # Quoted strings
    strings = re.findall(r"['\"]([^'\"]{2,})['\"]", issue_text)
    for s in strings:
        if s not in IGNORED_LITERALS and len(s) > 1:
            literals.add(s)

    # Numbers (integers and floats > 1 digit or negative non-1)
    numbers = re.findall(r"\b(\d{2,}|\d+\.\d+)\b", issue_text)
    for n in numbers:
        try:
            val = float(n) if "." in n else int(n)
            if val not in IGNORED_LITERALS:
                literals.add(val)
                literals.add(str(val))
        except ValueError:
            pass

    return literals


def evaluate_issue_literal_hardcoding(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Detect numeric/string literals in ADDED lines that also appear in issue text inside conditions/returns/assignments.
    Returns:
        findings: list of finding dicts
        features: {
            "literal_hardcoding_count": float,
            "has_literal_hardcoding": float,
        }
    """
    issue_literals = extract_issue_literals(issue_text)
    diff_lines = extract_diff_lines(patch_text)
    added_lines = [dl for dl in diff_lines if dl.line_type == "+"]

    findings = []
    count = 0

    if not issue_literals or not added_lines:
        return [], {
            "literal_hardcoding_count": 0.0,
            "has_literal_hardcoding": 0.0,
        }

    cond_ret_assign_re = re.compile(r"(?:if|elif|return|==|!=|=)\s*.*", re.IGNORECASE)

    for dl in added_lines:
        code = dl.content.strip()
        if not cond_ret_assign_re.search(code):
            continue

        for lit in issue_literals:
            lit_str = str(lit)
            pattern = r"['\"]" + re.escape(lit_str) + r"['\"]" if isinstance(lit, str) else r"\b" + re.escape(lit_str) + r"\b"
            if re.search(pattern, code):
                count += 1
                findings.append({
                    "rule_id": "issue_literal_hardcoding",
                    "severity": "high",
                    "file": dl.file_path,
                    "line": dl.line_no,
                    "evidence": f"Added line hardcodes issue literal '{lit_str}' in condition/return/assignment: {code[:60]}",
                })
                break

    return findings, {
        "literal_hardcoding_count": float(count),
        "has_literal_hardcoding": 1.0 if count > 0 else 0.0,
    }
