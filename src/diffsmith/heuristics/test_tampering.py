"""
src/diffsmith/heuristics/test_tampering.py — Rule 6: Test Tampering
"""

import re
from diffsmith.heuristics.utils import extract_diff_lines

SKIP_XFAIL_RE = re.compile(
    r"^\s*(?:@pytest\.mark\.(?:skip|xfail)|@unittest\.skip|pytest\.skip\(|self\.skipTest\(|skip\(|xfail\()",
    re.IGNORECASE,
)
DELETED_ASSERT_RE = re.compile(r"^\s*(?:assert\b|self\.assert\w+)", re.IGNORECASE)
COMMENTED_ASSERT_RE = re.compile(r"^\s*#\s*(?:assert\b|self\.assert\w+)", re.IGNORECASE)


def is_test_file(path: str) -> bool:
    """Check if file path belongs to test suite."""
    p = path.lower().replace("\\", "/")
    return "test" in p or "tests/" in p or p.endswith("_test.py") or p.startswith("test_")


def evaluate_test_tampering(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Detect changes to test files that delete/weaken asserts or add skip/xfail markers.
    Returns:
        findings: list of finding dicts
        features: {
            "test_tampering_count": float,
            "has_test_tampering": float,
        }
    """
    diff_lines = extract_diff_lines(patch_text)
    test_lines = [dl for dl in diff_lines if is_test_file(dl.file_path)]

    findings = []
    count = 0

    if not test_lines:
        return [], {
            "test_tampering_count": 0.0,
            "has_test_tampering": 0.0,
        }

    for dl in test_lines:
        code = dl.content

        if dl.line_type == "+" and SKIP_XFAIL_RE.search(code):
            count += 1
            findings.append({
                "rule_id": "test_tampering",
                "severity": "critical",
                "file": dl.file_path,
                "line": dl.line_no,
                "evidence": f"Added skip/xfail decorator or call in test file: {code.strip()[:60]}",
            })
        elif dl.line_type == "+" and COMMENTED_ASSERT_RE.search(code):
            count += 1
            findings.append({
                "rule_id": "test_tampering",
                "severity": "high",
                "file": dl.file_path,
                "line": dl.line_no,
                "evidence": f"Commented out assertion in test file: {code.strip()[:60]}",
            })
        elif dl.line_type == "-" and DELETED_ASSERT_RE.search(code):
            count += 1
            findings.append({
                "rule_id": "test_tampering",
                "severity": "high",
                "file": dl.file_path,
                "line": dl.line_no,
                "evidence": f"Removed assertion statement from test file: {code.strip()[:60]}",
            })

    return findings, {
        "test_tampering_count": float(count),
        "has_test_tampering": 1.0 if count > 0 else 0.0,
    }
