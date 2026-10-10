"""
src/diffsmith/safety/shell_pipe.py — Rule 2: Detect curl|sh and wget|sh pipeline executions.
"""

import re
from .safety_utils import extract_added_lines

RULE_ID = "SEC002_SHELL_PIPE"
SEVERITY = "CRITICAL"

SHELL_PIPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bcurl\b.*?\|\s*(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE), "curl piped directly to shell"),
    (re.compile(r"\bwget\b.*?\|\s*(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE), "wget piped directly to shell"),
    (re.compile(r"\bcurl\b.*?\|\s*python[23]?\b", re.IGNORECASE), "curl piped directly to python interpreter"),
    (re.compile(r"\bwget\b.*?\|\s*python[23]?\b", re.IGNORECASE), "wget piped directly to python interpreter"),
    (re.compile(r"curl\|(?:ba)?sh", re.IGNORECASE), "shorthand curl|sh pipeline invocation"),
]


def check_shell_pipe(patch_text: str) -> list[dict]:
    """Scan added diff lines for curl|sh and wget|sh pipeline executions."""
    findings = []
    added_lines = extract_added_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in SHELL_PIPE_PATTERNS:
            if pattern.search(line_info.content):
                findings.append({
                    "rule_id": RULE_ID,
                    "severity": SEVERITY,
                    "file": line_info.file_path,
                    "line": line_info.line_no,
                    "evidence": f"{desc}: {stripped[:120]}",
                })
                break

    return findings
