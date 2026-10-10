"""
src/diffsmith/safety/shell_pipe.py — Rule 2: Detect curl|sh and wget|sh pipeline executions.
"""

import re
from .safety_utils import extract_added_lines

RULE_ID = "SEC002_SHELL_PIPE"
SEVERITY = "CRITICAL"

SHELL_PIPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bcurl\b.*?\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE), "curl piped directly to shell"),
    (re.compile(r"\bwget\b.*?\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE), "wget piped directly to shell"),
    (re.compile(r"\bcurl\b.*?\|\s*python[23]?\b", re.IGNORECASE), "curl piped directly to python interpreter"),
    (re.compile(r"\bwget\b.*?\|\s*python[23]?\b", re.IGNORECASE), "wget piped directly to python interpreter"),
    (re.compile(r"curl\|(?:ba)?sh", re.IGNORECASE), "shorthand curl|sh pipeline invocation"),
    (re.compile(r"\b(?:bash|sh)\s+-c\s+[\"']?\$\((?:curl|wget)\b", re.IGNORECASE), "shell subshell download execution"),
    (re.compile(r"\bpython[23]?\s+-c\s+[\"']?\$\((?:curl|wget)\b", re.IGNORECASE), "python subshell download execution"),
    (re.compile(r"\beval\s+[\"']?\$\((?:curl|wget)\b", re.IGNORECASE), "eval subshell download execution"),
    (re.compile(r"\b(?:ba|z|da)?sh\s+<\s*\((?:curl|wget)\b", re.IGNORECASE), "process substitution shell execution"),
    (re.compile(r"\b(?:iwr|Invoke-WebRequest)\b.*?\|\s*(?:iex|Invoke-Expression)\b", re.IGNORECASE), "PowerShell download and execute"),
    (re.compile(r"\b(?:iex|Invoke-Expression)\s*(?:\(|&|\$)\s*(?:iwr|Invoke-WebRequest)\b", re.IGNORECASE), "PowerShell invoke expression on web request"),
    (re.compile(r"\b(?:curl|wget)\b.*?(?:;|&&)\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE), "download-then-run shell invocation"),
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
