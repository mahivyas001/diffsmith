"""
src/diffsmith/safety/command_exec.py — Rule 3: Detect subprocess, os.system, eval, exec additions.
"""

import re
from .safety_utils import extract_added_lines

RULE_ID = "SEC003_COMMAND_EXEC"
SEVERITY = "HIGH"

COMMAND_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsubprocess\.(?:Popen|run|call|check_call|check_output|getoutput|getstatusoutput)\s*\("), "subprocess execution"),
    (re.compile(r"\bos\.(?:system|popen|spawn[lpev]*|exec[lpev]*)\s*\("), "os execution command"),
    (re.compile(r"(?<!\w)eval\s*\("), "dynamic eval() execution"),
    (re.compile(r"(?<!\w)exec\s*\("), "dynamic exec() execution"),
    (re.compile(r"\bpty\.spawn\s*\("), "pty interactive shell spawn"),
]


def check_command_exec(patch_text: str) -> list[dict]:
    """Scan added diff lines for subprocess, os.system, eval, and exec invocations."""
    findings = []
    added_lines = extract_added_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in COMMAND_PATTERNS:
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
