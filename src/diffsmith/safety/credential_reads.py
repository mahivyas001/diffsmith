"""
src/diffsmith/safety/credential_reads.py — Rule 5: Detect environment variable and credential reads.
"""

import re
from .safety_utils import extract_added_lines, extract_context_lines, is_test_file

RULE_ID = "SEC005_CREDENTIAL_READS"

ENV_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bos\.environ\s*(?:\[|\.get\()"), "os.environ read"),
    (re.compile(r"\bos\.getenv\s*\("), "os.getenv read"),
    (re.compile(r"\bopen\s*\(\s*['\"][^'\"]*\.env(?:ironment|(?:\.[a-zA-Z0-9_-]+)*)?['\"]"), ".env credential file read"),
    (re.compile(r"\b(?:load_dotenv|dotenv_values)\s*\("), "dotenv credential load"),
    (re.compile(r"\bopen\s*\(\s*['\"][^'\"]*(?:id_rsa|\.aws/credentials|\.ssh/|\.netrc)['\"]"), "sensitive credential path access"),
]


def check_credential_reads(patch_text: str) -> list[dict]:
    """Scan added diff lines for environment variable or credential reads."""
    findings = []
    added_lines = extract_added_lines(patch_text)
    context_map = extract_context_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in ENV_CREDENTIAL_PATTERNS:
            if pattern.search(line_info.content):
                file_ctx = context_map.get(line_info.file_path, [])
                is_modifying_existing = any(pattern.search(ctx_line) for ctx_line in file_ctx)
                if is_test_file(line_info.file_path) or is_modifying_existing:
                    sev = "low"
                else:
                    sev = "HIGH"

                findings.append({
                    "rule_id": RULE_ID,
                    "severity": sev,
                    "file": line_info.file_path,
                    "line": line_info.line_no,
                    "evidence": f"{desc}: {stripped[:120]}",
                })
                break

    return findings
