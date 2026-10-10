"""
src/diffsmith/safety/credential_reads.py — Rule 5: Detect environment variable and credential reads.
"""

import re
from .safety_utils import extract_added_lines, extract_context_lines, is_test_file, is_scratch_script

RULE_ID = "SEC005_CREDENTIAL_READS"

ENV_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bos\.environ\s*(?:\[|\.get\()"), "os.environ read"),
    (re.compile(r"\bos\.getenv\s*\("), "os.getenv read"),
    (re.compile(r"\bopen\s*\(\s*['\"][^'\"]*\.env(?:ironment|(?:\.[a-zA-Z0-9_-]+)*)?['\"]"), ".env credential file read"),
    (re.compile(r"\b(?:load_dotenv|dotenv_values)\s*\("), "dotenv credential load"),
    (re.compile(r"\bopen\s*\(\s*['\"][^'\"]*(?:id_rsa|\.aws/credentials|\.ssh/|\.netrc|/etc/passwd)['\"]"), "sensitive credential path access"),
]

# Env assignments / writes are not a finding (e.g. os.environ['FOO'] = 'bar')
ENV_WRITE_PATTERN = re.compile(
    r"\bos\.environ\s*\[[^\]]+\]\s*=|"
    r"\bos\.environ\.setdefault\s*\(|"
    r"\bos\.environ\.update\s*\(|"
    r"\bos\.putenv\s*\(",
)

# Credential-like names that qualify for HIGH severity (when outside tests/scratch scripts)
CREDENTIAL_TARGET_PATTERN = re.compile(
    r"(?:^|[^a-zA-Z0-9])(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AWS_[A-Z0-9_]*|GITHUB_[A-Z0-9_]*|SSH_[A-Z0-9_]*)(?:$|[^a-zA-Z0-9])|"
    r"['\"][^'\"]*\.env(?:ironment|(?:\.[a-zA-Z0-9_-]+)*)?['\"]|"
    r"(?:id_rsa|\.aws/credentials|\.ssh/|\.netrc|/etc/passwd)",
    re.IGNORECASE,
)


def check_credential_reads(patch_text: str) -> list[dict]:
    """
    Scan added diff lines for environment variable or credential reads.
    - Env writes (os.environ[...] = ...) are ignored.
    - HIGH severity is assigned ONLY for credential-like names / files outside scratch and test files.
    - All other env reads, or reads in scratch/test files, are assigned 'low' severity.
    """
    findings = []
    added_lines = extract_added_lines(patch_text)
    context_map = extract_context_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        # Check if this line is strictly an environment variable write/assignment
        if ENV_WRITE_PATTERN.search(line_info.content):
            # Only ignore if not also attempting to read a credential file
            if not re.search(r"\bopen\s*\(\s*['\"][^'\"]*(?:\.env|id_rsa|\.aws|\.ssh|/etc/passwd)", line_info.content):
                continue

        for pattern, desc in ENV_CREDENTIAL_PATTERNS:
            if pattern.search(line_info.content):
                file_ctx = context_map.get(line_info.file_path, [])
                is_modifying_existing = any(pattern.search(ctx_line) for ctx_line in file_ctx)
                in_scratch_or_test = is_test_file(line_info.file_path) or is_scratch_script(line_info.file_path)

                has_credential_name = bool(CREDENTIAL_TARGET_PATTERN.search(line_info.content))

                if in_scratch_or_test or is_modifying_existing or not has_credential_name:
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
