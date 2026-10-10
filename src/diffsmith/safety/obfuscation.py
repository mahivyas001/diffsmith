"""
src/diffsmith/safety/obfuscation.py — Rule 4: Detect base64 and obfuscated string decoding.
"""

import re
from .safety_utils import extract_added_lines, extract_context_lines, is_test_file, is_scratch_script

RULE_ID = "SEC004_OBFUSCATION"

OBFUSCATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bbase64\.(?:b64decode|standard_b64decode|urlsafe_b64decode|decodestring)\s*\("), "base64 decoding"),
    (re.compile(r"(?<!\w)b64decode\s*\("), "b64decode invocation"),
    (re.compile(r"\bbinascii\.(?:a2b_base64|unhexlify|a2b_hex)\s*\("), "binascii decoding"),
    (re.compile(r"(?<!\w)unhexlify\s*\("), "unhexlify decoding"),
    (re.compile(r"\bcodecs\.decode\s*\(.*?['\"](?:rot_?13|base64|hex)['\"]", re.IGNORECASE), "codecs obfuscated decode"),
    (re.compile(r"__import__\s*\(\s*['\"]base64['\"]\s*\)"), "dynamic base64 import"),
]


def check_obfuscation(patch_text: str) -> list[dict]:
    """Scan added diff lines for base64 or obfuscated string decoding."""
    findings = []
    added_lines = extract_added_lines(patch_text)
    context_map = extract_context_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in OBFUSCATION_PATTERNS:
            if pattern.search(line_info.content):
                file_ctx = context_map.get(line_info.file_path, [])
                is_modifying_existing = any(pattern.search(ctx_line) for ctx_line in file_ctx)
                in_scratch_or_test = is_test_file(line_info.file_path) or is_scratch_script(line_info.file_path)

                if in_scratch_or_test or is_modifying_existing:
                    sev = "low"
                else:
                    sev = "MEDIUM"

                findings.append({
                    "rule_id": RULE_ID,
                    "severity": sev,
                    "file": line_info.file_path,
                    "line": line_info.line_no,
                    "evidence": f"{desc}: {stripped[:120]}",
                })
                break

    return findings
