"""
src/diffsmith/safety/obfuscation.py — Rule 4: Detect base64 and obfuscated string decoding.
"""

import re
from .safety_utils import extract_added_lines

RULE_ID = "SEC004_OBFUSCATION"
SEVERITY = "HIGH"

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

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in OBFUSCATION_PATTERNS:
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
