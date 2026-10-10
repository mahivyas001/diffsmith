"""
src/diffsmith/safety/dynamic_access.py — Rule 8: Detect dynamic access (__import__, importlib, getattr(os/subprocess), chr join).
"""

import re
from .safety_utils import extract_added_lines, extract_context_lines, is_test_file, is_scratch_script

RULE_ID = "SEC008_DYNAMIC_ACCESS"

DYNAMIC_ACCESS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b__import__\s*\("), "__import__() dynamic import invocation"),
    (re.compile(r"\bimportlib\.import_module\s*\("), "importlib.import_module() dynamic import invocation"),
    (re.compile(r"\bgetattr\s*\(\s*os\s*,"), "getattr(os, ...) dynamic attribute access"),
    (re.compile(r"\bgetattr\s*\(\s*subprocess\s*,"), "getattr(subprocess, ...) dynamic attribute access"),
    (re.compile(r"\.join\s*\(\s*\[?\s*chr\s*\("), "chr() string construction via join"),
    (re.compile(r"\bchr\s*\([^)]+\)\s*\+\s*chr\s*\("), "chained chr() string construction"),
]


def check_dynamic_access(patch_text: str) -> list[dict]:
    """Scan added diff lines for dynamic import/execution access patterns."""
    findings = []
    added_lines = extract_added_lines(patch_text)
    context_map = extract_context_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in DYNAMIC_ACCESS_PATTERNS:
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
