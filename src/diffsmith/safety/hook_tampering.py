"""
src/diffsmith/safety/hook_tampering.py — Rule 7: Detect postinstall or git-hook additions.
"""

import re
from .safety_utils import extract_added_lines, extract_touched_files

RULE_ID = "SEC007_HOOK_TAMPERING"
SEVERITY = "HIGH"

HOOK_FILE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\.git(?:/|\\)hooks(?:/|\\)"), "git hook directory edit"),
    (re.compile(r"^\.githooks(?:/|\\)"), "custom githooks directory edit"),
    (re.compile(r"^\.pre-commit-config\.ya?ml$"), "pre-commit git hook configuration edit"),
]

HOOK_LINE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"['\"]postinstall['\"]\s*:"), "package postinstall script hook"),
    (re.compile(r"\bclass\s+(?:PostInstall|CustomInstall|PreInstall)\w*\s*\("), "custom install command hook class"),
    (re.compile(r"cmdclass\s*=\s*\{[^}]*['\"](?:install|develop)['\"]"), "setuptools cmdclass install hook"),
]


def check_hook_tampering(patch_text: str) -> list[dict]:
    """Scan diff for postinstall scripts or git-hook additions."""
    findings = []
    touched_files = extract_touched_files(patch_text)

    # 1. Check touched file paths
    flagged_files = set()
    for f in touched_files:
        for pattern, desc in HOOK_FILE_PATTERNS:
            if pattern.search(f):
                findings.append({
                    "rule_id": RULE_ID,
                    "severity": SEVERITY,
                    "file": f,
                    "line": 1,
                    "evidence": f"Git hook file modified: {desc} ({f})",
                })
                flagged_files.add(f)
                break

    # 2. Check added lines for postinstall or cmdclass hooks
    added_lines = extract_added_lines(patch_text)
    for line_info in added_lines:
        if line_info.file_path in flagged_files:
            continue
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in HOOK_LINE_PATTERNS:
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
