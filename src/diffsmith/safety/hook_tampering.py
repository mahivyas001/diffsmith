"""
src/diffsmith/safety/hook_tampering.py — Rule 7: Detect postinstall or git-hook additions.
"""

import re
from .safety_utils import extract_added_lines, extract_touched_files

RULE_ID = "SEC007_HOOK_TAMPERING"
SEVERITY = "HIGH"

HOOK_FILE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?:^|[/\\])\.git[/\\]hooks(?:[/\\]|$)", re.IGNORECASE), "git hook directory edit"),
    (re.compile(r"(?:^|[/\\])\.githooks(?:[/\\]|$)", re.IGNORECASE), "custom githooks directory edit"),
    (re.compile(r"(?:^|[/\\])\.husky(?:[/\\]|$)", re.IGNORECASE), "husky git hook directory edit"),
    (re.compile(r"(?:^|[/\\])lefthook\.ya?ml$", re.IGNORECASE), "lefthook git hook configuration edit"),
    (re.compile(r"(?:^|[/\\])\.pre-commit-config\.ya?ml$", re.IGNORECASE), "pre-commit git hook configuration edit"),
]

GIT_CONFIG_RE = re.compile(r"(?:^|[/\\])\.git[/\\]config$", re.IGNORECASE)
GIT_CONFIG_HOOK_CMD_RE = re.compile(
    r"\b(?:hooksPath|hook|pre-commit|post-commit|post-checkout|post-merge)\b\s*=",
    re.IGNORECASE,
)

HOOK_LINE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"['\"]postinstall['\"]\s*:"), "package postinstall script hook"),
    (re.compile(r"\bclass\s+(?:PostInstall|CustomInstall|PreInstall)\w*\s*\("), "custom install command hook class"),
    (re.compile(r"cmdclass\s*=\s*\{[^}]*['\"](?:install|develop)['\"]"), "setuptools cmdclass install hook"),
]


def check_hook_tampering(patch_text: str) -> list[dict]:
    """Scan diff for postinstall scripts or git-hook additions."""
    findings = []
    touched_files = extract_touched_files(patch_text, include_vendored=True)

    # 1. Check touched file paths for git hook locations
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

    # 2. Check added lines for postinstall, cmdclass hooks, or .git/config hook commands
    added_lines = extract_added_lines(patch_text)
    for line_info in added_lines:
        if line_info.file_path in flagged_files:
            continue
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        # Check for .git/config hook configurations
        if GIT_CONFIG_RE.search(line_info.file_path):
            if GIT_CONFIG_HOOK_CMD_RE.search(line_info.content):
                findings.append({
                    "rule_id": RULE_ID,
                    "severity": SEVERITY,
                    "file": line_info.file_path,
                    "line": line_info.line_no,
                    "evidence": f"git config hook command: {stripped[:120]}",
                })
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
