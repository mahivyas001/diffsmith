"""
src/diffsmith/safety/workflow_build.py — Rule 6: Detect edits to workflows, build configs, and manifests.
"""

import re
from .safety_utils import extract_added_lines, extract_touched_files

RULE_ID = "SEC006_WORKFLOW_BUILD"
SEVERITY = "MEDIUM"

MANIFEST_FILE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\.github[/\\]workflows[/\\]", re.IGNORECASE), "GitHub Actions workflow edit"),
    (re.compile(r"(?:^|[/\\])setup\.(?:py|cfg)$", re.IGNORECASE), "setup configuration edit"),
    (re.compile(r"(?:^|[/\\])pyproject\.toml$", re.IGNORECASE), "pyproject.toml build edit"),
    (re.compile(r"(?:^|[/\\]).*requirements.*\.txt$", re.IGNORECASE), "requirements file edit"),
    (re.compile(r"(?:^|[/\\])Pipfile(?:|\.lock)$", re.IGNORECASE), "Pipfile dependency edit"),
    (re.compile(r"(?:^|[/\\])package\.json$", re.IGNORECASE), "package.json dependency edit"),
    (re.compile(r"(?:^|[/\\])environment\.ya?ml$", re.IGNORECASE), "conda environment dependency edit"),
]

DEPENDENCY_ADD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:install_requires|setup_requires|extras_require)\s*="), "build dependency specification"),
    (re.compile(r"\bdependencies\s*=\s*\["), "manifest dependency specification"),
]


def is_manifest_file(path: str) -> bool:
    """Return True if path points to a build config, workflow, or package manifest."""
    clean = path.replace("\\", "/")
    return any(p.search(clean) for p, _ in MANIFEST_FILE_PATTERNS)


def check_workflow_build(patch_text: str) -> list[dict]:
    """
    Scan diff for edits to CI workflows, build configurations, and dependency manifests.
    Dependency additions apply ONLY to manifest files (not regular Python files or migrations).
    """
    findings = []
    touched_files = extract_touched_files(patch_text)

    # 1. Check touched file paths for manifest files
    flagged_files = set()
    for f in touched_files:
        for pattern, desc in MANIFEST_FILE_PATTERNS:
            if pattern.search(f.replace("\\", "/")):
                findings.append({
                    "rule_id": RULE_ID,
                    "severity": SEVERITY,
                    "file": f,
                    "line": 1,
                    "evidence": f"Sensitive build/CI file modified: {desc} ({f})",
                })
                flagged_files.add(f)
                break

    # 2. Check added lines for new dependency specifications ONLY in manifest files
    added_lines = extract_added_lines(patch_text)
    for line_info in added_lines:
        if line_info.file_path in flagged_files:
            continue
        # Only check files that are manifests
        if not is_manifest_file(line_info.file_path):
            continue

        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in DEPENDENCY_ADD_PATTERNS:
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
