"""
src/diffsmith/safety/safety_utils.py — Shared parsing helpers for diff security rules.
"""

import re
from typing import NamedTuple

VENDORED_DIR_RE = re.compile(
    r"(?:^|[/\\])(?:venv|\.venv|site-packages|node_modules)(?:[/\\]|$)",
    re.IGNORECASE,
)

SCRATCH_SCRIPT_RE = re.compile(
    r"^(?:reproduce|repro|debug|tmp)[^/\\]*\.py$",
    re.IGNORECASE,
)

TEST_FILE_RE = re.compile(
    r"(?:^|[/\\])(?:tests?|testing)(?:[/\\]|$)|(?:^|[/\\])(?:test_[^/\\]+\.py|[^/\\]+_test\.py|conftest\.py)$",
    re.IGNORECASE,
)


def is_vendored_path(path: str) -> bool:
    """Check if file path belongs to a vendored or virtualenv directory."""
    if not path or not isinstance(path, str):
        return False
    clean = path.replace("\\", "/")
    return bool(VENDORED_DIR_RE.search(clean))


def is_scratch_script(path: str) -> bool:
    """Check if file path is a new top-level scratch script (e.g. reproduce*.py, tmp*.py)."""
    if not path or not isinstance(path, str):
        return False
    # Normalize slashes and get top-level relative path
    clean = path.replace("\\", "/").lstrip("/")
    return bool(SCRATCH_SCRIPT_RE.match(clean))


def is_test_file(path: str) -> bool:
    """Check if file path is part of a test suite."""
    if not path or not isinstance(path, str):
        return False
    return bool(TEST_FILE_RE.search(path))


class AddedDiffLine(NamedTuple):
    file_path: str
    line_no: int
    content: str


def extract_added_lines(patch_text: str) -> list[AddedDiffLine]:
    """Parse patch text into AddedDiffLine objects for added lines only (excluding vendored paths)."""
    if not patch_text or not isinstance(patch_text, str):
        return []

    lines = patch_text.splitlines()
    added_lines: list[AddedDiffLine] = []
    current_file = ""
    current_line_no = 0

    hunk_header_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            current_line_no = 0
            continue
        elif line.startswith("--- ") or line.startswith("diff --git"):
            continue

        match = hunk_header_re.match(line)
        if match:
            current_line_no = int(match.group(1))
            continue

        if current_file and not is_vendored_path(current_file):
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(AddedDiffLine(current_file, current_line_no, line[1:]))
                current_line_no += 1
            elif not line.startswith("-") and not line.startswith("\\"):
                current_line_no += 1

    return added_lines


def extract_context_lines(patch_text: str) -> dict[str, list[str]]:
    """Extract context (' ') and removed ('-') lines per file to detect existing code patterns."""
    if not patch_text or not isinstance(patch_text, str):
        return {}

    lines = patch_text.splitlines()
    context_map: dict[str, list[str]] = {}
    current_file = ""

    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            if current_file not in context_map:
                context_map[current_file] = []
            continue
        elif line.startswith("--- ") or line.startswith("diff --git"):
            continue
        elif line.startswith("@@"):
            continue

        if current_file and not is_vendored_path(current_file):
            if line.startswith(" ") or (line.startswith("-") and not line.startswith("---")):
                context_map[current_file].append(line[1:])

    return context_map


def extract_touched_files(patch_text: str, include_vendored: bool = False) -> list[str]:
    """Extract touched target file paths from diff."""
    if not patch_text or not isinstance(patch_text, str):
        return []

    files: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++ b/"):
            f = line[6:].strip()
            if f and f != "/dev/null" and (include_vendored or not is_vendored_path(f)) and f not in files:
                files.append(f)
        elif line.startswith("diff --git a/"):
            parts = line.split(" b/")
            if len(parts) == 2:
                f = parts[1].strip()
                if f and (include_vendored or not is_vendored_path(f)) and f not in files:
                    files.append(f)
    return files


def check_vendored_paths(patch_text: str) -> list[dict]:
    """Flag additions or edits in vendored directories (severity: review)."""
    findings = []
    all_files = extract_touched_files(patch_text, include_vendored=True)
    for f in all_files:
        if is_vendored_path(f):
            findings.append({
                "rule_id": "vendored_directory_added",
                "severity": "review",
                "file": f,
                "line": 1,
                "evidence": f"Vendored or virtualenv directory modified: {f}",
            })
    return findings


def check_scratch_scripts(patch_text: str) -> list[dict]:
    """Flag newly added or modified top-level scratch scripts (severity: low)."""
    findings = []
    all_files = extract_touched_files(patch_text, include_vendored=True)
    for f in all_files:
        if is_scratch_script(f):
            findings.append({
                "rule_id": "scratch_script_added",
                "severity": "low",
                "file": f,
                "line": 1,
                "evidence": f"Scratch or reproduction script added: {f}",
            })
    return findings
