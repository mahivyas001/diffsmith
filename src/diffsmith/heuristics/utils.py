"""
src/diffsmith/heuristics/utils.py — Diff & Issue Parsing Helper Utilities
"""

import re
from typing import NamedTuple


class DiffLine(NamedTuple):
    file_path: str
    line_no: int
    line_type: str  # '+' or '-'
    content: str


def parse_diff_files(patch_text: str) -> list[str]:
    """Extract touched file paths from diff text."""
    if not patch_text or not isinstance(patch_text, str):
        return []

    files = []
    for line in patch_text.splitlines():
        if line.startswith("+++ b/"):
            f = line[6:].strip()
            if f and f != "/dev/null" and f not in files:
                files.append(f)
        elif line.startswith("diff --git a/"):
            parts = line.split(" b/")
            if len(parts) == 2:
                f = parts[1].strip()
                if f and f not in files:
                    files.append(f)

    return files


def extract_diff_lines(patch_text: str) -> list[DiffLine]:
    """Parse patch text into structured DiffLine entries for added and removed lines."""
    if not patch_text or not isinstance(patch_text, str):
        return []

    lines = patch_text.splitlines()
    diff_lines: list[DiffLine] = []
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

        if current_file:
            if line.startswith("+") and not line.startswith("+++"):
                diff_lines.append(DiffLine(current_file, current_line_no, "+", line[1:]))
                current_line_no += 1
            elif line.startswith("-") and not line.startswith("---"):
                diff_lines.append(DiffLine(current_file, current_line_no, "-", line[1:]))
            elif not line.startswith("\\"):
                current_line_no += 1

    return diff_lines
