"""
tests/test_eval_controls.py — Unit tests for helper functions in scripts/eval_controls.py
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.eval_controls import extract_body_only_text, extract_file_paths_text


def test_extract_body_only_text_normal():
    patch = (
        "diff --git a/lib/foo.py b/lib/foo.py\n"
        "index 123456..7890ab 100644\n"
        "--- a/lib/foo.py\n"
        "+++ b/lib/foo.py\n"
        "@@ -1,4 +1,4 @@\n"
        " context line\n"
        "-old code line\n"
        "+new code line\n"
        " another context line\n"
    )
    result = extract_body_only_text(patch)
    assert "old code line" in result
    assert "new code line" in result
    assert "context line" not in result
    assert "diff --git" not in result
    assert "@@" not in result


def test_extract_body_only_text_empty_and_invalid():
    assert extract_body_only_text("") == ""
    assert extract_body_only_text(None) == ""
    patch_no_changes = (
        "diff --git a/lib/foo.py b/lib/foo.py\n"
        "--- a/lib/foo.py\n"
        "+++ b/lib/foo.py\n"
        " context line only\n"
    )
    assert extract_body_only_text(patch_no_changes) == ""


def test_extract_file_paths_text_normal():
    patch = (
        "diff --git a/lib/matplotlib/axis.py b/lib/matplotlib/axis.py\n"
        "--- a/lib/matplotlib/axis.py\n"
        "+++ b/lib/matplotlib/axis.py\n"
        "@@ -10,3 +10,3 @@\n"
        "-a\n"
        "+b\n"
    )
    result = extract_file_paths_text(patch)
    assert result == "lib/matplotlib/axis.py"


def test_extract_file_paths_text_empty_and_invalid():
    assert extract_file_paths_text("") == ""
    assert extract_file_paths_text(None) == ""
