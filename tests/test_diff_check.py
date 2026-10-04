import importlib.util
import os

_path = os.path.join(os.path.dirname(__file__), "..", "scripts", "diff_check.py")
_spec = importlib.util.spec_from_file_location("diff_check", _path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
check_diff = _mod.check_diff

GOOD = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,3 +1,3 @@
 x = 1
-y = 2
+y = 3
 z = 4
"""


def test_valid_diff():
    assert check_diff(GOOD) == (True, "ok")


def test_empty():
    assert check_diff("") == (False, "empty")


def test_missing_headers():
    assert check_diff("@@ -1,1 +1,1 @@\n-a\n+b\n") == (False, "missing_file_headers")


def test_truncated_hunk():
    cut = GOOD.rsplit("\n z = 4\n", 1)[0] + "\n"
    assert check_diff(cut) == (False, "truncated_or_miscounted_hunk")


def test_wrong_hunk_count():
    bad = GOOD.replace("@@ -1,3 +1,3 @@", "@@ -1,5 +1,5 @@")
    assert check_diff(bad)[0] is False


def test_no_newline_marker_ok():
    d = GOOD.replace("+y = 3\n", "+y = 3\n\\ No newline at end of file\n")
    assert check_diff(d) == (True, "ok")


def test_prose_instead_of_diff():
    assert check_diff("Here is the fix: change y to 3.")[0] is False


def test_form_feed_in_context_line_is_not_a_line_break():
    d = GOOD.replace(" x = 1\n", " x = 1\x0c# section\n")
    assert check_diff(d) == (True, "ok")


def test_glued_diff_header_is_tolerated():
    glued = GOOD.replace(
        "diff --git a/a.py b/a.py\n--- a/a.py", "diff --git a/a.py b/a.py--- a/a.py"
    )
    assert check_diff(glued) == (True, "ok")
