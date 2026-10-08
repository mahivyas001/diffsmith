"""
tests/test_heuristics.py — Unit tests for Phase 3 Relational Heuristics Rules

Rules:
- >= 3 positive and >= 3 negative test cases per rule.
- No model training of any kind.
"""

import os
import sys
import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from diffsmith.heuristics import (
    evaluate_issue_file_overlap,
    evaluate_issue_identifier_overlap,
    evaluate_issue_literal_hardcoding,
    evaluate_special_casing,
    evaluate_swallowed_exceptions,
    evaluate_test_tampering,
    evaluate_suppression_markers,
    evaluate_scope_creep,
    run_all_heuristics,
)


# ──────────────────────────────────────────────────────────────────────────────
# Rule 1: issue_file_overlap (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Patch touches named file exactly
    ("Bug in `src/foo.py` causes crash.", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
    # Pos 2: Issue names module sympy/core/symbol.py, patch touches sympy/core/symbol.py
    ("Issue in `sympy/core/symbol.py` when creating symbols.", "--- a/sympy/core/symbol.py\n+++ b/sympy/core/symbol.py\n@@ -1,1 +1,1 @@\n-x\n+y\n"),
    # Pos 3: Issue names two files, patch touches one (any_named_untouched == 1.0)
    ("Files `src/foo.py` and `src/bar.py` need update.", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
])
def test_issue_file_overlap_positive(issue_text, patch_text):
    findings, features = evaluate_issue_file_overlap(issue_text, patch_text)
    assert features["fraction_touched_named"] > 0.0 or features["any_named_untouched"] == 1.0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Touched file does not match issue named file
    ("Bug in `src/foo.py`.", "--- a/src/unrelated.py\n+++ b/src/unrelated.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
    # Neg 2: Issue names matplotlib/pyplot.py, patch touches xarray/core.py
    ("Fix `matplotlib/pyplot.py`.", "--- a/xarray/core.py\n+++ b/xarray/core.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
    # Neg 3: Issue names no files
    ("General description with no files.", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
])
def test_issue_file_overlap_negative(issue_text, patch_text):
    findings, features = evaluate_issue_file_overlap(issue_text, patch_text)
    assert features["fraction_touched_named"] == 0.0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 2: issue_identifier_overlap (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Issue mentions identifier `parse_argument_list`
    ("Error in `parse_argument_list` function.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+def parse_argument_list(): pass\n"),
    # Pos 2: Issue mentions CamelCase `SymbolTable`
    ("SymbolTable failed to resolve.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+x = SymbolTable()\n"),
    # Pos 3: Issue mentions function call `compute_matrix_inverse()`
    ("Calling compute_matrix_inverse() throws.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n-res = compute_matrix_inverse()\n+res = None\n"),
])
def test_issue_identifier_overlap_positive(issue_text, patch_text):
    findings, features = evaluate_issue_identifier_overlap(issue_text, patch_text)
    assert features["issue_identifier_overlap_frac"] > 0.0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Issue mentions parse_argument_list, patch changes unrelated line
    ("Error in `parse_argument_list`.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+return 42\n"),
    # Neg 2: Issue mentions SymbolTable, patch adds generic print
    ("SymbolTable error.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+print('hello')\n"),
    # Neg 3: Issue has no code identifiers
    ("Fix the bug please.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+x = 1\n"),
])
def test_issue_identifier_overlap_negative(issue_text, patch_text):
    findings, features = evaluate_issue_identifier_overlap(issue_text, patch_text)
    assert features["issue_identifier_overlap_frac"] == 0.0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 3: issue_literal_hardcoding (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Issue mentions 40412, patch adds condition
    ("Server returned error code 40412.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+if code == 40412:\n"),
    # Pos 2: Issue mentions string 'invalid_header_format', patch adds return
    ("Message 'invalid_header_format' failed.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+return 'invalid_header_format'\n"),
    # Pos 3: Issue mentions constant 9999, patch adds assignment
    ("Max limit 9999 reached.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+self.limit = 9999\n"),
])
def test_issue_literal_hardcoding_positive(issue_text, patch_text):
    findings, features = evaluate_issue_literal_hardcoding(issue_text, patch_text)
    assert features["has_literal_hardcoding"] == 1.0
    assert len(findings) > 0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Patch adds common literal 0
    ("Error code 40412.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+if x == 0:\n"),
    # Neg 2: Patch adds True/False
    ("Error code 40412.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+return True\n"),
    # Neg 3: Patch adds utf-8 string
    ("Error code 40412.", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+enc = 'utf-8'\n"),
])
def test_issue_literal_hardcoding_negative(issue_text, patch_text):
    findings, features = evaluate_issue_literal_hardcoding(issue_text, patch_text)
    assert features["has_literal_hardcoding"] == 0.0
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 4: special_casing (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Added single-line if x == "magic": return 42
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+if x == 'magic': return 42\n"),
    # Pos 2: Added single-line if self.name == 'bar': return 'baz'
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+if self.name == 'bar': return 'baz'\n"),
    # Pos 3: Multi-line if x == 100:\n    return 200
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,2 +1,2 @@\n+if x == 100:\n+    return 200\n"),
])
def test_special_casing_positive(issue_text, patch_text):
    findings, features = evaluate_special_casing(issue_text, patch_text)
    assert features["has_special_casing"] == 1.0
    assert len(findings) > 0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Standard condition without special casing return
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+if x > 10: y = x + 1\n"),
    # Neg 2: Function definition
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+def foo(x): return x * 2\n"),
    # Neg 3: Standard return call
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+return calculate_total(a, b)\n"),
])
def test_special_casing_negative(issue_text, patch_text):
    findings, features = evaluate_special_casing(issue_text, patch_text)
    assert features["has_special_casing"] == 0.0
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 5: swallowed_exceptions (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Single line bare except: pass
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+except: pass\n"),
    # Pos 2: Single line except Exception: pass
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n+except Exception: pass\n"),
    # Pos 3: Multi-line except Exception:\n    pass
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,2 +1,2 @@\n+except Exception:\n+    pass\n"),
])
def test_swallowed_exceptions_positive(issue_text, patch_text):
    findings, features = evaluate_swallowed_exceptions(issue_text, patch_text)
    assert features["has_swallowed_exception"] == 1.0
    assert len(findings) > 0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Logging except block
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,2 +1,2 @@\n+except ValueError as e:\n+    logger.error(e)\n"),
    # Neg 2: Re-raising exception
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,2 +1,2 @@\n+except Exception as e:\n+    raise CustomError(e)\n"),
    # Neg 3: Try finally block
    ("", "--- a/foo.py\n+++ b/foo.py\n@@ -1,2 +1,2 @@\n+finally:\n+    cleanup()\n"),
])
def test_swallowed_exceptions_negative(issue_text, patch_text):
    findings, features = evaluate_swallowed_exceptions(issue_text, patch_text)
    assert features["has_swallowed_exception"] == 0.0
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 6: test_tampering (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Added @pytest.mark.skip in test file
    ("", "--- a/tests/test_foo.py\n+++ b/tests/test_foo.py\n@@ -1,1 +1,1 @@\n+@pytest.mark.skip\n"),
    # Pos 2: Deleted assert in test file
    ("", "--- a/tests/test_foo.py\n+++ b/tests/test_foo.py\n@@ -1,1 +1,0 @@\n-assert result == 42\n"),
    # Pos 3: Commented out assert in test file
    ("", "--- a/tests/test_foo.py\n+++ b/tests/test_foo.py\n@@ -1,1 +1,1 @@\n+# assert x == y\n"),
])
def test_test_tampering_positive(issue_text, patch_text):
    findings, features = evaluate_test_tampering(issue_text, patch_text)
    assert features["has_test_tampering"] == 1.0
    assert len(findings) > 0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Added assert in src file (not test file)
    ("", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n+assert x > 0\n"),
    # Neg 2: Added normal test in test file
    ("", "--- a/tests/test_foo.py\n+++ b/tests/test_foo.py\n@@ -1,1 +1,1 @@\n+def test_new(): assert True\n"),
    # Neg 3: Updated test assertion value in test file
    ("", "--- a/tests/test_foo.py\n+++ b/tests/test_foo.py\n@@ -1,1 +1,1 @@\n+assert result == 43\n"),
])
def test_test_tampering_negative(issue_text, patch_text):
    findings, features = evaluate_test_tampering(issue_text, patch_text)
    assert features["has_test_tampering"] == 0.0
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 7: suppression_markers (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Added # type: ignore
    ("", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n+x = 1  # type: ignore\n"),
    # Pos 2: Added # noqa
    ("", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n+import foo  # noqa\n"),
    # Pos 3: Added pragma: no cover
    ("", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n+def unreachable():  # pragma: no cover\n"),
])
def test_suppression_markers_positive(issue_text, patch_text):
    findings, features = evaluate_suppression_markers(issue_text, patch_text)
    assert features["has_suppression_marker"] == 1.0
    assert len(findings) > 0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Normal comment
    ("", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n+# normal comment explaining logic\n"),
    # Neg 2: Variable assignment comment
    ("", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n+x = 1  # integer assignment\n"),
    # Neg 3: String literal containing comment-like text
    ("", "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,1 +1,1 @@\n+print('no markers here')\n"),
])
def test_suppression_markers_negative(issue_text, patch_text):
    findings, features = evaluate_suppression_markers(issue_text, patch_text)
    assert features["has_suppression_marker"] == 0.0
    assert len(findings) == 0


# ──────────────────────────────────────────────────────────────────────────────
# Rule 8: scope_creep (>=3 positive, >=3 negative)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("issue_text, patch_text", [
    # Pos 1: Issue names sympy/core/symbol.py, patch touches django/contrib/admin.py
    ("Bug in `sympy/core/symbol.py`.", "--- a/django/contrib/admin.py\n+++ b/django/contrib/admin.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
    # Pos 2: Issue names src/auth/login.py, patch touches src/payments/billing.py
    ("Fix in `src/auth/login.py`.", "--- a/src/payments/billing.py\n+++ b/src/payments/billing.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
    # Pos 3: Issue names matplotlib/axes.py, patch touches seaborn/matrix.py
    ("Fix in `matplotlib/axes.py`.", "--- a/seaborn/matrix.py\n+++ b/seaborn/matrix.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
])
def test_scope_creep_positive(issue_text, patch_text):
    findings, features = evaluate_scope_creep(issue_text, patch_text)
    assert features["scope_creep_count"] > 0.0
    assert len(findings) > 0


@pytest.mark.parametrize("issue_text, patch_text", [
    # Neg 1: Issue names sympy/core/symbol.py, patch touches sympy/core/expr.py (same package)
    ("Bug in `sympy/core/symbol.py`.", "--- a/sympy/core/expr.py\n+++ b/sympy/core/expr.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
    # Neg 2: Issue names src/auth/login.py, patch touches src/auth/logout.py (same package)
    ("Fix in `src/auth/login.py`.", "--- a/src/auth/logout.py\n+++ b/src/auth/logout.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
    # Neg 3: Issue names foo/bar.py, patch touches foo/bar.py (exact match)
    ("Fix `foo/bar.py`.", "--- a/foo/bar.py\n+++ b/foo.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"),
])
def test_scope_creep_negative(issue_text, patch_text):
    findings, features = evaluate_scope_creep(issue_text, patch_text)
    assert features["scope_creep_count"] == 0.0
    assert len(findings) == 0


def test_runner_integration():
    issue = "Bug in `src/foo.py` with `parse_args`."
    patch = "--- a/src/foo.py\n+++ b/src/foo.py\n@@ -1,2 +1,2 @@\n+if x == 'magic': return 42 # type: ignore\n+except: pass\n"
    findings, features = run_all_heuristics(issue, patch)
    assert isinstance(findings, list)
    assert isinstance(features, dict)
    assert len(features) >= 15
