import os
import sys

# Ensure repository root is on sys.path so scripts.build_heldout can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.build_heldout import parse_preds, repo_of


def test_repo_of():
    assert repo_of("django__django-11099") == "django/django"
    assert repo_of("matplotlib__matplotlib-18869") == "matplotlib/matplotlib"
    assert repo_of("sympy__sympy-13146") == "sympy/sympy"


def test_parse_preds_jsonl():
    jsonl_text = (
        '{"instance_id": "django__django-11099", "model_patch": "diff --git a/file.py b/file.py"}\n'
        '{"instance_id": "sympy__sympy-13146", "model_patch": "diff --git a/math.py b/math.py"}\n'
    )
    result = parse_preds(jsonl_text)
    assert len(result) == 2
    assert result["django__django-11099"] == "diff --git a/file.py b/file.py"
    assert result["sympy__sympy-13146"] == "diff --git a/math.py b/math.py"


def test_parse_preds_dict():
    dict_text = '{"django__django-11099": {"patch": "diff --git a/file.py b/file.py"}}'
    result = parse_preds(dict_text)
    assert result.get("django__django-11099") == "diff --git a/file.py b/file.py"


def test_parse_preds_empty_patch():
    jsonl_text = (
        '{"instance_id": "django__django-11099", "model_patch": ""}\n'
        '{"instance_id": "sympy__sympy-13146", "model_patch": "   "}\n'
    )
    result = parse_preds(jsonl_text)
    assert "django__django-11099" in result
    assert result["django__django-11099"] == ""
    assert "sympy__sympy-13146" in result
    assert result["sympy__sympy-13146"] == "   "
