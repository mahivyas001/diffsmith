"""
src/diffsmith/heuristics/__init__.py — Relational Heuristics Package
"""

from diffsmith.heuristics.issue_file_overlap import evaluate_issue_file_overlap
from diffsmith.heuristics.issue_identifier_overlap import evaluate_issue_identifier_overlap
from diffsmith.heuristics.issue_literal_hardcoding import evaluate_issue_literal_hardcoding
from diffsmith.heuristics.special_casing import evaluate_special_casing
from diffsmith.heuristics.swallowed_exceptions import evaluate_swallowed_exceptions
from diffsmith.heuristics.test_tampering import evaluate_test_tampering
from diffsmith.heuristics.suppression_markers import evaluate_suppression_markers
from diffsmith.heuristics.scope_creep import evaluate_scope_creep
from diffsmith.heuristics.runner import run_all_heuristics

__all__ = [
    "evaluate_issue_file_overlap",
    "evaluate_issue_identifier_overlap",
    "evaluate_issue_literal_hardcoding",
    "evaluate_special_casing",
    "evaluate_swallowed_exceptions",
    "evaluate_test_tampering",
    "evaluate_suppression_markers",
    "evaluate_scope_creep",
    "run_all_heuristics",
]
