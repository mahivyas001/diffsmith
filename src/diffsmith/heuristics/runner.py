"""
src/diffsmith/heuristics/runner.py — Relational Heuristics Pipeline Runner
"""

from diffsmith.heuristics.issue_file_overlap import evaluate_issue_file_overlap
from diffsmith.heuristics.issue_identifier_overlap import evaluate_issue_identifier_overlap
from diffsmith.heuristics.issue_literal_hardcoding import evaluate_issue_literal_hardcoding
from diffsmith.heuristics.special_casing import evaluate_special_casing
from diffsmith.heuristics.swallowed_exceptions import evaluate_swallowed_exceptions
from diffsmith.heuristics.test_tampering import evaluate_test_tampering
from diffsmith.heuristics.suppression_markers import evaluate_suppression_markers
from diffsmith.heuristics.scope_creep import evaluate_scope_creep

ALL_RULES = [
    evaluate_issue_file_overlap,
    evaluate_issue_identifier_overlap,
    evaluate_issue_literal_hardcoding,
    evaluate_special_casing,
    evaluate_swallowed_exceptions,
    evaluate_test_tampering,
    evaluate_suppression_markers,
    evaluate_scope_creep,
]


def run_all_heuristics(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Run all 8 relational heuristic rules on issue_text and patch_text.
    Returns:
        findings: combined list of finding dicts
        features: combined dict of numeric features
    """
    all_findings = []
    all_features = {}

    for rule_fn in ALL_RULES:
        findings, features = rule_fn(issue_text, patch_text)
        all_findings.extend(findings)
        all_features.update(features)

    return all_findings, all_features
