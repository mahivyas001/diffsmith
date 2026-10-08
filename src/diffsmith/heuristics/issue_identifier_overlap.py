"""
src/diffsmith/heuristics/issue_identifier_overlap.py — Rule 2: Issue Identifier Overlap
"""

import re
from diffsmith.heuristics.utils import extract_diff_lines

STOPWORDS = {
    "self", "def", "class", "import", "from", "return", "if", "else", "elif",
    "true", "false", "none", "for", "while", "try", "except", "raise", "with",
    "as", "pass", "in", "is", "not", "and", "or", "int", "str", "float", "bool",
    "list", "dict", "set", "tuple", "len", "the", "this", "that", "when", "where",
}


def extract_issue_identifiers(issue_text: str) -> set[str]:
    """Extract code identifiers (backticked terms, CamelCase, snake_case, functions) from issue text."""
    if not issue_text or not isinstance(issue_text, str):
        return set()

    identifiers = set()

    # Backticked terms e.g. `my_var` or `my_func()`
    backticked = re.findall(r"`([a-zA-Z_][a-zA-Z0-9_\.]*)(?:\(\))?`", issue_text)
    for b in backticked:
        for token in b.split("."):
            if len(token) > 2 and token.lower() not in STOPWORDS:
                identifiers.add(token)

    # Function calls in code blocks e.g. foo_bar()
    funcs = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(", issue_text)
    for f in funcs:
        if f.lower() not in STOPWORDS:
            identifiers.add(f)

    # CamelCase identifiers e.g. SymbolTable
    camel = re.findall(r"\b([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+)\b", issue_text)
    for c in camel:
        identifiers.add(c)

    # snake_case identifiers e.g. parse_args_list
    snake = re.findall(r"\b([a-z0-9]+(?:_[a-z0-9]+)+)\b", issue_text)
    for s in snake:
        if len(s) > 3 and s.lower() not in STOPWORDS:
            identifiers.add(s)

    return identifiers


def evaluate_issue_identifier_overlap(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Evaluate fraction of changed lines in patch that mention issue identifiers.
    Returns:
        findings: list of finding dicts
        features: {
            "issue_identifier_overlap_frac": float
        }
    """
    identifiers = extract_issue_identifiers(issue_text)
    diff_lines = extract_diff_lines(patch_text)

    if not diff_lines:
        return [], {"issue_identifier_overlap_frac": 0.0}

    matching_changed_lines = 0

    for dl in diff_lines:
        line_code = dl.content
        tokens = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", line_code))
        if any(ident in tokens for ident in identifiers):
            matching_changed_lines += 1

    frac = float(matching_changed_lines / len(diff_lines))

    findings = []
    if identifiers and frac == 0.0:
        findings.append({
            "rule_id": "issue_identifier_overlap",
            "severity": "medium",
            "file": diff_lines[0].file_path if diff_lines else "",
            "line": diff_lines[0].line_no if diff_lines else 1,
            "evidence": f"Changed lines have 0% overlap with issue identifiers: {list(identifiers)[:5]}",
        })

    return findings, {"issue_identifier_overlap_frac": frac}
