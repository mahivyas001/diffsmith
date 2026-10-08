"""
src/diffsmith/heuristics/issue_file_overlap.py — Rule 1: Issue File Overlap
"""

import os
import re
from diffsmith.heuristics.utils import parse_diff_files


def extract_named_files_and_modules(issue_text: str) -> set[str]:
    """Extract file paths, backticked names, and dotted module names from issue text."""
    if not issue_text or not isinstance(issue_text, str):
        return set()

    named = set()

    # Backticked names
    backticked = re.findall(r"`([a-zA-Z0-9_\-\./\\]+\.(?:py|c|h|cpp|js|ts|rst|md))`", issue_text)
    named.update(backticked)

    # Backticked modules or identifiers with dots
    backticked_mods = re.findall(r"`([a-zA-Z0-9_]+\.[a-zA-Z0-9_\.]+)`", issue_text)
    for mod in backticked_mods:
        named.add(mod)
        named.add(mod.replace(".", "/") + ".py")

    # Raw file paths (e.g. foo/bar.py or foo/bar/baz.py)
    paths = re.findall(r"\b([a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)+\.(?:py|c|h|cpp|js|ts))\b", issue_text)
    named.update(paths)

    # Dotted module patterns e.g. sympy.core.symbol
    dotted = re.findall(r"\b([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+){2,})\b", issue_text)
    for mod in dotted:
        named.add(mod)
        named.add(mod.replace(".", "/") + ".py")

    return {n.replace("\\", "/").strip() for n in named if n.strip()}


def evaluate_issue_file_overlap(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Evaluate issue file overlap.
    Returns:
        findings: list of finding dicts
        features: {
            "fraction_touched_named": float,
            "any_named_untouched": float,
        }
    """
    named_items = extract_named_files_and_modules(issue_text)
    touched_files = parse_diff_files(patch_text)

    if not touched_files:
        return [], {
            "fraction_touched_named": 0.0,
            "any_named_untouched": 1.0 if named_items else 0.0,
        }

    touched_and_named_count = 0
    matched_named_items = set()

    for tf in touched_files:
        tf_norm = tf.replace("\\", "/")
        tf_base = os.path.basename(tf_norm)
        is_named = False

        for item in named_items:
            item_norm = item.replace("\\", "/")
            item_base = os.path.basename(item_norm)

            if item_norm in tf_norm or tf_norm in item_norm:
                is_named = True
                matched_named_items.add(item)
            elif item_base and item_base == tf_base and item_base.endswith(".py"):
                is_named = True
                matched_named_items.add(item)
            elif item.replace(".", "/") in tf_norm:
                is_named = True
                matched_named_items.add(item)

        if is_named:
            touched_and_named_count += 1

    fraction_touched_named = float(touched_and_named_count / len(touched_files))
    any_named_untouched = 1.0 if len(matched_named_items) < len(named_items) else 0.0

    findings = []
    if named_items and fraction_touched_named == 0.0:
        findings.append({
            "rule_id": "issue_file_overlap",
            "severity": "medium",
            "file": touched_files[0] if touched_files else "",
            "line": 1,
            "evidence": f"None of the touched files {touched_files} match issue named files/modules: {list(named_items)[:3]}",
        })
    elif any_named_untouched == 1.0 and named_items:
        untouched = named_items - matched_named_items
        findings.append({
            "rule_id": "issue_file_overlap",
            "severity": "low",
            "file": touched_files[0] if touched_files else "",
            "line": 1,
            "evidence": f"Issue mentions files/modules {list(untouched)[:3]} that were not touched in patch.",
        })

    return findings, {
        "fraction_touched_named": fraction_touched_named,
        "any_named_untouched": any_named_untouched,
    }
