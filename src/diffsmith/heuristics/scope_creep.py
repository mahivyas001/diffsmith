"""
src/diffsmith/heuristics/scope_creep.py — Rule 8: Scope Creep
"""

import os
from diffsmith.heuristics.issue_file_overlap import extract_named_files_and_modules
from diffsmith.heuristics.utils import parse_diff_files


def get_package_or_dir(path: str) -> str:
    """Extract parent package or directory of a file path."""
    p = path.replace("\\", "/").strip("/")
    parts = p.split("/")
    if len(parts) > 1:
        return "/".join(parts[:-1])
    return ""


def evaluate_scope_creep(issue_text: str, patch_text: str) -> tuple[list[dict], dict[str, float]]:
    """
    Detect files touched in patch that are not named in issue and not in the same package/directory.
    Returns:
        findings: list of finding dicts
        features: {
            "scope_creep_count": float,
            "scope_creep_fraction": float,
        }
    """
    named_items = extract_named_files_and_modules(issue_text)
    touched_files = parse_diff_files(patch_text)

    if not touched_files or not named_items:
        return [], {
            "scope_creep_count": 0.0,
            "scope_creep_fraction": 0.0,
        }

    named_packages = {get_package_or_dir(item) for item in named_items if get_package_or_dir(item)}
    named_bases = {os.path.basename(item.replace("\\", "/")) for item in named_items}

    scope_creep_files = []

    for tf in touched_files:
        tf_norm = tf.replace("\\", "/")
        tf_base = os.path.basename(tf_norm)
        tf_pkg = get_package_or_dir(tf_norm)

        if any(item in tf_norm or tf_norm in item for item in named_items):
            continue
        if tf_base in named_bases:
            continue

        in_same_package = False
        for pkg in named_packages:
            if pkg and (pkg in tf_pkg or tf_pkg in pkg):
                in_same_package = True
                break

        if not in_same_package:
            scope_creep_files.append(tf)

    count = len(scope_creep_files)
    fraction = float(count / len(touched_files))

    findings = []
    for scf in scope_creep_files:
        findings.append({
            "rule_id": "scope_creep",
            "severity": "medium",
            "file": scf,
            "line": 1,
            "evidence": f"Touched file '{scf}' is not named in the issue and not in the same package/directory as named files ({list(named_items)[:3]})",
        })

    return findings, {
        "scope_creep_count": float(count),
        "scope_creep_fraction": fraction,
    }
