"""
tests/test_cli_verdict.py -- Comprehensive unit tests for diffsmith CLI and verdict logic.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from diffsmith.cli import (
    MANDATORY_FOOTER,
    deduplicate_findings,
    determine_verdict,
    run_audit,
)


@pytest.fixture
def sample_files(tmp_path: Path):
    """Create valid sample issue and diff files."""
    issue_file = tmp_path / "issue.txt"
    issue_file.write_text("Please fix the typo in documentation.", encoding="utf-8")

    diff_file = tmp_path / "patch.diff"
    diff_file.write_text(
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-# Typo\n"
        "+# Fixed\n",
        encoding="utf-8",
    )
    return str(diff_file), str(issue_file)


# ---------------------------------------------
# 1. Verdict Tiers & Exit Codes
# ---------------------------------------------
def test_verdict_tier_0_no_findings():
    """No findings returns exit 0 and clean verdict message."""
    verdict, code = determine_verdict([])
    assert code == 0
    assert verdict == "No risky patterns flagged."


def test_verdict_tier_0_low_review_only():
    """Only LOW/REVIEW severity findings return exit 0."""
    findings = [
        {"rule_id": "SEC001", "severity": "LOW", "evidence": "read env"},
        {"rule_id": "vendored_directory_added", "severity": "REVIEW", "evidence": "vendor dir"},
    ]
    verdict, code = determine_verdict(findings)
    assert code == 0
    assert verdict == "Low-severity notes only; listed below."


def test_verdict_tier_1_security_medium():
    """Security MEDIUM finding returns exit 1."""
    findings = [
        {"rule_id": "SEC006", "severity": "MEDIUM", "evidence": "build file edit"},
    ]
    verdict, code = determine_verdict(findings)
    assert code == 1
    assert verdict == "Review recommended: risky behavior flagged."


def test_verdict_tier_2_security_high_or_critical():
    """Security HIGH or CRITICAL findings return exit 2."""
    for sev in ("HIGH", "CRITICAL"):
        findings = [{"rule_id": "SEC002", "severity": sev, "evidence": "shell pipe"}]
        verdict, code = determine_verdict(findings)
        assert code == 2
        assert verdict == "Do not merge without manual review."


def test_verdict_injection_only():
    """Any injection finding with no security HIGH returns exit 1."""
    findings = [
        {"rule_id": "INJ001", "severity": "HIGH", "source": "issue", "evidence": "override prompt"},
    ]
    verdict, code = determine_verdict(findings)
    assert code == 1
    assert verdict == "Human should review: possible prompt-injection content in the issue or patch text."


def test_verdict_security_high_plus_injection():
    """Both security HIGH and injection finding returns exit 2 and lists both."""
    findings = [
        {"rule_id": "SEC002", "severity": "HIGH", "evidence": "curl | sh"},
        {"rule_id": "INJ001", "severity": "MEDIUM", "source": "comment", "evidence": "ignore rules"},
    ]
    verdict, code = determine_verdict(findings)
    assert code == 2
    assert "Do not merge without manual review." in verdict
    assert "Human should review: possible prompt-injection content in the issue or patch text." in verdict


def test_security_high_with_source_issue_is_not_injection():
    """A security finding with rule_id SEC002_PIPE severity HIGH and source='issue' yields exit 2 and is not injection."""
    findings = [
        {"rule_id": "SEC002_PIPE", "severity": "HIGH", "source": "issue", "evidence": "curl | sh"},
    ]
    verdict, code = determine_verdict(findings)
    assert code == 2
    assert verdict == "Do not merge without manual review."
    assert "prompt-injection" not in verdict


# ---------------------------------------------
# 2. De-duplication of Findings
# ---------------------------------------------
def test_duplicate_collapsing():
    """Duplicates with matching rule_id, file, line, and evidence are collapsed."""
    findings = [
        {"rule_id": "SEC001", "file": "app.py", "line": 10, "evidence": "os.getenv()", "severity": "LOW"},
        {"rule_id": "SEC001", "file": "app.py", "line": 10, "evidence": "os.getenv()", "severity": "LOW"},
        {"rule_id": "SEC001", "file": "app.py", "line": 12, "evidence": "os.getenv()", "severity": "LOW"},
        {"rule_id": "INJ001", "file": None, "line": 1, "evidence": "disregard instructions", "severity": "MEDIUM"},
        {"rule_id": "INJ001", "file": None, "line": 1, "evidence": "disregard instructions", "severity": "MEDIUM"},
    ]
    unique, collapsed = deduplicate_findings(findings)
    assert len(unique) == 3
    assert collapsed == 2


# ---------------------------------------------
# 3. Layer Exceptions & Internal Errors (Exit 3)
# ---------------------------------------------
def test_layer_raising_returns_exit_3(sample_files, monkeypatch, capsys):
    """If any scanner layer raises an exception, reports failure and exits 3."""
    diff_file, issue_file = sample_files

    def mock_raising_scan(diff_text):
        raise RuntimeError("Scanner DB failure")

    monkeypatch.setattr("diffsmith.cli.scan_patch", mock_raising_scan)
    monkeypatch.setattr("diffsmith.cli.scan_text", lambda text, source="issue": [])
    monkeypatch.setattr("diffsmith.cli.scan_patch_comments", lambda diff: [])

    code = run_audit(diff_file, issue_file)
    assert code == 3
    captured = capsys.readouterr()
    assert "ERROR:" in captured.out or "ERROR:" in captured.err
    assert "Security scanner layer failed" in captured.out or "Security scanner layer failed" in captured.err


def test_injection_issue_layer_raising_returns_exit_3(sample_files, monkeypatch, capsys):
    """If injection shield on issue text raises an exception, reports failure naming the layer and exits 3."""
    diff_file, issue_file = sample_files

    def mock_raising_scan_text(text, source="issue"):
        raise RuntimeError("Issue scanner error")

    monkeypatch.setattr("diffsmith.cli.scan_patch", lambda diff: [])
    monkeypatch.setattr("diffsmith.cli.scan_text", mock_raising_scan_text)
    monkeypatch.setattr("diffsmith.cli.scan_patch_comments", lambda diff: [])

    code = run_audit(diff_file, issue_file)
    assert code == 3
    captured = capsys.readouterr()
    err_text = captured.out + captured.err
    assert "ERROR:" in err_text
    assert "Injection shield (regex) on issue text failed" in err_text


def test_injection_patch_comments_layer_raising_returns_exit_3(sample_files, monkeypatch, capsys):
    """If injection shield on patch comments raises an exception, reports failure naming the layer and exits 3."""
    diff_file, issue_file = sample_files

    def mock_raising_scan_comments(diff):
        raise RuntimeError("Comments scanner error")

    monkeypatch.setattr("diffsmith.cli.scan_patch", lambda diff: [])
    monkeypatch.setattr("diffsmith.cli.scan_text", lambda text, source="issue": [])
    monkeypatch.setattr("diffsmith.cli.scan_patch_comments", mock_raising_scan_comments)

    code = run_audit(diff_file, issue_file)
    assert code == 3
    captured = capsys.readouterr()
    err_text = captured.out + captured.err
    assert "ERROR:" in err_text
    assert "Injection shield (regex) on patch comments failed" in err_text


def test_missing_diff_file_returns_exit_3(tmp_path, capsys):
    """Missing diff file produces ERROR and exit 3."""
    issue_file = tmp_path / "issue.txt"
    issue_file.write_text("Valid issue.", encoding="utf-8")
    missing_diff = str(tmp_path / "nonexistent.diff")

    code = run_audit(missing_diff, str(issue_file))
    assert code == 3
    captured = capsys.readouterr()
    assert "ERROR:" in captured.out or "ERROR:" in captured.err


def test_empty_diff_file_returns_exit_3(tmp_path, capsys):
    """Empty diff file produces ERROR and exit 3."""
    issue_file = tmp_path / "issue.txt"
    issue_file.write_text("Valid issue.", encoding="utf-8")
    empty_diff = tmp_path / "empty.diff"
    empty_diff.write_text("", encoding="utf-8")

    code = run_audit(str(empty_diff), str(issue_file))
    assert code == 3
    captured = capsys.readouterr()
    assert "ERROR:" in captured.out or "ERROR:" in captured.err


def test_non_text_binary_diff_returns_exit_3(tmp_path, capsys):
    """Non-text binary diff produces ERROR and exit 3."""
    issue_file = tmp_path / "issue.txt"
    issue_file.write_text("Valid issue.", encoding="utf-8")
    bin_diff = tmp_path / "binary.diff"
    bin_diff.write_bytes(b"\x00\x01\x02\xff")

    code = run_audit(str(bin_diff), str(issue_file))
    assert code == 3
    captured = capsys.readouterr()
    assert "ERROR:" in captured.out or "ERROR:" in captured.err


# ---------------------------------------------
# 4. CLI Argument Parsing & Usage Errors (Exit 3)
# ---------------------------------------------
def test_usage_error_exits_3():
    """Missing required arguments to CLI must exit with code 3, not 2."""
    cmd = [sys.executable, "-m", "diffsmith.cli"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert res.returncode == 3
    assert "error:" in res.stderr.lower() or "usage:" in res.stderr.lower()


# ---------------------------------------------
# 5. Footer & Forbidden Words Enforcement
# ---------------------------------------------
def test_mandatory_footer_present_in_text_and_json(sample_files, capsys):
    """Mandatory footer is present in text output and JSON payload."""
    diff_file, issue_file = sample_files

    with patch("diffsmith.cli.scan_patch", return_value=[]), \
         patch("diffsmith.cli.scan_text", return_value=[]), \
         patch("diffsmith.cli.scan_patch_comments", return_value=[]):

        # Text mode
        code_text = run_audit(diff_file, issue_file, json_mode=False)
        assert code_text == 0
        text_out = capsys.readouterr().out
        assert MANDATORY_FOOTER in text_out

        # JSON mode
        code_json = run_audit(diff_file, issue_file, json_mode=True)
        assert code_json == 0
        json_out = capsys.readouterr().out
        data = json.loads(json_out)
        assert data["footer"] == MANDATORY_FOOTER


def test_verdict_wording_never_contains_forbidden_words():
    """Verdict text must never contain 'safe', 'correct', 'genuine', or 'verified'."""
    forbidden = ["safe", "correct", "genuine", "verified"]

    test_finding_sets = [
        [],
        [{"rule_id": "SEC001", "severity": "LOW", "evidence": "ev"}],
        [{"rule_id": "SEC001", "severity": "REVIEW", "evidence": "ev"}],
        [{"rule_id": "SEC006", "severity": "MEDIUM", "evidence": "ev"}],
        [{"rule_id": "SEC002", "severity": "HIGH", "evidence": "ev"}],
        [{"rule_id": "SEC002", "severity": "CRITICAL", "evidence": "ev"}],
        [{"rule_id": "INJ001", "severity": "LOW", "source": "issue", "evidence": "ev"}],
        [
            {"rule_id": "SEC002", "severity": "HIGH", "evidence": "ev"},
            {"rule_id": "INJ001", "severity": "MEDIUM", "source": "issue", "evidence": "ev"},
        ],
    ]

    for f_set in test_finding_sets:
        verdict, _ = determine_verdict(f_set)
        verdict_lower = verdict.lower()
        for word in forbidden:
            assert word not in verdict_lower, f"Forbidden word '{word}' found in verdict: '{verdict}'"


# ---------------------------------------------
# 6. Optional CodeBERT Handling
# ---------------------------------------------
def test_codebert_without_weights_prints_not_run_and_preserves_exit_code(sample_files, capsys):
    """When --codebert is requested but weights are absent, prints NOT RUN and does not alter verdict."""
    diff_file, issue_file = sample_files

    with patch("diffsmith.cli.scan_patch", return_value=[]), \
         patch("diffsmith.cli.scan_text", return_value=[]), \
         patch("diffsmith.cli.scan_patch_comments", return_value=[]):

        # Test mode with no weights path
        code = run_audit(
            diff_file,
            issue_file,
            model_path="nonexistent/model/path",
            json_mode=True,
            use_codebert=True,
        )
        assert code == 0
        captured = capsys.readouterr().out
        payload = json.loads(captured)
        assert payload["exit_code"] == 0
        assert "NOT RUN" in payload["layers"]["CodeBERT"]
        assert "experimental" in payload


# ---------------------------------------------
# 7. JSON Output Structure Validation
# ---------------------------------------------
def test_json_structure_and_keys(sample_files, capsys):
    """JSON output contains all required keys and is valid JSON."""
    diff_file, issue_file = sample_files

    with patch("diffsmith.cli.scan_patch", return_value=[]), \
         patch("diffsmith.cli.scan_text", return_value=[]), \
         patch("diffsmith.cli.scan_patch_comments", return_value=[]):

        code = run_audit(diff_file, issue_file, json_mode=True)
        assert code == 0
        out = capsys.readouterr().out
        data = json.loads(out)

        required_keys = {
            "verdict",
            "exit_code",
            "layers",
            "findings",
            "duplicates_collapsed",
            "experimental",
            "footer",
        }
        assert required_keys.issubset(data.keys())
        assert isinstance(data["layers"], dict)
        assert isinstance(data["findings"], list)
        assert isinstance(data["duplicates_collapsed"], int)


# ---------------------------------------------
# 8. End-to-End Test on Benign Patch
# ---------------------------------------------
def test_end_to_end_benign_patch(tmp_path):
    """End-to-end audit on a trivial benign README patch expects exit code 0."""
    readme_diff = tmp_path / "readme.diff"
    readme_diff.write_text(
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-# Old Documentation\n"
        "+# Updated Documentation\n",
        encoding="utf-8",
    )
    issue = tmp_path / "issue.txt"
    issue.write_text("Please update the documentation header in README.", encoding="utf-8")

    code = run_audit(str(readme_diff), str(issue), json_mode=False)
    assert code == 0
