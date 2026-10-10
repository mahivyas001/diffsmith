"""
src/diffsmith/safety/scanner.py — Aggregator scanner running all diff security rules.
"""

from .network_calls import check_network_calls
from .shell_pipe import check_shell_pipe
from .command_exec import check_command_exec
from .obfuscation import check_obfuscation
from .credential_reads import check_credential_reads
from .workflow_build import check_workflow_build
from .hook_tampering import check_hook_tampering

ALL_RULES = [
    ("SEC001_NETWORK_CALL", check_network_calls),
    ("SEC002_SHELL_PIPE", check_shell_pipe),
    ("SEC003_COMMAND_EXEC", check_command_exec),
    ("SEC004_OBFUSCATION", check_obfuscation),
    ("SEC005_CREDENTIAL_READS", check_credential_reads),
    ("SEC006_WORKFLOW_BUILD", check_workflow_build),
    ("SEC007_HOOK_TAMPERING", check_hook_tampering),
]


def scan_patch(patch_text: str) -> list[dict]:
    """
    Run all patch-behavior security rules over patch_text.

    Returns a list of finding dicts:
        {rule_id, severity, file, line, evidence}
    """
    all_findings = []
    for _, rule_fn in ALL_RULES:
        findings = rule_fn(patch_text)
        if findings:
            all_findings.extend(findings)
    return all_findings
