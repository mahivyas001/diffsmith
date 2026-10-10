"""
src/diffsmith/safety/__init__.py — Patch behavior security scanner and rules.
"""

from .scanner import scan_patch, ALL_RULES
from .safety_utils import check_vendored_paths, check_scratch_scripts
from .network_calls import check_network_calls
from .shell_pipe import check_shell_pipe
from .command_exec import check_command_exec
from .obfuscation import check_obfuscation
from .credential_reads import check_credential_reads
from .workflow_build import check_workflow_build
from .hook_tampering import check_hook_tampering

__all__ = [
    "scan_patch",
    "ALL_RULES",
    "check_vendored_paths",
    "check_scratch_scripts",
    "check_network_calls",
    "check_shell_pipe",
    "check_command_exec",
    "check_obfuscation",
    "check_credential_reads",
    "check_workflow_build",
    "check_hook_tampering",
]
