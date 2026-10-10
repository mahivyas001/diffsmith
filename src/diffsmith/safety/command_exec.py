"""
src/diffsmith/safety/command_exec.py — Rule 3: Detect subprocess, os.system, eval, exec additions.
"""

import re
from .safety_utils import extract_added_lines, extract_context_lines, is_test_file, is_scratch_script

RULE_ID = "SEC003_COMMAND_EXEC"

COMMAND_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsubprocess\.(?:Popen|run|call|check_call|check_output|getoutput|getstatusoutput)\s*\("), "subprocess execution"),
    (re.compile(r"\basyncio\.(?:create_subprocess_exec|create_subprocess_shell)\s*\("), "asyncio subprocess execution"),
    (re.compile(r"\bos\.(?:system|popen|spawn[lpev]*|exec[lpev]*)\s*\("), "os execution command"),
    (re.compile(r"\brunpy\.(?:run_path|run_module)\s*\("), "runpy script execution"),
    (re.compile(r"\bcode\.(?:InteractiveInterpreter|InteractiveConsole)\s*\("), "code interactive execution"),
    (re.compile(r"(?<!\w)eval\s*\("), "dynamic eval() execution"),
    (re.compile(r"(?<!\w)exec\s*\("), "dynamic exec() execution"),
    (re.compile(r"\bpty\.spawn\s*\("), "pty interactive shell spawn"),
    (re.compile(r"\bctypes\b.*?\.system\s*\("), "ctypes system call execution"),
]


def check_command_exec(patch_text: str) -> list[dict]:
    """Scan added diff lines for subprocess, os.system, eval, and exec invocations."""
    findings = []
    added_lines = extract_added_lines(patch_text)
    context_map = extract_context_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in COMMAND_PATTERNS:
            if pattern.search(line_info.content):
                file_ctx = context_map.get(line_info.file_path, [])
                is_modifying_existing = any(pattern.search(ctx_line) for ctx_line in file_ctx)
                in_scratch_or_test = is_test_file(line_info.file_path) or is_scratch_script(line_info.file_path)

                if in_scratch_or_test or is_modifying_existing:
                    sev = "low"
                else:
                    sev = "MEDIUM"

                findings.append({
                    "rule_id": RULE_ID,
                    "severity": sev,
                    "file": line_info.file_path,
                    "line": line_info.line_no,
                    "evidence": f"{desc}: {stripped[:120]}",
                })
                break

    return findings
