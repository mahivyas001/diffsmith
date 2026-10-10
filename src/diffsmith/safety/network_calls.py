"""
src/diffsmith/safety/network_calls.py — Rule 1: Detect newly added network calls.
"""

import re
from .safety_utils import extract_added_lines

RULE_ID = "SEC001_NETWORK_CALL"
SEVERITY = "HIGH"

NETWORK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brequests\.(?:get|post|put|delete|patch|head|options|request|Session)\b"), "requests network call"),
    (re.compile(r"\burllib\.request\.(?:urlopen|Request|urlretrieve)\b"), "urllib.request network call"),
    (re.compile(r"\burllib2\.(?:urlopen|Request)\b"), "urllib2 network call"),
    (re.compile(r"\bhttp\.client\.(?:HTTPConnection|HTTPSConnection)\b"), "http.client connection"),
    (re.compile(r"\bhttpx\.(?:get|post|put|delete|patch|request|Client|AsyncClient)\b"), "httpx network call"),
    (re.compile(r"\baiohttp\.(?:ClientSession|request)\b"), "aiohttp network call"),
    (re.compile(r"\bsocket\.(?:socket|create_connection)\b"), "socket network call"),
    (re.compile(r"\b(?:curl|wget)\b.*?\bhttps?://", re.IGNORECASE), "curl/wget HTTP fetch"),
]


def check_network_calls(patch_text: str) -> list[dict]:
    """Scan added diff lines for newly introduced network calls."""
    findings = []
    added_lines = extract_added_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        # Skip pure comments
        if stripped.startswith("#"):
            continue

        for pattern, desc in NETWORK_PATTERNS:
            if pattern.search(line_info.content):
                findings.append({
                    "rule_id": RULE_ID,
                    "severity": SEVERITY,
                    "file": line_info.file_path,
                    "line": line_info.line_no,
                    "evidence": f"{desc}: {stripped[:120]}",
                })
                break

    return findings
