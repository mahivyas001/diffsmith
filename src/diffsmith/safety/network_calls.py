"""
src/diffsmith/safety/network_calls.py — Rule 1: Detect newly added network calls.
"""

import re
from .safety_utils import extract_added_lines, extract_context_lines, is_test_file, is_scratch_script

RULE_ID = "SEC001_NETWORK_CALL"

NETWORK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brequests\.(?:get|post|put|delete|patch|head|options|request|Session)\b"), "requests network call"),
    (re.compile(r"\burllib\.request\.(?:urlopen|Request|urlretrieve)\b"), "urllib.request network call"),
    (re.compile(r"\burllib2\.(?:urlopen|Request)\b"), "urllib2 network call"),
    (re.compile(r"\burllib3\.(?:PoolManager|ProxyManager|request|connection_from_url)\b"), "urllib3 network call"),
    (re.compile(r"\bhttp\.client\.(?:HTTPConnection|HTTPSConnection)\b"), "http.client connection"),
    (re.compile(r"\bhttpx\.(?:get|post|put|delete|patch|request|Client|AsyncClient)\b"), "httpx network call"),
    (re.compile(r"\baiohttp\.(?:ClientSession|request)\b"), "aiohttp network call"),
    (re.compile(r"\b(?:ftplib|smtplib|poplib|imaplib|telnetlib)\.[A-Za-z0-9_]+\b"), "standard library protocol network client"),
    (re.compile(r"\b(?:websocket|websockets)\.(?:connect|create_connection|WebSocketApp|serve)\b"), "websocket network connection"),
    (re.compile(r"\bparamiko\.(?:SSHClient|Transport)\b"), "paramiko SSH network connection"),
    (re.compile(r"\bpycurl\.Curl\b"), "pycurl network client"),
    (re.compile(r"\bxmlrpc\.client\.ServerProxy\b"), "xmlrpc.client network proxy"),
    (re.compile(r"\bgrpc\.(?:insecure_channel|secure_channel|aio)\b"), "grpc network channel"),
    (re.compile(r"\basyncio\.(?:open_connection|open_unix_connection|start_server)\b"), "asyncio network connection"),
    (re.compile(r"\bsocket\.(?:socket|create_connection)\b"), "socket creation"),
    (re.compile(r"\b(?:s|sock|socket|conn|client)\.connect(?:_ex)?\s*\("), "socket connect call"),
    (re.compile(r"\b(?:curl|wget)\b.*?\bhttps?://", re.IGNORECASE), "curl/wget HTTP fetch"),
]


def check_network_calls(patch_text: str) -> list[dict]:
    """Scan added diff lines for newly introduced network calls."""
    findings = []
    added_lines = extract_added_lines(patch_text)
    context_map = extract_context_lines(patch_text)

    for line_info in added_lines:
        stripped = line_info.content.strip()
        if stripped.startswith("#"):
            continue

        for pattern, desc in NETWORK_PATTERNS:
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
