"""
src/diffsmith/safety/injection.py — Prompt-injection shield for diffsmith.

Exposes:
    scan_text(text: str, source: str = "issue") -> list[dict]
    scan_patch_comments(patch_text: str) -> list[dict]

Each finding:
    {rule_id, severity, source, line, evidence}

Rules:
    INJ001: instruction override
    INJ002: role/system impersonation
    INJ003: exfiltration
    INJ004: concealment
    INJ005: authority claims
    INJ006: assistant command to add backdoors, extra accounts, reverse shells, or edit CI/dependencies
"""

import base64
import html
import re
import unicodedata
from typing import NamedTuple

# Common unicode look-alikes map to ASCII lowercase
HOMOGLYPH_MAP = {
    "а": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a",
    "b": "b", "в": "b",
    "с": "c", "ç": "c",
    "d": "d", "ԁ": "d",
    "е": "e", "è": "e", "é": "e", "ê": "e", "ë": "e",
    "f": "f",
    "ɡ": "g",
    "h": "h", "һ": "h",
    "і": "i", "í": "i", "ì": "i", "ï": "i", "î": "i",
    "j": "j", "ј": "j",
    "k": "k", "к": "k",
    "l": "l", "ӏ": "l",
    "m": "m", "м": "m",
    "n": "n", "п": "n",
    "о": "o", "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "р": "p",
    "q": "q",
    "r": "r", "г": "r",
    "s": "s", "ѕ": "s",
    "t": "t", "т": "t",
    "u": "u", "ù": "u", "ú": "u", "û": "u", "ü": "u",
    "v": "v", "ѵ": "v",
    "w": "w", "ш": "w",
    "x": "x", "х": "x",
    "у": "y", "ý": "y", "ÿ": "y",
    "z": "z",
}

LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
}

# Zero-width, formatting, and bidirectional control characters
CONTROL_CHAR_RE = re.compile(
    r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2060-\u206F\x00-\x08\x0B\x0C\x0E-\x1F]"
)

# HTML / markdown comment pattern: <!-- ... --> or [//]: # (...)
COMMENT_EXTRACT_RE = re.compile(
    r"<!--(.*?)-->|\[//\]:\s*#\s*\((.*?)\)",
    re.DOTALL,
)

# Potential Base64 string: sequences of base64 chunks possibly separated by whitespace
BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{4,}(?:[\s\r\n]+[A-Za-z0-9+/]{3,})*={0,2}")


def normalize_text(text: str, apply_leet: bool = False) -> str:
    """Normalize text by stripping control characters, folding homoglyphs, and optionally un-leeting."""
    if not text:
        return ""

    # Unescape HTML entities first
    text = html.unescape(text)

    # Strip zero-width & bidirectional control chars
    text = CONTROL_CHAR_RE.sub("", text)

    # Normalize unicode and strip combining marks (accents)
    text = "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))

    # Convert to lowercase
    lower = text.lower()

    # Fold homoglyphs
    chars = [HOMOGLYPH_MAP.get(c, c) for c in lower]
    res = "".join(chars)

    if apply_leet:
        leet_chars = [LEET_MAP.get(c, c) for c in res]
        res = "".join(leet_chars)

    # Collapse whitespace
    res = re.sub(r"\s+", " ", res).strip()
    return res


def extract_base64_payloads(text: str) -> list[str]:
    """Decode any plausible base64 strings in the text."""
    payloads = []
    candidates = BASE64_CANDIDATE_RE.findall(text)
    for cand in candidates:
        cleaned = re.sub(r"\s+", "", cand)
        if len(cleaned) < 16:
            continue
        try:
            decoded = base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")
            if len(decoded) >= 8 and any(c.isalpha() for c in decoded):
                payloads.append(decoded)
        except Exception:
            continue
    return payloads


def extract_embedded_comments(text: str) -> list[str]:
    """Extract contents of HTML comments and markdown hidden comments."""
    embedded = []
    for m in COMMENT_EXTRACT_RE.finditer(text):
        c = m.group(1) or m.group(2)
        if c:
            embedded.append(c.strip())
    return embedded


# ──────────────────────────────────────────────────────────────────────────────
# Injection Rule Definitions
# ──────────────────────────────────────────────────────────────────────────────

class RulePattern(NamedTuple):
    rule_id: str
    pattern: re.Pattern
    severity: str
    desc: str


# Address-to-AI markers
AI_PREFIX = r"(?:(?:assistant|ai|agent|system|bot|copilot)\s*[:,]\s*|to\s+(?:ai|assistant|agent)\s*:\s*)"

INJECTION_PATTERNS = [
    # ── INJ001: Instruction Override ──
    # High: clear command to ignore/forget previous instructions/rules
    RulePattern(
        "INJ001",
        re.compile(
            r"\b(?:ignore|disregard|forget|stop\s+following)\s+"
            r"(?:all\s+|any\s+|the\s+|your\s+|earlier\s+|everything\s+you\s+were\s+told\s+earlier\s+)*"
            r"(?:prior|previous|earlier|above|past)\s+"
            r"(?:instructions?|guidelines?|rules?|prompts?|constraints?|policies?|directives?)\b|"
            r"\bignorez\s+(?:toutes\s+les\s+)?instructions\s+pr[eé]c[eé]dentes\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "instruction override: ignore prior instructions/rules",
    ),
    RulePattern(
        "INJ001",
        re.compile(
            r"\bforget\s+everything\s+(?:you\s+were\s+told|you\s+know|earlier)\b|"
            r"\bpretend\s+(?:the\s+)?(?:earlier|previous|prior)\s+(?:guidance|rules?|instructions?)\s+never\s+existed\b|"
            r"\b(?:override|bypass)\s+(?:all\s+)?(?:previous|prior)\s+rules\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "instruction override: forget or pretend prior rules never existed",
    ),
    RulePattern(
        "INJ001",
        re.compile(
            r"\bnew\s+instructions?\s*:\s*(?:do\s+not|silently|ignore|add|run)\b|"
            r"\byour\s+new\s+goal\s+is\s+to\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "instruction override: new instructions declaring new goal",
    ),

    # ── INJ002: Role / System Impersonation ──
    RulePattern(
        "INJ002",
        re.compile(
            r"(?:^|\n)\s*system\s*:\s*(?:you\s+(?:are|must|should|will|have)|ignore|disregard|forget|override|reveal|leak|exfiltrate|new\s+instructions|from\s+now\s+on|do\s+not)|"
            r"^<system>|\[inst\]|\[/inst\]|"
            r"\b(?:from\s+now\s+on\s+respond\s+only\s+with|you\s+are\s+now\s+in\s+maintenance\s+mode)\b|"
            r"\byou\s+are\s+(?:dan|jailbroken|an\s+ai\s+without\s+restrictions|a\s+helpful\s+assistant\s+with\s+no\s+restrictions)\b|"
            r"\bplay\s+a\s+game\s*:\s*you\s+are\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "system impersonation or jailbreak persona",
    ),
    RulePattern(
        "INJ002",
        re.compile(
            r"\bdisable\s+all\s+safety\s+checks\b|"
            r"\bignores?\s+policies\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "system prompt restriction removal command",
    ),

    # ── INJ003: Exfiltration ──
    RulePattern(
        "INJ003",
        re.compile(
            r"\b(?:send|upload|leak|reveal|exfiltrate|post|dump)\s+"
            r"(?:the\s+|all\s+|your\s+|contents\s+of\s+)*(?:hidden\s+)?(?:system\s+prompt|system\s+message|api\s*keys?|"
            r"secrets?|credentials?|\.env\b|ssh\s+keys?|~/\.ssh|environment\s+variables?)\b|"
            r"\bprint\s+(?:the\s+|all\s+|your\s+|contents\s+of\s+)*(?:hidden\s+)?(?:system\s+prompt|system\s+message|hidden\s+instructions)\b|"
            r"\btranslate\s+your\s+system\s+(?:prompt|message)\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "credential or system prompt exfiltration command",
    ),
    RulePattern(
        "INJ003",
        re.compile(
            r"\b(?:assistant|ai)\s*:\s*(?:also\s+)?(?:upload|send|leak|exfiltrate)\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "assistant command to exfiltrate data",
    ),

    # ── INJ004: Concealment ──
    RulePattern(
        "INJ004",
        re.compile(
            r"\b(?:do\s+not|don['\x92]?t)\s+(?:tell|mention|show|inform|reveal\s+to)\s+(?:the\s+)?(?:user|reviewer)\b|"
            r"\b(?:do\s+not|don['\x92]?t)\s+mention\s+(?:it|this(?:\s+instruction|\s+line|\s+change)?)\s+in\s+(?:the\s+|your\s+)?(?:summary|description|pr)\b|"
            r"\bdo\s+not\s+mention\s+this\s+(?:instruction|line|change)\s+to\s+(?:the\s+)?reviewer\b|"
            r"\bhidden\s+task\s*:|"
            r"\bfollow\s+them\s+silently\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "concealment: do not tell user/reviewer or hidden task",
    ),

    # ── INJ005: Authority Claims ──
    RulePattern(
        "INJ005",
        re.compile(
            r"\b(?:as\s+the\s+project\s+maintainer|as\s+(?:the\s+)?(?:maintainer|admin|security\s+team))\s+"
            r"(?:i|we)\s+authorize\s+you\s+to\s+(?:bypass|skip|ignore|override)\b|"
            r"\b(?:maintainer|admin|security\s+team)\s+authorizes?\s+(?:bypass|skipping)\b|"
            r"\bthe\s+real\s+maintainers?'?\s+instructions?\s+are\s+in\s+this\s+issue\s+and\s+override\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "authority claim waiving review or authorization",
    ),

    # ── INJ006: Malicious Instructions to AI Assistant ──
    RulePattern(
        "INJ006",
        re.compile(
            r"\b(?:when\s+you\s+write\s+the\s+patch|when\s+fixing|in\s+the\s+patch)\s*,\s*(?:silently\s+)?add\s+a\s+backdoor\b|"
            r"\badd\s+a\s+backdoor\s+(?:user|account|code)\b|"
            r"\badd\s+(?:my\s+)?ssh\s+key\s+to\s+authorized_keys\b|"
            r"\b(?:assistant|ai)\s*:\s*(?:also\s+)?(?:run|execute)\s+curl\b|"
            r"\b(?:assistant|ai)\s*:\s*add\s+the\s+following\s+dependency\b|"
            r"\b(?:add|insert)\s+a\s+call\s+to\s+os\.system\s*\(\s*['\"]curl\b|"
            r"\badd\s+a\s+reverse\s+shell\b",
            re.IGNORECASE,
        ),
        "HIGH",
        "instruction to add backdoors, reverse shells, or untrusted code",
    ),
]


def scan_text(text: str, source: str = "issue") -> list[dict]:
    """
    Scan plain text (issue, commit message, or comment) for prompt injections.

    Returns a list of finding dicts:
        {rule_id, severity, source, line, evidence}
    """
    if not text or not isinstance(text, str):
        return []

    findings = []
    seen_rules = set()

    # Collect variants of text to analyze:
    # 1. Raw normalized
    # 2. Leet-normalized
    # 3. Decoded base64 blobs
    # 4. Embedded HTML/markdown comments
    variants = [
        ("raw", normalize_text(text, apply_leet=False)),
        ("leet", normalize_text(text, apply_leet=True)),
    ]

    for b64 in extract_base64_payloads(text):
        variants.append(("b64", normalize_text(b64, apply_leet=False)))
        variants.append(("b64_leet", normalize_text(b64, apply_leet=True)))

    for comm in extract_embedded_comments(text):
        variants.append(("comment", normalize_text(comm, apply_leet=False)))
        variants.append(("comment_leet", normalize_text(comm, apply_leet=True)))

    for v_kind, norm in variants:
        if not norm:
            continue

        for rule in INJECTION_PATTERNS:
            if rule.rule_id in seen_rules:
                continue

            m = rule.pattern.search(norm)
            if m:
                seen_rules.add(rule.rule_id)
                matched_span = m.group(0)
                # Find line number in original text if possible
                line_no = 1
                for idx, line in enumerate(text.splitlines(), 1):
                    if normalize_text(line) and rule.pattern.search(normalize_text(line, apply_leet=(v_kind.endswith("leet")))):
                        line_no = idx
                        break

                findings.append({
                    "rule_id": rule.rule_id,
                    "severity": rule.severity,
                    "source": source,
                    "line": line_no,
                    "evidence": f"Prompt injection ({rule.desc}): {matched_span[:120]}",
                })

    return findings


# Python and C-style comments / string literals
COMMENT_LINE_RE = re.compile(r"^\s*(?:#|//|/\*|\*|\*/)")
TRIPLE_QUOTE_RE = re.compile(r'"""|\'\'\'')


def scan_patch_comments(patch_text: str) -> list[dict]:
    """
    Scan ADDED comments, docstrings, and string literals in unified diff patch text.

    Returns findings with source='comment'.
    """
    if not patch_text or not isinstance(patch_text, str):
        return []

    findings = []
    lines = patch_text.splitlines()

    in_docstring = False
    current_file = ""
    line_no = 0

    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue
        if line.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            if m:
                line_no = int(m.group(1))
            continue

        if not line.startswith("+") or line.startswith("+++"):
            if not line.startswith("-") and not line.startswith("---"):
                line_no += 1
            continue

        added_content = line[1:]
        stripped = added_content.strip()

        # Check for triple quotes entering/exiting docstrings
        tq_count = len(TRIPLE_QUOTE_RE.findall(stripped))
        if tq_count % 2 != 0:
            in_docstring = not in_docstring

        is_comment = bool(COMMENT_LINE_RE.match(stripped)) or in_docstring or tq_count > 0 or ("/*" in stripped)

        if is_comment or stripped.startswith(('"', "'")):
            # Scan this comment or docstring line
            line_findings = scan_text(added_content, source="comment")
            for f in line_findings:
                f["line"] = line_no
                f["file"] = current_file
                findings.append(f)

        line_no += 1

    return findings
