"""
src/diffsmith/safety/injection_ml.py -- Optional ML prompt-injection detector layer.

A secondary layer alongside the regex shield (injection.py).
The regex layer is frozen at ed903a5 and must not change.

Public interface:
    is_available() -> bool
    unavailable_reason() -> str | None
    scan_text_ml(text: str, source: str = "issue", threshold: float) -> list[dict]
    scan_patch_comments_ml(patch_text: str, threshold: float) -> list[dict]
    scan_text_all(text: str, source: str = "issue", use_ml: bool = False, threshold: float | None = None) -> list[dict]
    scan_patch_comments_all(patch_text: str, use_ml: bool = False, threshold: float | None = None) -> list[dict]
    extract_patch_comment_segments(patch_text: str) -> list[tuple[str, int, str]]
    score_text_with_chunking(text: str, ...) -> tuple[float, bool]

ML is OFF by default. Pass use_ml=True plus an explicit threshold to activate it.
Without an explicit threshold, combined helpers return a
"ML disabled: no calibrated threshold" status finding instead of ML findings.

Finding schema:
    {rule_id, severity, source, line, evidence, score, status}
    rule_id:  "INJ_ML001"
    severity: "MEDIUM" at most
    status:   "scanned", "partially scanned", or "ML NOT RUN: <reason>"
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
from typing import Any

from diffsmith.safety.injection import COMMENT_LINE_RE, TRIPLE_QUOTE_RE
from diffsmith.safety.injection import scan_patch_comments as _regex_scan_patch_comments
from diffsmith.safety.injection import scan_text as _regex_scan_text

# -- Model configuration and constants -----------------------------------------

MODEL_NAME = "ProtectAI/deberta-v3-base-prompt-injection-v2"
MODEL_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
EXPECTED_SAFETENSORS_SHA256 = (
    "6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424"
)

RULE_ID = "INJ_ML001"
SEVERITY = "MEDIUM"

MAX_WINDOW_TOKENS = 400
WINDOW_OVERLAP_LINES = 1
MAX_CHUNKS_CAP = 50  # Cap pathological inputs to avoid unbounded runtime

# DEFAULT_THRESHOLD: No calibrated threshold was found during calibration.
# Calibration on 300 real issues and 5,123 real patches found no candidate that
# achieved 0 flags on both sets (see results/injection_ml_calibration.md).
# Set to None to signal "no calibrated threshold"; callers must pass an explicit
# threshold to scan_text_ml / scan_patch_comments_ml.  Combined helpers
# (scan_text_all, scan_patch_comments_all) require use_ml=True plus an explicit
# threshold; without an explicit threshold they return a
# "ML disabled: no calibrated threshold" status finding.
DEFAULT_THRESHOLD: float | None = None

# -- Lazy process-level cache --------------------------------------------------

_model_cache: dict[str, Any] = {
    "checked": False,
    "available": False,
    "reason": None,
    "tokenizer": None,
    "model": None,
    "inj_idx": None,
}


def _get_snapshot_dir() -> pathlib.Path:
    """Return the local snapshot directory for the pinned model revision."""
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        base = pathlib.Path(hf_home)
    else:
        profile = os.environ.get("USERPROFILE") or os.environ.get("HOME") or ""
        base = pathlib.Path(profile) / ".cache" / "huggingface"
    folder_name = f"models--{MODEL_NAME.replace('/', '--')}"
    return base / "hub" / folder_name / "snapshots" / MODEL_REVISION


def _verify_and_load() -> tuple[bool, str | None, Any, Any, int | None]:
    """
    Verify environment, local cache, and weights integrity once per process.
    Never downloads unless DIFFSMITH_ALLOW_MODEL_DOWNLOAD=1 is explicitly set.
    """
    if _model_cache["checked"]:
        return (
            _model_cache["available"],
            _model_cache["reason"],
            _model_cache["tokenizer"],
            _model_cache["model"],
            _model_cache["inj_idx"],
        )

    _model_cache["checked"] = True

    # 1. Check optional dependencies lazily
    try:
        import torch  # noqa: F401
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as err:
        reason = f"ML dependencies missing: {err}. Install diffsmith[ml]."
        _model_cache.update({"available": False, "reason": reason})
        return False, reason, None, None, None

    # 2. Check offline cache
    allow_download = os.environ.get("DIFFSMITH_ALLOW_MODEL_DOWNLOAD", "0") == "1"
    snapshot_dir = _get_snapshot_dir()
    safetensors_file = snapshot_dir / "model.safetensors"

    if not safetensors_file.exists():
        if not allow_download:
            reason = (
                f"Model not cached at {snapshot_dir} and DIFFSMITH_ALLOW_MODEL_DOWNLOAD!=1"
            )
            _model_cache.update({"available": False, "reason": reason})
            return False, reason, None, None, None

    # 3. Verify SHA-256 hash of model.safetensors if file exists
    if safetensors_file.exists():
        try:
            h = hashlib.sha256()
            with open(safetensors_file, "rb") as f:
                while chunk := f.read(1024 * 1024):
                    h.update(chunk)
            digest = h.hexdigest()
            if digest != EXPECTED_SAFETENSORS_SHA256:
                reason = (
                    f"model.safetensors SHA256 mismatch: expected {EXPECTED_SAFETENSORS_SHA256}, "
                    f"got {digest}"
                )
                _model_cache.update({"available": False, "reason": reason})
                return False, reason, None, None, None
        except Exception as exc:  # noqa: BLE001
            reason = f"Failed to verify model hash: {exc}"
            _model_cache.update({"available": False, "reason": reason})
            return False, reason, None, None, None

    # 4. Load tokenizer and model
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            str(snapshot_dir) if snapshot_dir.exists() else MODEL_NAME,
            revision=MODEL_REVISION,
            local_files_only=not allow_download,
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            str(snapshot_dir) if snapshot_dir.exists() else MODEL_NAME,
            revision=MODEL_REVISION,
            local_files_only=not allow_download,
            use_safetensors=True,
            trust_remote_code=False,
        )
        model.eval()

        id2label = model.config.id2label
        inj_idx = None
        for idx, lbl in id2label.items():
            if "INJECTION" in str(lbl).upper():
                inj_idx = int(idx)
                break
        if inj_idx is None:
            reason = f"INJECTION label not found in model id2label: {id2label}"
            _model_cache.update({"available": False, "reason": reason})
            return False, reason, None, None, None

        _model_cache.update({
            "available": True,
            "reason": None,
            "tokenizer": tokenizer,
            "model": model,
            "inj_idx": inj_idx,
        })
        return True, None, tokenizer, model, inj_idx

    except Exception as exc:  # noqa: BLE001
        reason = f"Failed to load model: {exc}"
        _model_cache.update({"available": False, "reason": reason})
        return False, reason, None, None, None


def is_available() -> bool:
    """Return True if the ML model is loaded and available for inference."""
    avail, _, _, _, _ = _verify_and_load()
    return avail


def unavailable_reason() -> str | None:
    """Return the reason why the ML model is unavailable, or None if available."""
    _, reason, _, _, _ = _verify_and_load()
    return reason


# -- Text windowing and token chunking -----------------------------------------

def _chunk_lines(
    lines: list[str],
    tokenizer: Any,
    max_tokens: int = MAX_WINDOW_TOKENS,
    overlap_lines: int = WINDOW_OVERLAP_LINES,
    max_chunks: int = MAX_CHUNKS_CAP,
) -> tuple[list[tuple[int, list[str]]], bool]:
    """
    Split lines into overlapping token windows under max_tokens.
    Returns (chunks, is_partially_scanned).
    Each chunk is (start_line_index_0_based, list_of_lines).
    """
    if not lines:
        return [], False

    chunks: list[tuple[int, list[str]]] = []
    i = 0
    n = len(lines)
    partially_scanned = False

    while i < n:
        if len(chunks) >= max_chunks:
            partially_scanned = True
            break

        current_chunk: list[str] = []
        token_count = 0
        j = i
        while j < n:
            line_str = lines[j]
            t_count = len(tokenizer.encode(line_str, add_special_tokens=False)) + 1
            if current_chunk and (token_count + t_count > max_tokens):
                break
            current_chunk.append(line_str)
            token_count += t_count
            j += 1

        if not current_chunk:
            current_chunk = [lines[i]]
            j = i + 1

        chunks.append((i, current_chunk))
        advance = max(1, len(current_chunk) - overlap_lines)
        i += advance

    return chunks, partially_scanned


def _score_texts(texts: list[str], tokenizer: Any, model: Any, inj_idx: int) -> list[float]:
    """Run model inference on a batch of texts and return injection probabilities."""
    if not texts:
        return []

    import torch
    import torch.nn.functional as F

    inputs = tokenizer(
        texts,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=512,
    )
    with torch.inference_mode():
        outputs = model(**inputs)
        probs = F.softmax(outputs.logits, dim=-1)
        scores = probs[:, inj_idx].tolist()
    return scores


def score_text_with_chunking(
    text: str,
    tokenizer: Any,
    model: Any,
    inj_idx: int,
    max_tokens: int = MAX_WINDOW_TOKENS,
    max_chunks: int = MAX_CHUNKS_CAP,
) -> tuple[float, bool]:
    """
    Score text through the chunked window path. Never truncates silently.
    Returns (max_score, is_partially_scanned).
    """
    if not text:
        return 0.0, False

    lines = text.splitlines()
    if not lines:
        lines = [text]

    chunks, partially_scanned = _chunk_lines(
        lines, tokenizer, max_tokens=max_tokens, max_chunks=max_chunks
    )
    if not chunks:
        return 0.0, False

    chunk_texts = ["\n".join(cl) for _, cl in chunks]
    chunk_scores = _score_texts(chunk_texts, tokenizer, model, inj_idx)
    max_score = max(chunk_scores) if chunk_scores else 0.0
    return max_score, partially_scanned


# -- Comment and Docstring Extraction (Parity with injection.py) ---------------

def extract_patch_comment_segments(patch_text: str) -> list[tuple[str, int, str]]:
    """
    Extract added comments, docstrings, and string literals from a patch diff.
    Reuses COMMENT_LINE_RE and TRIPLE_QUOTE_RE from injection.py, mirroring
    scan_patch_comments (lines 355-406) exactly.
    Returns list of (file_path, line_no, added_content).
    """
    if not patch_text or not isinstance(patch_text, str):
        return []

    segments: list[tuple[str, int, str]] = []
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

        is_comment = (
            bool(COMMENT_LINE_RE.match(stripped))
            or in_docstring
            or tq_count > 0
            or ("/*" in stripped)
        )

        if is_comment or stripped.startswith(('"', "'")):
            segments.append((current_file, line_no, added_content))

        line_no += 1

    return segments


# -- Public ML Scanning APIs ---------------------------------------------------

_SENTINEL = object()  # distinguishes "not passed" from any float value


def scan_text_ml(
    text: str,
    source: str = "issue",
    threshold: float = _SENTINEL,  # type: ignore[assignment]
) -> list[dict]:
    """
    Scan plain text for prompt injection using the ML classifier.
    Returns findings with rule_id='INJ_ML001', severity='MEDIUM'.
    If the ML layer cannot run, returns an explicit 'ML NOT RUN: <reason>' finding.

    threshold must be passed explicitly; there is no calibrated default.
    """
    if threshold is _SENTINEL:
        raise TypeError(
            "scan_text_ml() requires an explicit 'threshold' argument. "
            "No calibrated default exists; see results/injection_ml_calibration.md."
        )

    available, reason, tokenizer, model, inj_idx = _verify_and_load()
    if not available:
        return [{
            "rule_id": RULE_ID,
            "severity": SEVERITY,
            "source": source,
            "line": 1,
            "evidence": f"ML NOT RUN: {reason}",
            "score": 0.0,
            "status": f"ML NOT RUN: {reason}",
        }]

    if not text or not isinstance(text, str):
        return []

    lines = text.splitlines()
    if not lines:
        return []

    chunks, partially_scanned = _chunk_lines(lines, tokenizer)
    if not chunks:
        return []

    chunk_texts = ["\n".join(chunk_lines) for _, chunk_lines in chunks]
    chunk_scores = _score_texts(chunk_texts, tokenizer, model, inj_idx)

    findings: list[dict] = []
    status_str = "partially scanned" if partially_scanned else "scanned"

    for (start_line_idx, chunk_lines), chunk_score in zip(chunks, chunk_scores):
        if chunk_score >= threshold:
            # Re-score individual lines to localize
            if len(chunk_lines) == 1:
                best_rel_idx = 0
                best_line_score = chunk_score
            else:
                line_scores = _score_texts(chunk_lines, tokenizer, model, inj_idx)
                best_rel_idx = max(range(len(line_scores)), key=lambda idx: line_scores[idx])
                best_line_score = line_scores[best_rel_idx]

            abs_line_no = start_line_idx + best_rel_idx + 1
            evidence_line = chunk_lines[best_rel_idx].strip()[:200]

            findings.append({
                "rule_id": RULE_ID,
                "severity": SEVERITY,
                "source": source,
                "line": abs_line_no,
                "evidence": f"ML injection detector (score={best_line_score:.4f}): {evidence_line}",
                "score": round(best_line_score, 6),
                "status": status_str,
            })

    return findings


def scan_patch_comments_ml(
    patch_text: str,
    threshold: float = _SENTINEL,  # type: ignore[assignment]
) -> list[dict]:
    """
    Scan added comments, docstrings, and strings in a patch for prompt injection.
    Returns findings with rule_id='INJ_ML001', severity='MEDIUM'.
    If the ML layer cannot run, returns an explicit 'ML NOT RUN: <reason>' finding.

    threshold must be passed explicitly; there is no calibrated default.
    """
    if threshold is _SENTINEL:
        raise TypeError(
            "scan_patch_comments_ml() requires an explicit 'threshold' argument. "
            "No calibrated default exists; see results/injection_ml_calibration.md."
        )

    available, reason, tokenizer, model, inj_idx = _verify_and_load()
    if not available:
        return [{
            "rule_id": RULE_ID,
            "severity": SEVERITY,
            "source": "comment",
            "line": 1,
            "evidence": f"ML NOT RUN: {reason}",
            "score": 0.0,
            "status": f"ML NOT RUN: {reason}",
        }]

    if not patch_text or not isinstance(patch_text, str):
        return []

    segments = extract_patch_comment_segments(patch_text)
    if not segments:
        return []

    findings: list[dict] = []
    short_batch: list[tuple[str, int, str]] = []

    for file_path, line_no, content in segments:
        t_len = len(tokenizer.encode(content, add_special_tokens=False))
        if t_len > MAX_WINDOW_TOKENS:
            # Long segment: score with chunking to avoid silent truncation
            sc, partially_scanned = score_text_with_chunking(content, tokenizer, model, inj_idx)
            if sc >= threshold:
                evidence_line = content.strip()[:200]
                status_str = "partially scanned" if partially_scanned else "scanned"
                findings.append({
                    "rule_id": RULE_ID,
                    "severity": SEVERITY,
                    "source": "comment",
                    "file": file_path,
                    "line": line_no,
                    "evidence": f"ML injection detector (score={sc:.4f}): {evidence_line}",
                    "score": round(sc, 6),
                    "status": status_str,
                })
        else:
            short_batch.append((file_path, line_no, content))

    # Batch score short segments in groups of 16
    batch_size = 16
    for i in range(0, len(short_batch), batch_size):
        batch = short_batch[i : i + batch_size]
        texts = [content for _, _, content in batch]
        scores = _score_texts(texts, tokenizer, model, inj_idx)

        for (file_path, line_no, content), score in zip(batch, scores):
            if score >= threshold:
                evidence_line = content.strip()[:200]
                findings.append({
                    "rule_id": RULE_ID,
                    "severity": SEVERITY,
                    "source": "comment",
                    "file": file_path,
                    "line": line_no,
                    "evidence": f"ML injection detector (score={score:.4f}): {evidence_line}",
                    "score": round(score, 6),
                    "status": "scanned",
                })

    return findings


# -- Combined Regex + ML Helpers -----------------------------------------------

_ML_DISABLED_FINDING_TEXT = "ML disabled: no calibrated threshold"
_ML_DISABLED_STATUS = "ML disabled: no calibrated threshold"


def scan_text_all(
    text: str,
    source: str = "issue",
    use_ml: bool = False,
    threshold: float | None = None,
) -> list[dict]:
    """
    Run regex shield first; optionally add ML detector.

    ML is OFF by default (use_ml=False). To enable ML, pass use_ml=True and an
    explicit threshold.  If use_ml=True but threshold is None (no calibrated
    threshold exists), returns regex findings plus a single "ML disabled: no
    calibrated threshold" status finding instead of ML findings.

    When ML is active it only adds findings; lines already flagged by regex are
    deduplicated.
    """
    regex_findings = _regex_scan_text(text, source)

    if not use_ml:
        return regex_findings

    if threshold is None:
        return regex_findings + [{
            "rule_id": RULE_ID,
            "severity": SEVERITY,
            "source": source,
            "line": 1,
            "evidence": _ML_DISABLED_FINDING_TEXT,
            "score": 0.0,
            "status": _ML_DISABLED_STATUS,
        }]

    ml_findings = scan_text_ml(text, source, threshold=threshold)
    regex_lines = {f.get("line") for f in regex_findings}
    deduped_ml = [
        f for f in ml_findings
        if f.get("status", "").startswith("ML NOT RUN:") or f.get("line") not in regex_lines
    ]
    return regex_findings + deduped_ml


def scan_patch_comments_all(
    patch_text: str,
    use_ml: bool = False,
    threshold: float | None = None,
) -> list[dict]:
    """
    Run regex patch scanner first; optionally add ML patch comments detector.

    ML is OFF by default (use_ml=False). To enable ML, pass use_ml=True and an
    explicit threshold.  If use_ml=True but threshold is None (no calibrated
    threshold exists), returns regex findings plus a single "ML disabled: no
    calibrated threshold" status finding.

    When ML is active it only adds findings; (file, line) pairs already flagged
    by regex are deduplicated.
    """
    regex_findings = _regex_scan_patch_comments(patch_text)

    if not use_ml:
        return regex_findings

    if threshold is None:
        return regex_findings + [{
            "rule_id": RULE_ID,
            "severity": SEVERITY,
            "source": "comment",
            "line": 1,
            "evidence": _ML_DISABLED_FINDING_TEXT,
            "score": 0.0,
            "status": _ML_DISABLED_STATUS,
        }]

    ml_findings = scan_patch_comments_ml(patch_text, threshold=threshold)
    regex_keys = {(f.get("file"), f.get("line")) for f in regex_findings}
    deduped_ml = [
        f for f in ml_findings
        if f.get("status", "").startswith("ML NOT RUN:")
        or (f.get("file"), f.get("line")) not in regex_keys
    ]
    return regex_findings + deduped_ml


