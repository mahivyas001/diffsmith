"""
scripts/calibrate_injection_ml.py -- Threshold calibration for ML injection detector.

Uses ONLY data already in the repository:
  1. 300 distinct real SWE-bench issue texts (deduplicated).
  2. Added comment/docstring/string lines from the 5,123 real patches (deduplicated).

NO Set B content. Labelled 'calibrated, NOT held-out'.
Resumable score cache in results/injection_ml_cache.json (gitignored).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from diffsmith.safety.injection_ml import (
    MODEL_NAME,
    MODEL_REVISION,
    extract_patch_comment_segments,
    is_available,
    scan_text_ml,
    score_text_with_chunking,
    unavailable_reason,
)
from scripts.baselines import load_and_prepare_data

CACHE_FILE = os.path.join(
    os.path.dirname(__file__), "../results/injection_ml_cache.json"
)


def load_cache() -> dict[str, float]:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(cache: dict[str, float]) -> None:
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f)


def cache_key(text: str) -> str:
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"{h}:{MODEL_REVISION}"


def main() -> None:
    t_start = time.time()
    print("=== Diffsmith ML Injection Threshold Calibration ===")

    t_load_0 = time.time()
    avail = is_available()
    t_load = time.time() - t_load_0

    if not avail:
        print(f"ERROR: ML layer unavailable: {unavailable_reason()}")
        sys.exit(1)

    print(f"Model loaded and verified in {t_load:.2f}s")

    from diffsmith.safety.injection_ml import _model_cache, _score_texts

    tokenizer = _model_cache["tokenizer"]
    model = _model_cache["model"]
    inj_idx = _model_cache["inj_idx"]

    cache = load_cache()
    print(f"Loaded {len(cache)} existing cached scores from {CACHE_FILE}")

    # -- 1. Real SWE-bench Issue Texts (300 distinct) --------------------------
    print("\n[1/2] Scoring 300 distinct SWE-bench issue texts...")
    df = load_and_prepare_data().drop_duplicates("instance_id")
    unique_issues = [
        (str(row["instance_id"]), str(row.get("problem_statement", "")))
        for _, row in df.iterrows()
    ]
    n_unique_issues = len(unique_issues)
    print(f"Unique issue problem statements: {n_unique_issues}")

    t_issues_0 = time.time()
    issue_scores: list[tuple[str, float, str]] = []

    for idx, (iid, text) in enumerate(unique_issues, 1):
        ck = cache_key(text)
        if ck in cache:
            score = cache[ck]
            evidence = "(from cache)"
        else:
            findings = scan_text_ml(text, source="issue", threshold=0.0)
            if findings:
                best_f = max(findings, key=lambda f: f.get("score", 0.0))
                score = float(best_f.get("score", 0.0))
                evidence = str(best_f.get("evidence", ""))
            else:
                score = 0.0
                evidence = ""
            cache[ck] = score

        issue_scores.append((iid, score, evidence))

        if idx % 50 == 0 or idx == n_unique_issues:
            elapsed = time.time() - t_issues_0
            print(f"  Scored {idx}/{n_unique_issues} issues (elapsed: {elapsed:.1f}s)...")

    save_cache(cache)
    t_issues = time.time() - t_issues_0
    issue_scores.sort(key=lambda x: -x[1])
    max_issue_score = issue_scores[0][1] if issue_scores else 0.0
    print(f"Issues scoring completed in {t_issues:.2f}s. Max score: {max_issue_score:.6f}")

    # -- 2. Real Patch Added Comments/Docstrings (5,123 patches) ----------------
    print("\n[2/2] Extracting and scoring comments/docstrings from 5,123 real patches...")
    df_full = load_and_prepare_data()
    all_patch_segments: list[tuple[int, str, int, str]] = []

    for p_idx, (_, row) in enumerate(df_full.iterrows()):
        patch_text = str(row.get("patch", ""))
        if not patch_text.strip():
            continue
        segs = extract_patch_comment_segments(patch_text)
        for f, ln, c in segs:
            all_patch_segments.append((p_idx, f, ln, c))

    total_comment_segments = len(all_patch_segments)
    unique_comment_strings = list({c.strip() for _, _, _, c in all_patch_segments if c.strip()})
    print(f"Total extracted comment segments: {total_comment_segments}")
    print(f"Unique comment strings to score: {len(unique_comment_strings)}")

    # Check token lengths and count strings exceeding 512 tokens
    long_strings: list[str] = []
    short_strings_with_len: list[tuple[int, str]] = []

    for s in unique_comment_strings:
        t_len = len(tokenizer.encode(s, add_special_tokens=False))
        if t_len > 512:
            long_strings.append(s)
        else:
            short_strings_with_len.append((t_len, s))

    count_over_512 = len(long_strings)
    print(f"Unique strings exceeding 512 tokens: {count_over_512}")

    # Sort short strings by token length for efficient batching with padding
    short_strings_with_len.sort(key=lambda x: x[0])
    sorted_short_strings = [s for _, s in short_strings_with_len]

    t_patches_0 = time.time()
    batch_size = 16

    # Score long strings via chunked path
    print(f"Scoring {len(long_strings)} long strings (>512 tokens) via chunked path...")
    for idx, s in enumerate(long_strings, 1):
        ck = cache_key(s)
        if ck not in cache:
            sc, _ = score_text_with_chunking(s, tokenizer, model, inj_idx)
            cache[ck] = float(sc)
        if idx % 10 == 0 or idx == len(long_strings):
            elapsed = time.time() - t_patches_0
            print(f"  Long strings: {idx}/{len(long_strings)} (elapsed: {elapsed:.1f}s)...")

    # Score short strings in batches of 16
    uncached_short = [s for s in sorted_short_strings if cache_key(s) not in cache]
    print(f"Short strings to evaluate (uncached): {len(uncached_short)} (total short: {len(sorted_short_strings)})")

    for i in range(0, len(uncached_short), batch_size):
        batch = uncached_short[i : i + batch_size]
        scores = _score_texts(batch, tokenizer, model, inj_idx)
        for s_text, s_val in zip(batch, scores):
            cache[cache_key(s_text)] = float(s_val)

        processed = min(i + batch_size, len(uncached_short))
        if processed % 200 == 0 or processed == len(uncached_short):
            elapsed = time.time() - t_patches_0
            print(f"  Short strings progress: {processed}/{len(uncached_short)} (elapsed: {elapsed:.1f}s)...")
            save_cache(cache)

    save_cache(cache)
    t_patches = time.time() - t_patches_0

    # Map scores back to patches
    patch_max_scores: dict[int, tuple[float, str, str, int]] = {}
    for p_idx, f, ln, c in all_patch_segments:
        ck = cache_key(c.strip())
        sc = cache.get(ck, 0.0)
        if p_idx not in patch_max_scores or sc > patch_max_scores[p_idx][0]:
            patch_max_scores[p_idx] = (sc, f, c.strip(), ln)

    patch_scores_list = sorted(patch_max_scores.values(), key=lambda x: -x[0])
    max_patch_score = patch_scores_list[0][0] if patch_scores_list else 0.0
    print(f"Patch comments scoring completed in {t_patches:.2f}s. Max score: {max_patch_score:.6f}")

    # -- 5. Threshold Selection Rule -------------------------------------------
    candidate_thresholds = [0.50, 0.70, 0.80, 0.90, 0.95, 0.99, 0.999, 0.9999, 0.99999]

    # The new rule, fixed before seeing any results:
    # Among candidate_thresholds, choose the LOWEST threshold with 0 flags on the 300 real issues
    # AND 0 flagged patches among the 5,123 real patches.
    # If no candidate satisfies both, do NOT invent a threshold and do NOT use max_issue_score + 0.0001.
    chosen_threshold = None
    for thr in candidate_thresholds:
        issue_flags = sum(1 for _, sc, _ in issue_scores if sc >= thr)
        patch_flags = sum(1 for sc, _, _, _ in patch_scores_list if sc >= thr)
        if issue_flags == 0 and patch_flags == 0:
            chosen_threshold = thr
            break

    total_time = time.time() - t_start

    # Build Markdown Report (calibrated, NOT held-out; NO Set B content)
    lines: list[str] = [
        "# ML Injection Shield Threshold Calibration Report",
        "",
        "> **Notice:** This threshold was calibrated on repository development data, **NOT held-out data**.",
        "> Labelled: calibrated, NOT held-out.",
        "",
        f"- **Model**: `{MODEL_NAME}` (revision `{MODEL_REVISION}`)",
        f"- **Model load and verification time**: {t_load:.2f}s",
        f"- **Total calibration runtime**: {total_time:.2f}s",
        f"- **Unique issue texts scored**: {n_unique_issues}",
        f"- **Total comment segments extracted**: {total_comment_segments}",
        f"- **Unique comment strings scored**: {len(unique_comment_strings)}",
        f"- **Unique strings exceeding 512 tokens**: {count_over_512}",
    ]

    if chosen_threshold is not None:
        lines.append(f"- **Chosen default threshold**: `{chosen_threshold}`")
    else:
        lines.append("- **Chosen default threshold**: `None` (STOP: no candidate threshold achieved 0 flags on both issues and patches)")

    lines.extend([
        "",
        "## 1. Threshold Trade-Off Analysis",
        "",
        "| Threshold | Issue Flags (n=300) | Patch Flags (n=5,123) |",
        "|---|---|---|",
    ])

    for thr in candidate_thresholds:
        iss_fa = sum(1 for _, sc, _ in issue_scores if sc >= thr)
        patch_fa = sum(1 for sc, _, _, _ in patch_scores_list if sc >= thr)
        lines.append(f"| {thr:.5f} | {iss_fa} | {patch_fa} |")

    lines.extend([
        "",
        "## 2. Real SWE-bench Issues (300 distinct instances)",
        "",
        f"- **Maximum score across all 300 real issues**: `{max_issue_score:.6f}`",
        f"- **Number of issues flagged at 0.50**: {sum(1 for _, sc, _ in issue_scores if sc >= 0.50)}",
        f"- **Number of issues flagged at 0.90**: {sum(1 for _, sc, _ in issue_scores if sc >= 0.90)}",
        f"- **Number of issues flagged at 0.99**: {sum(1 for _, sc, _ in issue_scores if sc >= 0.99)}",
    ])

    if chosen_threshold is not None:
        lines.append(f"- **Number of issues flagged at {chosen_threshold}**: {sum(1 for _, sc, _ in issue_scores if sc >= chosen_threshold)}")

    lines.extend([
        "",
        "### Top 5 Highest-Scoring Real Issues",
        "",
        "| Rank | Instance ID | Max Score | Evidence Line |",
        "|---|---|---|---|",
    ])

    for rank, (iid, sc, ev) in enumerate(issue_scores[:5], 1):
        clean_ev = ev.replace("|", "\\|")[:120]
        lines.append(f"| {rank} | `{iid}` | `{sc:.6f}` | `{clean_ev}` |")

    lines.extend([
        "",
        "## 3. Real SWE-bench Patches (5,123 patches)",
        "",
        f"- **Maximum score across all patch comments**: `{max_patch_score:.6f}`",
        f"- **Number of patches flagged at 0.50**: {sum(1 for sc, _, _, _ in patch_scores_list if sc >= 0.50)}",
        f"- **Number of patches flagged at 0.90**: {sum(1 for sc, _, _, _ in patch_scores_list if sc >= 0.90)}",
        f"- **Number of patches flagged at 0.99**: {sum(1 for sc, _, _, _ in patch_scores_list if sc >= 0.99)}",
    ])

    if chosen_threshold is not None:
        lines.append(f"- **Number of patches flagged at {chosen_threshold}**: {sum(1 for sc, _, _, _ in patch_scores_list if sc >= chosen_threshold)}")

    lines.extend([
        "",
        "### Top 5 Highest-Scoring Patch Comment Segments",
        "",
        "| Rank | File | Line | Max Score | Comment Text Snippet |",
        "|---|---|---|---|---|",
    ])

    for rank, (sc, fpath, ctext, lno) in enumerate(patch_scores_list[:5], 1):
        clean_ctext = ctext.replace("|", "\\|")[:100]
        lines.append(f"| {rank} | `{fpath}` | {lno} | `{sc:.6f}` | `{clean_ctext}` |")

    lines.extend([
        "",
        "## 4. Threshold Selection Rule Code",
        "",
        "```python",
        "candidate_thresholds = [0.50, 0.70, 0.80, 0.90, 0.95, 0.99, 0.999, 0.9999, 0.99999]",
        "",
        "chosen_threshold = None",
        "for thr in candidate_thresholds:",
        "    issue_flags = sum(1 for _, sc, _ in issue_scores if sc >= thr)",
        "    patch_flags = sum(1 for sc, _, _, _ in patch_scores_list if sc >= thr)",
        "    if issue_flags == 0 and patch_flags == 0:",
        "        chosen_threshold = thr",
        "        break",
        "```",
        "",
        "## 5. Outcome",
        "",
    ])

    if chosen_threshold is not None:
        lines.append(f"Chosen threshold: `{chosen_threshold}` (0 flags on 300 issues, 0 flags on 5,123 patches).")
    else:
        lines.append("No candidate threshold achieved 0 flags on both 300 issues and 5,123 patches. Stopped for review.")

    md_content = "\n".join(lines) + "\n"

    out_file = os.path.join(os.path.dirname(__file__), "../results/injection_ml_calibration.md")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"\nCalibration report written to {out_file}")
    print("\n--- Calibration Summary ---")
    print(f"Max score on 300 real issues: {max_issue_score:.6f}")
    print(f"Max score on 5,123 patch comments: {max_patch_score:.6f}")
    print(f"Count of unique strings over 512 tokens: {count_over_512}")
    if chosen_threshold is not None:
        print(f"Chosen default threshold: {chosen_threshold}")
    else:
        print("STOP: No candidate threshold achieved 0 flags on both issues and patches.")
    print(f"Total calibration time: {total_time:.1f}s")


if __name__ == "__main__":
    main()
