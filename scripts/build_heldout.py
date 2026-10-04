"""Build a REAL labeled held-out set from public SWE-bench Lite submissions.

Verified layout (swe-bench/experiments):
  - GitHub:  evaluation/lite/<submission>/results/results.json
             keys include "resolved" and "generated" (lists of instance_ids)
  - Patches are NOT on GitHub. They are in the public S3 bucket
    swe-bench-submissions (verified by bucket listing):
             lite/<submission>/all_preds.jsonl

Free, stdlib only. Run from the repo root:
    python scripts/build_heldout.py --n 12
    python scripts/build_heldout.py --subs 20231010_rag_claude2 20240402_sweagent_gpt4
"""
import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

API = "https://api.github.com/repos/swe-bench/experiments/contents/evaluation/lite"
RAW = "https://raw.githubusercontent.com/swe-bench/experiments/main/evaluation/lite"
S3 = "https://swe-bench-submissions.s3.amazonaws.com/lite"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def fetch(url, retries=2):
    """Return (text or None, status). status is an int HTTP code or 'ERR'."""
    status = "ERR"
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "diffsmith-heldout"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read().decode("utf-8", errors="replace"), r.status
        except urllib.error.HTTPError as e:
            status = e.code
            if e.code in (403, 404):
                return None, status
        except Exception:
            status = "ERR"
        time.sleep(1.5 * (attempt + 1))
    return None, status


def parse_preds(text):
    """Return {instance_id: patch}. Handles jsonl, or one JSON dict/list."""
    out = {}

    def add(rec, key=None):
        if isinstance(rec, dict):
            iid = rec.get("instance_id") or key
            patch = rec.get("model_patch") or rec.get("patch") or ""
            if iid:
                out[iid] = patch

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for k, v in data.items():
                add(v, key=k)
        elif isinstance(data, list):
            for rec in data:
                add(rec)
        return out
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                add(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def list_submissions():
    text, status = fetch(API)
    if text is None:
        sys.exit(f"ERROR: GitHub API listing failed (status {status}). Unauthenticated "
                 "limit is 60/hour; wait, or pass folder names with --subs.")
    return sorted(i["name"] for i in json.loads(text) if i.get("type") == "dir")


def pick_spread(names, n):
    if n >= len(names):
        return names
    step = (len(names) - 1) / (n - 1) if n > 1 else 0
    return [names[round(i * step)] for i in range(n)]


def load_split_map():
    def ids(x):
        if isinstance(x, dict):
            for k in ("instance_ids", "ids", "instances"):
                if k in x:
                    return ids(x[k])
            return list(x.keys())
        return [i["instance_id"] if isinstance(i, dict) else i for i in x]
    mapping = {}
    for name in ("train", "val", "test"):
        path = os.path.join(ROOT, "data", "splits", f"{name}.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for iid in ids(json.load(f)):
                    mapping[iid] = name
    return mapping


def repo_of(iid):
    return iid.rsplit("-", 1)[0].replace("__", "/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--subs", nargs="*")
    args = ap.parse_args()

    chosen = args.subs or pick_spread(list_submissions(), args.n)
    split_map = load_split_map()
    rows, manifest, skipped, empty = [], [], [], 0

    for sub in chosen:
        res_text, st = fetch(f"{RAW}/{sub}/results/results.json")
        if not res_text:
            skipped.append((sub, f"results.json unavailable (status {st})"))
            continue
        res = json.loads(res_text)
        if not isinstance(res.get("resolved"), list):
            skipped.append((sub, f"no 'resolved' list in results.json "
                                 f"(keys: {sorted(res)[:8]})"))
            continue
        resolved = set(res["resolved"])
        applied = set(res["applied"]) if isinstance(res.get("applied"), list) else None

        pred_text, st = fetch(f"{S3}/{sub}/all_preds.jsonl")
        if pred_text is None:
            pred_text, st = fetch(f"{S3}/{sub}/preds.json")
        if pred_text is None:
            skipped.append((sub, f"predictions file not reachable (status {st})"))
            continue
        preds = parse_preds(pred_text)
        if not preds:
            skipped.append((sub, "predictions file parsed to zero patches"))
            continue
        got = list(preds.items())
        kept = n_res = 0
        for iid, patch in got:
            if not patch or not patch.strip():
                empty += 1
                continue
            label = 1 if iid in resolved else 0
            rows.append({"submission": sub, "instance_id": iid, "repo": repo_of(iid),
                         "split": split_map.get(iid, "unknown"), "patch": patch,
                         "resolved": label, "source": "real_agent",
                         "applied": "" if applied is None else int(iid in applied)})
            kept += 1
            n_res += label
        manifest.append({"submission": sub, "patches": kept, "resolved": n_res,
                         "resolve_rate": round(n_res / kept, 3) if kept else 0})
        print(f"  {sub}: {kept} patches, {n_res} resolved ({manifest[-1]['resolve_rate']:.1%})")

    for s, why in skipped:
        print(f"  SKIPPED {s}: {why}")
    if not rows:
        sys.exit("ERROR: no rows built. Paste the output above.")

    out = os.path.join(ROOT, "data", "heldout")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "heldout.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"submissions": manifest, "skipped": skipped,
                   "excluded_empty_patches": empty}, f, indent=2)

    pos = sum(r["resolved"] for r in rows)
    print("\n=== SUMMARY ===")
    print(f"submissions used: {len(manifest)}  skipped: {len(skipped)}")
    print(f"total labeled patches: {len(rows)}  (excluded empty: {empty})")
    print(f"resolved: {pos}  unresolved: {len(rows) - pos}  positive rate: {pos/len(rows):.1%}")
    known = [r for r in rows if r["applied"] != ""]
    if known:
        a = [r for r in known if r["applied"] == 1]
        print(f"rows with applied info: {len(known)}  applied cleanly: {len(a)}  "
              f"applied-but-failed: {sum(1 for r in a if r['resolved'] == 0)}  "
              f"resolved: {sum(r['resolved'] for r in a)}")
        print(f"rows WITHOUT applied info: {len(rows) - len(known)}")
    print("rows per split:", dict(Counter(r["split"] for r in rows)))
    print("rows per repo:", dict(Counter(r["repo"] for r in rows)))


if __name__ == "__main__":
    main()
