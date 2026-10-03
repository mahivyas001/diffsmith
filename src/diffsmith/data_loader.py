# data_loader.py — Responsible for loading and preprocessing code patch datasets.

import os
import re
import json
import random
import pandas as pd
from datasets import load_dataset

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
DATASET_NAME = "princeton-nlp/SWE-bench_Lite"
OUTPUT_DIR   = os.path.join(os.path.dirname(__file__), "..", "..", "data", "processed")
OUTPUT_FILE  = os.path.join(OUTPUT_DIR, "training_data.csv")

# Probability thresholds for corruption strategies
MAGIC_NUMBER_PROB   = 0.5   # 50 % chance to apply Logic A
COMMENT_OUT_PROB    = 0.5   # 50 % chance to apply Logic B
MAGIC_REPLACEMENTS  = ["== 0", "== -1", "== 1", "!= 0"]


SPLITS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "splits")


# ─────────────────────────────────────────────
# 1. Data Fetching
# ─────────────────────────────────────────────
def load_swe_bench_data() -> pd.DataFrame:
    """
    Load the SWE-bench Lite dataset from HuggingFace and extract the
    fields we care about: `problem_statement`, `patch`, `instance_id`, `repo`.

    Returns
    -------
    pd.DataFrame
        Columns: instance_id, repo, problem_statement, patch
    """
    print("[diffsmith] Fetching princeton-nlp/SWE-bench_Lite from HuggingFace ...")
    dataset = load_dataset(DATASET_NAME, split="test")

    records = []
    for item in dataset:
        iid     = item.get("instance_id", "").strip()
        repo    = item.get("repo", "").strip()
        problem = item.get("problem_statement", "").strip()
        patch   = item.get("patch", "").strip()
        if problem and patch:
            records.append({
                "instance_id":       iid,
                "repo":              repo,
                "problem_statement": problem,
                "patch":             patch,
            })

    df = pd.DataFrame(records)
    print(f"[diffsmith] Loaded {len(df)} valid samples from SWE-bench Lite.")
    return df


# ─────────────────────────────────────────────
# 2. Leak-Proof Split Manifests
# ─────────────────────────────────────────────
def create_and_save_splits(df: pd.DataFrame, splits_dir: str = SPLITS_DIR) -> dict[str, list[str]]:
    """
    Create leak-proof repo-based splits and save manifests to data/splits/*.json.

    Repo allocation (no repo overlap between splits):
    - Train (8 repos, ~191 instances): django, scikit-learn, pytest, sphinx, astropy, requests, pylint, flask
    - Val (1 repo, 77 instances): sympy
    - Test (3 repos, 32 instances): matplotlib, xarray, seaborn
    """
    os.makedirs(splits_dir, exist_ok=True)

    val_repos  = {"sympy/sympy"}
    test_repos = {"matplotlib/matplotlib", "pydata/xarray", "mwaskom/seaborn"}

    manifests = {"train": [], "val": [], "test": []}
    for _, row in df.iterrows():
        repo = row["repo"]
        iid  = row["instance_id"]
        if repo in val_repos:
            manifests["val"].append(iid)
        elif repo in test_repos:
            manifests["test"].append(iid)
        else:
            manifests["train"].append(iid)

    for split_name, iids in manifests.items():
        split_path = os.path.join(splits_dir, f"{split_name}.json")
        with open(split_path, "w", encoding="utf-8") as f:
            json.dump({
                "count": len(iids),
                "repos": sorted(list(set(df[df["instance_id"].isin(iids)]["repo"]))),
                "instance_ids": iids,
            }, f, indent=2)
        print(f"[diffsmith] Split manifest saved -> {os.path.abspath(split_path)} ({len(iids)} instances)")

    return manifests


# ─────────────────────────────────────────────
# 3. Synthetic Corruption
# ─────────────────────────────────────────────
def corrupt_patch(patch_text: str) -> str:
    """
    Intentionally degrade a correct code patch to simulate a "lazy AI hack".

    Logic A - Magic Numbers (~50% chance):
        Replace a safe comparison such as ``>= 0`` or ``== None`` with a
        hardcoded integer sentinel like ``== 0`` or ``== -1``.

    Logic B - Comment-Out (~50% chance):
        Prepend ``#`` to one randomly chosen non-empty, non-comment line of the
        diff body to simulate silencing an edge-case check.

    At least one strategy is always applied so the returned text is never
    identical to the original.
    """
    lines   = patch_text.splitlines()
    changed = False

    # -- Logic A: Magic Number replacement -----------------------------------
    if random.random() < MAGIC_NUMBER_PROB:
        safe_patterns = [
            r">=\s*0",
            r"==\s*None",
            r"is\s*None",
            r"!=\s*None",
            r">\s*0",
        ]
        combined = re.compile("|".join(safe_patterns))

        new_lines = []
        for line in lines:
            if combined.search(line) and not line.lstrip().startswith("#"):
                replacement = random.choice(MAGIC_REPLACEMENTS)
                line = combined.sub(replacement, line, count=1)
                changed = True
            new_lines.append(line)
        lines = new_lines

    # -- Logic B: Comment-Out one diff line ----------------------------------
    if random.random() < COMMENT_OUT_PROB or not changed:
        candidate_indices = [
            i for i, ln in enumerate(lines)
            if ln.strip()
            and not ln.lstrip().startswith("#")
            and not ln.startswith("---")
            and not ln.startswith("+++")
            and not ln.startswith("@@")
        ]
        if candidate_indices:
            idx = random.choice(candidate_indices)
            if lines[idx].startswith(("+", "-")):
                prefix    = lines[idx][0]
                code_part = lines[idx][1:]
                lines[idx] = f"{prefix}# {code_part}"
            else:
                lines[idx] = f"# {lines[idx]}"

    return "\n".join(lines)


# ─────────────────────────────────────────────
# 4. Build Training Dataset
# ─────────────────────────────────────────────
def build_training_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create a balanced binary-classification dataset with explicit 'source' tracking.

    For every real sample we produce **two** rows:
        - Label 0 (Genuine)      - source: "gold", original problem + original patch
        - Label 1 (Shallow/Fake) - source: "synthetic", original problem + corrupted patch

    Returns
    -------
    pd.DataFrame
        Columns: instance_id, repo, problem_statement, patch, label, source
    """
    print("[diffsmith] Generating synthetic negative (shallow) samples ...")
    rows = []
    for _, row in df.iterrows():
        # Genuine sample (gold human patch)
        rows.append({
            "instance_id":       row.get("instance_id", ""),
            "repo":              row.get("repo", ""),
            "problem_statement": row["problem_statement"],
            "patch":             row["patch"],
            "label":             0,
            "source":            "gold",
        })
        # Shallow / corrupted sample (synthetic negative)
        rows.append({
            "instance_id":       row.get("instance_id", ""),
            "repo":              row.get("repo", ""),
            "problem_statement": row["problem_statement"],
            "patch":             corrupt_patch(row["patch"]),
            "label":             1,
            "source":            "synthetic",
        })

    training_df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[diffsmith] Training dataset: {len(training_df)} rows "
          f"({training_df['label'].value_counts().to_dict()})  "
          f"sources: {training_df['source'].value_counts().to_dict()}")
    return training_df


# ─────────────────────────────────────────────
# 5. Save to CSV
# ─────────────────────────────────────────────
def save_dataset(df: pd.DataFrame, output_path: str = OUTPUT_FILE) -> None:
    """
    Persist the training DataFrame to a CSV file.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[diffsmith] Dataset saved -> {os.path.abspath(output_path)}")


# ─────────────────────────────────────────────
# 6. Orchestration Entry-Point
# ─────────────────────────────────────────────
def run_pipeline() -> pd.DataFrame:
    """
    End-to-end pipeline: fetch -> split manifests -> corrupt -> combine -> save.
    """
    raw_df      = load_swe_bench_data()
    create_and_save_splits(raw_df)
    training_df = build_training_dataset(raw_df)
    save_dataset(training_df)
    return training_df


# ─────────────────────────────────────────────
# CLI hook  (python -m diffsmith.data_loader)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    run_pipeline()
