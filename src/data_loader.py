# data_loader.py — Responsible for loading and preprocessing code patch datasets.

import os
import re
import random
import pandas as pd
from datasets import load_dataset

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
DATASET_NAME = "princeton-nlp/SWE-bench_Lite"
OUTPUT_DIR   = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
OUTPUT_FILE  = os.path.join(OUTPUT_DIR, "training_data.csv")

# Probability thresholds for corruption strategies
MAGIC_NUMBER_PROB   = 0.5   # 50 % chance to apply Logic A
COMMENT_OUT_PROB    = 0.5   # 50 % chance to apply Logic B
MAGIC_REPLACEMENTS  = ["== 0", "== -1", "== 1", "!= 0"]


# ─────────────────────────────────────────────
# 1. Data Fetching
# ─────────────────────────────────────────────
def load_swe_bench_data() -> pd.DataFrame:
    """
    Load the SWE-bench Lite dataset from HuggingFace and extract the two
    fields we care about: `problem_statement` and `patch`.

    Returns
    -------
    pd.DataFrame
        Columns: problem_statement (str), patch (str)
    """
    print("[Aegis] Fetching princeton-nlp/SWE-bench_Lite from HuggingFace ...")
    dataset = load_dataset(DATASET_NAME, split="test", trust_remote_code=True)

    records = []
    for item in dataset:
        problem = item.get("problem_statement", "").strip()
        patch   = item.get("patch", "").strip()
        if problem and patch:          # drop entries missing either field
            records.append({"problem_statement": problem, "patch": patch})

    df = pd.DataFrame(records)
    print(f"[Aegis] Loaded {len(df)} valid samples from SWE-bench Lite.")
    return df


# ─────────────────────────────────────────────
# 2. Synthetic Corruption
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

    Parameters
    ----------
    patch_text : str
        A unified-diff style patch string.

    Returns
    -------
    str
        The corrupted patch string.
    """
    lines   = patch_text.splitlines()
    changed = False

    # -- Logic A: Magic Number replacement -----------------------------------
    if random.random() < MAGIC_NUMBER_PROB:
        # Patterns that indicate a safe, correct boundary check
        safe_patterns = [
            r">=\s*0",       # e.g.  if x >= 0:
            r"==\s*None",    # e.g.  if x == None:
            r"is\s*None",    # e.g.  if x is None:
            r"!=\s*None",    # e.g.  if x != None:
            r">\s*0",        # e.g.  if count > 0:
        ]
        combined = re.compile("|".join(safe_patterns))

        new_lines = []
        for line in lines:
            if combined.search(line) and not line.lstrip().startswith("#"):
                replacement = random.choice(MAGIC_REPLACEMENTS)
                # Replace only the first match on the line
                line = combined.sub(replacement, line, count=1)
                changed = True
            new_lines.append(line)
        lines = new_lines

    # -- Logic B: Comment-Out one diff line ----------------------------------
    if random.random() < COMMENT_OUT_PROB or not changed:
        # Target lines that are additions in the diff (start with '+') or
        # plain code lines - avoid commenting out diff headers or blank lines
        candidate_indices = [
            i for i, ln in enumerate(lines)
            if ln.strip()                       # non-empty
            and not ln.lstrip().startswith("#") # not already a comment
            and not ln.startswith("---")        # not diff header
            and not ln.startswith("+++")
            and not ln.startswith("@@")
        ]
        if candidate_indices:
            idx = random.choice(candidate_indices)
            # Keep the leading '+'/'-' diff character if present, comment rest
            if lines[idx].startswith(("+", "-")):
                prefix    = lines[idx][0]
                code_part = lines[idx][1:]
                lines[idx] = f"{prefix}# {code_part}"
            else:
                lines[idx] = f"# {lines[idx]}"

    return "\n".join(lines)


# ─────────────────────────────────────────────
# 3. Build Training Dataset
# ─────────────────────────────────────────────
def build_training_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create a balanced binary-classification dataset from clean SWE-bench data.

    For every real sample we produce **two** rows:
        - Label 0 (Genuine)      - original problem_statement + original patch
        - Label 1 (Shallow/Fake) - original problem_statement + corrupted patch

    Parameters
    ----------
    df : pd.DataFrame
        Output of ``load_swe_bench_data()``.

    Returns
    -------
    pd.DataFrame
        Columns: problem_statement, patch, label
    """
    print("[Aegis] Generating synthetic negative (shallow) samples ...")
    rows = []
    for _, row in df.iterrows():
        # Genuine sample
        rows.append({
            "problem_statement": row["problem_statement"],
            "patch":             row["patch"],
            "label":             0,
        })
        # Shallow / corrupted sample
        rows.append({
            "problem_statement": row["problem_statement"],
            "patch":             corrupt_patch(row["patch"]),
            "label":             1,
        })

    training_df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[Aegis] Training dataset: {len(training_df)} rows "
          f"({training_df['label'].value_counts().to_dict()})")
    return training_df


# ─────────────────────────────────────────────
# 4. Save to CSV
# ─────────────────────────────────────────────
def save_dataset(df: pd.DataFrame, output_path: str = OUTPUT_FILE) -> None:
    """
    Persist the training DataFrame to a CSV file.

    Parameters
    ----------
    df : pd.DataFrame
        The dataset to save.
    output_path : str
        Destination file path. Parent directories are created automatically.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[Aegis] Dataset saved -> {os.path.abspath(output_path)}")


# ─────────────────────────────────────────────
# 5. Orchestration Entry-Point
# ─────────────────────────────────────────────
def run_pipeline() -> pd.DataFrame:
    """
    End-to-end pipeline: fetch -> corrupt -> combine -> save.

    Returns the final training DataFrame so callers can inspect it.
    """
    raw_df      = load_swe_bench_data()
    training_df = build_training_dataset(raw_df)
    save_dataset(training_df)
    return training_df


# ─────────────────────────────────────────────
# CLI hook  (python -m src.data_loader)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    run_pipeline()
