# model_architecture.py — CodeBERT fine-tuning pipeline for diffsmith patch auditing.

import os
import warnings
import numpy as np
import pandas as pd

import torch
from datasets import Dataset, DatasetDict
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
MODEL_NAME       = "microsoft/codebert-base"
NUM_LABELS       = 2                          # 0 = Genuine, 1 = Shallow/Fake
MAX_LENGTH       = 256                        # token budget per sample
TRAIN_SPLIT      = 0.8
EPOCHS           = 3
LEARNING_RATE    = 2e-5
BATCH_SIZE       = 8                          # drop to 4 if OOM on GPU / slow on CPU

DATA_CSV        = os.path.join(os.path.dirname(__file__), "..", "..", "data", "processed", "training_data.csv")
CHECKPOINT_DIR  = os.path.join(os.path.dirname(__file__), "..", "..", "models", "checkpoint")
FINAL_MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models", "diffsmith-core-v1")


# ─────────────────────────────────────────────
# Device Detection
# ─────────────────────────────────────────────
def get_device() -> str:
    """
    Return the best available compute device.

    Prints a friendly warning when falling back to CPU so the user knows
    training will be slower (~10-20 minutes for SWE-bench Lite).
    """
    if torch.cuda.is_available():
        device = "cuda"
        gpu_name = torch.cuda.get_device_name(0)
        print(f"[diffsmith] GPU detected: {gpu_name} — training on CUDA.")
    else:
        device = "cpu"
        warnings.warn(
            "\n[diffsmith] WARNING: No GPU found — training will run on CPU.\n"
            "          This may take 10-20 minutes for the full SWE-bench Lite dataset.\n"
            "          Consider using Google Colab (free T4 GPU) if you need faster results.",
            UserWarning,
            stacklevel=2,
        )
        print("[diffsmith] Running on CPU.")
    return device


# ─────────────────────────────────────────────
# 1. Tokenizer & Model Loading
# ─────────────────────────────────────────────
def load_tokenizer_and_model():
    """
    Download (or load from cache) the CodeBERT tokenizer and a
    sequence-classification head on top of it.

    Returns
    -------
    tokenizer : AutoTokenizer
    model     : AutoModelForSequenceClassification  (num_labels=2)
    """
    print(f"[diffsmith] Loading tokenizer from '{MODEL_NAME}' ...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    print(f"[diffsmith] Loading model from '{MODEL_NAME}' with {NUM_LABELS} output labels ...")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=NUM_LABELS,
        ignore_mismatched_sizes=True,   # classification head is freshly initialised
    )

    device = get_device()
    model = model.to(device)
    print(f"[diffsmith] Model moved to {device.upper()}.")
    return tokenizer, model


from typing import Optional, Tuple

# ─────────────────────────────────────────────
# 2. Preprocessing & Truncation Strategy
# ─────────────────────────────────────────────
def prioritize_patch_lines(patch_text: str, max_chars: int | None = None) -> str:
    """
    Filter and prioritize patch lines:
    1. Retains hunk headers (e.g. '@@ ... @@') and file headers ('---', '+++').
    2. Prioritizes added ('+') and removed ('-') lines over unchanged context lines (' ').
    3. Drops unchanged context lines first when constrained by budget.
    """
    lines = patch_text.splitlines()
    if not lines:
        return patch_text

    # Extract essential headers, changes, and context lines
    filtered = []
    for line in lines:
        if line.startswith(("---", "+++", "diff ", "index ")) or line.startswith("@@"):
            filtered.append(line)
        elif (line.startswith("+") and not line.startswith("+++")) or (
            line.startswith("-") and not line.startswith("---")
        ):
            filtered.append(line)
        elif max_chars is None:
            filtered.append(line)

    candidate = "\n".join(filtered)
    if max_chars is None or len(candidate) <= max_chars:
        return candidate

    # If still too long, keep hunk headers/file headers and as many change lines as fit
    final_lines = []
    curr = 0
    for line in filtered:
        if line.startswith("@@") or line.startswith(("---", "+++")):
            final_lines.append(line)
            curr += len(line) + 1
        elif curr + len(line) + 1 <= max_chars:
            final_lines.append(line)
            curr += len(line) + 1

    return "\n".join(final_lines)


def truncate_issue_and_patch(
    issue_text: str,
    patch_text: str,
    tokenizer: AutoTokenizer,
    max_length: int = MAX_LENGTH,
) -> tuple[str, str]:
    """
    Truncation strategy:
    1. Issue first: when total tokens exceed max_length, truncate the issue description
       first to protect patch and hunk structure.
    2. Keep hunk headers: preserves '@@ ... @@' diff hunk headers.
    3. Prioritize added/removed lines: context lines are dropped before change lines.
    """
    special_tokens_count = 3  # [CLS] issue [SEP] patch [SEP]
    budget = max_length - special_tokens_count
    if budget <= 0:
        return issue_text, patch_text

    issue_ids = tokenizer.encode(issue_text, add_special_tokens=False, truncation=False)
    patch_ids = tokenizer.encode(patch_text, add_special_tokens=False, truncation=False)

    if len(issue_ids) + len(patch_ids) <= budget:
        return issue_text, patch_text

    # Content exceeds budget.
    # Preserve patch priority while allocating a baseline floor for the issue
    min_issue_budget = min(len(issue_ids), max(16, min(48, budget // 4)))
    max_patch_budget = budget - min_issue_budget

    # If patch exceeds its budget, prioritize diff lines (prune context lines first)
    if len(patch_ids) > max_patch_budget:
        pruned_patch = prioritize_patch_lines(patch_text)
        pruned_ids = tokenizer.encode(pruned_patch, add_special_tokens=False, truncation=False)
        if len(pruned_ids) > max_patch_budget:
            char_limit = max_patch_budget * 4
            pruned_patch = prioritize_patch_lines(pruned_patch, max_chars=char_limit)
            pruned_ids = tokenizer.encode(pruned_patch, add_special_tokens=False, truncation=False)
            if len(pruned_ids) > max_patch_budget:
                pruned_patch = tokenizer.decode(pruned_ids[:max_patch_budget], skip_special_tokens=True)
                pruned_ids = pruned_ids[:max_patch_budget]
        patch_text = pruned_patch
        patch_ids = pruned_ids

    # Truncate issue first for whatever remaining budget exists
    remaining_issue_budget = max(0, budget - len(patch_ids))
    if len(issue_ids) > remaining_issue_budget:
        issue_ids = issue_ids[:remaining_issue_budget]
        issue_text = tokenizer.decode(issue_ids, skip_special_tokens=True)

    return issue_text, patch_text


def build_preprocess_fn(tokenizer: AutoTokenizer, max_length: int = MAX_LENGTH):
    """
    Factory that returns a ``preprocess_data`` function bound to *tokenizer*.

    Applies the truncation strategy:
      - Issue first: when total length exceeds budget, issue is truncated first.
      - Patch prioritization: keeps hunk headers ('@@') and prioritizes added/removed lines.
    Applies dynamic padding:
      - Tokens are NOT padded to max_length during tokenization (padding=False).
      - DataCollatorWithPadding dynamically pads batches to the longest sequence in that batch.
    """
    def preprocess_data(examples: dict) -> dict:
        issues = examples["problem_statement"]
        patches = examples["patch"]

        processed_issues = []
        processed_patches = []
        for issue, patch in zip(issues, patches):
            t_issue, t_patch = truncate_issue_and_patch(
                str(issue or ""),
                str(patch or ""),
                tokenizer,
                max_length=max_length,
            )
            processed_issues.append(t_issue)
            processed_patches.append(t_patch)

        # Dynamic padding: padding=False allows per-batch dynamic padding via collator
        encoded = tokenizer(
            processed_issues,
            processed_patches,
            truncation=True,
            padding=False,
            max_length=max_length,
        )
        encoded["labels"] = examples["label"]
        return encoded

    return preprocess_data


# ─────────────────────────────────────────────
# 3. Dataset Loading & Splitting
# ─────────────────────────────────────────────
def load_and_split_dataset(
    tokenizer: AutoTokenizer,
    csv_path: str = DATA_CSV,
    smoke: bool = False,
) -> DatasetDict:
    """
    Read the processed CSV, convert to a HuggingFace Dataset, tokenize,
    and split into train / validation sets.

    Parameters
    ----------
    tokenizer : AutoTokenizer
    csv_path  : str
        Path to ``training_data.csv`` produced by ``data_loader.py``.
    smoke     : bool
        If True, cap dataset at 50 samples for a quick end-to-end smoke test.

    Returns
    -------
    DatasetDict with keys ``"train"`` and ``"validation"``.
    """
    print(f"[diffsmith] Reading dataset from: {os.path.abspath(csv_path)}")
    df = pd.read_csv(csv_path)

    # Sanity checks
    required_cols = {"problem_statement", "patch", "label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"[diffsmith] CSV is missing required columns: {missing}")

    df = df.dropna(subset=list(required_cols))
    df["label"] = df["label"].astype(int)

    if smoke:
        df = df.sample(n=min(50, len(df)), random_state=42).reset_index(drop=True)
        print(f"[diffsmith] SMOKE MODE -- capped to {len(df)} samples.")

    print(f"[diffsmith] {len(df)} rows loaded  |  label distribution: {df['label'].value_counts().to_dict()}")

    # Convert to HuggingFace Dataset
    full_dataset = Dataset.from_pandas(df[["problem_statement", "patch", "label"]], preserve_index=False)

    # 80 / 20 split (reproducible via seed)
    split = full_dataset.train_test_split(test_size=1 - TRAIN_SPLIT, seed=42)

    # Tokenize
    preprocess = build_preprocess_fn(tokenizer)
    tokenized = split.map(preprocess, batched=True, remove_columns=["problem_statement", "patch"])
    tokenized.set_format("torch")

    dataset_dict = DatasetDict({
        "train":      tokenized["train"],
        "validation": tokenized["test"],
    })
    print(
        f"[diffsmith] Train: {len(dataset_dict['train'])} samples  "
        f"|  Val: {len(dataset_dict['validation'])} samples"
    )
    return dataset_dict


# ─────────────────────────────────────────────
# 4. Metrics
# ─────────────────────────────────────────────
def compute_metrics(eval_pred) -> dict:
    """
    Compute accuracy, precision, recall, and F1 for binary classification.

    Called by the HuggingFace Trainer at the end of every evaluation run.
    """
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)

    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", zero_division=0
    )
    acc = accuracy_score(labels, preds)

    return {
        "accuracy":  round(acc, 4),
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
    }


# ─────────────────────────────────────────────
# 5. Training
# ─────────────────────────────────────────────
def train_model(
    model,
    tokenizer: AutoTokenizer,
    dataset_dict: DatasetDict,
    checkpoint_dir: str = CHECKPOINT_DIR,
    smoke: bool = False,
) -> Trainer:
    """
    Configure and run the HuggingFace Trainer fine-tuning loop.

    Parameters
    ----------
    model         : AutoModelForSequenceClassification
    tokenizer     : AutoTokenizer
    dataset_dict  : DatasetDict  (keys: "train", "validation")
    checkpoint_dir: str
    smoke         : bool
        If True, run 1 epoch with batch_size=4 for a quick smoke test.

    Returns
    -------
    Trainer (already trained)

    Notes
    -----
    - EarlyStoppingCallback is intentionally absent: it requires eval_strategy != "no".
    - processing_class= replaces the deprecated tokenizer= kwarg (transformers >= 4.46).
    - dataloader_num_workers=0 is required on Windows (no fork-based multiprocessing).
    """
    os.makedirs(checkpoint_dir, exist_ok=True)

    # Smoke mode: 1 epoch, small batch; production: configured constants
    epochs = 1 if smoke else EPOCHS
    per_device_bs = 4 if smoke else (
        BATCH_SIZE if torch.cuda.is_available() else max(BATCH_SIZE // 2, 4)
    )
    print(f"[diffsmith] Epochs: {epochs}  |  Per-device batch size: {per_device_bs}")

    training_args = TrainingArguments(
        output_dir=checkpoint_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=per_device_bs,
        learning_rate=LEARNING_RATE,
        logging_steps=5 if smoke else 10,
        eval_strategy="no",       # EarlyStoppingCallback requires eval; keep disabled
        save_strategy="no",
        report_to="none",
        dataloader_num_workers=0, # Windows: fork-based workers not supported
        use_cpu=not torch.cuda.is_available(),
    )

    # transformers >= 4.46: processing_class= replaces the deprecated tokenizer= kwarg
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset_dict["train"],
        eval_dataset=dataset_dict["validation"],
        processing_class=tokenizer,   # replaces deprecated tokenizer= (>= 4.46)
        data_collator=data_collator,
        compute_metrics=compute_metrics,
    )

    print("[diffsmith] Starting fine-tuning ...")
    trainer.train()
    print("[diffsmith] Training complete.")
    return trainer


# ─────────────────────────────────────────────
# 6. Save Final Model
# ─────────────────────────────────────────────
def save_model(
    trainer: Trainer,
    tokenizer: AutoTokenizer,
    save_dir: str = FINAL_MODEL_DIR,
) -> None:
    """
    Persist the fine-tuned model and its tokenizer to *save_dir*.

    Parameters
    ----------
    trainer   : Trained HuggingFace Trainer instance.
    tokenizer : AutoTokenizer (saved alongside so inference is self-contained).
    save_dir  : str
    """
    os.makedirs(save_dir, exist_ok=True)
    trainer.save_model(save_dir)
    tokenizer.save_pretrained(save_dir)
    print(f"[diffsmith] Model + tokenizer saved to: {os.path.abspath(save_dir)}")


# ─────────────────────────────────────────────
# 7. Orchestration Entry-Point
# ─────────────────────────────────────────────
def run_training_pipeline(smoke: bool = False) -> None:
    """
    End-to-end pipeline:
        load model -> preprocess data -> train -> save (skipped in smoke mode).

    Run via:
        python -m diffsmith.model_architecture           # full training
        python -m diffsmith.model_architecture --smoke   # 50-sample / 1-epoch test
    """
    import time
    t0 = time.time()

    # Step 1 — Load model & tokenizer
    tokenizer, model = load_tokenizer_and_model()

    # Step 2 — Prepare dataset
    dataset_dict = load_and_split_dataset(tokenizer, smoke=smoke)

    # Step 3 — Fine-tune
    trainer = train_model(model, tokenizer, dataset_dict, smoke=smoke)

    # Step 4 — Persist (skip in smoke mode to avoid committing half-trained weights)
    if smoke:
        print("[diffsmith] Smoke mode: skipping model save.")
    else:
        save_model(trainer, tokenizer)

    # Step 5 — Final eval report
    print("\n[diffsmith] Final evaluation on validation set:")
    metrics = trainer.evaluate()
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    elapsed = time.time() - t0
    print(f"\n[diffsmith] Total wall time: {elapsed:.1f}s  ({elapsed/60:.1f} min)")


# ─────────────────────────────────────────────
# CLI hook
#   python -m diffsmith.model_architecture [--smoke]
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="diffsmith training pipeline — fine-tunes CodeBERT for patch auditing."
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Run a quick 50-sample / 1-epoch smoke test (no model saved).",
    )
    args = parser.parse_args()
    run_training_pipeline(smoke=args.smoke)
