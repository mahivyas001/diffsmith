# model_architecture.py — CodeBERT fine-tuning pipeline for Aegis patch auditing.

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
    EarlyStoppingCallback,
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

DATA_CSV         = os.path.join(os.path.dirname(__file__), "..", "data", "processed", "training_data.csv")
CHECKPOINT_DIR   = os.path.join(os.path.dirname(__file__), "..", "models", "checkpoint")
FINAL_MODEL_DIR  = os.path.join(os.path.dirname(__file__), "..", "models", "aegis-core-v1")


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
        print(f"[Aegis] GPU detected: {gpu_name} — training on CUDA.")
    else:
        device = "cpu"
        warnings.warn(
            "\n[Aegis] ⚠  No GPU found — training will run on CPU.\n"
            "          This may take 10–20 minutes for the full SWE-bench Lite dataset.\n"
            "          Consider using Google Colab (free T4 GPU) if you need faster results.",
            UserWarning,
            stacklevel=2,
        )
        print("[Aegis] Running on CPU.")
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
    print(f"[Aegis] Loading tokenizer from '{MODEL_NAME}' ...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    print(f"[Aegis] Loading model from '{MODEL_NAME}' with {NUM_LABELS} output labels ...")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=NUM_LABELS,
        ignore_mismatched_sizes=True,   # classification head is freshly initialised
    )

    device = get_device()
    model = model.to(device)
    print(f"[Aegis] Model moved to {device.upper()}.")
    return tokenizer, model


# ─────────────────────────────────────────────
# 2. Preprocessing
# ─────────────────────────────────────────────
def build_preprocess_fn(tokenizer: AutoTokenizer):
    """
    Factory that returns a ``preprocess_data`` function bound to *tokenizer*.

    The input representation follows the standard CodeBERT dual-sequence format:

        [CLS] <problem_statement> [SEP] <patch> [SEP]

    Parameters
    ----------
    tokenizer : AutoTokenizer

    Returns
    -------
    Callable[[dict], dict]
        A HuggingFace-compatible map function.
    """
    def preprocess_data(examples: dict) -> dict:
        """
        Tokenize a batch of examples.

        ``text_pair`` makes the tokenizer insert the special tokens and
        segment IDs automatically, giving the model the full
        [CLS] A [SEP] B [SEP] input it expects.
        """
        encoded = tokenizer(
            examples["problem_statement"],   # sequence A
            examples["patch"],              # sequence B
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
        )
        encoded["labels"] = examples["label"]
        return encoded

    return preprocess_data


# ─────────────────────────────────────────────
# 3. Dataset Loading & Splitting
# ─────────────────────────────────────────────
def load_and_split_dataset(tokenizer: AutoTokenizer, csv_path: str = DATA_CSV) -> DatasetDict:
    """
    Read the processed CSV, convert to a HuggingFace Dataset, tokenize,
    and split into train / validation sets.

    Parameters
    ----------
    tokenizer : AutoTokenizer
    csv_path  : str
        Path to ``training_data.csv`` produced by ``data_loader.py``.

    Returns
    -------
    DatasetDict with keys ``"train"`` and ``"validation"``.
    """
    print(f"[Aegis] Reading dataset from: {os.path.abspath(csv_path)}")
    df = pd.read_csv(csv_path)

    # Sanity checks
    required_cols = {"problem_statement", "patch", "label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"[Aegis] CSV is missing required columns: {missing}")

    df = df.dropna(subset=list(required_cols))
    df["label"] = df["label"].astype(int)
    print(f"[Aegis] {len(df)} rows loaded  |  label distribution: {df['label'].value_counts().to_dict()}")

    # Convert to HuggingFace Dataset
    full_dataset = Dataset.from_pandas(df[["problem_statement", "patch", "label"]], preserve_index=False)

    # 80 / 20 split (stratified-like via seed for reproducibility)
    split = full_dataset.train_test_split(test_size=1 - TRAIN_SPLIT, seed=42)

    # Tokenize
    preprocess = build_preprocess_fn(tokenizer)
    tokenized = split.map(preprocess, batched=True, remove_columns=["problem_statement", "patch"])

    tokenized.set_format("torch")

    dataset_dict = DatasetDict({
        "train":      tokenized["train"],
        "validation": tokenized["test"],
    })
    print(f"[Aegis] Train: {len(dataset_dict['train'])} samples  |  Val: {len(dataset_dict['validation'])} samples")
    return dataset_dict


# ─────────────────────────────────────────────
# 4. Metrics
# ─────────────────────────────────────────────
def compute_metrics(eval_pred) -> dict:
    """
    Compute accuracy, precision, recall, and F1 for binary classification.

    Called by the HuggingFace Trainer at the end of every evaluation epoch.
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
) -> Trainer:
    """
    Configure and run the HuggingFace Trainer fine-tuning loop.

    Parameters
    ----------
    model         : AutoModelForSequenceClassification
    tokenizer     : AutoTokenizer
    dataset_dict  : DatasetDict  (keys: "train", "validation")
    checkpoint_dir: str

    Returns
    -------
    Trainer (already trained)
    """
    os.makedirs(checkpoint_dir, exist_ok=True)

    # Determine per-device batch size — halve it on CPU to reduce memory pressure
    per_device_bs = BATCH_SIZE if torch.cuda.is_available() else max(BATCH_SIZE // 2, 4)
    print(f"[Aegis] Per-device batch size: {per_device_bs}")

    training_args = TrainingArguments(
        output_dir=checkpoint_dir,
        num_train_epochs=EPOCHS,
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=per_device_bs,
        per_device_eval_batch_size=per_device_bs,
        warmup_ratio=0.1,                   # 10 % of steps for LR warm-up
        weight_decay=0.01,                  # L2 regularisation
        eval_strategy="epoch",              # evaluate at end of each epoch
        save_strategy="epoch",
        load_best_model_at_end=True,        # restore best checkpoint after training
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_dir=os.path.join(checkpoint_dir, "logs"),
        logging_steps=50,
        report_to="none",                   # disable WandB / TB unless configured
        fp16=torch.cuda.is_available(),     # mixed precision only on CUDA
        dataloader_num_workers=0,           # 0 is safest on Windows
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset_dict["train"],
        eval_dataset=dataset_dict["validation"],
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
    )

    print("[Aegis] Starting fine-tuning ...")
    trainer.train()
    print("[Aegis] Training complete.")
    return trainer


# ─────────────────────────────────────────────
# 6. Save Final Model
# ─────────────────────────────────────────────
def save_model(trainer: Trainer, tokenizer: AutoTokenizer, save_dir: str = FINAL_MODEL_DIR) -> None:
    """
    Persist the best fine-tuned model and its tokenizer to *save_dir*.

    Parameters
    ----------
    trainer   : Trained HuggingFace Trainer instance.
    tokenizer : AutoTokenizer (saved alongside so inference is self-contained).
    save_dir  : str
    """
    os.makedirs(save_dir, exist_ok=True)
    trainer.save_model(save_dir)
    tokenizer.save_pretrained(save_dir)
    print(f"[Aegis] Model + tokenizer saved to: {os.path.abspath(save_dir)}")


# ─────────────────────────────────────────────
# 7. Orchestration Entry-Point
# ─────────────────────────────────────────────
def run_training_pipeline() -> None:
    """
    End-to-end pipeline:
        load model → preprocess data → train → save.
    """
    # Step 1 — Load model & tokenizer
    tokenizer, model = load_tokenizer_and_model()

    # Step 2 — Prepare dataset
    dataset_dict = load_and_split_dataset(tokenizer)

    # Step 3 — Fine-tune
    trainer = train_model(model, tokenizer, dataset_dict)

    # Step 4 — Persist
    save_model(trainer, tokenizer)

    # Step 5 — Final eval report
    print("\n[Aegis] Final evaluation on validation set:")
    metrics = trainer.evaluate()
    for k, v in metrics.items():
        print(f"  {k}: {v}")


# ─────────────────────────────────────────────
# CLI hook  (python -m src.model_architecture)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    run_training_pipeline()
