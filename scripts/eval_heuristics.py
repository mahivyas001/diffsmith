"""
scripts/eval_heuristics.py — Phase 3 Relational Heuristics Evaluation & Control Experiments

Usage:
    python scripts/eval_heuristics.py
"""

import json
import os
import sys
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_auc_score, average_precision_score, accuracy_score

# Ensure repository root is on sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from scripts.baselines import (
    load_and_prepare_data,
    extract_patch_size_features,
    calc_prec_at_fpr,
    calc_fp_per_100_at_recall,
    bootstrap_metric_ci,
    calc_within_instance_auc,
)
from diffsmith.heuristics import run_all_heuristics

RESULTS_DIR = os.path.join(ROOT, "results")
BASELINES_JSON = os.path.join(RESULTS_DIR, "baselines.json")
HEURISTICS_JSON = os.path.join(RESULTS_DIR, "heuristics.json")
HEURISTICS_MD = os.path.join(RESULTS_DIR, "heuristics.md")
DATA_MD = os.path.join(ROOT, "docs", "DATA.md")


def extract_dataset_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
    """Extract 15 rule features and 5 patch size features for all rows."""
    rule_feature_list = []
    size_features_arr = extract_patch_size_features(df["patch"])
    row_findings_list = []

    for _, row in df.iterrows():
        issue_text = str(row.get("problem_statement", ""))
        patch_text = str(row.get("patch", ""))
        findings, feats = run_all_heuristics(issue_text, patch_text)
        rule_feature_list.append(feats)
        row_findings_list.append(findings)

    df_rule_feats = pd.DataFrame(rule_feature_list, index=df.index)
    size_cols = ["lines_added", "lines_removed", "total_changed", "files_touched", "hunks_count"]
    df_size_feats = pd.DataFrame(size_features_arr, columns=size_cols, index=df.index)

    return df_rule_feats, df_size_feats, row_findings_list


def compute_rule_fire_indicators(df: pd.DataFrame, df_rule_feats: pd.DataFrame, row_findings: list[dict]) -> pd.DataFrame:
    """Determine binary fire indicator for each of the 8 rules."""
    fire_dict = {
        "rule_1_issue_file_overlap": [],
        "rule_2_issue_identifier_overlap": [],
        "rule_3_issue_literal_hardcoding": [],
        "rule_4_special_casing": [],
        "rule_5_swallowed_exceptions": [],
        "rule_6_test_tampering": [],
        "rule_7_suppression_markers": [],
        "rule_8_scope_creep": [],
    }

    for i in range(len(df)):
        r_finds = row_findings[i]
        find_rules = {f["rule_id"] for f in r_finds}
        rf = df_rule_feats.iloc[i]

        fire_dict["rule_1_issue_file_overlap"].append(1.0 if "issue_file_overlap" in find_rules else 0.0)
        fire_dict["rule_2_issue_identifier_overlap"].append(1.0 if rf["issue_identifier_overlap_frac"] > 0.0 else 0.0)
        fire_dict["rule_3_issue_literal_hardcoding"].append(1.0 if rf["has_literal_hardcoding"] > 0.0 else 0.0)
        fire_dict["rule_4_special_casing"].append(1.0 if rf["has_special_casing"] > 0.0 else 0.0)
        fire_dict["rule_5_swallowed_exceptions"].append(1.0 if rf["has_swallowed_exception"] > 0.0 else 0.0)
        fire_dict["rule_6_test_tampering"].append(1.0 if rf["has_test_tampering"] > 0.0 else 0.0)
        fire_dict["rule_7_suppression_markers"].append(1.0 if rf["has_suppression_marker"] > 0.0 else 0.0)
        fire_dict["rule_8_scope_creep"].append(1.0 if rf["scope_creep_count"] > 0.0 else 0.0)

    return pd.DataFrame(fire_dict, index=df.index)


def run_evaluation() -> dict:
    df = load_and_prepare_data()
    print(f"Loaded dataset: {len(df)} rows.")
    print("Extracting relational heuristic features and patch size features...")

    df_rule_feats, df_size_feats, row_findings = extract_dataset_features(df)
    df_fire = compute_rule_fire_indicators(df, df_rule_feats, row_findings)

    # ── 1. Rule Fire Rates ──────────────────────────────────────────────────
    rule_names = list(df_fire.columns)
    total_rows = len(df)
    overall_fire_rates = {}
    rare_rules = []

    for r_col in rule_names:
        cnt = int(df_fire[r_col].sum())
        pct = float((cnt / total_rows) * 100.0)
        overall_fire_rates[r_col] = {"count": cnt, "percentage": pct}
        if pct < 1.0:
            rare_rules.append(r_col)

    subs = sorted(df["submission"].unique())
    submission_fire_rates = {}
    for s in subs:
        sub_mask = df["submission"] == s
        sub_len = int(sub_mask.sum())
        sub_fire = {}
        for r_col in rule_names:
            cnt = int(df_fire.loc[sub_mask, r_col].sum())
            pct = float((cnt / sub_len) * 100.0) if sub_len > 0 else 0.0
            sub_fire[r_col] = {"count": cnt, "percentage": pct}
        submission_fire_rates[s] = {"patch_count": sub_len, "rules": sub_fire}

    # ── 2. Split Data ────────────────────────────────────────────────────────
    df_train = df[df["split"] == "train"].copy()
    df_val = df[df["split"] == "val"].copy()
    df_test = df[df["split"] == "test"].copy()

    y_train = df_train["resolved"].values.astype(int)
    y_val = df_val["resolved"].values.astype(int)
    y_test = df_test["resolved"].values.astype(int)

    X_train_rule = df_rule_feats.loc[df_train.index].values
    X_val_rule = df_rule_feats.loc[df_val.index].values
    X_test_rule = df_rule_feats.loc[df_test.index].values

    X_train_size = df_size_feats.loc[df_train.index].values
    X_val_size = df_size_feats.loc[df_val.index].values
    X_test_size = df_size_feats.loc[df_test.index].values

    scaler_rule = StandardScaler().fit(X_train_rule)
    X_tr_rule_scaled = scaler_rule.transform(X_train_rule)
    X_va_rule_scaled = scaler_rule.transform(X_val_rule)
    X_te_rule_scaled = scaler_rule.transform(X_test_rule)

    X_train_comb = np.hstack([X_train_rule, X_train_size])
    X_val_comb = np.hstack([X_val_rule, X_val_size])
    X_test_comb = np.hstack([X_test_rule, X_test_size])
    scaler_comb = StandardScaler().fit(X_train_comb)
    X_tr_comb_scaled = scaler_comb.transform(X_train_comb)
    X_va_comb_scaled = scaler_comb.transform(X_val_comb)
    X_te_comb_scaled = scaler_comb.transform(X_test_comb)

    val_probs: dict[str, np.ndarray] = {}
    test_probs: dict[str, np.ndarray] = {}

    # (H1) Single features alone — direction chosen on train
    rule_feature_cols = list(df_rule_feats.columns)
    for i, f_col in enumerate(rule_feature_cols):
        m_name = f"(H1) Feature: {f_col}"
        clf_1d = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
        clf_1d.fit(X_tr_rule_scaled[:, i:i+1], y_train)
        val_probs[m_name] = clf_1d.predict_proba(X_va_rule_scaled[:, i:i+1])[:, 1]
        test_probs[m_name] = clf_1d.predict_proba(X_te_rule_scaled[:, i:i+1])[:, 1]

    # (H2) All 15 rule features
    clf_h2 = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
    clf_h2.fit(X_tr_rule_scaled, y_train)
    val_probs["(H2) All Rule Features LogReg"] = clf_h2.predict_proba(X_va_rule_scaled)[:, 1]
    test_probs["(H2) All Rule Features LogReg"] = clf_h2.predict_proba(X_te_rule_scaled)[:, 1]

    # (H3) H2 + Baseline D patch-size features
    clf_h3 = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
    clf_h3.fit(X_tr_comb_scaled, y_train)
    val_probs["(H3) H2 + Baseline D Features LogReg"] = clf_h3.predict_proba(X_va_comb_scaled)[:, 1]
    test_probs["(H3) H2 + Baseline D Features LogReg"] = clf_h3.predict_proba(X_te_comb_scaled)[:, 1]

    def eval_split_metrics(df_split: pd.DataFrame, y_true: np.ndarray, model_probs: dict) -> dict:
        results = {}
        for m_name, probs in model_probs.items():
            w_inst = calc_within_instance_auc(df_split, y_true, probs)
            roc_auc = float(roc_auc_score(y_true, probs))
            pr_auc = float(average_precision_score(y_true, probs))
            prec_5fpr = calc_prec_at_fpr(y_true, probs, target_fpr=0.05)
            fp_100_rec80 = calc_fp_per_100_at_recall(y_true, probs, target_recall=0.80)
            roc_ci = bootstrap_metric_ci(df_split, y_true, probs, roc_auc_score)
            pr_ci = bootstrap_metric_ci(df_split, y_true, probs, average_precision_score)
            results[m_name] = {
                "within_instance_auc": w_inst["mean_auc"],
                "within_instance_auc_ci": list(w_inst["ci"]),
                "within_instance_n_instances": w_inst["n_instances"],
                "roc_auc": roc_auc,
                "roc_auc_ci": list(roc_ci),
                "pr_auc": pr_auc,
                "pr_auc_ci": list(pr_ci),
                "prec_at_5fpr": prec_5fpr,
                "fp_100_at_80rec": fp_100_rec80,
            }
        return results

    val_eval_results = eval_split_metrics(df_val, y_val, val_probs)
    test_eval_results = eval_split_metrics(df_test, y_test, test_probs)

    # ── 3. Agent-Fingerprint Controls ───────────────────────────────────────

    # Control (i): 3-Fold Submission-Group Leave-Out (submission-disjoint CV)
    # NOTE: In this dataset every instance_id appears in ALL 18 submissions by
    # construction (one patch per submission per instance). Per-submission
    # instance-disjoint exclusion would remove 100% of training rows — an
    # empty training set — for every single fold, so LSGO-1 is structurally
    # degenerate here. We use 3-fold submission-group CV instead:
    # hold out 6 submissions → train on the other 12 submissions' patches.
    # The held-out group's submissions never appear in training. Within-instance
    # AUC on the test fold requires ≥2 distinct submissions per instance.
    rng_ctrl = np.random.default_rng(42)
    shuffled_subs = rng_ctrl.permutation(sorted(subs))
    sub_folds = [list(fold) for fold in np.array_split(shuffled_subs, 3)]

    h2_lsgo_win_aucs: list[float] = []
    base_a_lsgo_win_aucs: list[float] = []
    lsgo_fold_sizes: list[int] = []

    vec_patch = TfidfVectorizer(
        max_features=5000, ngram_range=(1, 2),
        token_pattern=r"(?u)\b\w+\b|[\+\-\@\=\#]",
    )

    for fold_subs in sub_folds:
        df_te_fold = df[df["submission"].isin(fold_subs)]
        df_tr_fold = df[~df["submission"].isin(fold_subs)]

        y_tr_f = df_tr_fold["resolved"].values.astype(int)
        y_te_f = df_te_fold["resolved"].values.astype(int)

        if len(df_tr_fold) == 0 or len(np.unique(y_tr_f)) < 2 or len(np.unique(y_te_f)) < 2:
            continue

        lsgo_fold_sizes.append(len(df_te_fold))

        # H2
        X_tr_r = df_rule_feats.loc[df_tr_fold.index].values
        X_te_r = df_rule_feats.loc[df_te_fold.index].values
        sc = StandardScaler().fit(X_tr_r)
        clf_lsgo = LogisticRegression(C=1.0, max_iter=1000, random_state=42).fit(
            sc.transform(X_tr_r), y_tr_f
        )
        pr_h2 = clf_lsgo.predict_proba(sc.transform(X_te_r))[:, 1]
        res_h2 = calc_within_instance_auc(df_te_fold, y_te_f, pr_h2)
        if res_h2["n_instances"] > 0:
            h2_lsgo_win_aucs.append(res_h2["mean_auc"])

        # Baseline A (Patch TF-IDF)
        x_tr_p = vec_patch.fit_transform(df_tr_fold["patch"].fillna(""))
        x_te_p = vec_patch.transform(df_te_fold["patch"].fillna(""))
        clf_a_lsgo = LogisticRegression(C=1.0, max_iter=1000, random_state=42).fit(x_tr_p, y_tr_f)
        pr_a = clf_a_lsgo.predict_proba(x_te_p)[:, 1]
        res_a = calc_within_instance_auc(df_te_fold, y_te_f, pr_a)
        if res_a["n_instances"] > 0:
            base_a_lsgo_win_aucs.append(res_a["mean_auc"])

    ctrl_i_h2_within_auc = float(np.mean(h2_lsgo_win_aucs)) if h2_lsgo_win_aucs else 0.0
    ctrl_i_base_a_within_auc = float(np.mean(base_a_lsgo_win_aucs)) if base_a_lsgo_win_aucs else 0.0
    ctrl_i_note = (
        "3-fold submission-group CV (6 subs held out / 12 train). "
        "Per-submission instance-disjoint LSGO is degenerate in this dataset "
        "(every instance_id appears in all 18 submissions, so exclusion empties training)."
    )

    # Control (ii): Predict WHICH submission wrote the patch from rule features
    sub_to_idx = {s: i for i, s in enumerate(subs)}
    y_sub_all = np.array([sub_to_idx[s] for s in df["submission"]])
    X_all_rule_scaled = StandardScaler().fit_transform(df_rule_feats.values)
    clf_sub_id = LogisticRegression(C=1.0, max_iter=1000, random_state=42)
    # Use position-based indexing for train mask
    train_positional = [i for i, (idx, _) in enumerate(df.iterrows()) if idx in df_train.index]
    test_positional = [i for i, (idx, _) in enumerate(df.iterrows()) if idx in df_test.index]
    clf_sub_id.fit(X_all_rule_scaled[train_positional], y_sub_all[train_positional])
    y_sub_pred = clf_sub_id.predict(X_all_rule_scaled[test_positional])
    acc_sub_predict = float(accuracy_score(y_sub_all[test_positional], y_sub_pred))
    chance_level = float(1.0 / len(subs))
    sub_counts_test = pd.Series(list(df_test["submission"])).value_counts()
    majority_prevalence_test = float(sub_counts_test.max() / len(df_test))

    # ── 4. Pre-Registered Success Bar ───────────────────────────────────────
    h2_val_w_auc = val_eval_results["(H2) All Rule Features LogReg"]["within_instance_auc"]
    h2_test_ci_low = test_eval_results["(H2) All Rule Features LogReg"]["within_instance_auc_ci"][0]

    bar_pass_val = h2_val_w_auc >= 0.70
    bar_pass_ci = h2_test_ci_low > 0.50
    bar_pass_ctrl_i = ctrl_i_h2_within_auc > 0.50

    bar_met = bool(bar_pass_val and bar_pass_ci and bar_pass_ctrl_i)
    bar_status_str = "bar met" if bar_met else "bar NOT met"

    print("\n==========================================")
    print(f"Pre-registered Success Bar Result: {bar_status_str}")
    print(f" - Val Within-Inst AUC >= 0.70:          {h2_val_w_auc:.3f} ({'PASSED' if bar_pass_val else 'FAILED'})")
    print(f" - Test 95% CI Lower Bound > 0.50:       {h2_test_ci_low:.3f} ({'PASSED' if bar_pass_ci else 'FAILED'})")
    print(f" - Control (i) LSGO Within-Inst AUC > 0.50: {ctrl_i_h2_within_auc:.3f} ({'PASSED' if bar_pass_ctrl_i else 'FAILED'})")
    print("==========================================\n")

    # ── 5. Top 10 Worst Ranked Patches by H2 (test multi-label instances) ──
    h2_test_probs = test_probs["(H2) All Rule Features LogReg"]
    test_multi_inst_ids = {
        iid for iid in df_test["instance_id"].unique()
        if len(np.unique(df_test[df_test["instance_id"] == iid]["resolved"].values)) > 1
    }

    patch_errors = []
    for idx_rel, (idx_abs, row) in enumerate(df_test.iterrows()):
        iid = row["instance_id"]
        if iid in test_multi_inst_ids:
            yt = int(row["resolved"])
            yp = float(h2_test_probs[idx_rel])
            patch_errors.append({
                "abs_idx": int(idx_abs),
                "instance_id": iid,
                "submission": row["submission"],
                "resolved": yt,
                "h2_prob": yp,
                "error": abs(yt - yp),
                "patch_snippet": str(row["patch"])[:500],
            })

    patch_errors.sort(key=lambda x: x["error"], reverse=True)
    top10_worst_patches = patch_errors[:10]

    # Load Baseline A, D, E from results/baselines.json
    baselines_json_data = {}
    if os.path.exists(BASELINES_JSON):
        with open(BASELINES_JSON, encoding="utf-8") as f:
            baselines_json_data = json.load(f)

    results_data = {
        "bar_status": bar_status_str,
        "bar_criteria": {
            "val_within_instance_auc": h2_val_w_auc,
            "val_pass": bar_pass_val,
            "test_ci_lower_bound": h2_test_ci_low,
            "ci_pass": bar_pass_ci,
            "control_i_h2_within_auc": ctrl_i_h2_within_auc,
            "control_i_pass": bar_pass_ctrl_i,
        },
        "overall_fire_rates": overall_fire_rates,
        "rare_rules_under_1pct": rare_rules,
        "submission_fire_rates": submission_fire_rates,
        "val_eval_results": val_eval_results,
        "test_eval_results": test_eval_results,
        "controls": {
            "control_i_method_note": ctrl_i_note,
            "control_i_lsgo_within_auc": {
                "H2_All_Rule_Features": ctrl_i_h2_within_auc,
                "Baseline_A_Patch_TFIDF": ctrl_i_base_a_within_auc,
                "n_folds": len(h2_lsgo_win_aucs),
            },
            "control_ii_submission_prediction": {
                "accuracy": acc_sub_predict,
                "chance_level": chance_level,
                "majority_prevalence_test": majority_prevalence_test,
            },
        },
        "top10_worst_patches": top10_worst_patches,
        "baselines_reference": baselines_json_data.get("eval_results", {}).get("all_test_rows", {}),
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(HEURISTICS_JSON, "w", encoding="utf-8") as f:
        json.dump(results_data, f, indent=2)

    md_content = generate_markdown_report(results_data)
    with open(HEURISTICS_MD, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(md_content)
    append_phase3_to_data_md(results_data)
    return results_data


def generate_markdown_report(data: dict) -> str:
    lines = [
        f"{data['bar_status']}",
        "",
        "# Phase 3 Relational Heuristics Evaluation & Control Experiments",
        "",
        "## 1. Pre-Registered Success Bar Evaluation",
        "",
        f"- **Status:** `{data['bar_status']}`",
        "- **Criteria Check:**",
        f"  1. H2 Within-Instance AUC on Validation Set >= 0.70: `{data['bar_criteria']['val_within_instance_auc']:.3f}` ({'PASSED' if data['bar_criteria']['val_pass'] else 'FAILED'})",
        f"  2. H2 Within-Instance AUC 95% CI Lower Bound on Test Set > 0.50: `{data['bar_criteria']['test_ci_lower_bound']:.3f}` ({'PASSED' if data['bar_criteria']['ci_pass'] else 'FAILED'})",
        f"  3. H2 Within-Instance AUC under LSGO Control (i) > 0.50: `{data['bar_criteria']['control_i_h2_within_auc']:.3f}` ({'PASSED' if data['bar_criteria']['control_i_pass'] else 'FAILED'})",
        "",
        "## 2. Rule Fire Rates",
        "",
        "### Overall Rule Fire Rates (5,123 Total Patches)",
        "",
        "| Rule ID | Fire Count | Fire Percentage |",
        "|---|---|---|",
    ]

    for r_id, r_info in data["overall_fire_rates"].items():
        lines.append(f"| `{r_id}` | {r_info['count']} | {r_info['percentage']:.2f}% |")

    lines.extend(["", "### Rules Firing on <1% of Rows"])
    if data["rare_rules_under_1pct"]:
        for r_id in data["rare_rules_under_1pct"]:
            lines.append(f"- `{r_id}` (Fire rate: `{data['overall_fire_rates'][r_id]['percentage']:.2f}%`)")
    else:
        lines.append("- None (all 8 rules fired on >=1% of total patches).")

    lines.extend([
        "",
        "### Submission Fire Rates Matrix",
        "",
        "| Submission | Patches | R1 FileOverlap | R2 IdentOverlap | R3 LitHardcode | R4 SpecialCase | R5 Swallowed | R6 TestTamp | R7 Suppress | R8 ScopeCreep |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ])

    for sub, sub_info in data["submission_fire_rates"].items():
        n_p = sub_info["patch_count"]
        r = sub_info["rules"]
        lines.append(
            f"| `{sub}` | {n_p} | "
            f"{r['rule_1_issue_file_overlap']['count']} ({r['rule_1_issue_file_overlap']['percentage']:.1f}%) | "
            f"{r['rule_2_issue_identifier_overlap']['count']} ({r['rule_2_issue_identifier_overlap']['percentage']:.1f}%) | "
            f"{r['rule_3_issue_literal_hardcoding']['count']} ({r['rule_3_issue_literal_hardcoding']['percentage']:.1f}%) | "
            f"{r['rule_4_special_casing']['count']} ({r['rule_4_special_casing']['percentage']:.1f}%) | "
            f"{r['rule_5_swallowed_exceptions']['count']} ({r['rule_5_swallowed_exceptions']['percentage']:.1f}%) | "
            f"{r['rule_6_test_tampering']['count']} ({r['rule_6_test_tampering']['percentage']:.1f}%) | "
            f"{r['rule_7_suppression_markers']['count']} ({r['rule_7_suppression_markers']['percentage']:.1f}%) | "
            f"{r['rule_8_scope_creep']['count']} ({r['rule_8_scope_creep']['percentage']:.1f}%) |"
        )

    lines.extend([
        "",
        "## 3. Evaluation Results Tables",
        "",
        "### Test Set Evaluation Table",
        "",
        "| Model | Within-Inst AUC (95% CI) [Primary] | Global ROC-AUC (95% CI) | PR-AUC (95% CI) | Prec @ 5% FPR | FP / 100 @ 80% Rec |",
        "|---|---|---|---|---|---|",
    ])

    for m_name, m_metrics in data["test_eval_results"].items():
        w_str = f"{m_metrics['within_instance_auc']:.3f} [{m_metrics['within_instance_auc_ci'][0]:.3f}-{m_metrics['within_instance_auc_ci'][1]:.3f}]"
        roc_str = f"{m_metrics['roc_auc']:.3f} [{m_metrics['roc_auc_ci'][0]:.3f}-{m_metrics['roc_auc_ci'][1]:.3f}]"
        pr_str = f"{m_metrics['pr_auc']:.3f} [{m_metrics['pr_auc_ci'][0]:.3f}-{m_metrics['pr_auc_ci'][1]:.3f}]"
        prec_str = f"{m_metrics['prec_at_5fpr']:.1%}"
        fp_str = f"{m_metrics['fp_100_at_80rec']:.1f}"
        lines.append(f"| **{m_name}** | {w_str} | {roc_str} | {pr_str} | {prec_str} | {fp_str} |")

    lines.append("|---|---|---|---|---|---|")
    ref_b = data.get("baselines_reference", {})
    for b_name in ["(A) Patch TF-IDF + LogReg", "(D) Patch-Size Features LogReg", "(E) Combined A+B+D LogReg"]:
        if b_name in ref_b:
            bm = ref_b[b_name]
            w_str = f"{bm['within_instance_auc']:.3f} [{bm['within_instance_auc_ci'][0]:.3f}-{bm['within_instance_auc_ci'][1]:.3f}]"
            roc_str = f"{bm['roc_auc']:.3f} [{bm['roc_auc_ci'][0]:.3f}-{bm['roc_auc_ci'][1]:.3f}]"
            pr_str = f"{bm['pr_auc']:.3f} [{bm['pr_auc_ci'][0]:.3f}-{bm['pr_auc_ci'][1]:.3f}]"
            prec_str = f"{bm['prec_at_5fpr']:.1%}"
            fp_str = f"{bm['fp_100_at_80rec']:.1f}"
            lines.append(f"| *[Ref] {b_name}* | {w_str} | {roc_str} | {pr_str} | {prec_str} | {fp_str} |")

    lines.extend([
        "",
        "### Validation Set Evaluation Table (SymPy)",
        "",
        "| Model | Within-Inst AUC (95% CI) | Global ROC-AUC | PR-AUC | Prec @ 5% FPR | FP / 100 @ 80% Rec |",
        "|---|---|---|---|---|---|",
    ])

    for m_name, m_metrics in data["val_eval_results"].items():
        w_str = f"{m_metrics['within_instance_auc']:.3f} [{m_metrics['within_instance_auc_ci'][0]:.3f}-{m_metrics['within_instance_auc_ci'][1]:.3f}]"
        roc_str = f"{m_metrics['roc_auc']:.3f}"
        pr_str = f"{m_metrics['pr_auc']:.3f}"
        prec_str = f"{m_metrics['prec_at_5fpr']:.1%}"
        fp_str = f"{m_metrics['fp_100_at_80rec']:.1f}"
        lines.append(f"| **{m_name}** | {w_str} | {roc_str} | {pr_str} | {prec_str} | {fp_str} |")

    ctrls = data["controls"]
    c_i = ctrls["control_i_lsgo_within_auc"]
    c_ii = ctrls["control_ii_submission_prediction"]
    lines.extend([
        "",
        "## 4. Agent-Fingerprint Controls",
        "",
        "### Control (i): 3-Fold Submission-Group Leave-Out (LSGO) Within-Instance AUC",
        "",
        f"> **Method note:** {ctrls['control_i_method_note']}",
        "",
        f"- Model H2 (All Rule Features): `{c_i['H2_All_Rule_Features']:.3f}` ({c_i['n_folds']} folds)",
        f"- Baseline A (Patch TF-IDF): `{c_i['Baseline_A_Patch_TFIDF']:.3f}` ({c_i['n_folds']} folds)",
        "",
        "### Control (ii): Submission Origin Prediction from Rule Features",
        "",
        f"- Rule Features Model Accuracy: `{c_ii['accuracy']:.1%}`",
        f"- Random Chance Level (1/{int(round(1/c_ii['chance_level']))}): `{c_ii['chance_level']:.1%}`",
        f"- Majority Class Prevalence (Test): `{c_ii['majority_prevalence_test']:.1%}`",
        "",
        "### Control (iii): Submission Fire Rates Matrix",
        "",
        "See Section 2 Submission Fire Rates Matrix above.",
        "",
        "## 5. Top 10 Most Wrongly Ranked Patches by Model H2 (Test Split)",
        "",
    ])

    for rank, p_err in enumerate(data["top10_worst_patches"], 1):
        lines.extend([
            f"### {rank}. Instance `{p_err['instance_id']}` | Submission `{p_err['submission']}`",
            f"- **Resolved Label:** `{p_err['resolved']}` | **H2 Predicted Prob:** `{p_err['h2_prob']:.4f}` | **Error:** `{p_err['error']:.4f}`",
            "```diff",
            p_err["patch_snippet"].strip(),
            "```",
            "",
        ])

    return "\n".join(lines)


def append_phase3_to_data_md(data: dict) -> None:
    """Append Phase 3 evaluation section to docs/DATA.md."""
    if not os.path.exists(DATA_MD):
        return

    c_i = data["controls"]["control_i_lsgo_within_auc"]
    c_ii = data["controls"]["control_ii_submission_prediction"]
    te_h2 = data["test_eval_results"]["(H2) All Rule Features LogReg"]
    te_h3 = data["test_eval_results"]["(H3) H2 + Baseline D Features LogReg"]

    phase3_section = "\n".join([
        "",
        "---",
        "",
        "## 5. Phase 3 Relational Heuristics Evaluation & Controls",
        "",
        f"- **Pre-Registered Success Bar Status:** `{data['bar_status']}`",
        f"  - Val Within-Instance AUC: `{data['bar_criteria']['val_within_instance_auc']:.3f}` (target >= 0.70)",
        f"  - Test 95% CI Lower Bound: `{data['bar_criteria']['test_ci_lower_bound']:.3f}` (target > 0.50)",
        f"  - Control (i) LSGO Within-Instance AUC: `{data['bar_criteria']['control_i_h2_within_auc']:.3f}` (target > 0.50)",
        "- **Model Performance Summary (Test Set):**",
        f"  - H2 (All Rule Features): Within-Inst AUC = `{te_h2['within_instance_auc']:.3f}` [{te_h2['within_instance_auc_ci'][0]:.3f}-{te_h2['within_instance_auc_ci'][1]:.3f}]",
        f"  - H3 (H2 + Baseline D): Within-Inst AUC = `{te_h3['within_instance_auc']:.3f}` [{te_h3['within_instance_auc_ci'][0]:.3f}-{te_h3['within_instance_auc_ci'][1]:.3f}]",
        "- **Agent Fingerprinting Controls:**",
        f"  - Submission Origin Prediction Accuracy: `{c_ii['accuracy']:.1%}` vs Chance `{c_ii['chance_level']:.1%}`",
        f"  - 3-Fold LSGO Within-Instance AUC (H2): `{c_i['H2_All_Rule_Features']:.3f}` | Baseline A: `{c_i['Baseline_A_Patch_TFIDF']:.3f}`",
        "  - Note: Per-submission instance-disjoint LSGO is degenerate in this dataset (all instance_ids appear in all submissions).",
    ])

    with open(DATA_MD, "a", encoding="utf-8") as f:
        f.write(phase3_section)


if __name__ == "__main__":
    run_evaluation()
