"""
scripts/eval_injection.py — Evaluation of prompt-injection shield on real SWE-bench issues.

Scans distinct real issue texts across all SWE-bench instances (nothing known to be
malicious; any hit is a potential false alarm).
Reports flagged count, per-rule fire counts, and flagged examples (up to 10).
"""

import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.getcwd(), "src"))
sys.path.insert(0, os.getcwd())

from diffsmith.safety.injection import scan_text
from scripts.baselines import load_and_prepare_data


def main():
    random.seed(42)
    df = load_and_prepare_data().drop_duplicates("instance_id")
    total_instances = len(df)

    flagged_instances = []
    rule_counts = Counter()

    for _, row in df.iterrows():
        instance_id = str(row["instance_id"])
        text = str(row.get("problem_statement", ""))
        findings = scan_text(text, source="issue")
        if findings:
            flagged_instances.append((instance_id, findings))
            for f in findings:
                rule_counts[f["rule_id"]] += 1

    lines = [
        "# Prompt-Injection Shield Evaluation: Real SWE-Bench Issues",
        "",
        "Evaluation of prompt injection shield across distinct real-world issue statements.",
        "Nothing in this dataset is known to be malicious, so hits measure false-positive rate.",
        "",
        f"- **Total distinct instances scanned**: {total_instances}",
        f"- **Total flagged instances**: {len(flagged_instances)} ({len(flagged_instances) / total_instances * 100:.2f}%)",
        "",
        "## Per-Rule Fire Counts",
        "",
        "| Rule ID | Description | Fires |",
        "|---|---|---|",
    ]

    rule_descriptions = {
        "INJ001": "Instruction override",
        "INJ002": "Role/system impersonation",
        "INJ003": "Exfiltration",
        "INJ004": "Concealment",
        "INJ005": "Authority claims",
        "INJ006": "Malicious assistant instructions",
    }

    for rule_id in sorted(rule_descriptions.keys()):
        count = rule_counts.get(rule_id, 0)
        lines.append(f"| {rule_id} | {rule_descriptions[rule_id]} | {count} |")

    lines.extend([
        "",
        "## Flagged Examples (up to 10)",
        "",
    ])

    if not flagged_instances:
        lines.append("*(No real issue texts flagged: zero false alarms.)*")
    else:
        sample_count = min(10, len(flagged_instances))
        sampled = random.sample(flagged_instances, sample_count)
        for iid, findings in sampled:
            rules_str = ", ".join(sorted({f["rule_id"] for f in findings}))
            ev = findings[0].get("evidence", "")[:120]
            lines.append(f"- **{iid}** ({rules_str}): `{ev}`")

    output_text = "\n".join(lines) + "\n"
    print(output_text)

    # Save report
    results_dir = os.path.join(os.getcwd(), "results")
    if os.path.isdir(results_dir):
        out_path = os.path.join(results_dir, "injection.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(output_text)


if __name__ == "__main__":
    main()
