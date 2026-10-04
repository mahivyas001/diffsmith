"""
tests/test_baselines.py — Unit tests for metric helper functions in scripts/baselines.py

Rule: No model training of any kind.
"""

import os
import sys
import numpy as np

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.baselines import (
    calc_fp_per_100_at_recall,
    calc_prec_at_fpr,
    extract_patch_size_features,
)


def test_calc_prec_at_fpr():
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0])
    y_prob = np.array([0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.1])
    prec = calc_prec_at_fpr(y_true, y_prob, target_fpr=0.05)
    assert isinstance(prec, float)
    assert prec >= 0.0 and prec <= 1.0


def test_calc_fp_per_100_at_recall():
    y_true = np.array([1, 1, 1, 1, 0, 0, 0, 0])
    y_prob = np.array([0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.1])
    fp_100 = calc_fp_per_100_at_recall(y_true, y_prob, target_recall=0.80)
    assert isinstance(fp_100, float)
    assert fp_100 >= 0.0 and fp_100 <= 100.0


def test_extract_patch_size_features():
    patch_sample = (
        "diff --git a/test.py b/test.py\n"
        "--- a/test.py\n"
        "+++ b/test.py\n"
        "@@ -1,3 +1,4 @@\n"
        " context line\n"
        "+added line 1\n"
        "+added line 2\n"
        "-removed line 1\n"
    )
    features = extract_patch_size_features([patch_sample])
    assert features.shape == (1, 5)
    # lines_added=2, lines_removed=1, total=3, files=2 (--- and diff), hunks=1
    assert features[0][0] == 2.0  # added
    assert features[0][1] == 1.0  # removed
    assert features[0][2] == 3.0  # total
