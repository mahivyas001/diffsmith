"""scripts/wilson_intervals.py — Wilson 95% confidence intervals for empirical metrics.

Computes Wilson score intervals (without continuity correction) using Python stdlib.
"""

from __future__ import annotations

import math


def wilson_interval(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Compute the Wilson score interval for k successes out of n trials.

    Args:
        k: Number of successes / positive counts.
        n: Total number of trials / observations.
        confidence: Desired confidence level (default 0.95).

    Returns:
        tuple (lower, upper) bounded in [0.0, 1.0].
    """
    if n <= 0:
        return 0.0, 0.0

    # z = 1.959964 for 95% two-sided normal quantile
    # Derived from standard normal distribution quantile for alpha = 1 - confidence
    z = 1.959963984540054 if confidence == 0.95 else 1.959964
    p = k / n
    denominator = 1.0 + (z**2) / n
    centre = (p + (z**2) / (2.0 * n)) / denominator
    spread = (z * math.sqrt((p * (1.0 - p) / n) + ((z**2) / (4.0 * (n**2))))) / denominator

    lower = max(0.0, centre - spread)
    upper = min(1.0, centre + spread)
    return lower, upper


def main() -> None:
    cases = [
        ("Security Set B v1: plain (expected rule)", 21, 36),
        ("Security Set B v1: plain (any rule)", 22, 36),
        ("Security Set B v1: evasion (expected rule)", 5, 14),
        ("Security Set B v1: evasion (any rule)", 10, 14),
        ("Security Set B v1: benign false alarms", 1, 16),
        ("Injection Set C v1: plain", 2, 22),
        ("Injection Set C v1: evasion", 2, 14),
        ("Injection Set C v1: benign false alarms", 0, 37),
        ("Real patches (SWE-bench): flagged", 186, 5123),
    ]

    print(f"{'Label':<42} {'k/n':<12} {'Rate':<8} {'Wilson 95% CI':<24} {'Percent CI':<24}")
    print("-" * 115)
    for label, k, n in cases:
        p = k / n
        low, high = wilson_interval(k, n)
        pct = p * 100
        pct_low = low * 100
        pct_high = high * 100
        kn_str = f"{k}/{n}"
        rate_str = f"{p:.4f}"
        ci_str = f"[{low:.4f}, {high:.4f}]"
        pct_ci_str = f"{pct:.2f}% [{pct_low:.2f}%, {pct_high:.2f}%]"
        print(f"{label:<42} {kn_str:<12} {rate_str:<8} {ci_str:<24} {pct_ci_str:<24}")


if __name__ == "__main__":
    main()
