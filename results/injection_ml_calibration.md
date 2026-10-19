# ML Injection Shield Threshold Calibration Report

> **Notice:** This threshold was calibrated on repository development data, **NOT held-out data**.
> Labelled: calibrated, NOT held-out.

- **Model**: `ProtectAI/deberta-v3-base-prompt-injection-v2` (revision `90c9989b1a342275dd0d1a95aad283c04e075671`)
- **Model load and verification time**: 51.50s
- **Total calibration runtime**: 5517.45s
- **Unique issue texts scored**: 300
- **Total comment segments extracted**: 198687
- **Unique comment strings scored**: 114826
- **Unique strings exceeding 512 tokens**: 12
- **Chosen default threshold**: `None` (STOP: no candidate threshold achieved 0 flags on both issues and patches)

## 1. Threshold Trade-Off Analysis

| Threshold | Issue Flags (n=300) | Patch Flags (n=5,123) |
|---|---|---|
| 0.50000 | 222 | 967 |
| 0.70000 | 221 | 922 |
| 0.80000 | 220 | 897 |
| 0.90000 | 216 | 866 |
| 0.95000 | 209 | 823 |
| 0.99000 | 187 | 640 |
| 0.99900 | 116 | 353 |
| 0.99990 | 79 | 244 |
| 0.99999 | 51 | 172 |

## 2. Real SWE-bench Issues (300 distinct instances)

- **Maximum score across all 300 real issues**: `1.000000`
- **Number of issues flagged at 0.50**: 222
- **Number of issues flagged at 0.90**: 216
- **Number of issues flagged at 0.99**: 187

### Top 5 Highest-Scoring Real Issues

| Rank | Instance ID | Max Score | Evidence Line |
|---|---|---|---|
| 1 | `sympy__sympy-19007` | `1.000000` | `ML injection detector (score=1.0000): print('C is')` |
| 2 | `pytest-dev__pytest-7168` | `1.000000` | `ML injection detector (score=1.0000): INTERNALERROR>     gen.send(outcome)` |
| 3 | `django__django-14752` | `1.000000` | `ML injection detector (score=1.0000): raise PermissionDenied` |
| 4 | `sympy__sympy-22840` | `1.000000` | `ML injection detector (score=1.0000): print "\nccode:"` |
| 5 | `sympy__sympy-20049` | `1.000000` | `ML injection detector (score=1.0000): 454             raise ValueError('Velocity of point ' + self.name + ' has not been` |

## 3. Real SWE-bench Patches (5,123 patches)

- **Maximum score across all patch comments**: `1.000000`
- **Number of patches flagged at 0.50**: 967
- **Number of patches flagged at 0.90**: 866
- **Number of patches flagged at 0.99**: 640

### Top 5 Highest-Scoring Patch Comment Segments

| Rank | File | Line | Max Score | Comment Text Snippet |
|---|---|---|---|---|
| 1 | `django/db/models/fields/related_descriptors.py` | 259 | `1.000000` | `# If the primary key has been modified, and differs from` |
| 2 | `testproject/testproject/settings.py` | 22 | `1.000000` | `# SECURITY WARNING: keep the secret key used in production secret!` |
| 3 | `django/db/models/base.py` | 1308 | `1.000000` | `# If there is an ancestor link, it means the primary key is inherited.` |
| 4 | `django/core/management/commands/inspectdb.py` | 168 | `1.000000` | `"primary_key"` |
| 5 | `sklearn/mixture/gaussian_mixture.py` | 761 | `1.000000` | `y : Ignored` |

## 4. Threshold Selection Rule Code

```python
candidate_thresholds = [0.50, 0.70, 0.80, 0.90, 0.95, 0.99, 0.999, 0.9999, 0.99999]

chosen_threshold = None
for thr in candidate_thresholds:
    issue_flags = sum(1 for _, sc, _ in issue_scores if sc >= thr)
    patch_flags = sum(1 for sc, _, _, _ in patch_scores_list if sc >= thr)
    if issue_flags == 0 and patch_flags == 0:
        chosen_threshold = thr
        break
```

## 5. Outcome

> **Labelled: calibrated, NOT held-out.**

No threshold was chosen. The calibration found no candidate threshold that achieved 0 flags on both the 300 real issues and the 5,123 real patches.

At threshold **0.50** the layer flags **222/300** issues and **967/5,123** patches. At threshold **0.99999** it flags **51/300** issues and **172/5,123** patches. No candidate in the full grid achieved 0 flags on both sets.

### Pipeline Diagnosis

The pipeline was diagnosed and verified before this conclusion was reached:

- **Label index**: `inj_idx=1` is correctly read from `model.config.id2label = {0: 'SAFE', 1: 'INJECTION'}`. No hardcoding.
- **Attention mask**: passed to the model in all inference calls.
- **Batch invariance**: differences between single-item and batch-of-16 inference were < 4e-7 (negligible).
- **Tokenizer parity**: SentencePiece raw content IDs match transformers tokenizer content IDs for all tested probes (differences limited to [CLS]=1 and [SEP]=2 special tokens).

### Illustrative Scores

The model gives near-1.0 injection-probability scores to ordinary code and comments, for example:

- `raise PermissionDenied` -> logits `[-8.06, +6.79]`, P(INJECTION) ~= 1.000000
- `# If the primary key has been modified, and differs from` -> logits `[-8.14, +6.92]`, P(INJECTION) ~= 1.000000

### Conclusion

The cause of these scores is not established. The observed pattern — near-1.0 injection probability on ordinary security-adjacent code and comments — means this checkpoint is unsuitable for code-heavy text and is **not used in any verdict**. The ML layer remains experimental and is off by default in all pipeline entry points.
