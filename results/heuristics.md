bar NOT met

# Phase 3 Relational Heuristics Evaluation & Control Experiments

## 1. Pre-Registered Success Bar Evaluation

- **Status:** `bar NOT met`
- **Criteria Check:**
  1. H2 Within-Instance AUC on Validation Set >= 0.70: `0.505` (FAILED)
  2. H2 Within-Instance AUC 95% CI Lower Bound on Test Set > 0.50: `0.409` (FAILED)
  3. H2 Within-Instance AUC under LSGO Control (i) > 0.50: `0.502` (PASSED)

## 2. Rule Fire Rates

### Overall Rule Fire Rates (5,123 Total Patches)

| Rule ID | Fire Count | Fire Percentage |
|---|---|---|
| `rule_1_issue_file_overlap` | 3385 | 66.07% |
| `rule_2_issue_identifier_overlap` | 3342 | 65.24% |
| `rule_3_issue_literal_hardcoding` | 576 | 11.24% |
| `rule_4_special_casing` | 33 | 0.64% |
| `rule_5_swallowed_exceptions` | 24 | 0.47% |
| `rule_6_test_tampering` | 78 | 1.52% |
| `rule_7_suppression_markers` | 11 | 0.21% |
| `rule_8_scope_creep` | 1686 | 32.91% |

### Rules Firing on <1% of Rows
- `rule_4_special_casing` (Fire rate: `0.64%`)
- `rule_5_swallowed_exceptions` (Fire rate: `0.47%`)
- `rule_7_suppression_markers` (Fire rate: `0.21%`)

### Submission Fire Rates Matrix

| Submission | Patches | R1 FileOverlap | R2 IdentOverlap | R3 LitHardcode | R4 SpecialCase | R5 Swallowed | R6 TestTamp | R7 Suppress | R8 ScopeCreep |
|---|---|---|---|---|---|---|---|---|---|
| `20231010_rag_claude2` | 299 | 197 (65.9%) | 174 (58.2%) | 15 (5.0%) | 2 (0.7%) | 1 (0.3%) | 1 (0.3%) | 1 (0.3%) | 95 (31.8%) |
| `20240402_rag_claude3opus` | 300 | 197 (65.7%) | 172 (57.3%) | 18 (6.0%) | 3 (1.0%) | 0 (0.0%) | 2 (0.7%) | 0 (0.0%) | 98 (32.7%) |
| `20240523_aider` | 290 | 188 (64.8%) | 177 (61.0%) | 24 (8.3%) | 2 (0.7%) | 0 (0.0%) | 1 (0.3%) | 0 (0.0%) | 87 (30.0%) |
| `20240612_IBM_Research_Agent101` | 293 | 194 (66.2%) | 238 (81.2%) | 87 (29.7%) | 2 (0.7%) | 1 (0.3%) | 10 (3.4%) | 2 (0.7%) | 83 (28.3%) |
| `20240617_moatless_gpt4o` | 289 | 191 (66.1%) | 170 (58.8%) | 26 (9.0%) | 1 (0.3%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 87 (30.1%) |
| `20240627_abanteai_mentatbot_gpt4o` | 296 | 193 (65.2%) | 236 (79.7%) | 73 (24.7%) | 2 (0.7%) | 0 (0.0%) | 10 (3.4%) | 0 (0.0%) | 140 (47.3%) |
| `20240721_amazon-q-developer-agent-20240719-dev` | 299 | 196 (65.6%) | 202 (67.6%) | 24 (8.0%) | 1 (0.3%) | 0 (0.0%) | 3 (1.0%) | 1 (0.3%) | 92 (30.8%) |
| `20240808_RepoGraph_gpt4o` | 294 | 194 (66.0%) | 165 (56.1%) | 23 (7.8%) | 1 (0.3%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 88 (29.9%) |
| `20240829_Isoform` | 297 | 195 (65.7%) | 171 (57.6%) | 21 (7.1%) | 0 (0.0%) | 0 (0.0%) | 1 (0.3%) | 0 (0.0%) | 89 (30.0%) |
| `20241016_IBM-SWE-1.0` | 299 | 198 (66.2%) | 185 (61.9%) | 27 (9.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 89 (29.8%) |
| `20241113_navie-2-gpt4o-sonnet` | 299 | 197 (65.9%) | 195 (65.2%) | 24 (8.0%) | 1 (0.3%) | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) | 89 (29.8%) |
| `20241127_globant_codefixer_agent` | 285 | 190 (66.7%) | 185 (64.9%) | 21 (7.4%) | 2 (0.7%) | 1 (0.4%) | 2 (0.7%) | 0 (0.0%) | 84 (29.5%) |
| `20241207_kodu_sonnet_v1` | 232 | 156 (67.2%) | 197 (84.9%) | 53 (22.8%) | 2 (0.9%) | 4 (1.7%) | 38 (16.4%) | 2 (0.9%) | 141 (60.8%) |
| `20250104_patched_codes_claude-3.5-sonnet-20241022` | 192 | 132 (68.8%) | 144 (75.0%) | 24 (12.5%) | 5 (2.6%) | 8 (4.2%) | 2 (1.0%) | 2 (1.0%) | 58 (30.2%) |
| `20250226_sweagent_claude-3-7-sonnet-20250219` | 298 | 196 (65.8%) | 222 (74.5%) | 49 (16.4%) | 6 (2.0%) | 3 (1.0%) | 0 (0.0%) | 1 (0.3%) | 93 (31.2%) |
| `20250509_Lingxi_claude-3-5-sonnet-20241022` | 299 | 197 (65.9%) | 201 (67.2%) | 30 (10.0%) | 2 (0.7%) | 2 (0.7%) | 4 (1.3%) | 0 (0.0%) | 97 (32.4%) |
| `20250627_agentless_MCTS-Refine-7B` | 262 | 177 (67.6%) | 134 (51.1%) | 13 (5.0%) | 0 (0.0%) | 1 (0.4%) | 0 (0.0%) | 2 (0.8%) | 83 (31.7%) |
| `20250911_isea_claude-3.5-sonnet-20241022` | 300 | 197 (65.7%) | 174 (58.0%) | 24 (8.0%) | 1 (0.3%) | 3 (1.0%) | 4 (1.3%) | 0 (0.0%) | 93 (31.0%) |

## 3. Evaluation Results Tables

### Test Set Evaluation Table

| Model | Within-Inst AUC (95% CI) [Primary] | Global ROC-AUC (95% CI) | PR-AUC (95% CI) | Prec @ 5% FPR | FP / 100 @ 80% Rec |
|---|---|---|---|---|---|
| **(H1) Feature: fraction_touched_named** | 0.461 [0.418-0.498] | 0.555 [0.432-0.663] | 0.309 [0.190-0.437] | 24.0% | 53.5 |
| **(H1) Feature: any_named_untouched** | 0.502 [0.500-0.506] | 0.492 [0.423-0.580] | 0.282 [0.188-0.404] | 26.9% | 58.0 |
| **(H1) Feature: issue_identifier_overlap_frac** | 0.484 [0.382-0.571] | 0.538 [0.415-0.652] | 0.320 [0.218-0.453] | 36.7% | 55.2 |
| **(H1) Feature: literal_hardcoding_count** | 0.496 [0.455-0.536] | 0.487 [0.417-0.533] | 0.280 [0.174-0.384] | 9.5% | 57.1 |
| **(H1) Feature: has_literal_hardcoding** | 0.491 [0.450-0.530] | 0.483 [0.407-0.531] | 0.279 [0.173-0.383] | 9.5% | 57.1 |
| **(H1) Feature: special_casing_count** | 0.501 [0.500-0.504] | 0.509 [0.500-0.524] | 0.289 [0.192-0.393] | 5.0% | 59.9 |
| **(H1) Feature: has_special_casing** | 0.501 [0.500-0.504] | 0.509 [0.500-0.524] | 0.289 [0.192-0.393] | 5.0% | 59.9 |
| **(H1) Feature: swallowed_exception_count** | 0.496 [0.488-0.503] | 0.496 [0.486-0.504] | 0.284 [0.186-0.388] | 5.0% | 60.1 |
| **(H1) Feature: has_swallowed_exception** | 0.496 [0.488-0.503] | 0.496 [0.486-0.504] | 0.284 [0.186-0.388] | 5.0% | 60.1 |
| **(H1) Feature: test_tampering_count** | 0.521 [0.500-0.562] | 0.503 [0.500-0.513] | 0.290 [0.196-0.395] | 36.7% | 57.1 |
| **(H1) Feature: has_test_tampering** | 0.521 [0.500-0.562] | 0.503 [0.500-0.513] | 0.290 [0.196-0.395] | 36.7% | 57.1 |
| **(H1) Feature: suppression_marker_count** | 0.500 [0.500-0.500] | 0.501 [0.500-0.504] | 0.286 [0.190-0.391] | 5.0% | 60.1 |
| **(H1) Feature: has_suppression_marker** | 0.500 [0.500-0.500] | 0.501 [0.500-0.504] | 0.286 [0.190-0.391] | 5.0% | 60.1 |
| **(H1) Feature: scope_creep_count** | 0.417 [0.354-0.475] | 0.497 [0.386-0.608] | 0.285 [0.180-0.412] | 26.9% | 56.7 |
| **(H1) Feature: scope_creep_fraction** | 0.452 [0.413-0.487] | 0.516 [0.406-0.622] | 0.291 [0.182-0.420] | 26.9% | 55.4 |
| **(H2) All Rule Features LogReg** | 0.503 [0.409-0.592] | 0.557 [0.426-0.677] | 0.354 [0.225-0.502] | 45.7% | 53.5 |
| **(H3) H2 + Baseline D Features LogReg** | 0.502 [0.408-0.599] | 0.587 [0.475-0.686] | 0.389 [0.247-0.537] | 50.0% | 49.4 |
|---|---|---|---|---|---|
| *[Ref] (A) Patch TF-IDF + LogReg* | 0.625 [0.540-0.704] | 0.613 [0.515-0.708] | 0.366 [0.223-0.531] | 42.4% | 44.0 |
| *[Ref] (D) Patch-Size Features LogReg* | 0.511 [0.432-0.586] | 0.593 [0.507-0.681] | 0.383 [0.223-0.567] | 51.3% | 50.9 |
| *[Ref] (E) Combined A+B+D LogReg* | 0.675 [0.579-0.769] | 0.721 [0.650-0.800] | 0.444 [0.330-0.575] | 45.7% | 33.6 |

### Validation Set Evaluation Table (SymPy)

| Model | Within-Inst AUC (95% CI) | Global ROC-AUC | PR-AUC | Prec @ 5% FPR | FP / 100 @ 80% Rec |
|---|---|---|---|---|---|
| **(H1) Feature: fraction_touched_named** | 0.480 [0.445-0.508] | 0.579 | 0.294 | 21.3% | 55.7 |
| **(H1) Feature: any_named_untouched** | 0.502 [0.491-0.512] | 0.461 | 0.240 | 18.6% | 58.1 |
| **(H1) Feature: issue_identifier_overlap_frac** | 0.507 [0.448-0.557] | 0.611 | 0.339 | 45.5% | 49.5 |
| **(H1) Feature: literal_hardcoding_count** | 0.492 [0.474-0.507] | 0.486 | 0.248 | 12.7% | 61.3 |
| **(H1) Feature: has_literal_hardcoding** | 0.490 [0.471-0.505] | 0.485 | 0.247 | 12.7% | 61.3 |
| **(H1) Feature: special_casing_count** | 0.504 [0.500-0.509] | 0.505 | 0.255 | 12.7% | 61.8 |
| **(H1) Feature: has_special_casing** | 0.504 [0.500-0.508] | 0.505 | 0.255 | 12.7% | 61.8 |
| **(H1) Feature: swallowed_exception_count** | 0.491 [0.474-0.503] | 0.501 | 0.253 | 12.7% | 62.0 |
| **(H1) Feature: has_swallowed_exception** | 0.490 [0.472-0.503] | 0.501 | 0.253 | 12.7% | 62.0 |
| **(H1) Feature: test_tampering_count** | 0.520 [0.498-0.551] | 0.501 | 0.256 | 21.3% | 62.5 |
| **(H1) Feature: has_test_tampering** | 0.520 [0.498-0.551] | 0.501 | 0.253 | 21.3% | 62.5 |
| **(H1) Feature: suppression_marker_count** | 0.501 [0.500-0.502] | 0.501 | 0.253 | 12.7% | 62.3 |
| **(H1) Feature: has_suppression_marker** | 0.501 [0.500-0.502] | 0.501 | 0.253 | 12.7% | 62.3 |
| **(H1) Feature: scope_creep_count** | 0.472 [0.440-0.496] | 0.516 | 0.260 | 2.0% | 59.2 |
| **(H1) Feature: scope_creep_fraction** | 0.480 [0.456-0.497] | 0.520 | 0.260 | 9.4% | 59.1 |
| **(H2) All Rule Features LogReg** | 0.505 [0.442-0.571] | 0.628 | 0.355 | 42.9% | 45.6 |
| **(H3) H2 + Baseline D Features LogReg** | 0.538 [0.469-0.609] | 0.638 | 0.363 | 42.9% | 45.8 |

## 4. Agent-Fingerprint Controls

### Control (i): 3-Fold Submission-Group Leave-Out (LSGO) Within-Instance AUC

> **Method note:** 3-fold submission-group CV (6 subs held out / 12 train). Per-submission instance-disjoint LSGO is degenerate in this dataset (every instance_id appears in all 18 submissions, so exclusion empties training).

- Model H2 (All Rule Features): `0.502` (3 folds)
- Baseline A (Patch TF-IDF): `0.670` (3 folds)

### Control (ii): Submission Origin Prediction from Rule Features

- Rule Features Model Accuracy: `12.3%`
- Random Chance Level (1/18): `5.6%`
- Majority Class Prevalence (Test): `6.0%`

### Control (iii): Submission Fire Rates Matrix

See Section 2 Submission Fire Rates Matrix above.

## 5. Top 10 Most Wrongly Ranked Patches by Model H2 (Test Split)

### 1. Instance `matplotlib__matplotlib-25442` | Submission `20241207_kodu_sonnet_v1`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.0006` | **Error:** `0.9994`
```diff
diff --git a/lib/matplotlib/offsetbox.py b/lib/matplotlib/offsetbox.py
index 77768e7..2a85a9f 100644
--- a/lib/matplotlib/offsetbox.py
+++ b/lib/matplotlib/offsetbox.py
@@ -1508,7 +1508,15 @@ class DraggableBase:
         ]

     # A property, not an attribute, to maintain picklability.
-    canvas = property(lambda self: self.ref_artist.figure.canvas)
+    @property
+    def canvas(self):
+        """Get the canvas, handling the case where figure is None."""
+        try:
+            if self.r
```

### 2. Instance `matplotlib__matplotlib-26020` | Submission `20250226_sweagent_claude-3-7-sonnet-20250219`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.0018` | **Error:** `0.9982`
```diff
diff --git a/lib/mpl_toolkits/axes_grid1/axes_grid.py b/lib/mpl_toolkits/axes_grid1/axes_grid.py
index 2b1b1d3200..a0098ea520 100644
--- a/lib/mpl_toolkits/axes_grid1/axes_grid.py
+++ b/lib/mpl_toolkits/axes_grid1/axes_grid.py
@@ -13,8 +13,48 @@ from .mpl_axes import Axes
 def _tick_only(ax, bottom_on, left_on):
     bottom_off = not bottom_on
     left_off = not left_on
-    ax.axis["bottom"].toggle(ticklabels=bottom_off, label=bottom_off)
-    ax.axis["left"].toggle(ticklabels=left_off, label=
```

### 3. Instance `matplotlib__matplotlib-23562` | Submission `20240721_amazon-q-developer-agent-20240719-dev`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2503` | **Error:** `0.7497`
```diff
--- a/lib/mpl_toolkits/mplot3d/art3d.py
+++ b/lib/mpl_toolkits/mplot3d/art3d.py
@@ -867,10 +867,17 @@
         self.stale = True
 
     def get_facecolor(self):
-        return self._facecolors2d
+        if hasattr(self, '_facecolors2d'):
+            return self._facecolors2d
+        else:
+            return self._facecolor3d
 
     def get_edgecolor(self):
-        return self._edgecolors2d
+        # Check if _edgecolors2d exists, otherwise fall back to _edgecolor3d
+        if hasattr(sel
```

### 4. Instance `matplotlib__matplotlib-23562` | Submission `20241113_navie-2-gpt4o-sonnet`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2503` | **Error:** `0.7497`
```diff
diff --git a/lib/mpl_toolkits/mplot3d/art3d.py b/lib/mpl_toolkits/mplot3d/art3d.py
index 8fe6e7a..ee4bc48 100644
--- a/lib/mpl_toolkits/mplot3d/art3d.py
+++ b/lib/mpl_toolkits/mplot3d/art3d.py
@@ -467,6 +467,9 @@ class Patch3DCollection(PatchCollection):
             return np.nan
 
     def _maybe_depth_shade_and_sort_colors(self, color_array):
+        if color_array is None or len(color_array) == 0:
+            return np.empty((0, 4))
+            
         color_array = (
             _zalp
```

### 5. Instance `matplotlib__matplotlib-24265` | Submission `20250226_sweagent_claude-3-7-sonnet-20250219`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2503` | **Error:** `0.7497`
```diff
diff --git a/lib/matplotlib/style/core.py b/lib/matplotlib/style/core.py
index fb0a5426e6..c4b0d16928 100644
--- a/lib/matplotlib/style/core.py
+++ b/lib/matplotlib/style/core.py
@@ -259,3 +259,66 @@ def reload_library():
 
 
 reload_library()
+
+
+# Add backward compatibility for direct access to seaborn styles
+class _StyleLibrary(dict):
+    """Dictionary-like object that provides backward compatibility for seaborn styles."""
+    
+    _SEABORN_STYLES = [
+        "seaborn",
+        "seabor
```

### 6. Instance `matplotlib__matplotlib-23562` | Submission `20250911_isea_claude-3.5-sonnet-20241022`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2503` | **Error:** `0.7497`
```diff
diff --git a/lib/mpl_toolkits/mplot3d/art3d.py b/lib/mpl_toolkits/mplot3d/art3d.py
index 8fe6e7a9c1..5a7849782d 100644
--- a/lib/mpl_toolkits/mplot3d/art3d.py
+++ b/lib/mpl_toolkits/mplot3d/art3d.py
@@ -681,6 +681,7 @@ class Poly3DCollection(PolyCollection):
         triangulation and thus generates consistent surfaces.
     """
 
+
     def __init__(self, verts, *args, zsort='average', **kwargs):
         """
         Parameters
@@ -708,7 +709,8 @@ class Poly3DCollection(PolyCollection):
```

### 7. Instance `matplotlib__matplotlib-24265` | Submission `20241207_kodu_sonnet_v1`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2626` | **Error:** `0.7374`
```diff
diff --git a/lib/matplotlib/style/core.py b/lib/matplotlib/style/core.py
index fb0a542..4751d95 100644
--- a/lib/matplotlib/style/core.py
+++ b/lib/matplotlib/style/core.py
@@ -251,10 +251,31 @@ library = None
 available = []


+class StyleLibrary(dict):
+    """A dict subclass for style library that handles deprecated style names."""
+    def __getitem__(self, style):
+        try:
+            return super().__getitem__(style)
+        except KeyError as e:
+            # Handle deprecated sea
```

### 8. Instance `matplotlib__matplotlib-23562` | Submission `20240523_aider`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2677` | **Error:** `0.7323`
```diff
diff --git a/lib/mpl_toolkits/mplot3d/art3d.py b/lib/mpl_toolkits/mplot3d/art3d.py
index 8fe6e7a9c1..bdfa4ff7a8 100644
--- a/lib/mpl_toolkits/mplot3d/art3d.py
+++ b/lib/mpl_toolkits/mplot3d/art3d.py
@@ -707,6 +707,8 @@ class Poly3DCollection(PolyCollection):
             if any(len(np.shape(vert)) != 2 for vert in verts):
                 raise ValueError('verts must be a list of (N, 3) array-like')
         self.set_zsort(zsort)
+        self._facecolors2d = np.empty((0, 4))
+        self._edge
```

### 9. Instance `pydata__xarray-5131` | Submission `20240402_rag_claude3opus`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2774` | **Error:** `0.7226`
```diff
diff --git a/xarray/core/groupby.py b/xarray/core/groupby.py
index 1d4c8d8e..c1c1c1d5 100644
--- a/xarray/core/groupby.py
+++ b/xarray/core/groupby.py
@@ -436,7 +436,7 @@ class GroupBy(SupportsArithmetic):
         return zip(self._unique_coord.values, self._iter_grouped())
 
     def __repr__(self):
-        return "{}, grouped over {!r} \n{!r} groups with labels {}.".format(
+        return "{}, grouped over {!r}\n{!r} groups with labels {}.".format(
             self.__class__.__name__,
```

### 10. Instance `pydata__xarray-5131` | Submission `20240523_aider`
- **Resolved Label:** `1` | **H2 Predicted Prob:** `0.2774` | **Error:** `0.7226`
```diff
diff --git a/xarray/core/groupby.py b/xarray/core/groupby.py
index 8a097251..af5abd9a 100644
--- a/xarray/core/groupby.py
+++ b/xarray/core/groupby.py
@@ -436,7 +436,7 @@ class GroupBy(SupportsArithmetic):
         return zip(self._unique_coord.values, self._iter_grouped())
 
     def __repr__(self):
-        return "{}, grouped over {!r} \n{!r} groups with labels {}.".format(
+        return "{}, grouped over {!r}\n{!r} groups with labels {}.".format(
             self.__class__.__name__,
```
