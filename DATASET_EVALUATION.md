# IGU Sentinel — Model Evaluation Report

**Date:** 2026-09-17 · **Scope:** the model artifacts this repo actually serves,
tested against the traffic the repo actually generates.

---

## 0. Answering the question that was asked: is there a Kaggle dataset here?

**No. There is no external dataset in this project.** Verified by exhaustive
search of the tree (excluding `.venv/`, `.git/`, `node_modules/`):

```
$ ls datasets/                                    -> no such directory
$ find . -name "*.csv" -o -name "*.parquet" \
       -o -name "*.arff" -o -name "*.zip"         -> no matches
$ grep -riE "kaggle|cic-ids|unsw|ctu-13|nb15"     -> only prose in
                                                     CLAUDE.md, ARCHITECTURE.md,
                                                     TASKS.md, eval.py comments
```

CIC-IDS2017/2018, UNSW-NB15 and CTU-13 appear **only as unimplemented intent**.
`eval.py:317` even ends by printing a note recommending validation against an
independent dataset — a recommendation nothing acts on.

So a Kaggle/external-dataset evaluation could not be run. Instead this report
runs every test that *is* possible with what is in the repo. Those tests found
more than an external dataset would have, because they found that **the system
does not detect four of its six mandated threat classes in production.**

---

## Executive summary

| # | Finding | Severity |
|---|---|---|
| 1 | The **served** XGBoost model is a degraded 5-class artifact. `recon_scanning` and `data_exfiltration` are **not in the model at all**. | **Critical** |
| 2 | Served-model accuracy is **33.2%**, not the 99.7% in `eval_report.txt`. The report describes a different model than the one running. | **Critical** |
| 3 | `encrypted_malware` recall drops **1.000 → 0.000** under live-capture conditions, in *both* the ML and rules layers. | **Critical** |
| 4 | The `c2_beaconing` rule **can never fire** — its thresholds don't overlap the generator's output, arithmetically. | **High** |
| 5 | A healthy 7-class model scores a perfect **1.000 on every class** — the signature of a memorizable dataset. | **High** |

**Net effect: of six PS-mandated threat classes, only `volumetric_ddos`,
`dga_dns_tunneling` and (partially) `recon_scanning` work in production.**

---

## 1. The served model is not the model that was evaluated

### 1.1 What the loader serves

`detect/xgb.py::_latest_model_path()` picks the highest version number. That is
currently `xgb_v14.json`. Its label map:

```json
{"0": "benign", "1": "volumetric_ddos", "2": "c2_beaconing",
 "3": "dga_dns_tunneling", "4": "encrypted_malware"}
```

**Five classes. `recon_scanning` and `data_exfiltration` are absent.** The model
has no output neuron for them; it cannot emit those labels under any input.

Version history shows this is an artifact-hygiene failure, not a design choice:

| version | classes |
|---|---|
| v9, v10 | 7 ✓ |
| **v11** | **5 ✗** |
| v12, v13 | 7 ✓ |
| **v14 (served)** | **5 ✗** |

`tests/conftest.py`'s own docstring predicted this exactly:

> *"`test_xgb_end_to_end_with_held_out` in particular trains on a class-ordered
> 70% split, dropping the last two threat classes and producing a degraded
> 5-class model."*

The `isolate_model_artifacts` fixture was added to stop it recurring — but it
only prevents *new* pollution. `v11` and `v14` were written before it existed and
were never cleaned up, and `v14` sorts highest, so it is what the service loads.

### 1.2 Measured impact

Both models, same 1,005-flow balanced test set (150 per class), no perturbation:

| class | v14 (served) recall | v14 F1 | v13 (7-class) F1 |
|---|---:|---:|---:|
| volumetric_ddos | 1.000 | 0.380 | 1.000 |
| c2_beaconing | 0.000 | **0.000** | 1.000 |
| dga_dns_tunneling | 0.227 | 0.370 | 1.000 |
| encrypted_malware | 1.000 | 1.000 | 1.000 |
| recon_scanning | 0.000 | **0.000** ← not in model | 1.000 |
| data_exfiltration | 0.000 | **0.000** ← not in model | 1.000 |
| benign | 0.000 | **0.000** | 1.000 |
| **overall accuracy** | **0.332** | | **1.000** |

**66.8 accuracy points are lost purely to serving the wrong artifact.**

Note `volumetric_ddos` precision of 0.234 with recall 1.000 on v14: the model
labels almost everything `volumetric_ddos`, including all benign traffic. In
production that is an alert flood on top of the missed detections.

### 1.3 Fix

Immediate (minutes):

```bash
cp models/xgb_v13.json        models/xgb_v15.json
cp models/xgb_v13.labels.json models/xgb_v15.labels.json
```

Then verify `python -c "import igu_sentinel.detect.xgb as x; print(x._latest_model_path())"`.

Durable (see `REMAINING_FIXES.md` R29): add a `models/CURRENT` pointer so the
serving version is declared rather than inferred from a filename sort, and commit
it. Also delete or archive `v11` and `v14` so they cannot be re-selected.

---

## 2. Live-capture conditions break two more classes

The generator and the JSONL fixtures populate `beacon_interval_stats` and `ja4`.
**Real ingest never does:**

- `ingest/__init__.py:430` — `beacon_interval_stats=None`, hardcoded.
- `ingest/__init__.py:596` — the live path calls `_build_flow_records(packets, ja4_map={})`.
  Only the *pcap* path runs `_extract_ja4_map()`.

So every field the models lean on for those two classes is structurally absent in
production. Re-running the healthy `v13` model with those two fields nulled —
which is exactly what ingest produces on a live interface:

| class | as generated | as live capture | Δ |
|---|---:|---:|---:|
| volumetric_ddos | 1.000 | 1.000 | — |
| c2_beaconing | 1.000 | 0.854 | −0.146 |
| dga_dns_tunneling | 1.000 | 1.000 | — |
| **encrypted_malware** | **1.000** | **0.000** | **−1.000** |
| recon_scanning | 1.000 | 1.000 | — |
| data_exfiltration | 1.000 | 0.750 | −0.250 |
| **overall** | **1.000** | **0.851** | **−0.149** |

`encrypted_malware` recall goes to **zero**. The model identifies encrypted
malware *entirely* by the JA4 presence/shape flags (features 12–15), which are
always 0 on live traffic.

The rules layer fails the same way, and worse:

| class | rules hit-rate, as generated | rules hit-rate, live |
|---|---:|---:|
| volumetric_ddos | 0.787 | 0.787 |
| **c2_beaconing** | **0.000** | **0.000** |
| dga_dns_tunneling | 1.000 | 1.000 |
| **encrypted_malware** | 1.000 | **0.000** |
| recon_scanning | 1.000 | 1.000 |
| data_exfiltration | 0.600 | 0.600 |

**`encrypted_malware` is therefore undetectable in production by both layers
simultaneously** — the ML layer scores 0.000 and the rules layer scores 0.000.
Fusion cannot recover a class that no layer detects.

Fix: `REMAINING_FIXES.md` **R5** (populate beacon stats from cross-window state)
and **R6** (extract JA4 on the live path — `compute_ja4()` is already correct and
tested; only the plumbing is missing).

---

## 3. The `c2_beaconing` rule cannot fire — arithmetically

`detect/rules.py` requires **both**:

```python
if interval_mean > 0 and (interval_std / interval_mean) < 0.05:
    if 25 < interval_mean < 65:
```

`traffic_gen/generators/mock.py:67` emits:

```python
beacon_interval = {"mean": 10.0, "std": 0.5}
```

Checking both conditions:

| test | computation | result |
|---|---|---|
| `std / mean < 0.05` | `0.5 / 10.0 = 0.05`, and `0.05 < 0.05` | **False** |
| `25 < mean < 65` | `25 < 10.0` | **False** |

Both fail. This is why the rules hit-rate for `c2_beaconing` is 0.000 even on
data where the beacon field *is* populated. The generator models a 10-second
beacon; the rule only recognises 25–65 seconds. Neither is wrong in isolation —
they were simply never checked against each other.

The `< 0.05` comparison is also a boundary bug: a perfectly regular beacon at
exactly 5% jitter is rejected. It should be `<=`.

**Fix (minutes):**

```python
# rules.py — widen to the range real C2 frameworks use (Cobalt Strike
# defaults to 60s; Empire and Meterpreter commonly 5-300s), and make the
# regularity test inclusive.
BEACON_INTERVAL_MIN_S = 5
BEACON_INTERVAL_MAX_S = 300
BEACON_JITTER_MAX = 0.05

if interval_mean > 0 and (interval_std / interval_mean) <= BEACON_JITTER_MAX:
    if BEACON_INTERVAL_MIN_S <= interval_mean <= BEACON_INTERVAL_MAX_S:
```

Then vary the generator's beacon interval across that range instead of always
emitting 10.0, so the two are tested against each other.

---

## 4. Perfect scores are the problem, not the achievement

`xgb_v13` scores **1.000 precision, 1.000 recall, 1.000 F1 on all seven classes**
across 1,005 flows. That is not a good result; it is a symptom.

**Why:** the generator emits constant feature vectors. Across the full 25,275-flow
corpus there are only **66 distinct points** in 16-dimensional space:

| threat_class | flows | distinct feature vectors |
|---|---:|---:|
| volumetric_ddos | 21,500 | **6** |
| recon_scanning | 2,025 | **5** |
| dga_dns_tunneling | 875 | 40 |
| data_exfiltration | 575 | **5** |
| encrypted_malware | 195 | **5** |
| c2_beaconing | 105 | **5** |

Classifying 66 points with a 200-tree ensemble is a lookup table.

### 4.1 Robustness probe

Since no external dataset exists, the next-best generalization test is to perturb
features by increasing amounts and watch the decay. Gaussian relative noise
applied to all continuous features (packet sizes, inter-arrival, entropy,
byte ratio, TTL, fan-out, DNS entropy); binary flags untouched.

**`xgb_v13` (healthy, 7-class):**

| jitter | accuracy | macro F1 | ddos | c2 | dga | enc_mal | recon | exfil |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0% | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| 5% | 0.955 | 0.956 | 0.977 | 1.000 | 0.993 | 1.000 | 0.990 | 0.846 |
| 10% | 0.936 | 0.938 | 0.949 | 1.000 | 0.986 | 0.997 | 0.990 | 0.782 |
| 20% | 0.901 | 0.906 | 0.872 | 1.000 | 0.969 | 0.997 | 0.990 | 0.686 |
| 30% | 0.873 | 0.879 | 0.834 | 1.000 | 0.930 | 0.993 | 0.966 | 0.633 |
| 50% | 0.818 | 0.828 | 0.732 | 1.000 | 0.864 | 1.000 | 0.938 | 0.550 |

**Reading this honestly — it is better news than expected, with a catch.**

The *good* news: decay is graceful, not a cliff. 87% accuracy at 30% feature
noise means the tree boundaries do carve real regions of feature space, not just
memorised points. The model is not purely a lookup table.

The *catch*: `c2_beaconing` holds at **exactly 1.000 through 50% jitter**, and
`encrypted_malware` never drops below 0.993. Noise cannot move them because
**they are not classified by any continuous feature** — they are classified by
binary presence flags (feature 11 `has_beacon_interval`, features 12–15 JA4).
Those two classes are decided by "is this field set at all", which is:

- perfectly separable in the generator (only those classes set the fields), and
- **always zero in production** (§2).

That is the whole story of §2 visible in one table. The two classes that look
most robust are the two that do not work at all on real traffic.

`data_exfiltration` decaying fastest (0.550 at 50%) is the *healthy* signature —
it is the class genuinely keyed on continuous features (`byte_ratio`,
`packet_size_mean`), so noise legitimately degrades it.

### 4.2 Isolation Forest

Same probe, unsupervised layer (anomalous = raw score ≥ 0.5):

| jitter | attack recall | benign FPR |
|---:|---:|---:|
| 0% | 0.373 | 0.000 |
| 5% | 0.365 | 0.000 |
| 10% | 0.380 | 0.007 |
| 20% | 0.387 | 0.100 |
| 30% | 0.393 | 0.213 |
| 50% | 0.404 | 0.327 |

**Attack recall never exceeds 0.404.** The Isolation Forest misses roughly 60% of
attacks at every noise level, while its false-positive rate on benign traffic
climbs to 32.7% under perturbation. As a corroborating layer it contributes
little; as a zero-day detector — its stated purpose — it is weak.

This also interacts badly with `REMAINING_FIXES.md` R8: an anomaly the supervised
layers do not name is dropped entirely, and this layer is the one that would have
caught it.

Worth investigating: `contamination=0.05` is unjustified (R26), and the model is
trained on benign fixtures whose spread may not cover real benign traffic.

---

## 5. What the current `eval_report.txt` actually measures

It reports XGBoost at 0.997 accuracy with per-class F1 of 1.000 for five of six
attack classes. Three reasons that number should not be quoted:

1. **It is not the served model.** `eval.py` trains a fresh 7-class model on a
   split and evaluates that. The artifact in production is the 5-class `v14`,
   which scores 0.332 (§1).
2. **The test set has 5–8 flows per attack class.** One error moves recall by
   0.20. A "1.000" on 5 samples has a 95% CI of roughly 0.48–1.00.
3. **Train and test come from the same 66 points.** With constant vectors per
   class, the split does not separate anything — test rows are exact duplicates
   of train rows.

### Recommended replacement protocol

1. Fix the generator to emit distributions (R1), then confirm distinct-vector
   count approaches flow count.
2. Regenerate with ≥2,000 flows per attack class.
3. Stratified 5-fold CV; report **mean ± std** per class, never a bare number.
4. Include the robustness table from §4.1 — graceful decay is a *stronger* claim
   than a perfect score, and it is defensible under questioning.
5. Report live-capture-conditions results (§2) separately from fixture results.
   The gap between them is the honest measure of production readiness.
6. Add an external dataset (R4) as the independent check.

Expect accuracy to land around 0.85–0.95. **That drop is the goal**, not a
regression.

---

## 6. Reproducing this report

All scripts are in the session scratchpad and use only what is in the repo:

```bash
# distinct feature vectors per class  (§4)
python - <<'PY'
from collections import defaultdict
from igu_sentinel.traffic_gen.runner import run_all_configs
from igu_sentinel.detect.features import extract_features
by = defaultdict(list)
for r in run_all_configs():
    by[r["threat_class"]].append(tuple(extract_features(r["flow"])))
for tc, v in sorted(by.items()):
    print(f"{tc:<22}{len(v):>8} flows{len(set(v)):>6} distinct")
PY

# which model is served, and how many classes it knows  (§1)
python -c "import igu_sentinel.detect.xgb as x; print(x._latest_model_path())"
cat models/xgb_v14.labels.json

# the c2_beaconing arithmetic  (§3)
python -c "print(0.5/10.0 < 0.05, 25 < 10.0 < 65)"   # -> False False
```

---

## 7. Priority actions from this report

| # | Action | Effort | Impact |
|---|---|---|---|
| 1 | Promote a 7-class model over `v14`; delete/archive `v11` and `v14` | 5 min | +66.8 accuracy points |
| 2 | Add `models/CURRENT` so the served version is declared, not inferred | 2 h | prevents recurrence |
| 3 | Fix the `c2_beaconing` rule thresholds (§3) | 30 min | restores a dead rule |
| 4 | Populate `ja4` on the live path (R6) | 4 h | restores `encrypted_malware` |
| 5 | Populate `beacon_interval_stats` from cross-window state (R5) | 3 h | restores `c2_beaconing` |
| 6 | Generator jitter (R1), then re-evaluate (R3) | 4 h | makes all metrics meaningful |
| 7 | Investigate Isolation Forest's 0.40 recall ceiling (R26) | 3 h | the zero-day layer barely works |
| 8 | Download CIC-IDS2017 or CTU-13 and implement the loader (R4) | 1 day | independent validation |

Items 1 and 3 are near-free and recover the most.

---

## Appendix — test conditions

- **Models tested:** `models/xgb_v14.json` (served), `models/xgb_v13.json`,
  `models/isoforest_v18.pkl` (served).
- **Test set:** 1,005 flows — 150 per class (105 for `c2_beaconing`, the maximum
  the config produces), sampled with `random.Random(42)` from the full
  `run_all_configs()` output plus 300 generated benign flows.
- **Jitter:** relative Gaussian noise, `random.Random(1234)`, applied to
  continuous features only; values clamped to valid ranges (entropy 0–8,
  byte_ratio 0–1, sizes and counts ≥ 0).
- **Live simulation:** `beacon_interval_stats=None, ja4=None`, matching what
  `ingest/__init__.py` produces on a live interface.
- **Caveat:** the test set is drawn from the same generator the models were
  trained on. Absolute numbers are therefore optimistic; the *comparisons*
  between conditions are the meaningful output, and they are valid because only
  one variable changes at a time.
