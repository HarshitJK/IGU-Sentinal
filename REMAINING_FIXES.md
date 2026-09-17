# IGU Sentinel — Remaining Fixes

Everything found during the 2026-09-17 audit that is **not** fixed. Companion to
[CHANGES_APPLIED.md](CHANGES_APPLIED.md), which covers what was fixed.

Each item states what is wrong, where, why it matters, and how to fix it.
Every claim marked **[verified]** was reproduced against this tree; items marked
**[design]** are judgement calls about the architecture rather than observed
failures.

**Priority key** — P0: will be exposed under scrutiny or breaks a core claim ·
P1: real detection or security gap · P2: correctness/robustness · P3: cleanup.

---

## Table of contents

- [P0 — Production is serving a broken model](#p0--production-is-serving-a-broken-model)
- [P0 — Evaluation integrity](#p0--evaluation-integrity)
- [P1 — Detection gaps](#p1--detection-gaps)
- [P1 — Security not fully closed](#p1--security-not-fully-closed)
- [P2 — Correctness and robustness](#p2--correctness-and-robustness)
- [P3 — Cleanup and hygiene](#p3--cleanup-and-hygiene)
- [Unverified work](#unverified-work)
- [Suggested order of work](#suggested-order-of-work)

---

## P0 — Production is serving a broken model

> Found while running the evaluation requested after the initial audit. Full
> analysis in [DATASET_EVALUATION.md](DATASET_EVALUATION.md). These are the
> highest-value fixes in this document and two of them take minutes.

### R0a. The served XGBoost model is missing two threat classes **[verified]**

**Where:** `models/xgb_v14.json` + `models/xgb_v14.labels.json`

`detect/xgb.py::_latest_model_path()` serves the highest version number, which is
`v14`. Its label map has **five** classes:

```json
{"0":"benign","1":"volumetric_ddos","2":"c2_beaconing",
 "3":"dga_dns_tunneling","4":"encrypted_malware"}
```

`recon_scanning` and `data_exfiltration` are **not in the model**. It has no
output for them and cannot emit those labels under any input. Two of the six
PS-mandated threat classes are structurally undetectable by the ML layer.

Measured on 1,005 balanced flows: **served `v14` scores 0.332 accuracy** with F1
of 0.000 for `c2_beaconing`, `recon_scanning`, `data_exfiltration` *and* `benign`.
The last 7-class model, `v13`, scores 1.000 on the same set. **66.8 accuracy
points lost to serving the wrong artifact.**

`v14` also labels nearly everything `volumetric_ddos` (precision 0.234, recall
1.000), so in production it both misses attacks and floods on benign traffic.

This is exactly what `tests/conftest.py`'s own docstring predicted — the
isolation fixture was added to prevent it, but only stops *new* pollution; `v11`
and `v14` predate it and were never cleaned up.

**Fix (5 minutes):**

```bash
cp models/xgb_v13.json        models/xgb_v15.json
cp models/xgb_v13.labels.json models/xgb_v15.labels.json
mkdir -p models/archive && mv models/xgb_v11.* models/xgb_v14.* models/archive/
python -c "import igu_sentinel.detect.xgb as x; print(x._latest_model_path())"
```

Better: retrain cleanly via `train_models.py`, then add the `models/CURRENT`
pointer from **R29** so the served version is declared rather than inferred.

**Effort:** 5 min (swap) / 2 h (durable). **Impact:** +66.8 accuracy points.

---

### R0b. `encrypted_malware` is undetectable on live traffic — by both layers **[verified]**

**Where:** consequence of R6 (`ja4` never set on the live path)

Re-running the healthy `v13` model with `ja4=None`, which is exactly what
`ingest/__init__.py:596` produces on a live interface:

| class | as generated | as live capture |
|---|---:|---:|
| **encrypted_malware** | **1.000** | **0.000** |
| c2_beaconing | 1.000 | 0.854 |
| data_exfiltration | 1.000 | 0.750 |
| overall | 1.000 | 0.851 |

The model classifies encrypted malware *entirely* via the JA4 presence flags
(features 12-15). With JA4 absent, recall is **zero**.

The rules layer fails identically: `encrypted_malware` hit-rate goes 1.000 →
**0.000** under live conditions. **Both layers score zero simultaneously**, so
fusion has nothing to recover from.

**Fix:** implement **R6**. `compute_ja4()` in `ingest/ja4.py` is already correct
and tested; only the live-path plumbing is missing.

**Effort:** ~4 h. **Impact:** restores a mandated class from zero.

---

### R0c. The `c2_beaconing` rule can never fire — arithmetically **[verified]**

**Where:** `detect/rules.py` vs `traffic_gen/generators/mock.py:67`

The rule requires **both** conditions; the generator emits
`{"mean": 10.0, "std": 0.5}`:

| test | computation | result |
|---|---|---|
| `std / mean < 0.05` | `0.5 / 10.0 = 0.05`; `0.05 < 0.05` | **False** |
| `25 < mean < 65` | `25 < 10.0` | **False** |

Both fail. Measured rules hit-rate for `c2_beaconing`: **0/105 = 0.000**, even on
data where the beacon field *is* populated. The generator models a 10-second
beacon; the rule only recognises 25-65 seconds. Neither is wrong alone — they
were never checked against each other.

The strict `<` is also a boundary bug: a perfectly regular beacon at exactly 5%
jitter is rejected.

**Fix (30 minutes):**

```python
BEACON_INTERVAL_MIN_S = 5      # Empire/Meterpreter run 5-300s
BEACON_INTERVAL_MAX_S = 300    # Cobalt Strike defaults to 60s
BEACON_JITTER_MAX = 0.05

if interval_mean > 0 and (interval_std / interval_mean) <= BEACON_JITTER_MAX:
    if BEACON_INTERVAL_MIN_S <= interval_mean <= BEACON_INTERVAL_MAX_S:
```

Then vary the generator's beacon interval across that range rather than always
emitting 10.0, so the two are tested against each other.

**Effort:** 30 min. **Impact:** restores a rule that has never once fired.

---

### R0d. Isolation Forest attack recall never exceeds 0.40 **[verified]**

**Where:** `models/isoforest_v18.pkl`, `detect/isoforest.py`

Measured across all perturbation levels (anomalous = raw score >= 0.5):

| jitter | attack recall | benign FPR |
|---:|---:|---:|
| 0% | 0.373 | 0.000 |
| 20% | 0.387 | 0.100 |
| 50% | 0.404 | 0.327 |

**It misses ~60% of attacks at every noise level**, while its false-positive rate
on benign traffic climbs to 32.7% under perturbation.

**Why it matters.** This is the zero-day layer — the only one that can flag an
attack the supervised model has never seen. At 0.37 recall it contributes little
to corroboration, and combined with **R8** (unnamed anomalies are dropped
entirely) the unsupervised path is close to inert.

**Fix.** Investigate in this order: (1) `contamination=0.05` is unjustified and
sets the boundary directly — see **R26**; (2) the benign training set may not
cover real benign spread — see **R22**; (3) the `raw_score >= 0.5` cut is
arbitrary — select it from the benign score distribution (e.g. 99th percentile)
and report a precision/recall curve rather than one operating point.

**Effort:** ~3 h investigation.

---

## P0 — Evaluation integrity

> This block is the single biggest risk. The reported model metrics do not
> measure detection ability, and the reason is visible in ten lines of code.

### R1. The traffic generator emits constant feature vectors **[verified]**

**Where:** `igu_sentinel/traffic_gen/generators/mock.py`

Every flow of a given threat class gets **identical** feature values. Only
`flow_id`, `src_port` and `timestamp` vary, and none of those reach the model —
`extract_features()` uses neither. `dga_dns_tunneling` is the sole partial
exception (it alternates `entropy` and cycles `dns_ngram_entropy` over 5 values).

Measured over the full generated corpus:

| threat_class | flows generated | distinct feature vectors |
|---|---:|---:|
| volumetric_ddos | 21,500 | **6** |
| recon_scanning | 2,025 | **5** |
| dga_dns_tunneling | 875 | 40 |
| data_exfiltration | 575 | **5** |
| encrypted_malware | 195 | **5** |
| c2_beaconing | 105 | **5** |

25,275 generated flows collapse to **66 distinct points** in a 16-dimensional
space.

**Why it matters.** XGBoost's reported 99.7% accuracy and 1.000 per-class F1
(`eval_report.txt`) is the model memorising 66 points. It says nothing about
detecting an attack that does not sit exactly on one of them. This directly
contradicts the warning already in `CLAUDE.md`:

> *never rely on one tool's default parameters for a given threat class, or the
> model learns the tool's fingerprint instead of the attack pattern*

A judge who asks "what happens if the attacker sends packets 10% larger?" will
get a bad answer.

**Fix.** Add per-flow jitter so each class becomes a *distribution*, not a point.
Minimum viable version, in `mock.generate()`:

```python
import random

rng = random.Random(seed)          # seed per variant for reproducibility

# Draw each feature from a distribution instead of assigning a constant.
packet_size_mean = rng.gauss(base_size, base_size * 0.25)
inter_arrival_mean = abs(rng.gauss(base_ia, base_ia * 0.30))
entropy = min(8.0, max(0.0, rng.gauss(base_entropy, 0.4)))
byte_ratio = min(1.0, max(0.0, rng.gauss(base_ratio, 0.08)))
ttl = rng.choice([64, 128, 255]) - rng.randint(0, 5)   # OS variety + hops
fanout = max(1, int(rng.gauss(base_fanout, base_fanout * 0.3)))
```

Then make the classes **overlap deliberately** — real recon and real DDoS both
look "fast"; the model must learn the fan-out distinction, not a lookup table.

**Verify the fix** by re-running the distinct-vector count; it should approach
the flow count. Then re-run `eval.py` and expect accuracy to *drop* into a
believable 0.85–0.95 band. A drop is the success signal here.

**Effort:** ~2 hours. **Impact:** makes every downstream number mean something.

---

### R2. No real traffic-generation tool is ever invoked **[verified]**

**Where:** `igu_sentinel/traffic_gen/generators/{ddos,scanning,exfiltration,beaconing,dns_tunneling,encrypted_malware}.py`

All six delegate to `mock.generate()`. hping3, iperf3, nmap, masscan, Ostinato,
TRex, Slowloris, dnscat2 and DGArchive appear only in docstrings, as
*"In production, this would invoke: ..."*.

**Why it matters.** `CLAUDE.md` specifies these as thin wrappers around real
tools, and the PS mandates synthetic traffic generation. Right now `traffic_gen/`
is a feature-vector factory, not a traffic generator — no packet is ever emitted.

**Fix.** Wire at least two real tools end to end, so the pipeline is proven
against traffic it did not invent:

```python
# generators/ddos.py
import shutil, subprocess

def generate(threat_class, source_mode, rate, size, port, duration, target="127.0.0.1"):
    if not shutil.which("hping3"):
        raise RuntimeError("hping3 not installed; install it or use tool: mock")
    cmd = ["hping3", "--flood" if rate > 5000 else f"-i u{int(1e6/rate)}",
           "-d", str(size), "-p", str(port), "-S"]
    if source_mode == "rand":
        cmd.append("--rand-source")
    cmd.append(target)
    subprocess.run(cmd, timeout=duration, check=False)   # needs root
```

Capture the result with `tshark -w`, then feed the pcap through
`extract_flows_from_pcap()` — that path already exists and is tested. That gives
a genuinely end-to-end labelled corpus.

**Constraints to plan around:** hping3/nmap need root and a target host; run them
inside the `prod-net` containers (already defined in `docker-compose.yml`) rather
than on the host.

**Effort:** ~1 day for two tools. **Impact:** closes the largest PS gap.

---

### R3. Test split is far too small to support the reported figures **[verified]**

**Where:** `eval_report.txt`, `eval.py`

Per-class test support: `volumetric_ddos` 8, `recon_scanning` 7, `c2_beaconing` 6,
`data_exfiltration` 6, `dga_dns_tunneling` 5, `encrypted_malware` 5 — against 300
benign.

**Why it matters.** With support of 5, one misclassification moves recall by 0.20.
A reported "1.000 F1" on 5 samples is not a measurement. The 95% confidence
interval on 5/5 correct runs roughly 0.48–1.00.

**Fix.** Once R1 lands, generate ≥2,000 flows per attack class and use stratified
k-fold rather than a single split:

```python
from sklearn.model_selection import StratifiedKFold
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
# report mean ± std of per-class P/R/F1 across folds
```

Report **mean ± std**, never a single number. Keep the existing per-class
breakdown — `CLAUDE.md` is right that aggregate accuracy alone is misleading.

**Effort:** ~2 hours after R1.

---

### R4. Secondary-dataset cross-validation is absent **[verified]**

**Where:** nothing implements it; `CLAUDE.md` §Benchmarking specifies it.

CIC-IDS2017/2018, UNSW-NB15 and CTU-13 are named as the generalization check.
No loader, no mapping, no results exist.

**Why it matters.** It is the only evidence that the model learned attack
structure rather than the generator. Without it, R1 has no independent rebuttal.

**Fix.** Write a converter to `FlowRecord`, **stripping bidirectional-only fields**
to respect the diode constraint (this is the subtle part — those datasets are
full of reverse-direction features the diode can never observe):

| Dataset field | FlowRecord | Note |
|---|---|---|
| `Flow Duration`, `Fwd IAT Mean` | `inter_arrival_stats.mean` | forward only |
| `Fwd Packet Length Mean/Std/Min/Max` | `packet_size_stats` | forward only |
| `Destination Port` | `dst_port` | |
| `Bwd *` (any) | — | **drop**: unobservable through a diode |
| `Label` | ground truth | map to the six classes |

CTU-13 is the highest-value one for `c2_beaconing`. Report per-class P/R/F1
separately from the synthetic results — do not merge the corpora.

**Effort:** ~1 day. **Impact:** turns R1 from a fatal objection into a caveat.

---

## P1 — Detection gaps

### R5. `beacon_interval_stats` is always `None` from real capture **[verified]**

**Where:** `igu_sentinel/ingest/__init__.py:430` — hardcoded `beacon_interval_stats=None`

**Why it matters.** The C2 beaconing rule in `detect/rules.py` is gated on
`if flow.beacon_interval_stats:`. Since ingest never populates it, **the
`c2_beaconing` rule can never fire on real captured traffic.** It only fires on
fixtures and generator output, where the field is set by hand. One of the six
mandated threat classes has no working rule-layer detection on live data.

**Fix.** Beaconing is a property of a flow *across* windows, so it needs state
the 120 ms window does not have (see R10). Minimum version — keep a bounded
per-flow-key history of window arrival times:

```python
# module-level, bounded to avoid unbounded growth
_flow_history: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=64))

# in _build_flow_records(), per flow:
_flow_history[flow_key].append(timestamps[0])
arrivals = _flow_history[flow_key]
beacon_stats = None
if len(arrivals) >= 4:
    gaps = [b - a for a, b in zip(arrivals, list(arrivals)[1:])]
    if gaps:
        beacon_stats = {"mean": mean(gaps),
                        "std": stdev(gaps) if len(gaps) > 1 else 0.0}
```

The rule already checks `std/mean < 0.05` for regularity, which is the right
test once the field is real.

**Effort:** ~3 hours incl. eviction policy. **Impact:** restores one of six classes.

---

### R6. JA4 is never populated on the live capture path **[verified]**

**Where:** `igu_sentinel/ingest/__init__.py:596` — `yield _build_flow_records(packets, ja4_map={})`

The pcap path calls `_extract_ja4_map()` (a second tshark pass filtered to
`tls.handshake.type == 1`). The live path passes an empty dict, always.

**Why it matters.** `ja4` is `None` for every live flow, so in `detect/rules.py`
the entire JA4 block is dead on live traffic, and features 12–15 of the model
vector are always 0. `CLAUDE.md` calls JA4 the *"mandated primary signal for
encrypted_malware"* — on live capture that signal does not exist. Combined with
R5, two of the six classes are significantly degraded on real traffic.

**Fix.** Add the TLS handshake fields to the live tshark invocation so no second
pass is needed:

```python
def _live_tshark_command(interface: str) -> list[str]:
    return ["tshark", "-i", interface, "-l", "-n", "-T", "json",
            "-e", "tls.handshake.type", "-e", "tls.handshake.ciphersuite",
            "-e", "tls.handshake.extension.type",
            "-e", "tls.handshake.extensions_alpn_str",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "tls.handshake.extensions.supported_version"]
```

Then build the map from the Client Hellos within each window and pass it in.
`compute_ja4()` in `ingest/ja4.py` is already correct and tested — only the
plumbing is missing.

**Effort:** ~4 hours. **Impact:** restores the mandated encrypted-malware signal.

---

### R7. Cross-layer corroboration is effectively two layers, not four **[design]**

**Where:** `igu_sentinel/fusion/__init__.py`, `detect/stats.py`, `detect/isoforest.py`

Fusion grants the high-confidence tier when **≥2 layers name the same threat
class**. But only `rules` and `xgb` ever set `threat_class_guess` — `stats` and
`isoforest` are unsupervised and hardcode `threat_class_guess=None`.

So the ≥2 condition can be satisfied by **exactly one pair**. The system markets
four-layer corroboration and delivers two-layer agreement, with the two
statistical layers unable to contribute to a high-confidence verdict no matter
how strongly they fire.

**Fix (recommended).** Let unsupervised layers *corroborate* without classifying —
they vote for whichever class the supervised layers proposed, when their own
score is high:

```python
CORROBORATION_THRESHOLD = 0.75

def fuse_layers(scores):
    named = {s.threat_class_guess for s in scores
             if s.threat_class_guess and s.threat_class_guess != BENIGN_LABEL}
    if len(named) == 1:
        candidate = next(iter(named))
        for s in scores:
            if (s.threat_class_guess is None
                    and s.calibrated_probability >= CORROBORATION_THRESHOLD):
                threat_guesses[candidate].append(s.calibrated_probability)
                all_evidence.append(f"{s.layer_name}_corroborates={s.raw_score:.3f}")
```

This keeps the "no single layer is trusted alone" principle while making all four
layers count. Decide and document either way — silence here is the problem.

**Effort:** ~3 hours incl. tests.

---

### R8. Strong anomalies with no class label are silently dropped **[design]**

**Where:** `igu_sentinel/fusion/__init__.py` → `is_actionable_alert()`

The gate requires that some layer named a threat class. A flow that `isoforest`
and `stats` both find wildly anomalous, but that neither `rules` nor `xgb`
recognises, produces **no alert at all** — precisely the novel/zero-day case the
unsupervised layer exists to catch.

This gate is correct as far as it goes: the `Alert` schema is PS-fixed to six
classes with no "unknown", and the earlier behaviour (labelling everything
`volumetric_ddos`) was worse. But the current behaviour is silent loss.

**Fix options, in preference order:**

1. **Route to the nearest class by evidence** — a high-fanout unexplained anomaly
   is `recon_scanning`; a high-byte-ratio one is `data_exfiltration`. Keeps the
   schema intact, states the reasoning in `evidence`.
2. **Emit at advisory confidence** with `evidence` leading with
   `unclassified_anomaly`, letting the analyst triage.
3. **Log to a separate anomaly stream** that does not use the `Alert` schema, so
   nothing is lost even if it is not an alert.

Do **not** silently drop. At minimum add a counter so the rate is visible.

**Effort:** ~4 hours.

---

### R9. `fanout_count` resets every 120 ms window **[verified]**

**Where:** `igu_sentinel/ingest/__init__.py` — `targets_by_source` is built per call

Fan-out is computed only over flows *within the current window*. `detect/rules.py`
uses `SCAN_FANOUT_THRESHOLD = 15`.

**Why it matters.** An attacker who probes **14 targets per 120 ms window** —
roughly 116 targets/second, a leisurely scan — never crosses the threshold and is
invisible to the primary recon signal. The threshold is trivially evaded by
pacing, and the ingest comment itself notes scanners touch "tens to thousands".

**Fix.** Maintain a decaying cross-window fan-out per source:

```python
_fanout_window_s = 10.0
_source_targets: dict[str, dict[tuple, float]] = defaultdict(dict)  # target -> last seen

def _fanout(src_ip, targets, now):
    seen = _source_targets[src_ip]
    for t in targets:
        seen[t] = now
    cutoff = now - _fanout_window_s
    for t in [t for t, ts in seen.items() if ts < cutoff]:
        del seen[t]
    return len(seen)
```

Keep the 120 ms *capture* window fixed (that decision is locked and correct);
this is detector state layered on top, not an adaptive window.

**Effort:** ~4 hours incl. memory bounds. **Impact:** closes an easy evasion.

---

### R10. No cross-window state at all — low-and-slow attacks evade by design **[design]**

**Where:** architecture-wide

Each 120 ms window is processed independently and discarded. R5 (beaconing) and
R9 (fan-out) are two symptoms of the same root cause. A beacon with a 30-second
interval, a scan paced at 10 probes/second, or an exfiltration trickled at
1 KB/s produce, in any single window, a flow indistinguishable from background
noise.

**Why it matters.** Three of the six mandated classes — `c2_beaconing`,
`recon_scanning`, `data_exfiltration` — are *defined* by behaviour over
minutes, not milliseconds. A stateless pipeline cannot see them by construction.

**Fix.** Add a bounded, evicting flow-state table between ingest and detect —
keyed by 5-tuple and by source IP, holding rolling aggregates (arrival times,
byte totals, distinct targets) over a configurable horizon (60–300 s), with a
hard entry cap and LRU eviction so memory stays bounded under a flood. Feed those
aggregates into the existing nullable `FlowRecord` fields, which already exist
for exactly this purpose.

This is the most architecturally significant remaining item. The fixed capture
window stays fixed; what changes is that detectors gain memory.

**Effort:** ~2–3 days. **Impact:** the difference between detecting fast attacks
and detecting attacks.

---

### R11. `confidence_score` is documented as a calibrated probability but is not **[verified]**

**Where:** `igu_sentinel/fusion/__init__.py`

```python
fused_confidence = min(0.95, avg_probability * 1.1)   # ≥2 layers agree
fused_confidence = avg_probability * 0.7              # 1 layer
fused_confidence = avg_probability * 0.6              # none
```

Those multipliers are tier weighting. They destroy calibration: after a ×1.1, a
reported 0.8 no longer means "80% of flows scored this way are threats".

`CLAUDE.md` states the field *"stays named `confidence_score` (PS wording) but is
a calibrated probability under the hood"*. That is currently untrue.

**Fix.** Keep the fused probability calibrated and express the tier separately:

```python
fused_confidence = avg_probability          # leave calibration intact
tier = "high" if agreement_count >= 2 else "advisory"
evidence.append(f"tier={tier}")
evidence.append(f"corroborating_layers={agreement_count}")
```

The `Alert` schema is PS-fixed so the tier cannot become a field — putting it in
`evidence` keeps the schema exact while preserving the information. Then
`is_actionable_alert()` gates on `tier` plus a threshold rather than on a number
whose meaning was multiplied away.

**Effort:** ~2 hours. Re-tune `ALERT_CONFIDENCE_THRESHOLD` afterwards.

---

### R12. Platt scaling is not actually fitted **[verified]**

**Where:** `detect/rules.py`, `detect/stats.py`

Both hardcode `1 / (1 + exp(-5 * (score - 0.25)))`. The constants 5 and 0.25 are
not fitted to anything. Only `isoforest` fits its midpoint, and only from the
benign training distribution (so it is calibrated against "how unusual", not
"how likely to be a threat").

`CLAUDE.md` requires calibration *"fit on held-out labeled data"*. What exists is
sigmoid squashing, which is not Platt scaling.

**Fix.** Fit real coefficients per layer, using the held-out split `eval.py`
already builds:

```python
from sklearn.linear_model import LogisticRegression
import numpy as np

def fit_platt(raw_scores, labels):          # labels: 1 = threat, 0 = benign
    lr = LogisticRegression()
    lr.fit(np.array(raw_scores).reshape(-1, 1), labels)
    return float(lr.coef_[0][0]), float(lr.intercept_[0])   # a, b
```

Persist `(a, b)` per layer alongside the model artifacts (versioned like the
others) and load at startup. Then verify with a reliability diagram — bucket
predictions by confidence and check the observed threat rate tracks the
predicted one. **That plot is strong evidence for a judge**, and it is currently
not producible.

**Effort:** ~4 hours. **Impact:** makes the headline field defensible.

---

### R13. Bounded retrain is implemented but never triggered automatically **[verified]**

**Where:** `igu_sentinel/api/__init__.py` → `_feed_drift_monitor()`

`monitor_drift()` and `submit_confirmed_benign()` are now wired into the pipeline
(they previously were not — see CHANGES_APPLIED.md). `trigger_bounded_retrain()`
is fully implemented and tested, but nothing calls it: drift is detected and
logged, then nothing happens.

**Why it matters.** The adaptive half of the drift story is manual-only.

**Fix.** Trigger from the drift signal, with a cooldown so a persistently drifted
distribution cannot cause a retrain storm:

```python
_last_retrain = 0.0
RETRAIN_COOLDOWN_S = 3600

if monitor_drift(iso_scores):
    now = time.monotonic()
    if (now - _last_retrain > RETRAIN_COOLDOWN_S
            and get_retrain_pool_size() >= MIN_RETRAIN_SAMPLES):
        _last_retrain = now
        # off the scoring path — retraining must never block detection
        threading.Thread(target=trigger_bounded_retrain, daemon=True).start()
```

The existing bound + rollback + permanent-baseline machinery makes this safe; it
just needs an edge. Consider requiring explicit operator approval instead of full
automation — defensible either way, but decide deliberately.

**Effort:** ~2 hours.

---

## P1 — Security not fully closed

### R14. `joblib.load()` unpickles model artifacts — still code execution **[partially mitigated]**

**Where:** `igu_sentinel/detect/isoforest.py` → `_load_model_from_disk()`

**Mitigated:** path containment (nothing outside `models/` loads), bundle-shape
validation, feature-dimension check.

**Not closed:** unpickling executes arbitrary code. Anyone who can write a
`.pkl` into `models/` gets code execution in the service, and the loader
automatically adopts the **highest version number** — so an attacker just writes
`isoforest_v999.pkl`.

**Fix.** Sign artifacts and verify before loading:

```python
import hmac, hashlib, json

def _verify_artifact(path: Path) -> bool:
    manifest = _MODELS_DIR / "MANIFEST.json"      # {filename: sha256}
    if not manifest.exists():
        return False
    expected = json.loads(manifest.read_text()).get(path.name)
    if not expected:
        log.error("isoforest: %s is not in MANIFEST.json — refusing", path.name)
        return False
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    return hmac.compare_digest(actual, expected)
```

Write `MANIFEST.json` in `train_models.py`, ship it with the repo, and make the
loader refuse anything unlisted. Complementary hardening: mount `models/`
read-only in the container (`volumes: ["./models:/app/models:ro"]`), and prefer
skops or ONNX over pickle for sklearn artifacts.

**Effort:** ~4 hours. **Impact:** closes the last RCE path.

---

### R15. The alert chain is in-memory only and lost on restart **[verified]**

**Where:** `igu_sentinel/alert/__init__.py`

The chain now genuinely detects tampering, but `_alert_log` is a `deque` in
process memory. On restart the chain resets to genesis; `log_alert_to_file()`
exists but nothing calls it, and `/detect` and the capture worker use `log_alert()`.

**Why it matters.** A tamper-evident log that vanishes on restart is not an audit
trail. An attacker who can restart the service erases history without breaking a
single hash.

**Fix.**
1. Make file persistence the default path — append every entry to a configurable
   append-only file (`IGU_ALERT_LOG_PATH`).
2. On startup, read the last line, restore `_chain_head` and `_next_seq`, and
   **continue** the chain rather than restarting it.
3. Set the file `chattr +a` / append-only where the platform allows.
4. Persist the chain head somewhere the service cannot rewrite, and expose it for
   external pinning (`get_chain_head()` already returns it).
5. Add log rotation that carries the chain across files — the first entry of
   file *N+1* must reference the last hash of file *N*.

Set `IGU_ALERT_HMAC_KEY` in any real deployment; without it an attacker with
write access can recompute a fully self-consistent chain.

**Effort:** ~6 hours.

---

### R16. Both dashboards break if you enable authentication **[verified]**

**Where:** `igu_sentinel/api/dashboard.html`, `frontend/src/api/client.ts`

Neither sends an `Authorization` header or a `token` query parameter — grepping
both for `token`/`Authorization` returns nothing. The moment `IGU_API_TOKEN` is
set, the React app and the built-in dashboard both get 401s and the WebSocket
handshake is refused.

**Why it matters.** The security control added in this audit is, in practice,
unusable with the UI as shipped. That is a strong incentive to leave auth off.

**Fix.** In `frontend/src/api/client.ts`:

```typescript
const TOKEN = import.meta.env.VITE_API_TOKEN as string | undefined;

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options?.headers as Record<string, string>),
  };
  if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
  const res = await fetch(BASE_URL + path, { ...options, headers });
  ...
}

export function wsUrl(): string {
  const u = new URL(BASE_URL || window.location.origin);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.pathname = '/ws/alerts';
  if (TOKEN) u.searchParams.set('token', TOKEN);   // browsers cannot set WS headers
  return u.toString();
}
```

Add the same to `dashboard.html`. Note the token then lives in the browser
bundle — acceptable for a demo, but a real deployment wants a session cookie or
a short-lived token from a login endpoint.

**Effort:** ~2 hours.

---

### R17. `/dashboard` and `/health` are unauthenticated **[by design, confirm]**

**Where:** `igu_sentinel/api/__init__.py`

`/health` is intentionally open so the container `HEALTHCHECK` works — that is
standard and fine. `/dashboard` serves the HTML unauthenticated; the page itself
carries no alert data (it fetches over the authenticated WS), so exposure is low,
but it does disclose that the service exists and what it is.

**Fix (if exposed beyond localhost):** put `/dashboard` behind `require_token`
too, or behind a reverse proxy with real auth. Keep `/health` open but ensure it
never leaks version or config detail.

**Effort:** ~15 minutes.

---

### R18. No TLS, no rate limiting **[verified — absent]**

**Where:** service-wide

Traffic is plaintext HTTP/WS. `/detect` has a batch-size cap (added in this
audit) but no request-rate limit, so it can still be driven at full CPU by
repeated valid requests. `/capture/start` and `/capture/stop` can be cycled
rapidly.

**Fix.** Terminate TLS at a reverse proxy (Caddy or nginx) rather than in
uvicorn — simpler and better-audited. For rate limiting, `slowapi` fits FastAPI
directly:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/detect", dependencies=[Depends(require_token)])
@limiter.limit("10/second")
async def detect(request: Request, flows: list[dict]) -> list[dict]:
    ...
```

Add a cooldown on `/capture/start` specifically — spawning tshark is expensive.

**Effort:** ~3 hours.

---

### R19. No dependency scanning, no hashes, no SBOM **[verified]**

**Where:** `requirements.txt`, `.github/workflows/ci.yml`

Versions now carry upper bounds (added in this audit), but there are no hashes,
so a compromised or yanked-and-republished package installs silently. Nothing
scans for known CVEs.

**Fix.** Add to CI:

```yaml
- name: Audit dependencies
  run: pip install pip-audit && pip-audit -r requirements.txt

- name: Generate SBOM
  run: pip install cyclonedx-bom && cyclonedx-py requirements -o sbom.json
```

For full supply-chain integrity move to `pip-compile --generate-hashes`
(pip-tools) producing a fully pinned, hash-locked `requirements.lock`. Keep
`requirements.txt` as the human-edited input.

**Effort:** ~2 hours.

---

### R20. `tshark` cannot capture as a non-root container user **[verified by inspection]**

**Where:** `Dockerfile`

The image now runs as `USER sentinel` (good — it previously ran as root). But
live capture needs `CAP_NET_RAW`, which that user does not have, so `/capture/*`
inside the container will fail.

**Fix.** Grant the capability to the binary rather than reverting to root:

```dockerfile
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
```

and run the container with `cap_add: [NET_RAW, NET_ADMIN]` plus
`network_mode: host` (capture needs to see the real interface). Keep `USER
sentinel`. Alternatively, accept that the container serves `/detect` only and
run live capture on the host — but then say so explicitly in the README, because
right now the capability gap is silent.

**Effort:** ~1 hour.

---

## P2 — Correctness and robustness

### R21. `_ensure_stats_baseline()` is not thread-safe **[verified]**

**Where:** `igu_sentinel/api/__init__.py:382-407`

Guarded by a plain `global _stats_trained` boolean. The capture worker thread and
a concurrent request can both observe `False` and both call
`train_stats_baseline()`, which rebinds the module-global `_baseline` in
`detect/stats.py`. A `detect_stats()` call racing that rebind can read a
partially-updated baseline.

**Fix.** Same pattern already applied to the model swaps:

```python
_stats_lock = threading.Lock()

def _ensure_stats_baseline() -> None:
    global _stats_trained
    if _stats_trained:
        return
    with _stats_lock:
        if _stats_trained:      # re-check inside the lock
            return
        ...
        _stats_trained = True
```

**Effort:** ~30 minutes.

---

### R22. Production image depends on test fixtures **[verified]**

**Where:** `Dockerfile` copies `tests/fixtures/`; `_ensure_stats_baseline()` reads
`tests/fixtures/benign_sample.jsonl`

The stats baseline is trained at runtime from a **test fixture** shipped into the
production image. If it is missing, the code logs a warning and proceeds with no
baseline, and `detect_stats()` then raises `RuntimeError` per flow.

**Fix.** Treat the baseline like the other models: fit it in `train_models.py`,
persist it as a versioned artifact (`models/stats_baseline_v{n}.json`), and load
at startup. Remove `tests/` from the image. Fail fast and loudly at startup if no
baseline can be loaded, rather than degrading per flow.

**Effort:** ~3 hours.

---

### R23. `byte_ratio` silently defaults to a magic `0.7` **[verified]**

**Where:** `igu_sentinel/ingest/__init__.py` — `byte_ratio = 0.7  # Default for valid traffic`

When no payload bytes are extractable the flow gets 0.7, a value with no
derivation. It feeds feature 7 and several rules (the exfiltration rule triggers
above 0.95, the flood rule above 0.85).

**Why it matters.** Encrypted traffic frequently yields no extractable payload,
so a meaningful fraction of real flows get a fabricated mid-range value that the
model cannot distinguish from a measured one.

**Fix.** Make "not measurable" explicit rather than imputing. Either compute from
frame lengths (`payload_bytes / total_frame_bytes`, which is always available),
or add a companion `byte_ratio_measured: bool` feature so the model can learn
that absence is itself informative. Do not impute a plausible-looking constant.

**Effort:** ~2 hours.

---

### R24. Entropy is computed over concatenated payloads **[verified]**

**Where:** `igu_sentinel/ingest/__init__.py` — `all_payloads = "".join(...)` then `_extract_payload_entropy(all_payloads)`

Concatenating every packet's payload and taking one Shannon entropy is not the
same as the flow's characteristic entropy: concatenation smooths over per-packet
structure, and a flow of many small distinct payloads scores differently from one
large payload with identical byte statistics.

**Fix.** Compute per-packet entropy and report the distribution:

```python
per_packet = [_extract_payload_entropy(p["payload"]) for p in packets_info if p["payload"]]
entropy = mean(per_packet) if per_packet else 0.0
entropy_std = stdev(per_packet) if len(per_packet) > 1 else 0.0
```

`entropy_std` is a genuinely useful signal — tunnelling shows uniformly high
entropy, mixed application traffic varies. Adding it changes `FEATURE_DIM`, so
models must be retrained (the loader's dimension check will catch a stale model).

**Effort:** ~2 hours + retrain.

---

### R25. `compute_psi()` returns an arbitrary `1.0` for a degenerate baseline **[verified]**

**Where:** `igu_sentinel/drift/__init__.py`

When the baseline has zero spread (all identical values) the function returns
`0.0` or `1.0`. `1.0` is not a PSI value on the same scale as the 0.2 threshold —
it is a sentinel being compared as if it were a measurement.

**Fix.** Signal the condition rather than encoding it in the return value —
return `float('inf')`, or raise, or return `(psi, is_valid)`. A degenerate
baseline usually means too few samples, which the caller should handle
explicitly.

**Effort:** ~1 hour.

---

### R26. Isolation Forest hyperparameters are unjustified **[design]**

**Where:** `igu_sentinel/detect/isoforest.py` — `contamination=0.05`, `n_estimators=200`

`contamination=0.05` asserts that 5% of benign training data is anomalous. It is
not derived from anything and directly sets the decision boundary.

**Fix.** Tune against the held-out set and record the justification, or switch to
`contamination='auto'` and select the threshold explicitly from the benign score
distribution (e.g. the 99th percentile), which is at least interpretable. Either
way, write down why the number is what it is — "we picked 0.05" will be asked
about.

**Effort:** ~3 hours.

---

### R27. `flow_id` has no time component **[verified]**

**Where:** `igu_sentinel/ingest/__init__.py` — `hashlib.md5(f"{src_ip}:{src_port}:{dst_ip}:{dst_port}:{protocol}")[:16]`

The same 5-tuple always yields the same `flow_id`. A host reusing an ephemeral
port produces a *different flow* with an *identical* ID, so alerts minutes apart
are indistinguishable and the audit log cannot separate them.

MD5 here is a non-cryptographic identifier, which is acceptable, but the
truncation to 64 bits plus no time component makes collisions a practical
concern over a long capture.

**Fix.** Include the flow's first-seen window:

```python
flow_id = hashlib.sha256(
    f"{src_ip}:{src_port}:{dst_ip}:{dst_port}:{protocol}:{int(timestamps[0])}".encode()
).hexdigest()[:16]
```

**Effort:** ~30 minutes.

---

### R28. `models/` accumulates without bound **[verified]**

**Where:** `models/` currently holds 46 files across `isoforest_v1..v18` and
`xgb_v1..v14`

`CLAUDE.md` correctly requires never overwriting a version. But nothing prunes,
and with R13 automated the growth rate rises.

**Fix.** Add a retention policy — keep the original baseline (never delete), the
current serving version, and the last *N* — with an explicit archive step rather
than deletion. Combine with the `MANIFEST.json` from R14 and a `models/CURRENT`
pointer (R29) so the serving version stops being "whatever sorts highest".

**Effort:** ~2 hours.

---

### R29. Serving model version is inferred from a filename sort, and is untracked **[verified]**

**Where:** `detect/isoforest.py` and `detect/xgb.py` → `_latest_model_path()`; `git status`

The loader takes the highest version number. The current highest —
`isoforest_v18.pkl`, `xgb_v14.json` — is **untracked in git**. A fresh clone
loads `isoforest_v9` / `xgb_v9` and therefore does not reproduce the reported
results. It is also the mechanism R14's attack abuses.

**Fix.** Pin explicitly:

```python
def _latest_model_path() -> Optional[Path]:
    pointer = _MODELS_DIR / "CURRENT"
    if pointer.exists():
        candidate = _MODELS_DIR / pointer.read_text().strip()
        if candidate.exists() and candidate.parent == _MODELS_DIR:
            return candidate
    ...   # fall back to highest version
```

Commit `models/CURRENT` and the artifact it names. Decide whether model binaries
belong in git at all — if they grow, Git LFS or a release asset is better, but
*something* must pin the version.

**Effort:** ~2 hours.

---

### R30. `capture.stop()` reports "stopped" even when the worker never ran **[verified]**

**Where:** `igu_sentinel/api/__init__.py` → `CaptureController.stop()`

`stop()` sets `status = "stopped"` whenever the status is not `"error"` —
including when no capture was ever started, and when the thread did not join
within its 6-second timeout. In the latter case the API reports stopped while the
worker is still running.

**Fix.** Report what actually happened:

```python
if thread is not None:
    thread.join(timeout=6)
    if thread.is_alive():
        self.state["status"] = "stopping"
        self.state["error"] = "capture thread did not stop within 6s"
        return
```

**Effort:** ~1 hour.

---

### R31. WebSocket input is read and discarded without validation **[verified]**

**Where:** `igu_sentinel/api/__init__.py` → `websocket_alerts()`

```python
while True:
    await websocket.receive_text()
```

The loop exists to keep the connection open, but a client can send unbounded data
and the server buffers each message before discarding it.

**Fix.** Cap message size and ignore content explicitly, or switch to a
server-side keepalive (`websocket.send_json({"type": "ping"})` on a timer) and
stop reading from the client entirely.

**Effort:** ~1 hour.

---

## P3 — Cleanup and hygiene

### R32. `.venv` is a Linux virtualenv and cannot run on this machine **[verified]**

Built at `/home/luffy/SIH/IGU-Sentinal/.venv`; `.venv/bin/python` gives
`exec format error` on macOS. Every `make` target that sources it fails.

**Deliberately not deleted** — it is your directory. Fix:

```bash
rm -rf .venv && make venv       # the venv target was added in this audit
```

---

### R33. `run_tests.py` duplicates pytest **[verified — 475 lines]**

A hand-rolled runner alongside the real suite. It is a second source of truth
that can drift and report success while pytest fails.

**Fix.** Delete it, or reduce it to `subprocess.run(["pytest", "-v"])`. CI runs
pytest, so pytest is the source of truth.

---

### R34. `eval.py` and `train_models.py` have no tests **[verified]**

338 and 249 lines, both producing artifacts the project's claims rest on, neither
exercised by the suite. A silent break there corrupts the reported metrics.

**Fix.** Add smoke tests that run each on a tiny fixture subset and assert the
outputs exist and are well-formed.

---

### R35. XGBoost constructor carries deprecated parameters **[verified — not currently breaking]**

`use_label_encoder=False` and `num_class` are passed to `XGBClassifier` in
`detect/xgb.py`. Confirmed against xgboost 3.4.1: accepted without warning today.
`use_label_encoder` has been a no-op since 2.0, and `num_class` is inferred.

**Fix.** Remove both — they are cruft that implies a version constraint that no
longer applies. Low urgency, zero risk.

---

### R36. React frontend exists although CLAUDE.md defers it **[verified]**

`CLAUDE.md` §Deferred says *"React dashboard / UX — parked, do not build yet."*
`frontend/` contains a full Vite + React + TypeScript app (23 files).

Not a defect — but the scope note and the tree disagree. Either update
`CLAUDE.md` to record that the dashboard was brought forward, or park the app.
Leaving the contradiction is the only wrong option, since `CLAUDE.md` is the
working agreement.

---

### R37. Docker test helpers still shell out with `shell=True` **[verified]**

`tests/test_diode.py`, `test_docker_compose.py` build command strings and run
them with `shell=True`, interpolating `root_dir` — which contains a space in this
checkout (`IGU-Sentinal 2`). It happens to work because the path is inside a
`cd {root_dir} && ...` that the shell parses forgivingly, but it is fragile.

**Fix.** Pass argument lists and use `cwd=`:

```python
subprocess.run([*compose_command().split(), "-f", str(compose_file), "up", "-d"],
               cwd=root_dir, capture_output=True, text=True, timeout=60)
```

---

### R38. `scripts/red-button.sh` hardcodes a host IP **[verified]**

`HOST_IP="192.168.1.41"`, `ROUTER_IP="192.168.2.254"`. Same class of problem as
the `wlp8s0` macvlan parent that broke `compose up` everywhere — it works on one
machine.

**Fix.** Take them from environment variables with sane defaults, and detect the
host IP at runtime.

---

## Unverified work

Stated plainly because it affects how much the audit can be relied on.

**Docker is not installed on this machine** (`docker: command not found`), so
these changes are **reviewed but not executed**:

| Change | Status |
|---|---|
| Diode on `alpine` with `set -eu` | Not run |
| Subnet-based interface resolution in the diode | Not run |
| `iptables -C` verification step | Not run |
| Pinned subnets `172.31.10.0/24` / `172.31.20.0/24` | Not run |
| `docker-compose.macvlan.yml` overlay | Not run (also needs a Linux host) |
| Dockerfile non-root user, tshark, models | Not built |
| CI `docker` job | Not run |

**Before relying on the diode fix, run this on a Linux host with Docker:**

```bash
docker compose build
docker compose up -d
sleep 10

# The diode must have verified its own rules and reported ready.
docker compose logs diode | grep 'Diode online'
docker exec igusentinel-diode iptables -S FORWARD      # expect -P FORWARD DROP

# The return path must FAIL. If this ping succeeds, the diode is not enforcing.
docker exec igusentinel-prod-test ping -c 1 -W 2 igusentinel-enclave-test \
  && echo "FAIL: diode not enforcing" || echo "PASS: return traffic blocked"

docker compose down -v
```

`make diode-proof` runs this sequence. 12 Docker tests currently report
`skipped`, not `passed` — they will run for real once Docker is present.

---

## Suggested order of work

**Immediately — minutes, highest value in this document**

0. **R0a** — promote a 7-class model over `xgb_v14`. The system currently cannot
   detect `recon_scanning` or `data_exfiltration` at all. +66.8 accuracy points
   for a file copy.
1. **R0c** — fix the `c2_beaconing` rule thresholds. 30 minutes to revive a rule
   that has never fired.

**Before any demo or submission (~2 days)**

2. **R1** — generator jitter. Everything downstream is currently meaningless.
3. **R3** — re-evaluate with adequate support and k-fold. Expect the accuracy to
   fall; that is the correct outcome.
4. **Verify the diode** (see [Unverified work](#unverified-work)). It is the
   central security claim and is currently unproven on this machine.
5. **R16** — dashboards cannot authenticate, so auth is unusable as shipped.
6. **R32** — `.venv`, a one-line fix that currently breaks every `make` target.
7. **R0b/R6** — `encrypted_malware` scores zero on live traffic in both layers.

**To make the detection claims true (~1 week)**

6. **R5, R6** — beaconing and JA4 are dead on live traffic; two of six classes
   are degraded.
7. **R9, R10** — cross-window state. Three of six classes are defined by
   behaviour the pipeline cannot currently see.
8. **R11, R12** — make `confidence_score` mean what the docs say. A reliability
   diagram is strong, and currently unproducible, evidence.
9. **R7, R8** — decide the fusion questions explicitly, either way.

**Hardening (~3 days)**

10. **R14, R15** — signed model artifacts and a durable alert chain.
11. **R29, R28** — pin the serving model version; prune artifacts.
12. **R18, R19** — TLS, rate limiting, dependency scanning.
13. **R21–R31** — the correctness batch.

**Strongest single addition if time allows:** **R4** (secondary datasets). It is
the only thing that independently answers "did it learn attacks, or your
generator?" — which is the first question a technical judge will ask.
