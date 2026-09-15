# IGU Sentinel — Work Log

Record of verification and fixes carried out on the P1/P2/P5A/P5B codebase, written
for the project team and for anyone who has to defend these numbers to a judge.

Each section states what was wrong, why it was wrong, what changed, and how it was
verified. Where something is still weak, it says so.

---

## 1. Verification of prior work (P1, P2, P5A)

Ten checks were run against the existing build. Seven passed as-is: the eval
accuracy reproduced exactly, the API booted cleanly, `/health` and `/detect`
returned well-formed responses, alerts streamed live over `/ws/alerts`, the
SHA-256 hash chain verified (and correctly rejected a tampered entry), and
throughput/latency reproduced within normal run-to-run variance.

Three problems were found and fixed.

### 1.1 tshark was not installed

Two ingest tests hard-require `tshark`, so the suite was 84/86, not 86/86.
Installed Wireshark 4.6.8 (`brew install wireshark`). Also created a working
`.venv` — the system Python had only numpy — and installed `httpx`, `websockets`
and `scipy`, which `requirements.txt` omits but the WebSocket/TestClient tests need.

### 1.2 The service was loading a degraded 5-class model

`detect/isoforest.py` and `detect/xgb.py` load the **highest-numbered** artifact in
`models/`, and `train_*` writes a new version on every call. The detector unit tests
call `train_*` on small fixture subsets, so every test run wrote throwaway models
into the shared `models/` directory, and whichever test ran last became the model
the API served.

`test_xgb_end_to_end_with_held_out` trains on a class-ordered 70% split, which drops
the last two classes entirely — producing a 5-class model with no `recon_scanning`
and no `data_exfiltration`. The highest committed model, `xgb_v11`, was also 5-class,
so even a fresh clone served a model that could not detect two of the six mandated
threat classes.

**Fix.** Added `tests/conftest.py`, an autouse fixture that redirects `_MODELS_DIR`
to a temp directory for the training test modules. Tests stay hermetic and no longer
touch `models/`. Regenerated a full 7-class canonical model and committed it.

### 1.3 Malformed JA4 strings in fixtures

`c2_beaconing` (1 flow) and `data_exfiltration` (4 flows) carried 27-character JA4
strings instead of the spec's 36. Replaced with well-formed values that are
feature-equivalent (domain SNI present, ALPN present, not on the malicious list), so
the correction introduced no model drift.

---

## 2. P5B — live streaming ingest

Replaced static-pcap-only ingest with continuous live capture.

- **`extract_flows_from_interface(interface, window_ms=120)`** spawns
  `tshark -i <iface> -l -n -T json`, parses packet objects off the stream
  incrementally (a string-aware brace counter, since `-T json` streams an array that
  only closes when capture ends), and flushes each fixed 120 ms window.
- **`_build_flow_records()`** was extracted from the pcap path so both sources share
  one feature-extraction path. Only packet arrival and windowing differ.
- **`CaptureController`** runs capture on a background thread and feeds each window
  through the *same* `detect → fusion → alert` pipeline as `POST /detect`, broadcasting
  to the *same* `/ws/alerts` clients.
- **`POST /capture/start`**, **`POST /capture/stop`**, **`GET /capture/status`**.
- Capture failures are isolated: a bad interface or missing permission returns
  HTTP 400 with a clear message and never crashes the service.

Nine tests were added (`tests/test_live_ingest.py`) covering incremental parsing,
windowing/batching, graceful failure, and the live-window-to-WebSocket wiring. They
mock the tshark subprocess, so they need no capture permissions in CI.

**One subtle bug fixed during this work:** the live WebSocket test deadlocked when run
after the existing WebSocket test. Cause was `RuntimeError: Event loop is closed` —
`TestClient` used without a context manager runs each request on an ephemeral loop that
closes on return, so the worker's cross-thread broadcast targeted a dead loop. Under
real uvicorn the loop lives for the whole process, so this was a test-harness artifact;
fixed by using `with TestClient(...) as client:`.

---

## 3. Issue 1 — port scans were reported as `volumetric_ddos`

### Root cause

Not a tuning problem. `_build_flow_records` hard-coded `fanout_count=None`, so the
ingest layer **never computed fan-out at all**. Every live flow reached the model with
`fanout = 0`.

Fan-out was the only strong feature separating scanning from flooding: the synthetic
training data gave `recon_scanning` a `fanout` of 50 and `volumetric_ddos` a `fanout`
of `None`. With the real feature always absent, a scan is indistinguishable from a
flood on rate-based features alone — both are "many packets, very fast" — so it
collapsed into `volumetric_ddos`. The `recon_scanning` fixtures also had
`fanout_count: null`, which is why eval showed F1 = 0.000 as well.

### What changed

1. **ingest now measures fan-out.** Per capture window, it counts the distinct
   `(dst_ip, dst_port)` targets each source touched and assigns that to every flow from
   that source. This is the correct discriminator: a scan is one source spraying many
   targets; a flood concentrates on one target regardless of speed.
   Measured on real crafted captures: a 200-port scan yields `fanout = 200` for every
   flow, a flood yields `fanout = 1`.
2. **`rules.py` now uses fan-out** as a first-class scanning IOC, and the DDoS rule
   gained a fan-out qualifier so it stops firing on scans.
3. **Fixtures filled in** the `fanout_count` field the ingest layer now produces, using
   the measured values (scan ≈ 200, flood = 1).
4. **Removed a bad heuristic:** rules previously flagged "ephemeral source port +
   small packets + fast" as a scan. On loopback and LAN that describes completely
   ordinary traffic, and it was a false-positive source.

### A second, larger bug found on the way

`generate_synthetic_flows` sliced `flows[:150]`. The first YAML variant alone produces
thousands of flows, so **the entire synthetic training set for every threat class came
from variant #1** — one rate, one packet size, one port. That defeats the whole purpose
of the multi-variant config and is exactly the tool-fingerprint overfitting CLAUDE.md
warns against. Replaced with `_sample_across_variants()`, which strides across the full
list. DDoS training data went from a single packet size to spanning 64–1500 bytes
across four ports.

---

## 4. Issue 2 — false-positive flood on idle traffic

### Root cause

Two independent bugs, neither of them a threshold problem.

1. **`fuse_layers` always returned an Alert.** There was no benign gate anywhere in the
   pipeline, so *every observed flow became an alert*. The reported 1731 alerts across
   281 windows is simply ~6 flows per window — a 100% alert rate by construction.
2. **When no layer named a threat class, fusion hard-coded
   `threat_class = "volumetric_ddos"`** as a fallback. That is why quiet background
   traffic was not just alerting, but alerting *as DDoS*.

A third, contributing cause: the benign baseline was trained entirely on
"internet-like" traffic with 20–300 ms inter-arrival. Real local/idle traffic is 10–1000×
faster, so every quiet loopback flow was a large z-score outlier.

### What changed

1. **`fusion.is_actionable_alert(scores, alert)`** gates emission. An alert is surfaced
   only if at least one layer actually named a threat class (not `None`, not `benign`)
   **and** the fused confidence clears `ALERT_CONFIDENCE_THRESHOLD` (0.5). The ≥2-layer
   consensus mechanism itself is untouched — this only decides whether the already-fused
   verdict is surfaced.
2. An explicit `benign` vote from a layer is no longer counted as a threat vote.
3. The no-consensus fallback is now tagged `no_layer_named_a_threat_class` and is always
   suppressed by the gate.
4. **The benign baseline is now built from real ingest output.** Rather than
   hand-writing values, representative idle traffic was generated, run through the actual
   ingest path with 120 ms windowing, and the resulting FlowRecords added to the benign
   class. Measured ranges: entropy 0–5.4, byte_ratio 0–0.82, fan-out 1–6.
5. **The DDoS rule no longer fires on rate alone.** Sub-2 ms inter-arrival is normal on
   loopback. It now also requires concentration (low fan-out) and actual volume
   (high byte ratio or large packets).
6. **`dns_ngram_entropy` is now computed by ingest** (it had the same "never populated"
   bug as fan-out), so DNS tunnelling has a real signal and non-DNS traffic can no longer
   look like DGA. Threshold set to 7.0 from measurement: ordinary resolver names score
   5.2–6.3, DGA names 7.4–8.5.
7. **`detect_stats` now combines mean and max z-score.** Averaging alone diluted genuine
   anomalies once the benign baseline was widened; a flow that is extremely abnormal in
   one dimension is anomalous even if ordinary in five others.

---

## 5. Results

### Eval (per-class F1, XGBoost)

| Class | Before | After |
|---|---|---|
| `recon_scanning` | **0.000** | **1.000** |
| `volumetric_ddos` | 0.593 | **1.000** |
| `data_exfiltration` | 0.500 | **1.000** |
| `encrypted_malware` | 1.000 | 1.000 |
| `c2_beaconing` | 1.000 | 1.000 |
| `dga_dns_tunneling` | 0.889 | 0.889 |
| `benign` | 0.993 | 0.998 |

XGBoost accuracy 0.8929 → 0.9970, macro F1 0.7107 → 0.9839.
IsolationForest accuracy 0.8393 → 0.9318.

Before, 100% of `recon_scanning` test samples were misclassified as `volumetric_ddos`.
After, that cell of the confusion matrix is zero.

### Held-out validation

Because the fixtures and the generator were both authored in-repo, the fixes were also
checked against **independently crafted packet captures** run through the real ingest
path with live-style 120 ms windowing, using a different random seed from the data used
for training.

| Scenario | Expected | Result |
|---|---|---|
| Idle background, no attack | no alerts | **0 alerts / 311 flows** |
| Port scan, ports 1–1000 | `recon_scanning` | **1000/1000 `recon_scanning`**, conf 0.80 |
| Volumetric flood | `volumetric_ddos` | **448 alerts, all `volumetric_ddos`**, conf 0.84 |
| DGA / DNS tunnelling | `dga_dns_tunneling` | **correctly classified**, conf 0.79 |
| Normal DNS resolver traffic | no alerts | **0 alerts** |

False-positive rate on idle traffic went from ~100% of flows to **0%**.

### Test suite

**95 passed, 0 failed** (Docker/diode tests excluded as usual).

---

## 6. Known weaknesses — be upfront about these

1. **`dga_dns_tunneling` recall is 0.800**, the weakest class. One of five test flows is
   classified benign. DNS tunnelling that uses few, short query names does not accumulate
   enough character-bigram evidence to clear the entropy threshold.
2. **Small scans will be missed.** `SCAN_FANOUT_THRESHOLD` is 15 distinct targets per
   120 ms window, chosen because measured idle hosts touch 1–6. A deliberately slow scan
   ("low and slow", a few ports per window) stays under it. This is a real evasion path
   and a conscious precision/recall trade.
3. **Per-class F1 values at or near 1.000 should be treated with suspicion.** The test
   set is small (5–8 flows per attack class) and synthetic. The held-out pcap validation
   in section 5 is the more meaningful evidence; the fixture numbers alone would be easy
   to overfit.
4. **Fan-out is window-scoped.** It counts distinct targets inside one 120 ms window, so a
   scanner that spreads probes across windows reduces its own measured fan-out.
5. **IsolationForest's "anomalous" precision is 0.652** — it flags 16 of 300 benign flows.
   This does not by itself produce alerts, because the gate requires a *named* threat
   class and IsolationForest never names one, but it is the noisiest layer.
6. **`entropy` and `byte_ratio` are 0 for DNS traffic**, because tshark parses DNS into
   its own layer and the payload extractor does not read it. The generator now models both
   shapes, but the underlying extractor gap remains.
7. **Live capture needs elevated permissions** (ChmodBPF on macOS, `setcap` on Linux) and
   `traffic_gen` does **not** emit real packets — its generators build FlowRecords
   in-process. A live demo needs a real traffic source such as nmap or hping3.
