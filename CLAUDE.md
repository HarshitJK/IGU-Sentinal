# IGU Sentinel — CLAUDE.md

## Project
IGU Sentinel — passive AI/ML threat detection for diode-fed, unidirectional IP traffic.
Built for SIH26145 (NTRO, Blockchain & Cybersecurity theme).

## Hard constraints (never violate these — they come directly from the problem statement)
- Read-only ingest. Never assume a return path, a live query to the source, or an inline block/mitigation action exists.
- No payload decryption. TLS/QUIC sessions are analyzed from metadata only (JA4, packet size/timing).
- Streaming, not batch. Process incrementally with bounded latency, not end-of-run reports.
- Every module must state and be benchmarked against a concrete throughput number (flows/sec).
- Alert schema is fixed: `{timestamp, flow_id, threat_class, confidence_score, evidence}` — field names must match exactly, do not rename.

## Stack
Python + FastAPI (backend/orchestration) + React (dashboard — deferred, not in scope yet).
Single in-process FastAPI service. No HTTP calls between internal modules — plain function/async calls only.
tshark is the only external process (packet capture); everything downstream of it is in-process Python.

## Architecture style
Unix philosophy applied at the module level, not literal shell pipes: every module is small,
single-responsibility, independently testable via fixture files, with a strict input/output contract.
Zero trust at three levels:
1. Network — diode enforces one-way flow (built last, see TASKS.md).
2. Data — every module validates its own input against schema, never trusts an upstream module blindly.
3. Decision — no single detection layer's verdict is trusted alone; fusion requires cross-layer corroboration.

## Module layout
```
igu_sentinel/
├── ingest/          # tshark capture (subprocess, piped) -> feature extraction -> FlowRecord
├── detect/
│   ├── rules.py     # FlowRecord -> LayerScore
│   ├── stats.py     # FlowRecord -> LayerScore (z-score baseline)
│   ├── isoforest.py # FlowRecord -> LayerScore (unsupervised, benign-only trained)
│   └── xgb.py       # FlowRecord -> LayerScore (supervised, multi-class)
├── fusion/          # List[LayerScore] -> Alert (Platt calibration + cross-layer correlation)
├── alert/           # Alert -> hash-chained (SHA-256) log + schema output
├── drift/           # monitors isoforest score distribution -> triggers bounded retrain
├── traffic_gen/     # config-driven generator harness (see below)
├── api/             # FastAPI app: orchestrates pipeline, exposes WebSocket
└── tests/
    ├── fixtures/    # JSONL sample flows per threat type
    └── test_*.py    # one test file per module, fixture-driven, written BEFORE implementation
```

## Data contracts (JSON, one object per record — these are the module interfaces)

**FlowRecord** (ingest output; input to every detect_*):
`flow_id, timestamp, src_port, dst_port, protocol, packet_size_stats{min,max,mean,std}, inter_arrival_stats{mean,std}, entropy, byte_ratio, ttl, ja4 (nullable), beacon_interval_stats (nullable), dns_ngram_entropy (nullable), fanout_count (nullable)`

**LayerScore** (each detect_* output; input to fusion):
`flow_id, layer_name, raw_score, calibrated_probability, threat_class_guess (nullable), evidence[]`

**Alert** (fusion output; input to alert/) — matches PS schema exactly:
`timestamp, flow_id, threat_class, confidence_score, evidence`

## Threat classes (six, PS-mandated — every detector must map to at least one)
volumetric_ddos, c2_beaconing, dga_dns_tunneling, encrypted_malware, recon_scanning, data_exfiltration

## Detection pipeline decisions (locked)
- Window: fixed 120ms capture window. Do NOT make this adaptive — an adaptive window is gameable by an attacker who manipulates traffic rate to force a weak window size. Fixed and simple is the correct, defensible choice.
- Capture: tshark as a subprocess (`-T json` or `-T fields`), piped into Python — do not hand-roll packet parsing.
- Isolation Forest: trained once on a benign-only warmup batch (baseline). Never retrain on unvalidated traffic — only retrain on flows confirmed benign by the FUSED cross-layer verdict, not by isoforest's own low score alone (prevents poisoning).
- Drift detection: monitor rolling-window mean/variance of isoforest anomaly scores; compare current vs. original baseline distribution using KS test or PSI (PSI > 0.2 = literature-standard "significant drift" threshold). Bound how much a single retrain can shift the decision boundary. Never discard the original baseline model — keep it as a permanent fallback/reference.
- XGBoost: multi-class classifier (one class per threat type + benign), trained on labeled synthetic traffic from traffic_gen. Use class weighting — benign traffic will vastly outnumber attacks. Report per-class precision/recall/F1, never aggregate accuracy alone (misleading on imbalanced data).
- Confidence fusion: each layer's raw score calibrated to a probability via Platt scaling (fit on held-out labeled data) BEFORE fusion. Cross-layer correlation: require agreement across >=2 independent layers to reach high-confidence tier; single-layer-only detections downgrade to advisory. Output field stays named `confidence_score` (PS wording) but is a calibrated probability under the hood.
- Models load once at service startup, held in memory; drift/ swaps in a retrained model atomically, never reloads from disk per-flow.

## traffic_gen — reusable, config-driven (build once, reuse across all attack types)
```
traffic_gen/
├── config/*.yaml     # list of {tool, source_mode, rate, size, port, duration} variant combos
├── runner.py         # loops through a yaml's variants, invokes the right generator, auto-labels output
└── generators/{ddos,scan,exfil}.py   # thin wrappers around hping3/iperf3/Ostinato/TRex/Slowloris/dnscat2/DGArchive
```
Vary source-IP mode (`hping3 --rand-source` or a fixed spoof pool), rate (`-i`), packet size (`-d`), and target port across runs — never rely on one tool's default parameters for a given threat class, or the model learns the tool's fingerprint instead of the attack pattern.

## Benchmarking / evaluation
- Primary: train and evaluate on traffic_gen output (PS-mandated synthetic traffic).
- Secondary (generalization check, not primary training): cross-validate against CIC-IDS2017/2018, UNSW-NB15, CTU-13 (botnet/C2 focus) after stripping any bidirectional-only fields to respect the diode constraint.
- Report per-class precision/recall/F1 on both. Do not optimize toward a single target accuracy number — that invites overfitting to the synthetic generator.
- A dedicated benchmark harness module must measure and log sustained flows/sec and end-to-end latency (capture window + processing) — this is a graded PS requirement, not optional polish.

## Naming conventions
- snake_case for all Python modules/files.
- Model artifacts: `isoforest_v{n}.pkl`, `xgb_v{n}.json` — version every retrain, never overwrite.
- Test fixtures: `tests/fixtures/{threat_class}_sample.jsonl`.

## Deferred (not in scope for current build phase)
- React dashboard / UX — parked, do not build yet.
- Docker/diode containerization — build LAST, after skeleton + backend/ML are working and tested in-process.

## Working agreement for this agent loop
- Read this file fully before touching TASKS.md.
- Every task requires a passing test (fixture-driven) before its checkbox in TASKS.md is marked done. Code existing without a passing test is NOT done.
- Write the test first, against the data contracts above, then write the implementation to pass it.
- Do not invent new modules, folders, or abstractions beyond what's listed here. If something seems missing, add a note under a new "## Open questions" section at the bottom of this file rather than improvising silently.
- Keep changes scoped to the current task only. Commit after each completed task.

## Open questions

Raised during the 2026-09-17 security and correctness audit. Recorded here rather
than improvised silently, per the working agreement above.

### Additions made that the module layout does not list
These were added because a CLAUDE.md requirement elsewhere in this file demanded
them and no listed module provided one. Confirm or relocate:

1. **`igu_sentinel/benchmark/`** — "Benchmarking / evaluation" requires *"a
   dedicated benchmark harness module [that] must measure and log sustained
   flows/sec and end-to-end latency"* and calls it graded, but the module layout
   has no entry for it. Only `tests/test_benchmark.py` existed. Added as a
   module; building it revealed the pipeline was running at ~112 flows/sec.
2. **Batch entry points** `score_isoforest_batch()` / `predict_xgb_batch()` in
   the existing detect modules. The stated contract is `FlowRecord -> LayerScore`
   and that is unchanged — the per-flow functions remain and now delegate to the
   batch ones. The batch form exists because per-call model overhead, not
   per-row work, was capping throughput ~100x below what the layers can do.
3. **`docker-compose.macvlan.yml`** — the macvlan sandbox pinned
   `parent: wlp8s0`, a specific machine's wireless interface, so `compose up`
   failed at network creation everywhere else and took the whole stack with it.
   Split into an opt-in overlay.

### Unresolved design questions

4. **Cross-layer corroboration is effectively two layers, not four.** Fusion
   grants the high-confidence tier when >=2 layers name the *same* threat class,
   but only `rules` and `xgb` ever set `threat_class_guess` — `stats` and
   `isoforest` are unsupervised and always return `None`. So the >=2 agreement
   condition can only ever be satisfied by exactly one pair, and the two
   statistical layers can never contribute to a high-confidence verdict. Should
   they vote (e.g. an anomaly score above a threshold corroborating whichever
   class the supervised layers propose), or is the current design intentional?

5. **A strong anomaly with no class is silently dropped.** `is_actionable_alert`
   requires that some layer named a threat class. A flow that `isoforest` and
   `stats` both find wildly anomalous, but that neither `rules` nor `xgb`
   recognises, produces no alert at all — which is precisely the novel/zero-day
   case the unsupervised layer exists to catch. The `Alert` schema is PS-fixed
   to six classes with no "unknown", so surfacing it needs a decision: map to
   the closest class, or accept that unclassifiable anomalies are not reported?

6. **`confidence_score` is documented as a calibrated probability but is not
   one.** Fusion multiplies the averaged probability by 1.1 for the agreement
   tier and by 0.7/0.6 otherwise. Those factors are tier weighting, and they
   destroy calibration — a "0.8" no longer means 80% of such flows are threats.
   Either drop the multipliers and express tiers separately, or stop describing
   the field as calibrated.

7. **Platt scaling is not fitted.** CLAUDE.md requires calibration *"fit on
   held-out labeled data"*. `rules` and `stats` both hardcode
   `1/(1+exp(-5*(s-0.25)))`; only `isoforest` fits its midpoint, and only from
   the benign training distribution. A held-out labeled split exists in
   `eval.py` and could fit real Platt coefficients per layer.

8. **The traffic generator emits constant vectors, so the reported metrics are
   not meaningful.** `mock.generate()` produces identical features for every
   flow of a class (only `flow_id`, `src_port` and `timestamp` vary; DGA varies
   two fields on a 5-cycle). Every "generator" — `ddos.py`, `scanning.py`,
   `exfiltration.py`, `beaconing.py`, `dns_tunneling.py`,
   `encrypted_malware.py` — delegates to it; none invokes hping3, iperf3, nmap,
   Slowloris, dnscat2 or TRex as their docstrings describe. XGBoost's 99.7%
   accuracy and 1.000 per-class F1 in `eval_report.txt` reflect memorising six
   points in feature space. This directly contradicts the warning already in
   this file — *"never rely on one tool's default parameters ... or the model
   learns the tool's fingerprint instead of the attack pattern"* — and the test
   split is 5-8 flows per attack class, far too small to support any figure.
   Needs either real tool invocation or, at minimum, per-flow parameter jitter.

9. **Model artifacts are unversioned relative to the repo.** `models/` holds 46
   files; the loader takes the highest version number, which is currently
   `isoforest_v18.pkl` / `xgb_v14.json` — both untracked in git. A fresh clone
   loads `v9`, so a clone does not reproduce the reported numbers. Should the
   serving version be pinned explicitly (a `models/CURRENT` pointer) rather than
   inferred from a filename sort?

10. **`joblib.load()` on model artifacts unpickles, which executes arbitrary
    code.** `models/` is therefore a trust boundary equivalent to executable
    code. Path containment and bundle-shape validation are now enforced, but
    anyone who can write to `models/` still achieves code execution in the
    service. A signed-manifest or hash-allowlist scheme would close this.
