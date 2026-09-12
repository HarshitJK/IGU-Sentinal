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
