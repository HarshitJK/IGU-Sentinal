# IGU Sentinel — SIH26145

A passive monitoring prototype: read-only PCAP/live capture or one-way UDP flow
records → streaming features → rules, statistics, Isolation Forest and XGBoost
→ fused alerts → hash-chained log and dashboard. It does not probe production,
decrypt TLS/QUIC payloads, or send mitigation commands.

**Status:** working prototype; representative six-class detection validation is
incomplete. [Verification status](VERIFICATION_STATUS.md) is authoritative.
Older `PROJECT_STATUS.md` is a historical report, not a readiness claim.

## Run

Use Python 3.12 and tshark. Install locked dependencies:

```bash
make venv
make test-unit
.venv/bin/python -m uvicorn igu_sentinel.api:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/dashboard`. Set `IGU_API_TOKEN` before starting the
service to require operator login. The token is not embedded in dashboard HTML.
The React dashboard can be built with `npm ci` and `npm run build` in `frontend/`;
`npm run dev` starts its development server with API proxies.

For the simulated diode demo:

```bash
docker compose up -d --build
python3 scripts/verify-diode.py
```

The proof checks forwarding counters, reverse DROP counters and actual scored
flows. This is a software network-isolation simulation, not a hardware diode.
The API is published on loopback only. `docker compose down` preserves the alert
history volume; do not use `-v` if you want to retain it.

## Contracts and operational status

- V1 (16 model inputs) remains the serving default with the pinned artifacts.
- `IGU_FEATURE_CONTRACT_VERSION=2` selects the staged 27-input contract. V1 models
  are rejected in that mode. Models, calibration and extraction must agree.
- `IGU_PROTECTED_CIDRS=10.0.0.0/8` identifies inside/outside traffic. An unobserved
  reverse direction is unknown, not zero. Payload/frame fraction is not an
  outbound/inbound volume ratio.
- `/ready` distinguishes model/ingest/calibration failures from `/health`
  liveness. `/capture/status` includes capture counters. Authenticated
  `/metrics/ws` reports delivery, overload and error counters.
- Dashboard severity is a class-based triage policy, independent of confidence.
  It is not a measured business-impact assessment.
- Confidence is explicitly marked heuristic unless a fitted calibration artifact
  is configured. The fixed alert schema remains timestamp, flow ID, threat class,
  confidence score and supporting evidence.
- Artifact manifests are SHA-256 integrity records, not signatures. Missing or
  mismatched manifests fail closed. Model directories remain trusted executable
  input because Isolation Forest bundles use pickle/joblib.

## Reproduce candidate training

These captures are synthetic regression data, not evidence of real-world accuracy.
Commands create files locally and send no attack traffic:

```bash
IGU_FEATURE_CONTRACT_VERSION=2 IGU_PROTECTED_CIDRS=10.0.0.0/8 .venv/bin/python scripts/build-training-captures.py --seed 26145 --output data/corpus/train
IGU_FEATURE_CONTRACT_VERSION=2 IGU_PROTECTED_CIDRS=10.0.0.0/8 .venv/bin/python scripts/build-training-captures.py --seed 27145 --output data/corpus/calibration
IGU_FEATURE_CONTRACT_VERSION=2 IGU_PROTECTED_CIDRS=10.0.0.0/8 .venv/bin/python scripts/build-training-captures.py --seed 28145 --output data/corpus/test
IGU_FEATURE_CONTRACT_VERSION=2 .venv/bin/python -m igu_sentinel.eval.candidate --train data/corpus/train/flows.jsonl --calibration data/corpus/calibration/flows.jsonl --test data/corpus/test/flows.jsonl --output data/new-candidate
```

Use an empty candidate output directory. The command rejects overlapping capture
groups and identical captures across partitions. It writes versioned models, a
statistics baseline, fitted confidence calibration, hashes, class metrics,
confusion matrix, false-positive rate and Brier score. It never promotes models.
Encrypted-malware coverage is absent from this synthetic corpus.

For a separately reviewed candidate, `IGU_MODELS_DIR` selects its directory;
`IGU_STATS_BASELINE_PATH` and `IGU_CONFIDENCE_CALIBRATION` select its saved baseline
and calibration JSON. Calibration is bound to model, baseline and pipeline hashes.
Changing those requires recalibration. Restart after changing serving artifacts.

Drift monitoring stays inactive until `IGU_TRUSTED_BASELINE_PATH` names a trusted
benign FlowRecord JSONL reference. Live model verdicts cannot establish it.
Automatic retraining is disabled. Manual retraining fits an isolated candidate,
checks the fixed reference before installing, and retains rollback. Calibrated
serving deployments require offline retraining and recalibration instead.

## Measure streaming performance

```bash
.venv/bin/python -m igu_sentinel.benchmark.streaming --rate 200 --duration 10 --output data/new-streaming-run
make benchmark
```

The first command measures loopback UDP export through validation, inference and
alert-file append. It reports unscored records, errors and latency percentiles;
it excludes raw packet extraction, fsync and browser rendering. The second is
in-process scoring only. Output directories must be fresh to preserve logs.

## Public dataset acquired

A CTU-13 scenario 7 PCAP and original flow labels were downloaded directly from
[the official capture directory](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/).
See [PUBLIC_DATA.md](PUBLIC_DATA.md) for attribution, hashes and download commands.
The PCAP produced 3,366 streaming records. They are not automatically labelled:
the label file covers the full network, while the PCAP covers the infected host.
A validated timestamp/tuple join is needed before training or accuracy reporting.

CSV adapters preserve partial source observations and conservative label mappings.
They do not manufacture entropy, payload fractions, timestamps or TTLs to make
CSV rows resemble complete packet-derived records. The legacy proxy-feature
converter now refuses that operation explicitly.
