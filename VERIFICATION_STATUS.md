# SIH26145 verification status — 2026-09-28

The repository is a working prototype, not a validated production detector.
This report supersedes readiness and performance claims in older documents.

## Verified fixes

- The dashboard no longer embeds the API secret. Operators sign in using an
  HttpOnly session cookie; cross-origin cookie requests and sockets are checked.
- Sentinel has no production-network interface. The simulated diode receives
  production UDP records and forwards them to the enclave. Forwarding counters,
  blocked reverse traffic, and actual scored flows are checked by
  `scripts/verify-diode.py`. This software simulation is not a hardware diode.
- Python 3.12 dependencies are pinned in `requirements.lock`; the XGBoost CPU
  package matches the saved model. Frontend builds after removal of accidentally
  tracked `frontend/src/node_modules`, which shadowed installed dependencies.
- PCAP replay now parses incrementally through the same capture-time windows
  as live ingest. Capture state is scoped per stream, beacon history survives
  ephemeral source-port changes, and TLS fields retain duplicate JSON keys.
- Capture queues and packet windows have bounds. The retraining candidate pool
  is capped at 5,000 and requires conservative agreement across all detectors.
  Automatic retraining is disabled; candidate labels are not ground truth.
- Configured alert-log write failures propagate instead of being ignored.
  Unverifiable persisted chains prevent startup. Appends are not fsync-backed.
- Aggregate traffic generation defaults to mock records. Lab commands require
  an explicit single configuration and `--allow-lab`.

## Checks completed

- Backend: **225 passed, 12 skipped** with `SKIP_DOCKER_TESTS=1`. Docker checks
  are separate; skipped tests must not be counted as verified.
- React production build: passed.
- Docker diode proof: forward ACCEPT and reverse DROP counters increased;
  one-way ingestion produced scored flows and persisted alerts.

## Independent packet lab

Run `.venv/bin/python scripts/validate-packet-lab.py`. It writes deterministic
Ethernet/IP PCAPs and `data/packet-lab/report.json`, then runs tshark extraction
and the existing inference pipeline. It sends no packets on any network and
does not reuse the model-training FlowRecord generator.

| Scenario | Input packets | Extracted flows | Result |
|---|---:|---:|---|
| Irregular benign UDP | 80 | 80 | All suppressed |
| TCP port scan | 150 | 150 | 141 scan alerts, 9 suppressed |
| 30-second UDP callbacks | 20 | 20 | 17 beacon alerts, 3 warm-up flows suppressed |
| UDP flood | 2,000 | 3 | All incorrectly labelled data exfiltration |

These are tiny, constructed functional checks, not representative accuracy
estimates. DNS tunnelling, encrypted malware, and directional exfiltration have
not been validated by this lab. Replay wall time is not live detection latency.

## Remaining work, in priority order

1. Version the feature contract and rebuild training data. `byte_ratio` currently
   measures payload/frame size, not outbound/inbound byte volume. Add observed
   directional volumes with explicit visibility/missing-value semantics,
   SYN and source-entropy rate features, and DNS query-length/type features.
   Do not reinterpret the existing 16-feature model without retraining it.
2. Evaluate all six classes on held-out packet captures and legitimate traffic;
   fix the UDP-flood/exfiltration confusion above. Fit probability calibration
   on held-out data and publish per-class metrics and false-positive rates.
3. Establish drift baselines from trusted benign data. The current monitor can
   initialize from the first observed batch. Manual bounded retraining still
   installs candidates before evaluation and needs an isolated candidate path
   and a fixed reference sample before it can be enabled automatically.
4. Bound outstanding WebSocket broadcasts, then measure sustained input rate,
   drops and capture-to-alert latency including extraction and persistence.
   `make benchmark` measures in-process scoring only.
5. Separate severity from confidence in the dashboard. Complete operational
   documentation and artifact lifecycle checks. The artifact manifest contains
   SHA-256 digests, not cryptographic signatures; absent-manifest enforcement
   remains permissive.

## Reproduce

Use Python 3.12 (`make venv`, or install `requirements.lock` in an existing
environment). Install tshark for PCAP replay. Run `make test-unit` and
`cd frontend && npm ci && npm run build`. Run `docker compose up -d --build`
and `python3 scripts/verify-diode.py` for the isolated demo. The API is published
only on `127.0.0.1:8000`; `/ready` checks model and configured ingest availability.
Set `IGU_API_TOKEN` before starting Compose to require operator sign-in.
`docker compose down` preserves the alert-history volume.
