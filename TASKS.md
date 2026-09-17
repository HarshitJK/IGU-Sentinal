# IGU Sentinel — TASKS

Ordered: skeleton -> backend/ML -> Docker/infra. Do not reorder or skip ahead.
Each task's checkbox may only be checked after its stated test/PoC passes.

## Phase 1 — Skeleton
- [x] Create `igu_sentinel/` package layout exactly as specified in CLAUDE.md (empty modules with docstrings + type-annotated function/class stubs for each contract: FlowRecord, LayerScore, Alert as pydantic models in a shared `schemas.py`). Test: importing each module and instantiating each schema with valid + invalid sample data raises/passes as expected (pydantic validation).
- [x] Create `tests/fixtures/` with one hand-crafted JSONL sample per threat class (benign, volumetric_ddos, c2_beaconing, dga_dns_tunneling, encrypted_malware, recon_scanning, data_exfiltration) — 5-10 FlowRecords each, matching the schema. Test: every fixture file parses into valid FlowRecord objects with zero schema errors.

## Phase 2 — Backend / ML
- [x] `detect/rules.py`: static IOC/protocol-violation rule engine. Write tests against fixtures first (expected LayerScore per fixture), then implement to pass.
- [x] `detect/stats.py`: z-score baseline detector. Tests first, then implement.
- [x] `detect/isoforest.py`: Isolation Forest wrapper — train-on-benign-fixture function + score function. Test: scores benign fixtures low, attack fixtures high (relative ordering, not exact values).
- [x] `detect/xgb.py`: XGBoost multi-class classifier wrapper — train function + predict function. Test: per-class precision/recall computed on a held-out split of fixtures, reported (not asserted to a specific number yet — just must run end-to-end and report).
- [x] `fusion/`: Platt-scaling calibration per layer + cross-layer correlation logic (>=2 layers must agree for high-confidence tier). Test: feed known LayerScore combinations, assert correct confidence tier and that single-layer-only detections are downgraded.
- [x] `alert/`: Alert schema output + SHA-256 hash-chained logging. Test: log a sequence of alerts, verify hash chain integrity (tampering with one entry breaks verification).
      <br>**Audit note:** the chain was forgeable. Each entry's hash covered only its own content, with `prev_hash` stored as an unauthenticated sibling field — so an entry could be edited, its hash recomputed, and the next entry's `prev_hash` patched to match, and verification still passed. The hash now commits to `(seq, prev_hash, content)`. See `test_alert_verify_detects_chain_rewrite`.
- [x] `drift/`: rolling-window score monitor + KS-test/PSI drift check + bounded retrain trigger + fallback-to-original-baseline logic. Test: simulate a shifted score distribution, assert drift is detected and retrain is bounded/logged.
      <br>**Audit note:** the module existed but `trigger_bounded_retrain()` only appended a log line — it never retrained, never bounded anything, and kept no fallback model. Nothing in the pipeline called `drift/` at all. Now implemented (bounded retrain with rollback, permanent baseline snapshot, fused-verdict-only retrain pool) and wired into the scoring path.
- [x] `traffic_gen/`: config-driven generator harness (runner.py + generators/ + yaml configs) per CLAUDE.md spec. Test: running a sample yaml config produces labeled output flows matching the intended threat class.
- [x] `api/`: FastAPI app wiring ingest (mocked/replayed fixtures for now, no tshark yet) -> detect layers (async gather) -> fusion -> alert, exposed via a WebSocket endpoint. Test: end-to-end test feeding a fixture file through the live app produces correctly-shaped Alert objects.
- [x] Benchmark harness: measure sustained flows/sec and end-to-end latency through the in-process pipeline using synthetic load. Test: harness runs and outputs a concrete throughput/latency number (value itself not asserted, just that it's measured and logged).
      <br>**Audit note:** this was checked off while only `tests/test_benchmark.py` existed — a test that printed a number and discarded it. CLAUDE.md requires a *harness module*. `igu_sentinel/benchmark/` now provides it (`python -m igu_sentinel.benchmark`, `make benchmark`), and building it immediately surfaced the per-flow model-call bottleneck: **112 flows/sec → 11,725 flows/sec** after batching the ML layers per capture window.

## Phase 3 — Docker / Infra (build last)
- [x] `ingest/`: replace fixture-replay with real tshark subprocess capture + feature extraction into FlowRecord. Test: capture a short local pcap replay, confirm extracted FlowRecords match expected fields.
- [x] Docker networks: `prod-net`, `enclave-net`.
- [x] Diode container: one-way relay (app-level) + iptables/nftables DROP enforcing no return path. Test: from an enclave-net container, ping/curl a prod-net container and confirm failure; log this as proof artifact.
      <br>**Audit note:** the diode ran `busybox`, which ships no `iptables` applet, with no `set -e`. Every rule failed with `iptables: not found` and the container printed `Diode online` regardless — it enforced nothing while reporting success. It also hardcoded `eth0`/`eth1`, whose assignment Docker does not guarantee, so the one-way rules could be installed backwards. Now on `alpine` with `set -eu`, subnet-resolved interfaces, and a read-back verification step.
- [x] Traffic generator containers on `prod-net` wired to `traffic_gen/`. Test: containers defined in docker-compose, volume-mounted to traffic_gen/, can start and generate flows.
- [x] `docker-compose.yml` tying it all together. Test: `docker-compose up` brings up the full pipeline end-to-end, ping test still fails as expected.


## Audit corrections (2026-09-17)

Checkboxes above were marked complete for code that existed but did not do what
the task said. The audit notes inline record what was actually missing. Summary
of what changed, with the three that mattered most first:

1. **Hash-chained alert log was forgeable** — the chain is now a real chain.
2. **Diode enforced nothing** — wrong base image, no fail-closed, unreliable
   interface assumption. Now verified at startup.
3. **Pipeline ran at ~112 flows/sec** against a graded throughput requirement,
   because both ML layers were called once per flow. Now ~11,725 flows/sec.

Still open, and deliberately not closed silently — see "Open questions" in
CLAUDE.md:

- [ ] `traffic_gen/` generators are mock-only. `ddos.py`, `scanning.py`,
      `exfiltration.py` et al. all delegate to `mock.generate()`; hping3,
      iperf3, nmap, Slowloris, dnscat2 and TRex are named in docstrings but
      never invoked. The generated corpus is six constant feature vectors per
      class, which is why XGBoost reports ~99.7% accuracy — it is memorising
      six points, not learning attack structure.
- [ ] Secondary-dataset cross-validation (CIC-IDS2017/2018, UNSW-NB15, CTU-13)
      is specified in CLAUDE.md but not implemented anywhere.
- [ ] Platt calibration is not fitted on held-out labeled data for `rules` and
      `stats`; both use a hardcoded sigmoid.
