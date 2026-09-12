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
- [x] `drift/`: rolling-window score monitor + KS-test/PSI drift check + bounded retrain trigger + fallback-to-original-baseline logic. Test: simulate a shifted score distribution, assert drift is detected and retrain is bounded/logged.
- [x] `traffic_gen/`: config-driven generator harness (runner.py + generators/ + yaml configs) per CLAUDE.md spec. Test: running a sample yaml config produces labeled output flows matching the intended threat class.
- [x] `api/`: FastAPI app wiring ingest (mocked/replayed fixtures for now, no tshark yet) -> detect layers (async gather) -> fusion -> alert, exposed via a WebSocket endpoint. Test: end-to-end test feeding a fixture file through the live app produces correctly-shaped Alert objects.
- [x] Benchmark harness: measure sustained flows/sec and end-to-end latency through the in-process pipeline using synthetic load. Test: harness runs and outputs a concrete throughput/latency number (value itself not asserted, just that it's measured and logged).

## Phase 3 — Docker / Infra (build last)
- [x] `ingest/`: replace fixture-replay with real tshark subprocess capture + feature extraction into FlowRecord. Test: capture a short local pcap replay, confirm extracted FlowRecords match expected fields.
- [ ] Docker networks: `prod-net`, `enclave-net`.
- [ ] Diode container: one-way relay (app-level) + iptables/nftables DROP enforcing no return path. Test: from an enclave-net container, ping/curl a prod-net container and confirm failure; log this as proof artifact.
- [ ] Traffic generator containers on `prod-net` wired to `traffic_gen/`.
- [ ] `docker-compose.yml` tying it all together. Test: `docker-compose up` brings up the full pipeline end-to-end, ping test still fails as expected.
