# SIH26145 verification status — 2026-09-28

Working prototype; real-world detection accuracy is not established. This report
supersedes historical claims in PROJECT_STATUS.md. Machine-readable evidence is
in [VALIDATION_RESULTS.json](VALIDATION_RESULTS.json).

## Completed

- Bounded streaming ingest and incremental PCAP replay; malformed/truncated JSON,
  reader failures and subprocess stderr are handled explicitly.
- Corrected v2 contract: 27 model features, fixed-window rates, SYN statistics,
  target source entropy, DNS length/type and observed directional volumes.
  Missing reverse traffic stays unknown; byte_ratio remains payload/frame size.
- Model loaders reject missing digests, incompatible contracts/dimensions,
  invalid pins and malformed label maps. SHA-256 manifests are not signatures.
- Isolated candidate training with capture-group/source-hash partition checks,
  training-only statistics baseline, held-out fusion calibration and test metrics.
  Calibration checks model, baseline and pipeline fingerprints.
- Trusted drift reference initialization and isolated candidate fitting before
  replacement. Manual retraining requires explicitly trusted data and a fixed
  reference; automatic retraining is disabled. PSI does not prove poisoning safety.
- Bounded dashboard broadcasts and per-client sends, authenticated WebSocket
  metrics, and readiness checks for models, ingest and calibration.
- Dashboard separates policy severity from confidence and displays degraded
  readiness. Default confidence is explicitly heuristic.
- External CSV adapters retain partial measurements/provenance rather than invent
  required features or map arbitrary malware labels to exfiltration.
- Updated runbook and public dataset acquisition/extraction documentation.

Existing cookie authentication, alert-chain verification, one-way Docker feed
and explicit opt-in attack lab configuration remain covered. Disk appends are
not fsync-backed; software isolation is not a physical data diode.

## Final checks

- Backend: **257 passed, 12 skipped**, with SKIP_DOCKER_TESTS=1; one dependency
  deprecation warning. Docker checks below ran separately.
- React production build: passed.
- Docker rebuild and diode proof: passed forward delivery, reverse DROP and live
  scoring; 522 flows scored and 470 alerts emitted at the verification snapshot.
- Isolated v2 model/calibration fingerprint startup check: passed.
- Exported-flow benchmark: **200 flows/sec for 10 seconds**, 2,000 sent/scored,
  no observed loss. Send-to-log-append p95 **199.31ms**, p99 **219.12ms**.
  Includes UDP buffering, validation, inference and disk append; excludes packet
  extraction, fsync and browser rendering. Host: x86_64, 16 logical CPUs,
  Python 3.12.14. This is neither a long soak nor raw-packet throughput proof.

## Candidate results and serving status

The isolated candidate is in data/candidate-v2-final/. Train/calibration/test
captures have different seeds and hashes but share synthetic scenario families.
These functional results do not establish independent real-world accuracy.

| Test class | Test flows | Correct after alert gating |
|---|---:|---:|
| Benign | 127 | 126 |
| Volumetric DDoS | 1,506 | 1,506 |
| C2 beaconing | 40 | 40 |
| DNS tunnelling/DGA | 50 | 50 |
| Reconnaissance | 300 | 287 |
| Exfiltration | 12 | 12 |
| Encrypted malware | 0 | Unvalidated |

One benign false alert (0.79%); six scans labelled beaconing and seven suppressed.
Full precision/recall/F1, confusion matrix and hashes are in the JSON report.
Flood/exfiltration confusion is resolved on these candidate scenarios. The
original v1 packet-lab failure is not claimed fixed in default serving.

**Candidate not promoted.** Default serving retains v1, 16-feature pinned models
isoforest_v18.pkl and xgb_v15.json. Enabling v2 without compatible artifacts
fails readiness. See README for the candidate workflow.

## Public data and remaining work

Downloaded official CTU-13 scenario 7 PCAP and flow labels; extracted **3,366**
measured flows. [PUBLIC_DATA.md](PUBLIC_DATA.md) records URLs, citation, sizes,
hashes and commands. Full-network labels and the infected-host PCAP require
validated temporal joins and threat-specific interpretation before training.
Generic botnet labels do not prove periodic C2 or encrypted malware.

Remaining acceptance work:

1. Representative independently labelled packet captures for all six classes,
   especially encrypted malware and legitimate encrypted traffic.
2. Validated public label joins, evaluation on unseen capture families,
   representative calibration and false-positive review before v2 promotion.
3. Raw-packet extraction-to-alert measurements and longer-duration tests on the
   intended deployment hardware; browser delivery latency is also unmeasured.

The first two depend on suitable data and label quality. The third is additional
performance validation; the exported-flow target above is demonstrated.
