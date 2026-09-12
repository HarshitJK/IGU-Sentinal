# IGU Sentinel — Architecture

## Problem context

Critical-infrastructure operators monitor gateway/peering links using hardware data diodes
that copy traffic into a monitoring enclave in one direction only. The enclave sees everything
crossing the link but has no physical or protocol-level path back into the production network.
This removes an entire class of attack (a compromised monitoring system pivoting into the core
network) and preserves forensic chain of custody. The cost: any intelligence layer here must
work from passive observation alone — no probes, no completed handshakes, no return-path action.

IGU Sentinel is that intelligence layer: an AI/ML pipeline that ingests one-directional traffic
and produces labeled, evidence-backed alerts in near real time.

## What this system is not

It is not an inline mitigation system (Cloudflare, a WAF, an IPS). It cannot block, rate-limit,
or reroute traffic — there is no return path to act on. Output is intelligence only: alerts,
confidence scores, evidence, for a human analyst or a separate system to act on. This is a
deliberate constraint, not a limitation to work around — it's the security property that makes
the monitoring enclave safe to deploy against a production network in the first place.

## System overview

```
[Production network]              [Diode: one-way, enforced]        [Monitoring enclave]
traffic_gen (benign + attack)  →   relay + iptables DROP on return →   ingest → detect (x4) → fusion → alert
                                                                              ↓
                                                                            drift (monitors isoforest, retrains)
```

Everything right of the diode runs as a single in-process FastAPI service. No HTTP calls
between internal modules — plain async function calls — since introducing local network
endpoints between trusted internal components would create unnecessary attack surface on a
security product. tshark is the one external process (packet capture); it's a mature,
decades-audited parser, deliberately used instead of a hand-rolled one, since packet parsers
are a classic source of memory-safety bugs and reinventing one adds risk without adding
anything the PS actually asks to be evaluated on.

## Zero trust, at three levels

1. **Network** — the diode enforces one-way flow both at the application level (relay logic
   only reads from production, only writes to enclave) and at the network level (iptables/nftables
   DROP rules on the return path), so a bug in the relay code alone can't break the guarantee.
2. **Data** — every module validates its own input against the schemas below, rather than
   trusting that an upstream module produced well-formed output. This also makes each module
   independently fuzz-testable.
3. **Decision** — no single detection layer's verdict is trusted alone. An alert only reaches
   high-confidence tier when at least two independent layers (rules, statistics, Isolation
   Forest, XGBoost) corroborate it. This directly targets alert fatigue: industry data shows
   SOC analysts often trust and act on only a small fraction of raw NIDS alerts.

## Data contracts

**FlowRecord** — produced by `ingest`, consumed by every `detect_*` module:
`flow_id, timestamp, src_port, dst_port, protocol, packet_size_stats{min,max,mean,std}, inter_arrival_stats{mean,std}, entropy, byte_ratio, ttl, ja4, beacon_interval_stats, dns_ngram_entropy, fanout_count`

**LayerScore** — produced by each `detect_*`, consumed by `fusion`:
`flow_id, layer_name, raw_score, calibrated_probability, threat_class_guess, evidence[]`

**Alert** — produced by `fusion`, consumed by `alert` — matches the PS-mandated schema exactly:
`timestamp, flow_id, threat_class, confidence_score, evidence`

## Detection pipeline

**Ingest**: tshark subprocess captures on a fixed 120ms window. Fixed, not adaptive — an
adaptive window is gameable (an attacker can manipulate their traffic rate to force a window
size that weakens detection). Feature extraction happens in plain Python on tshark's output.

**Four independent detection layers**, each scoring every FlowRecord:
- *Rules* — static IOC/protocol-violation matching.
- *Statistics* — z-score deviation against a rolling baseline.
- *Isolation Forest* (unsupervised) — trained once on a benign-only warmup batch; anomaly score
  from isolation path depth.
- *XGBoost* (supervised, multi-class) — one class per threat type + benign, trained on labeled
  synthetic traffic; uses class weighting since benign traffic vastly outnumbers any single
  attack type.

**Six mandated threat classes**, each mapped to the layer(s) that primarily detect it:
| Threat class | Primary signal |
|---|---|
| Volumetric/protocol DDoS | flow-rate + source-IP entropy (statistics) |
| Botnet C2 beaconing | periodicity/inter-arrival regularity (new feature) |
| DGA / DNS tunneling | entropy + n-gram analysis on DNS query names |
| Encrypted malware | JA4 fingerprint + packet-size/timing sequence (no decryption) |
| Reconnaissance/scanning | fan-out pattern, one source across many dest ports/hosts |
| Data exfiltration | asymmetric flow volume, outbound/inbound byte-ratio anomaly |

**Fusion**: each layer's raw score is calibrated to a probability via Platt scaling (fit on
held-out labeled data) before combination — a raw Isolation Forest path-length score and a raw
XGBoost logit are not directly comparable, so calibration happens first. The combined score is
still called `confidence_score` in the output schema (matching the PS's exact wording) but is a
calibrated probability under the hood, computed only after cross-layer correlation gates it into
a confidence tier.

**Drift & adaptivity**: the Isolation Forest baseline is re-evaluated over time, not fixed
forever — but retraining is deliberately hard to poison:
- Only flows confirmed benign by the *fused* cross-layer verdict are eligible for retraining
  data, never flows that merely scored low on Isolation Forest alone.
- Drift is measured via KS-test or Population Stability Index (PSI > 0.2 is the standard
  significant-drift threshold) comparing the current score distribution to the original baseline.
- Any single retrain is bounded in how far it can shift the decision boundary.
- The original baseline model is kept permanently as a fallback/reference; if the current model
  diverges too far from it, that divergence itself is raised as a meta-alert for human review.

## Environment simulation

Traffic is generated with the PS-mandated toolchain (iperf3/Ostinato/TRex for benign; hping3,
Slowloris, dnscat2/iodine, DGA samples for attacks) through a config-driven harness
(`traffic_gen/`) that varies source-IP mode, rate, packet size, and target port across runs —
so models learn attack *behavior*, not one tool's default parameter fingerprint. The one-way
constraint is enforced architecturally, not just by stripping fields from a bidirectional
dataset: separate Docker networks for "production" and "monitoring enclave," connected only
through a diode container that is application- and network-level one-way, with the no-return-path
property tested and logged as submission evidence.

## Evaluation

Primary training/evaluation is on the PS-mandated synthetic traffic. Secondary cross-validation
against CIC-IDS2017/2018, UNSW-NB15, and CTU-13 (botnet/C2 focus) checks generalization beyond
the synthetic generator's own signature, after stripping any bidirectional-only fields. Results
are reported as per-class precision/recall/F1, not aggregate accuracy, since aggregate accuracy
is misleading on the heavily benign-skewed traffic this system will actually see. A dedicated
benchmark harness measures and logs sustained throughput (flows/sec) and end-to-end latency, per
the PS's explicit requirement to state and demonstrate a concrete throughput target.
