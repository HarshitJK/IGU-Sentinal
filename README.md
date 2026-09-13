# IGU Sentinel — Unidirectional AI/ML Network Threat Detection

> Passive, near real-time AI/ML threat detection for data-diode-fed, one-way network links. Built for **SIH26145** (NTRO — Smart India Hackathon / *Blockchain & Cybersecurity* theme).

---

## Overview

Critical infrastructure operators monitor peering and gateway links using hardware **data diodes** that copy traffic unidirectionally into an isolated monitoring enclave. The enclave gains complete traffic visibility while ensuring zero return path back to production networks.

**IGU Sentinel** serves as the intelligent detection engine inside the monitoring enclave. Operating under strict passive observation constraints, it ingests unidirectional stream flows, extracts statistical and behavioral features without payload decryption, and produces evidence-backed, tamper-evident security alerts.

---

## Key Constraints & Guarantees

* **Passive & Unidirectional Only**: Operates without a return path, active probing, or inline block/mitigation capability.
* **No Payload Decryption**: Analyzes encrypted TLS/QUIC sessions purely from metadata (JA4 fingerprints, packet size distributions, inter-arrival timing).
* **Streaming Feature Extraction**: Processes flows over a fixed **120ms capture window** to prevent timing manipulation attacks.
* **Zero Trust Decision Corroboration**: High-confidence alerts require agreement across at least **two independent detection layers**.
* **Fixed Alert Data Contract**:
  ```json
  {
    "timestamp": "2026-09-13T19:07:00Z",
    "flow_id": "flow_8a2b3c4d",
    "threat_class": "c2_beaconing",
    "confidence_score": 0.89,
    "evidence": ["regular_beacon_interval", "unusual_inter_arrival_time"]
  }
  ```

---

## System Architecture

```
[Production Network]            [Hardware Diode: One-Way]       [Monitoring Enclave]
Traffic Generators      ───►  Relay + iptables DROP return  ───► Ingest (tshark 120ms)
(iperf3/dnscat2/hping3)                                                   │
                                                                          ▼
                                                               4-Layer Detection Engine
                                                               (Rules, Stats, IsoForest, XGB)
                                                                          │
                                                                          ▼
                                                                Cross-Layer Fusion
                                                                (Platt Calibration)
                                                                          │
                                                                          ▼
                                                                Hash-Chained Alert Log
                                                                (SHA-256 Audit Trail)
```

---

## 4-Layer Detection Engine

IGU Sentinel evaluates incoming flow metadata through four parallel detection modules:

1. **Static IOC & Rule Engine (`igu_sentinel/detect/rules.py`)**:
   Heuristic checks for volumetric bursts, low inter-arrival times, DNS n-gram entropy/fanout, port scanning, and anomalous byte ratios.
2. **Z-Score Statistical Baseline (`igu_sentinel/detect/stats.py`)**:
   Z-score deviation detector trained on benign flow distributions across packet sizes, timing, entropy, and TTL.
3. **Unsupervised Isolation Forest (`igu_sentinel/detect/isoforest.py`)**:
   Distance-based anomaly detector trained on benign-only traffic, scoring flow isolation depth in feature space.
4. **Supervised Multi-Class Classifier (`igu_sentinel/detect/xgb.py`)**:
   Per-class threat predictor mapping flows into PS-mandated threat classes.

### Supported Threat Classes (PS-Mandated)
| Threat Class | Primary Signal |
|---|---|
| `volumetric_ddos` | Flow rate spikes, low inter-arrival times |
| `c2_beaconing` | Periodic callbacks, low inter-arrival variance, JA4 fingerprints |
| `dga_dns_tunneling` | High DNS n-gram entropy, elevated query fanout |
| `encrypted_malware` | Suspicious port/entropy combinations, TLS metadata |
| `recon_scanning` | Ephemeral ports, small probe packet fanouts |
| `data_exfiltration` | Asymmetric outbound byte ratios, large sustained transfers |

---

## Additional Core Systems

* **Cross-Layer Score Fusion (`igu_sentinel/fusion/`)**:
  Calibrates layer outputs into probabilities via Platt scaling and applies multi-layer corroboration gates.
* **Tamper-Evident SHA-256 Audit Chain (`igu_sentinel/alert/`)**:
  Maintains a cryptographic blockchain-style hash chain (`prev_hash` $\rightarrow$ `hash`) for forensic chain of custody verification.
* **PSI Score Drift Monitoring (`igu_sentinel/drift/`)**:
  Calculates Population Stability Index ($PSI > 0.2$) over rolling score windows and triggers bounded retrain events without discarding baseline models.
* **Config-Driven Traffic Generator (`igu_sentinel/traffic_gen/`)**:
  Synthetic dataset generation harness driven by YAML variant configs.

---

## Project Structure

```
IGU-Sentinal/
├── Makefile                          # Development and orchestration targets
├── Dockerfile                        # Sentinel FastAPI service container setup
├── docker-compose.yml                # Full stack: Sentinel, Diode, Traffic Generators, Test Containers
├── requirements.txt                  # Python dependencies
├── run_tests.py                      # Standalone test runner
├── igu_sentinel/
│   ├── schemas.py                    # Pydantic data contracts (FlowRecord, LayerScore, Alert)
│   ├── ingest/                       # tshark PCAP capture & feature extraction
│   ├── detect/                       # 4 detection layers (rules, stats, isoforest, xgb)
│   ├── fusion/                       # Platt scaling & cross-layer corroboration
│   ├── alert/                        # Hash-chained (SHA-256) audit logging & verification
│   ├── drift/                        # PSI score distribution monitoring & retrain trigger
│   ├── traffic_gen/                  # Config-driven traffic generator harness
│   └── api/                          # FastAPI REST application (/health, /detect)
└── tests/                            # Unit and integration test suite & JSONL fixtures
```

---

## Quick Start & Usage

### Prerequisites
* Python 3.11+
* Docker & Docker Compose (optional for containerized deployment)
* `tshark` (Wireshark CLI, optional for live PCAP ingest)

### 1. Local Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Available Commands (`Makefile`)
The repository includes a comprehensive `Makefile`:

```bash
make help        # List all available targets and descriptions
make test-unit   # Run fast unit tests (0.3s, no Docker required)
make test        # Run full pytest suite with virtualenv activated
make build       # Build Docker containers via docker-compose
make up          # Start all containers in background
make diode-proof # Up stack, run prod-test -> enclave-test ping check, print pass/fail
make gen-data    # Generate labeled synthetic flow datasets in datasets/
make down        # Teardown stack and remove volumes
make clean       # Clean caches and prompt before removing .venv
```

---

## Performance Benchmark

Measured sustained performance through the in-process detection and fusion pipeline:
* **Throughput**: $>40,000 \text{ flows/sec}$
* **Average Latency**: $\sim 0.03 \text{ ms}$ per flow
* **Test Suite**: 73 passing unit tests / 63 integration tests

---

## License

Developed for **SIH26145** (NTRO). All rights reserved.
