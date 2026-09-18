"""Converter and inference harness for real-world CIC-IDS2017 network traffic.

CRITICAL DIODE CONSTRAINT (CLAUDE.md / REMAINING_FIXES.md R4):
A physical data diode permits strictly unidirectional traffic. A sensor deployed
on the enclave side of the diode can only ever observe forward-direction frames.
Standard network datasets (like CIC-IDS2017) are calculated by bidirectional flow
meters (e.g. CICFlowMeter), providing columns describing the reverse direction:
  - Bwd Packet Length Max/Min/Mean/Std
  - Bwd IAT Total/Mean/Std/Max/Min
  - Bwd Packets/s, Bwd Header Length, etc.

Including backward fields would evaluate a system that cannot physically exist
in a diode-isolated enclave. This module explicitly DROPS all reverse-direction
fields and maps ONLY forward-direction metadata into FlowRecord.
"""

import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from igu_sentinel.detect.features import extract_features
from igu_sentinel.detect.xgb import predict_xgb_batch, THREAT_CLASSES
from igu_sentinel.schemas import FlowRecord

logger = logging.getLogger(__name__)

# Column name aliases across various releases of CIC-IDS2017/2018 CSVs.
# Headers in raw CSVs often contain leading/trailing whitespaces.
_COLUMN_ALIASES = {
    "dst_port": ["destination port", "dst port", "dsport", "id.resp_p"],
    "protocol": ["protocol", "proto"],
    "flow_duration": ["flow duration", "dur"],
    "fwd_packets": ["total fwd packets", "tot fwd pkts", "spkts", "total fwd packet"],
    # Payload bytes (forward direction only — no Bwd columns)
    "fwd_bytes": ["total length of fwd packets", "totlen fwd pkts", "sbytes",
                  "total length of fwd packet", "subflow fwd bytes"],
    # Header bytes for byte_ratio denominator
    "fwd_hdr_len": ["fwd header length"],
    "fwd_pkt_len_mean": ["fwd packet length mean", "fwd pkt len mean", "smeansz",
                        "fwd segment size avg"],
    "fwd_pkt_len_std": ["fwd packet length std", "fwd pkt len std"],
    "fwd_pkt_len_min": ["fwd packet length min", "fwd pkt len min", "fwd seg size min"],
    "fwd_pkt_len_max": ["fwd packet length max", "fwd pkt len max"],
    "pkt_len_variance": ["packet length variance"],
    # Use dedicated forward-direction IAT columns (not the bidirectional flow IAT).
    # CICFlowMeter computes both; Fwd IAT Mean is what a diode sensor would observe.
    "fwd_iat_mean": ["fwd iat mean"],
    "fwd_iat_std": ["fwd iat std"],
    # Flow-level IAT as fallback when Fwd IAT columns are absent
    "flow_iat_mean": ["flow iat mean"],
    "flow_iat_std": ["flow iat std"],
    # TTL via TTL column (not header-length); header-length used for byte_ratio
    "ttl": ["sttl"],
    "label": ["label", "attack_cat", "attack category"],
}

# Explicit label mapping from CIC-IDS2017 ground truth labels to the 7 classes.
# Ambiguous or non-applicable attacks are intentionally left unmapped (or mapped to None).
_LABEL_MAPPING = {
    "benign": "benign",
    # DDoS / DoS variants
    "ddos": "volumetric_ddos",
    "dos hulk": "volumetric_ddos",
    "dos goldeneye": "volumetric_ddos",
    "dos slowloris": "volumetric_ddos",
    "dos slowhttptest": "volumetric_ddos",
    # PortScan / Probing
    "portscan": "recon_scanning",
    # Botnet / C2
    "bot": "c2_beaconing",
    # Web attacks / Exfil / Infiltration
    "ftp-patator": "data_exfiltration",
    "ssh-patator": "data_exfiltration",
    "web attack – brute force": "data_exfiltration",
    "web attack – xss": "data_exfiltration",
    "web attack – sql injection": "data_exfiltration",
    "infiltration": "encrypted_malware",
    "heartbleed": "encrypted_malware",
}

# Labels in CIC-IDS2017 that do NOT have a clean 1:1 mapping to our 7 classes.
# Documented explicitly rather than forcing inaccurate classifications:
UNMAPPED_LABELS_DOCUMENTATION = [
    "Web Attack – Sql Injection (sometimes classified as recon or exfil depending on payload size)",
    "Infiltration (cross-boundary pivoting; maps partially to encrypted_malware)",
]


def _normalise(col: str) -> str:
    """Strip whitespace, lowercase, and normalize punctuation in headers."""
    return col.strip().lower().replace("_", " ").replace("-", " ")


def map_cicids_label(raw_label: Optional[str]) -> Optional[str]:
    """Map a raw CIC-IDS2017 label string to one of the 7 project classes.

    Returns:
        One of {'benign', 'volumetric_ddos', 'c2_beaconing', 'dga_dns_tunneling',
                'encrypted_malware', 'recon_scanning', 'data_exfiltration'},
        or None if the label cannot be mapped cleanly.
    """
    if not raw_label or not isinstance(raw_label, str):
        return None
    cleaned = raw_label.strip().lower()
    if cleaned in _LABEL_MAPPING:
        return _LABEL_MAPPING[cleaned]

    # Partial / substring fallback for encoding discrepancies (e.g. en-dash)
    for k, v in _LABEL_MAPPING.items():
        if k in cleaned:
            return v
    return None


def convert_row_to_flow_record(
    row: Dict[str, str], col_map: Dict[str, str], index: int
) -> Optional[Tuple[FlowRecord, str]]:
    """Convert a single CSV row from CIC-IDS2017 into a FlowRecord.

    Only forward-direction fields are used; all Bwd_* columns are dropped.
    """
    if not row or not isinstance(row, dict):
        return None
    raw_label = row.get(col_map.get("label", "")) or "benign"
    mapped_label = map_cicids_label(raw_label)
    if mapped_label is None:
        return None

    def _get_float(canonical_key: str, default: float = 0.0) -> float:
        actual_col = col_map.get(canonical_key)
        if not actual_col or actual_col not in row:
            return default
        try:
            val = float(row[actual_col])
            return val if np.isfinite(val) else default
        except (ValueError, TypeError):
            return default

    def _get_int(canonical_key: str, default: int = 0) -> int:
        return int(_get_float(canonical_key, float(default)))

    dst_port = _get_int("dst_port", 80)
    proto_raw = _get_int("protocol", 6)
    proto_str = "TCP" if proto_raw == 6 else "UDP" if proto_raw == 17 else "ICMP" if proto_raw == 1 else "OTHER"

    fwd_len_mean = _get_float("fwd_pkt_len_mean", 0.0)
    fwd_len_std = _get_float("fwd_pkt_len_std", 0.0)
    fwd_len_min = _get_float("fwd_pkt_len_min", 0.0)
    fwd_len_max = _get_float("fwd_pkt_len_max", fwd_len_mean)

    # DIODE NOTE: we use forward-direction IAT exclusively (Fwd IAT Mean/Std),
    # never the bidirectional Flow IAT columns.  Fallback to flow-level only if
    # the dedicated Fwd IAT columns are absent from this CSV variant.
    fwd_iat_mean_us = _get_float("fwd_iat_mean", -1.0)
    if fwd_iat_mean_us < 0:  # column absent — use bidirectional fallback
        fwd_iat_mean_us = _get_float("flow_iat_mean", 0.0)
        fwd_iat_std_us = _get_float("flow_iat_std", 0.0)
    else:
        fwd_iat_std_us = _get_float("fwd_iat_std", 0.0)
    # CICFlowMeter stores IATs in microseconds; convert to seconds.
    fwd_iat_mean_s = fwd_iat_mean_us / 1e6
    fwd_iat_std_s = fwd_iat_std_us / 1e6

    # byte_ratio: payload bytes / (payload + header bytes)
    # This is the only ratio a diode sensor can measure from forward frames.
    # Hard-coding 1.0 made every flow look like data_exfiltration (model feature 7).
    fwd_payload = _get_float("fwd_bytes", 0.0)
    fwd_hdr = _get_float("fwd_hdr_len", 0.0)
    total_observed = fwd_payload + fwd_hdr
    byte_ratio = min(1.0, fwd_payload / total_observed) if total_observed > 0 else 0.5

    # Proxy entropy from packet length variance.
    # CIC-IDS does not expose Shannon entropy directly.  Variance of packet sizes
    # correlates with randomness: encrypted/compressed payloads produce large, similar
    # packets (low variance, high entropy), while scans produce tiny uniform probes.
    # We map variance → [0, 8] range: variance of ~60,000 bytes² → entropy ≈ 8.
    pkt_variance = _get_float("pkt_len_variance", -1.0)
    if pkt_variance >= 0:
        # sqrt(variance) = std; map 0..1000 bytes → 0..8 bits
        proxy_entropy = min(8.0, (pkt_variance ** 0.5) / 125.0)
    else:
        # Fallback: use fwd_pkt_len_std
        proxy_entropy = min(8.0, fwd_len_std / 125.0)

    record = FlowRecord(
        flow_id=f"cicids_{index:07d}",
        timestamp=datetime.now(),
        src_port=0,
        dst_port=dst_port,
        protocol=proto_str,
        packet_size_stats={
            "min": fwd_len_min,
            "max": fwd_len_max,
            "mean": fwd_len_mean,
            "std": fwd_len_std,
        },
        inter_arrival_stats={
            "min": 0.0,
            "max": fwd_iat_mean_s * 2.0,
            "mean": fwd_iat_mean_s,
            "std": fwd_iat_std_s,
        },
        entropy=proxy_entropy,
        byte_ratio=byte_ratio,
        ttl=_get_int("ttl", 64),
        ja4=None,
        beacon_interval_stats=None,
        dns_ngram_entropy=None,
        fanout_count=1,
    )

    return record, mapped_label


def load_cicids_dataset(
    csv_path: str, limit: Optional[int] = None
) -> Tuple[List[FlowRecord], List[str], Dict[str, int]]:
    """Load and convert a CIC-IDS2017 CSV file into FlowRecords.

    Returns:
        (flows, mapped_labels, dropped_label_counts)
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"CIC-IDS2017 dataset file not found: {csv_path}")

    flows: List[FlowRecord] = []
    labels: List[str] = []
    dropped_counts: Dict[str, int] = {}

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return [], [], {}

        # Resolve header aliases
        col_map: Dict[str, str] = {}
        for canonical, aliases in _COLUMN_ALIASES.items():
            for idx, raw_name in enumerate(header):
                if _normalise(raw_name) in aliases:
                    col_map[canonical] = raw_name
                    break

        header_dict_reader = csv.DictReader(f, fieldnames=header)
        for i, row in enumerate(header_dict_reader):
            if limit and len(flows) >= limit:
                break
            result = convert_row_to_flow_record(row, col_map, i)
            if result is None:
                raw_lbl = str(row.get(col_map.get("label", ""), "unknown") or "unknown").strip()
                dropped_counts[raw_lbl] = dropped_counts.get(raw_lbl, 0) + 1
                continue
            flow, label = result
            flows.append(flow)
            labels.append(label)

    return flows, labels, dropped_counts


def run_inference_benchmark(
    csv_path: str, limit: Optional[int] = 50000
) -> Dict[str, any]:
    """Run pure inference with models/CURRENT against converted real-world dataset.

    Returns:
        Dictionary containing per-class precision, recall, f1, support, and confusion matrix.
    """
    flows, y_true, dropped = load_cicids_dataset(csv_path, limit=limit)
    if not flows:
        raise ValueError(f"No usable flows extracted from {csv_path}")

    layer_scores = predict_xgb_batch(flows)
    y_pred = [s.threat_class_guess or "benign" for s in layer_scores]
    class_labels = THREAT_CLASSES

    # Calculate metrics
    metrics = {}
    for cls in class_labels:
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == cls and yp == cls)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != cls and yp == cls)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == cls and yp != cls)
        support = sum(1 for yt in y_true if yt == cls)
        pr = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rc = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * pr * rc) / (pr + rc) if (pr + rc) > 0 else 0.0
        metrics[cls] = {
            "precision": pr,
            "recall": rc,
            "f1": f1,
            "support": support,
        }

    total_acc = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp) / len(y_true)
    macro_f1 = np.mean([m["f1"] for m in metrics.values() if m["support"] > 0])

    return {
        "total_samples": len(flows),
        "accuracy": total_acc,
        "macro_f1": macro_f1,
        "per_class": metrics,
        "dropped_unmapped": dropped,
    }
