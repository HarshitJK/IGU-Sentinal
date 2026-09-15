"""Shared feature extraction for detection layers.

Converts a FlowRecord into a fixed-order numeric feature vector.
Both isoforest.py and xgb.py import this — do NOT duplicate it.

Feature vector (16 dimensions, order is fixed — never reorder):
  0  inter_arrival_mean      – mean inter-packet gap (seconds)
  1  inter_arrival_std       – std of inter-packet gap
  2  pkt_size_mean           – mean packet size (bytes)
  3  pkt_size_std            – std of packet size
  4  pkt_size_min            – min packet size
  5  pkt_size_max            – max packet size
  6  entropy                 – Shannon payload entropy [0, 8]
  7  byte_ratio              – byte ratio (asymmetry indicator) [0, 1]
  8  ttl                     – IP TTL (float)
  9  fanout_count            – connection fan-out; 0 when absent
  10 dns_ngram_entropy        – DNS n-gram entropy; 0.0 when absent
  11 has_beacon_interval      – binary: 1.0 if beacon_interval_stats present
  12 has_ja4                  – binary: 1.0 if flow has TLS/QUIC JA4 fingerprint
  13 ja4_is_malicious         – binary: 1.0 if JA4 matches malware IOC/profile
  14 ja4_no_sni               – binary: 1.0 if JA4 indicates missing SNI ('i')
  15 ja4_no_alpn              – binary: 1.0 if JA4 indicates missing ALPN ('00')

Nullable optional fields are imputed with 0 (neutral/absent) rather than the
feature mean so the vector stays deterministic without access to training data.
Fusion does NOT re-calibrate raw_score — each detector must output
calibrated_probability already Platt-scaled to [0, 1].
"""

from typing import List, Optional
from igu_sentinel.schemas import FlowRecord

# Total number of features — other modules reference this constant so a
# dimension mismatch is caught at import time, not at predict time.
FEATURE_DIM = 16

# Known malicious JA4 fingerprints (fixtures, mock generation, malware toolsets)
KNOWN_MALICIOUS_JA4 = {
    "t13d1200h1_5b20,21,35_00",
    "t13d1618h0_002f,00-02-01_1301-1302-1303-1201-1200_000b-000a-0009-0008_0016,_45,1",
    "t13i050200_e133e205ac38_000000000000",
    "t13i040200_002f1301c02f_000000000000",
    "t12i040400_002fc02fc030_000000000000",
    "t13i050100_e133e205ac38_b9a491fefe05",
}


def is_malicious_ja4(ja4: Optional[str]) -> bool:
    """Return True if JA4 matches known malware fingerprints or signature patterns."""
    if not ja4:
        return False
    if ja4 in KNOWN_MALICIOUS_JA4:
        return True
    if len(ja4) >= 10:
        # 'i' indicates missing domain SNI (connecting directly to IP or custom C2)
        if ja4[3] == "i":
            return True
    return False


def has_no_sni_ja4(ja4: Optional[str]) -> bool:
    """Return True if JA4 indicates absence of domain SNI ('i' flag)."""
    if not ja4 or len(ja4) < 4:
        return False
    return ja4[3] == "i"


def has_no_alpn_ja4(ja4: Optional[str]) -> bool:
    """Return True if JA4 indicates absence of ALPN ('00')."""
    if not ja4 or len(ja4) < 10:
        return False
    return ja4[8:10] == "00"


def extract_features(flow: FlowRecord) -> List[float]:
    """Convert a FlowRecord into a fixed-order 16-dimensional feature vector.

    Args:
        flow: FlowRecord instance (validated by Pydantic before reaching here).

    Returns:
        List of 16 floats in the canonical order documented at module level.
    """
    ja4 = flow.ja4
    return [
        # 0: inter-arrival mean (DDoS → very small; C2 beacon → large & regular)
        float(flow.inter_arrival_stats.get("mean", 0.0)),
        # 1: inter-arrival std (regularity: low std = beaconing or DDoS burst)
        float(flow.inter_arrival_stats.get("std", 0.0)),
        # 2-5: packet size distribution
        float(flow.packet_size_stats.get("mean", 0.0)),
        float(flow.packet_size_stats.get("std", 0.0)),
        float(flow.packet_size_stats.get("min", 0.0)),
        float(flow.packet_size_stats.get("max", 0.0)),
        # 6: entropy (high = encrypted/compressed; low = repetitive/simple)
        float(flow.entropy),
        # 7: byte ratio (exfil → very high; scan → very low)
        float(flow.byte_ratio),
        # 8: TTL (OS fingerprinting; spoofed DDoS may show unusual values)
        float(flow.ttl),
        # 9: fanout count (scan → high; DGA → moderate; benign → 0 or 1)
        float(flow.fanout_count) if flow.fanout_count is not None else 0.0,
        # 10: DNS n-gram entropy (DGA → very high; benign DNS → moderate)
        float(flow.dns_ngram_entropy) if flow.dns_ngram_entropy is not None else 0.0,
        # 11: beacon interval presence flag (C2 → 1; others → 0)
        1.0 if flow.beacon_interval_stats is not None else 0.0,
        # 12: JA4 presence (TLS/QUIC handshake present)
        1.0 if ja4 is not None else 0.0,
        # 13: JA4 known malicious or suspicious profile
        1.0 if is_malicious_ja4(ja4) else 0.0,
        # 14: JA4 missing SNI domain ('i')
        1.0 if has_no_sni_ja4(ja4) else 0.0,
        # 15: JA4 missing ALPN ('00')
        1.0 if has_no_alpn_ja4(ja4) else 0.0,
    ]
