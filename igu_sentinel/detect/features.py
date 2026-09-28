"""Shared feature extraction for detection layers.

Converts a FlowRecord into a fixed-order numeric feature vector.
Both isoforest.py and xgb.py import this — do NOT duplicate it.

Feature vector (27 dimensions, contract v2 — order is fixed; never reorder):

  ── v1 features (0–15) — layout unchanged from v1 ─────────────────────────
   0  inter_arrival_mean      – mean inter-packet gap (seconds)
   1  inter_arrival_std       – std of inter-packet gap
   2  pkt_size_mean           – mean packet size (bytes)
   3  pkt_size_std            – std of packet size
   4  pkt_size_min            – min packet size
   5  pkt_size_max            – max packet size
   6  entropy                 – Shannon payload entropy [0, 8]
   7  payload_frame_ratio     – payload bytes / total frame bytes [0, 1]
                                (old name: byte_ratio; same field in FlowRecord)
   8  ttl                     – IP TTL (float)
   9  fanout_count            – connection fan-out; 0 when absent
  10  dns_ngram_entropy        – DNS n-gram entropy; 0.0 when absent
  11  has_beacon_interval      – binary: 1.0 if beacon_interval_stats present
  12  has_ja4                  – binary: 1.0 if flow has TLS/QUIC JA4 fingerprint
  13  ja4_is_malicious         – binary: 1.0 if JA4 matches malware IOC/profile
  14  ja4_no_sni               – binary: 1.0 if JA4 indicates missing SNI ('i')
  15  ja4_no_alpn              – binary: 1.0 if JA4 indicates missing ALPN ('00')

  ── v2 features (16–26) — new in feature contract v2 ──────────────────────
  16  pkt_rate                 – packets / second in the capture window
  17  byte_rate                – total frame bytes / second in the capture window
  18  syn_count                – TCP SYN packets in this window
  19  syn_fraction             – SYN packets / total packets [0, 1]
  20  src_ip_entropy           – Shannon entropy of distinct source IPs;
                                 near 0 for single-source; high for spoofed floods
  21  outbound_observed        – 1.0 if outbound_bytes is not None, else 0.0
  22  outbound_bytes_log1p     – log1p(outbound_bytes) when observed, else 0.0
  23  inbound_observed         – 1.0 if inbound_bytes is not None, else 0.0
  24  inbound_bytes_log1p      – log1p(inbound_bytes) when observed, else 0.0
  25  dns_is_txt               – 1.0 if dns_record_type == 'TXT', else 0.0
                                 (TXT at high rate is the primary DNS-tunnel signal)

  26  dns_query_len           – mean DNS query label length; -1 when absent

Nullable optional fields are imputed as documented above (observed/unobserved
flags instead of silent zeros) so the vector stays deterministic without access
to training data, and so the model can distinguish "not available" from "zero".

Fusion does NOT re-calibrate raw_score — each detector must output
calibrated_probability already Platt-scaled to [0, 1].
"""

import math
from typing import List, Optional
from igu_sentinel.schemas import FlowRecord, FEATURE_CONTRACT_VERSION

# Total number of features — other modules reference this constant so a
# dimension mismatch is caught at import time, not at predict time.
FEATURE_DIM = 27 if FEATURE_CONTRACT_VERSION == 2 else 16

# The version of the feature contract this file implements.  Saved model
# artifacts embed this value; loaders reject any artifact whose stored version
# does not match FEATURE_CONTRACT_VERSION.
_FEATURE_CONTRACT_VERSION = FEATURE_CONTRACT_VERSION

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
    """Return True only for JA4 fingerprints on the known-malicious IOC list.

    This is an exact-match IOC check and nothing else.

    It previously also returned True for *any* fingerprint whose SNI flag was
    'i' (no domain SNI). That was wrong in three compounding ways:

      * No SNI is ordinary, not malicious — every TLS connection made to a bare
        IP has it, which on a monitored segment includes health checks, probes,
        container-to-container traffic and captive-portal checks. It is a weak
        signal, so it belongs to the weighted rule that corroborates it with
        payload entropy, not to a hard IOC verdict worth +0.40.
      * It made :func:`has_no_sni_ja4` redundant, so the `elif has_no_sni_ja4`
        branch in ``detect/rules.py`` was unreachable dead code — the weaker,
        corroborated rule could never fire because the stronger uncorroborated
        one always won first.
      * Features 13 and 14 of the model vector became perfectly collinear,
        wasting a dimension and letting the classifier key on "no SNI" alone.

    The no-SNI signal is still available via :func:`has_no_sni_ja4`, which is
    where it is correctly weighted.
    """
    if not ja4:
        return False
    return ja4 in KNOWN_MALICIOUS_JA4


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
    """Convert a FlowRecord into a fixed-order contract-versioned feature vector.

    Args:
        flow: FlowRecord instance (validated by Pydantic before reaching here).

    Returns:
        List of FEATURE_DIM floats in the canonical order documented at module level.
    """
    ja4 = flow.ja4
    features = [
        # ── v1 features (0–15) ───────────────────────────────────────────────
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
        # 7: payload/frame ratio (payload bytes / total frame bytes)
        # NOTE: does NOT indicate traffic direction; see features 21–24 for that.
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

        # ── v2 features (16–26) ──────────────────────────────────────────────
        # 16: packet rate (packets/sec) — distinguishes high-rate floods from
        #     slow exfiltration even when both have large packets
        float(flow.pkt_rate),
        # 17: byte rate (bytes/sec) — absolute volume separates floods from trickle
        float(flow.byte_rate),
        # 18: SYN count — TCP SYN flood has syn_count ≈ total_packets
        float(flow.syn_count),
        # 19: SYN fraction [0, 1] — 1.0 = pure SYN flood; 0.0 = data transfer
        float(flow.syn_fraction),
        # 20: source-IP entropy — near 0 = single source; high = distributed/spoofed
        float(flow.src_ip_entropy),
        # 21: outbound direction observed flag
        1.0 if flow.outbound_bytes is not None else 0.0,
        # 22: log1p(outbound_bytes) when observed, else 0 — log scale for byte volumes
        math.log1p(float(flow.outbound_bytes)) if flow.outbound_bytes is not None else 0.0,
        # 23: inbound direction observed flag
        1.0 if flow.inbound_bytes is not None else 0.0,
        # 24: log1p(inbound_bytes) when observed, else 0
        math.log1p(float(flow.inbound_bytes)) if flow.inbound_bytes is not None else 0.0,
        # 25: modal DNS query type indicator; not a fraction or a verdict
        1.0 if (flow.dns_record_type or "").upper() == "TXT" else 0.0,
        float(flow.dns_query_len) if flow.dns_query_len is not None else -1.0,
    ]

    return features[:FEATURE_DIM]
