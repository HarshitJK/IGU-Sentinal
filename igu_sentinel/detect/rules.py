"""Static IOC and protocol-violation rule engine."""
from igu_sentinel.schemas import FlowRecord, LayerScore


# Suspicious port numbers (common C2, malware, etc.)
SUSPICIOUS_PORTS = {
    6666, 6667, 6668, 6669, 7777, 8888, 9999,  # Common IRC/C2 ports
    4444, 5555,  # Malware beacons
    31337, 27374, 27373,  # Classic backdoor ports
}

# Distinct targets touched by one source within a capture window before we call
# it reconnaissance. Real idle hosts talk to a handful of local services
# (measured 1-6 per 120ms window); scanners touch tens to thousands.
SCAN_FANOUT_THRESHOLD = 15

# A flood is distinguished from ordinary fast traffic by actually moving volume:
# either the frames are mostly payload, or they are large.
FLOOD_BYTE_RATIO_MIN = 0.85
FLOOD_PACKET_SIZE_MIN = 700

# DNS service ports - DNS-tunnelling rules only apply to actual DNS traffic.
DNS_PORTS = {53, 5353, 5355, 853}

# Bigram-entropy floor for calling DNS names algorithmically generated.
# Measured through the real ingest path: ordinary resolver traffic
# (www.google.com, api.github.com, _ipp._tcp.local ...) lands at 5.2-6.3, while
# DGA/tunnelling names (random 20+ char labels) land at 7.4-8.5.
DNS_NGRAM_ENTROPY_THRESHOLD = 7.0

# Known safe ports (can lower suspicion for legitimate services)
SAFE_PORTS = {22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080}


def detect_rules(flow: FlowRecord) -> LayerScore:
    """Detect threats using static rules.

    Rules check for:
    - Volumetric patterns (very high packet rates → DDoS)
    - Regular beaconing intervals (→ C2)
    - DNS anomalies (high entropy, fanout → DGA)
    - Port scanning patterns
    - Encrypted payloads on suspicious ports
    - Data exfiltration (large volumes)

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with raw_score and calibrated_probability
    """
    score = 0.0
    evidence = []
    threat_guess = None

    # Check for volumetric DDoS: extremely low inter-arrival times AND traffic
    # concentrated on a single target. Without the fan-out qualifier this rule
    # also fired on port scans (equally fast, but spread across many targets).
    if flow.inter_arrival_stats["mean"] < 0.002:
        score += 0.20
        evidence.append("extremely_low_inter_arrival_time")
        # Rate alone is NOT a flood: on loopback and fast LAN links, ordinary
        # background traffic is routinely sub-millisecond. A volumetric attack
        # is fast AND concentrated on one target AND actually pushing volume.
        concentrated = (not flow.fanout_count) or flow.fanout_count < SCAN_FANOUT_THRESHOLD
        high_volume = (
            flow.byte_ratio >= FLOOD_BYTE_RATIO_MIN
            or flow.packet_size_stats["mean"] >= FLOOD_PACKET_SIZE_MIN
        )
        if concentrated and high_volume:
            score += 0.25
            evidence.append("sustained_high_volume_on_single_target")
            threat_guess = "volumetric_ddos"

    # Check for beaconing: regular, predictable intervals
    if flow.beacon_interval_stats:
        interval_mean = flow.beacon_interval_stats.get("mean", 0)
        interval_std = flow.beacon_interval_stats.get("std", 1)
        # Regular intervals (low std dev relative to mean)
        if interval_mean > 0 and (interval_std / interval_mean) < 0.05:
            if 25 < interval_mean < 65:  # Common beacon windows
                score += 0.35
                evidence.append("regular_beacon_interval")
                threat_guess = "c2_beaconing"

    # Check for DGA/DNS tunneling
    if (
        flow.dns_ngram_entropy
        and flow.dns_ngram_entropy >= DNS_NGRAM_ENTROPY_THRESHOLD
        and flow.dst_port in DNS_PORTS
    ):
        score += 0.45
        evidence.append(f"high_dns_ngram_entropy={flow.dns_ngram_entropy:.2f}")
        threat_guess = "dga_dns_tunneling"

    # Check for port scanning: multiple unusual destination ports
    # Port outside safe and suspicious ranges might indicate scanning from attacker
    if flow.dst_port > 8000 and flow.dst_port not in SAFE_PORTS:
        score += 0.15
        evidence.append("unusual_destination_port")

    # ── Fan-out: the defining IOC of reconnaissance ───────────────────────────
    # ingest now measures how many DISTINCT (dst_ip, dst_port) targets this
    # flow's source touched inside the capture window. One source spraying many
    # targets is a scan; a flood hammering a single target keeps fan-out ~1 no
    # matter how fast it goes. Rate alone cannot separate the two, which is why
    # scans used to be reported as volumetric_ddos.
    if flow.fanout_count and flow.fanout_count >= SCAN_FANOUT_THRESHOLD:
        score += 0.45
        evidence.append(f"high_target_fanout={flow.fanout_count}")
        threat_guess = "recon_scanning"
        # Probes are tiny and carry essentially no payload - corroborating signal.
        if flow.packet_size_stats["mean"] < 200 and flow.byte_ratio < 0.35:
            score += 0.15
            evidence.append("low_volume_probe_traffic")


    # Check for suspicious port combinations (encrypted malware pattern)
    if flow.dst_port in SUSPICIOUS_PORTS:
        score += 0.20
        evidence.append("suspicious_destination_port")
        if flow.entropy > 7.5:
            score += 0.15
            evidence.append("high_entropy_payload")
            threat_guess = "encrypted_malware"

    # JA4 TLS/QUIC fingerprint inspection (mandated primary signal for encrypted_malware)
    if flow.ja4:
        from igu_sentinel.detect.features import is_malicious_ja4, has_no_sni_ja4, has_no_alpn_ja4
        if is_malicious_ja4(flow.ja4):
            score += 0.40
            evidence.append(f"malicious_ja4_fingerprint={flow.ja4}")
            threat_guess = "encrypted_malware"
        elif has_no_sni_ja4(flow.ja4) and flow.entropy > 6.5:
            score += 0.30
            evidence.append(f"ja4_missing_sni_encrypted={flow.ja4[:10]}")
            threat_guess = "encrypted_malware"
        elif has_no_alpn_ja4(flow.ja4) and (flow.dst_port in SUSPICIOUS_PORTS or flow.entropy > 7.2):
            score += 0.20
            evidence.append(f"ja4_anomalous_no_alpn={flow.ja4[:10]}")
            if not threat_guess:
                threat_guess = "encrypted_malware"

    # High entropy indicates encryption (malware or exfiltration)
    if flow.entropy > 7.8:
        score += 0.10
        evidence.append("very_high_entropy_payload")

    # Check for data exfiltration: large packets over sustained connection
    if flow.byte_ratio > 0.95 and flow.packet_size_stats["mean"] > 900:
        score += 0.25
        evidence.append("large_sustained_byte_transfer")
        threat_guess = "data_exfiltration"

    # Normalize score to [0, 1]
    raw_score = min(score, 1.0)

    # Platt-scale calibration: convert raw score to probability
    # Use a simple logistic function: P = 1 / (1 + exp(-a * (score - b)))
    # where a=5 (steepness) and b=0.25 (threshold)
    import math
    try:
        calibrated = 1.0 / (1.0 + math.exp(-5.0 * (raw_score - 0.25)))
    except (ValueError, OverflowError):
        # Fallback for extreme values
        calibrated = 1.0 if raw_score > 0.5 else 0.0

    return LayerScore(
        flow_id=flow.flow_id,
        layer_name="rules",
        raw_score=raw_score,
        calibrated_probability=calibrated,
        threat_class_guess=threat_guess,
        evidence=evidence if evidence else None,
    )
