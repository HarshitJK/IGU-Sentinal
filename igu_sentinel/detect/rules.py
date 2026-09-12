"""Static IOC and protocol-violation rule engine."""
from igu_sentinel.schemas import FlowRecord, LayerScore


# Suspicious port numbers (common C2, malware, etc.)
SUSPICIOUS_PORTS = {
    6666, 6667, 6668, 6669, 7777, 8888, 9999,  # Common IRC/C2 ports
    4444, 5555,  # Malware beacons
    31337, 27374, 27373,  # Classic backdoor ports
}

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

    # Check for volumetric DDoS: extremely low inter-arrival times
    if flow.inter_arrival_stats["mean"] < 0.002:
        score += 0.4
        evidence.append("extremely_low_inter_arrival_time")
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
    if flow.dns_ngram_entropy and flow.dns_ngram_entropy >= 7.4:
        score += 0.25
        evidence.append("high_dns_entropy")
        if flow.fanout_count and flow.fanout_count > 10:
            score += 0.20
            evidence.append("high_dns_fanout")
            threat_guess = "dga_dns_tunneling"

    # Check for port scanning: multiple unusual destination ports
    # Port outside safe and suspicious ranges might indicate scanning from attacker
    if flow.dst_port > 8000 and flow.dst_port not in SAFE_PORTS:
        score += 0.15
        evidence.append("unusual_destination_port")

    # Scanning from ephemeral source port to many targets indicated by small packets
    if flow.src_port > 49152 and flow.packet_size_stats["mean"] < 100:
        score += 0.15
        evidence.append("potential_port_scan")
        if flow.inter_arrival_stats["mean"] < 0.01:
            threat_guess = "recon_scanning"
            score += 0.15

    # Check for suspicious port combinations (encrypted malware pattern)
    if flow.dst_port in SUSPICIOUS_PORTS:
        score += 0.20
        evidence.append("suspicious_destination_port")
        if flow.entropy > 7.5:
            score += 0.15
            evidence.append("high_entropy_payload")
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
