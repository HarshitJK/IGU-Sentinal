"""Static IOC and protocol-violation rule engine."""
import math

from igu_sentinel.schemas import FlowRecord, LayerScore
# Imported at module scope, not inside detect_rules(): this runs once per flow
# on the hot path, and re-entering the import machinery per call costs
# measurable throughput against the flows/sec target.
from igu_sentinel.detect.features import (
    has_no_alpn_ja4,
    has_no_sni_ja4,
    is_malicious_ja4,
)


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

# ── C2 beacon timing ─────────────────────────────────────────────────────────
# Callback intervals real C2 frameworks use: Cobalt Strike defaults to 60s,
# Empire and Meterpreter are commonly configured anywhere from 5s to several
# minutes. The previous window was 25-65s, which excluded most of that range —
# and in particular excluded the 10s beacon the traffic generator emits, so the
# rule could not fire on a single flow the project produces. Measured hit rate
# before this change: 0/105.
BEACON_INTERVAL_MIN_S = 5
BEACON_INTERVAL_MAX_S = 300

# Max jitter (std/mean) for a callback to count as machine-regular. Compared
# with <= : a beacon at exactly 5% jitter is regular, and the strict < rejected
# it. That boundary is not hypothetical — the generator emits mean=10.0,
# std=0.5, which is exactly 0.05.
BEACON_JITTER_MAX = 0.05

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
    # Candidate threat classes with the weight of the evidence supporting each.
    #
    # This was a single `threat_guess` variable that every matching rule simply
    # overwrote, so the class reported was whichever rule happened to be written
    # LAST in this function, not the one with the strongest evidence. A C2
    # beacon whose JA4 is also on the IOC list matched the beacon rule, then had
    # its verdict silently replaced by `encrypted_malware` twenty lines later —
    # measured c2_beaconing hit rate was 0/105 for exactly this reason, even
    # after its thresholds were corrected. Accumulating weights and taking the
    # maximum makes the verdict a function of the evidence instead of source
    # ordering, and keeps every match visible in `evidence`.
    candidates: dict[str, float] = {}

    def vote(threat_class: str, weight: float) -> None:
        candidates[threat_class] = candidates.get(threat_class, 0.0) + weight

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
            vote("volumetric_ddos", 0.45)   # 0.20 rate + 0.25 volume

    # Check for beaconing: regular, predictable intervals
    if flow.beacon_interval_stats:
        interval_mean = flow.beacon_interval_stats.get("mean", 0)
        interval_std = flow.beacon_interval_stats.get("std", 1)
        # Regular intervals (low std dev relative to mean)
        if interval_mean > 0 and (interval_std / interval_mean) <= BEACON_JITTER_MAX:
            if BEACON_INTERVAL_MIN_S <= interval_mean <= BEACON_INTERVAL_MAX_S:
                score += 0.35
                evidence.append("regular_beacon_interval")
                # Weighted ABOVE the JA4 IOC match below, deliberately.
                #
                # These two signals genuinely co-occur: a TLS C2 beacon has both
                # a regular callback interval and, often, a known-bad JA4. When
                # both fire the flow must still be given one class, and beacon
                # regularity is the better discriminator:
                #   * It is behavioural. Sub-5% jitter across repeated callbacks
                #     is rare in ordinary traffic and expensive for an attacker
                #     to disguise without giving up the beacon.
                #   * A JA4 IOC identifies the TLS *library/toolkit*, which is
                #     shared across families and says nothing about what the
                #     flow is doing.
                # So "this flow is beaconing to a C2" is the more specific
                # description than "this flow used a known-bad TLS stack".
                vote("c2_beaconing", 0.50)

    # Check for DGA/DNS tunneling
    if (
        flow.dns_ngram_entropy
        and flow.dns_ngram_entropy >= DNS_NGRAM_ENTROPY_THRESHOLD
        and flow.dst_port in DNS_PORTS
    ):
        score += 0.45
        evidence.append(f"high_dns_ngram_entropy={flow.dns_ngram_entropy:.2f}")
        vote("dga_dns_tunneling", 0.45)

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
        vote("recon_scanning", 0.45)
        # Probes are tiny and carry essentially no payload - corroborating signal.
        if flow.packet_size_stats["mean"] < 200 and flow.byte_ratio < 0.35:
            score += 0.15
            evidence.append("low_volume_probe_traffic")
            vote("recon_scanning", 0.15)


    # Check for suspicious port combinations (encrypted malware pattern)
    if flow.dst_port in SUSPICIOUS_PORTS:
        score += 0.20
        evidence.append("suspicious_destination_port")
        if flow.entropy > 7.5:
            score += 0.15
            evidence.append("high_entropy_payload")
            vote("encrypted_malware", 0.35)   # 0.20 port + 0.15 entropy

    # JA4 TLS/QUIC fingerprint inspection (mandated primary signal for encrypted_malware)
    if flow.ja4:
        if is_malicious_ja4(flow.ja4):
            score += 0.40
            evidence.append(f"malicious_ja4_fingerprint={flow.ja4}")
            vote("encrypted_malware", 0.40)
        elif has_no_sni_ja4(flow.ja4) and flow.entropy > 6.5:
            score += 0.30
            evidence.append(f"ja4_missing_sni_encrypted={flow.ja4[:10]}")
            vote("encrypted_malware", 0.30)
        elif has_no_alpn_ja4(flow.ja4) and (flow.dst_port in SUSPICIOUS_PORTS or flow.entropy > 7.2):
            score += 0.20
            evidence.append(f"ja4_anomalous_no_alpn={flow.ja4[:10]}")
            # Weakest JA4 signal: a vote, not an override. It previously only
            # applied when nothing else had matched, which made it invisible
            # whenever it would have mattered as corroboration.
            vote("encrypted_malware", 0.20)

    # High entropy indicates encryption (malware or exfiltration)
    if flow.entropy > 7.8:
        score += 0.10
        evidence.append("very_high_entropy_payload")

    # Check for data exfiltration: large packets over sustained connection
    if flow.byte_ratio > 0.95 and flow.packet_size_stats["mean"] > 900:
        score += 0.25
        evidence.append("large_sustained_byte_transfer")
        vote("data_exfiltration", 0.25)

    # Strongest-evidence verdict wins; ties break on the class name so the
    # result is deterministic rather than dependent on dict insertion order.
    threat_guess = None
    if candidates:
        best = max(candidates.values())
        threat_guess = sorted(c for c, w in candidates.items() if w == best)[0]
        if len(candidates) > 1:
            # Keep the runners-up visible: fusion and an analyst both benefit
            # from knowing the rule engine saw more than one possibility.
            others = ", ".join(
                f"{c}={w:.2f}" for c, w in sorted(candidates.items(), key=lambda kv: -kv[1])
            )
            evidence.append(f"rule_candidates[{others}]")

    # Normalize score to [0, 1]
    raw_score = min(score, 1.0)

    # Platt-scale calibration: convert raw score to probability
    # Use a simple logistic function: P = 1 / (1 + exp(-a * (score - b)))
    # where a=5 (steepness) and b=0.25 (threshold)
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
