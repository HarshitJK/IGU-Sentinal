"""Synthetic traffic generator for training and evaluation.

Every feature is drawn from a DISTRIBUTION, not assigned a constant.

This matters more than it looks. The generator previously gave every flow of a
class identical feature values - only flow_id, src_port and timestamp varied,
and none of those reach the model. Across the full 25,275-flow corpus there were
just 66 distinct points in the 16-dimensional feature space (21,500 DDoS flows
collapsed to 6). XGBoost's reported 99.7% accuracy and 1.000 per-class F1 was the
model memorising those points; it measured nothing about detecting an attack that
did not sit exactly on one.

It also contradicted the warning in CLAUDE.md:

    never rely on one tool's default parameters for a given threat class, or the
    model learns the tool's fingerprint instead of the attack pattern

Two properties are deliberate here:

1. **Spread.** Each class is a cloud, not a point, so the classifier has to find
   a boundary rather than a lookup table.
2. **Overlap.** Classes are NOT drawn to be trivially separable. Real recon and
   real DDoS both look "fast"; the model must learn that fan-out separates them,
   not that inter-arrival alone does. Expect accuracy to land around 0.85-0.95 -
   that is the honest number, and a drop from 0.997 is the goal.

Determinism: every draw comes from a seeded Random, so a given
(threat_class, source_mode, rate, size, port, duration) reproduces exactly.
"""
import hashlib
import random
from datetime import datetime, timedelta
from typing import List, Optional
from igu_sentinel.schemas import FlowRecord


def _seeded_rng(*parts) -> random.Random:
    """Deterministic RNG keyed on the variant parameters.

    Seeded rather than global so a regenerated dataset is byte-identical, and so
    two different variants never accidentally draw the same sequence.
    """
    key = "|".join(str(p) for p in parts)
    return random.Random(int(hashlib.sha256(key.encode()).hexdigest()[:16], 16))


def _pos(rng: random.Random, mean: float, rel_std: float, lo: float = 0.0) -> float:
    """Draw a positive value from a relative-gaussian around ``mean``."""
    return max(lo, rng.gauss(mean, abs(mean) * rel_std))


def _clamped(rng: random.Random, mean: float, std: float, lo: float, hi: float) -> float:
    """Draw from a gaussian and clamp into [lo, hi]."""
    return max(lo, min(hi, rng.gauss(mean, std)))


def generate(
    threat_class: str,
    source_mode: str = "fixed",
    rate: int = 10,
    size: int = 128,
    port: int = 80,
    duration: int = 1,
    seed: Optional[int] = None,
) -> List[FlowRecord]:
    """
    Generate synthetic flows matching threat class characteristics.

    Each feature is sampled from a distribution centred on the class profile, so
    a class is a region of feature space rather than a single point. See the
    module docstring for why that matters.

    Args:
        threat_class: One of {volumetric_ddos, c2_beaconing, dga_dns_tunneling,
                     encrypted_malware, recon_scanning, data_exfiltration}
        source_mode: "fixed" or "rand" (randomize source IPs)
        rate: Flows per second
        size: Packet size in bytes
        port: Destination port
        duration: Duration in seconds
        seed: Override the derived seed (tests that need two distinct draws).

    Returns:
        List of synthetic FlowRecord objects.
    """
    num_flows = int(max(1, rate * duration))
    flows = []
    base_time = datetime.now()
    rng = _seeded_rng(threat_class, source_mode, rate, size, port, duration, seed)

    for i in range(num_flows):
        pkt_std_factor = _clamped(rng, 0.20, 0.05, 0.05, 0.40)
        pkt_min = pkt_max = None
        flow_id = f"{threat_class}_{source_mode}_{i}"
        ja4 = None
        beacon_interval = None
        dns_entropy = None

        if threat_class == "volumetric_ddos":
            # Fast AND concentrated AND actually moving volume. Inter-arrival
            # overlaps recon_scanning on purpose: rate alone must not separate
            # them — fan-out is the real discriminator.
            inter_arrival_mean = _pos(rng, 1.0 / rate if rate > 0 else 0.1, 0.45, 1e-6)
            packet_size_mean = _pos(rng, size or 64, 0.35, 20.0)
            entropy = _clamped(rng, 3.5, 0.9, 0.0, 8.0)
            byte_ratio = _clamped(rng, 0.85, 0.10, 0.0, 1.0)
            # A flood concentrates on one target, but a distributed flood hits a
            # handful — not always exactly 1.
            fanout = max(1, int(_pos(rng, 2.0, 0.8, 1.0)))
            ia_std_factor = _clamped(rng, 0.05, 0.03, 0.005, 0.20)
            # Real floods mix tiny SYNs with MTU-sized payloads, so the size
            # spread is wide. Drawn rather than fixed: the previous hardcoded
            # (40, 1500) pair appeared on volumetric_ddos flows and no others,
            # which made packet_size_min/max an exact class label and kept this
            # class at a perfect 1.000 F1 no matter what else changed.
            pkt_std_factor = _clamped(rng, 0.75, 0.15, 0.30, 1.10)
            pkt_min = _clamped(rng, 48.0, 12.0, 40.0, 90.0)
            pkt_max = _clamped(rng, 1400.0, 120.0, 600.0, 1500.0)

        elif threat_class == "c2_beaconing":
            inter_arrival_mean = _pos(rng, 1.0 / rate if rate > 0 else 0.5, 0.40, 1e-6)
            packet_size_mean = _pos(rng, size or 128, 0.30, 20.0)
            entropy = _clamped(rng, 5.5, 0.8, 0.0, 8.0)
            byte_ratio = _clamped(rng, 0.50, 0.12, 0.0, 1.0)
            fanout = max(1, int(_pos(rng, 1.5, 0.5, 1.0)))
            ia_std_factor = _clamped(rng, 0.05, 0.02, 0.005, 0.15)
            # Callback period spread across the range real frameworks use
            # (Cobalt Strike 60s, Empire/Meterpreter 5-300s) rather than a fixed
            # 10.0 — a constant here taught the model one number, and happened to
            # fall outside the rule engine's window entirely.
            beacon_mean = _clamped(rng, 60.0, 45.0, 6.0, 280.0)
            beacon_jitter = _clamped(rng, 0.02, 0.015, 0.0, 0.048)
            beacon_interval = {"mean": beacon_mean, "std": beacon_mean * beacon_jitter}
            # Only some C2 is TLS, and only some of that uses a known-bad stack.
            if rng.random() < 0.5:
                ja4 = rng.choice([
                    "t13d1618h0_002f,00-02-01_1301-1302-1303-1201-1200_000b-000a-0009-0008_0016,_45,1",
                    "t13i040200_002f1301c02f_000000000000",
                ])

        elif threat_class == "dga_dns_tunneling":
            inter_arrival_mean = _pos(rng, 1.0 / rate if rate > 0 else 0.2, 0.50, 1e-6)
            packet_size_mean = _pos(rng, size or 100, 0.35, 20.0)
            # Two real shapes: plain UDP DNS (tshark parses it, so ingest
            # extracts no raw payload and entropy/byte_ratio read ~0) and
            # payload-bearing tunnels (iodine-style) that do carry bytes.
            if rng.random() < 0.5:
                entropy = _clamped(rng, 0.0, 0.05, 0.0, 8.0)
                byte_ratio = _clamped(rng, 0.02, 0.02, 0.0, 1.0)
            else:
                entropy = _clamped(rng, 7.8, 0.25, 0.0, 8.0)
                byte_ratio = _clamped(rng, 0.40, 0.12, 0.0, 1.0)
            fanout = max(1, int(_pos(rng, 1.5, 0.6, 1.0)))
            ia_std_factor = _clamped(rng, 0.30, 0.12, 0.05, 0.80)
            # Measured through real ingest: DGA/tunnelling names land 7.4-8.5.
            dns_entropy = _clamped(rng, 7.8, 0.35, 7.0, 8.0)

        elif threat_class == "encrypted_malware":
            inter_arrival_mean = _pos(rng, 1.0 / rate if rate > 0 else 0.3, 0.45, 1e-6)
            packet_size_mean = _pos(rng, size or 256, 0.30, 20.0)
            entropy = _clamped(rng, 7.2, 0.45, 0.0, 8.0)
            byte_ratio = _clamped(rng, 0.70, 0.12, 0.0, 1.0)
            fanout = max(1, int(_pos(rng, 1.5, 0.5, 1.0)))
            ia_std_factor = _clamped(rng, 0.20, 0.08, 0.02, 0.60)
            # Not every sample uses a fingerprint we already know. A generator
            # where this class is the ONLY one with a JA4 lets the model key on
            # "has JA4" — which is also always absent on live capture.
            roll = rng.random()
            if roll < 0.55:
                ja4 = rng.choice([
                    "t13i050200_e133e205ac38_000000000000",
                    "t13i040200_002f1301c02f_000000000000",
                    "t12i040400_002fc02fc030_000000000000",
                ])
            elif roll < 0.85:
                ja4 = f"t13i{rng.randint(10,20):02d}{rng.randint(1,9):02d}00_" \
                      f"{rng.getrandbits(48):012x}_{rng.getrandbits(48):012x}"

        elif threat_class == "recon_scanning":
            # Overlaps volumetric_ddos on timing by design.
            inter_arrival_mean = _pos(rng, 1.0 / rate if rate > 0 else 0.05, 0.50, 1e-6)
            packet_size_mean = _pos(rng, size or 100, 0.30, 20.0)
            entropy = _clamped(rng, 4.0, 1.0, 0.0, 8.0)
            byte_ratio = _clamped(rng, 0.15, 0.08, 0.0, 1.0)
            # The defining signature: one source, many distinct targets. Spread
            # widely so the model learns "high fan-out", not one magic value.
            fanout = max(16, int(_pos(rng, max(40, int(rate) * 2), 0.60, 16.0)))
            ia_std_factor = _clamped(rng, 0.15, 0.07, 0.02, 0.50)

        elif threat_class == "data_exfiltration":
            inter_arrival_mean = _pos(rng, 1.0 / rate if rate > 0 else 0.1, 0.45, 1e-6)
            packet_size_mean = _pos(rng, size or 512, 0.30, 40.0)
            entropy = _clamped(rng, 6.5, 0.7, 0.0, 8.0)
            byte_ratio = _clamped(rng, 0.95, 0.04, 0.0, 1.0)
            fanout = max(1, int(_pos(rng, 1.3, 0.4, 1.0)))
            ia_std_factor = _clamped(rng, 0.10, 0.05, 0.01, 0.40)
            if rng.random() < 0.25:
                ja4 = f"t13d{rng.randint(10,20):02d}{rng.randint(1,9):02d}h2_" \
                      f"{rng.getrandbits(48):012x}_{rng.getrandbits(48):012x}"

        else:  # benign
            # Benign traffic is deliberately given CONFOUNDERS — flows that
            # share an attack class's signature feature while being legitimate.
            #
            # Without them every discriminating field is a free class label:
            # only c2_beaconing ever set beacon_interval_stats, only
            # recon_scanning ever had high fan-out, only the malware classes
            # ever carried a JA4. A classifier then reaches ~0.995 by reading
            # one field, and learns nothing that survives contact with a real
            # network — where NTP polls on a fixed interval, proxies fan out to
            # hundreds of hosts, and backups push a sustained high byte ratio.
            #
            # These confounders are what make the problem hard, and they are the
            # reason a realistic accuracy here is ~0.85-0.95 rather than ~1.0.
            profile = rng.random()

            inter_arrival_mean = _pos(rng, 1.0 / rate if rate > 0 else 0.1, 0.70, 1e-6)
            packet_size_mean = _pos(rng, size or 128, 0.50, 20.0)
            entropy = _clamped(rng, 5.0, 1.6, 0.0, 8.0)
            byte_ratio = _clamped(rng, 0.50, 0.22, 0.0, 1.0)
            fanout = max(1, int(_pos(rng, 3.0, 1.0, 1.0)))
            # Human/app traffic arrives in bursts, not evenly.
            ia_std_factor = _clamped(rng, 0.80, 0.30, 0.20, 2.00)

            if profile < 0.15:
                # Heartbeat/polling: NTP, monitoring agents, health checks.
                # Periodic and low-jitter — the c2_beaconing signature.
                bm = rng.choice([30.0, 60.0, 64.0, 120.0, 300.0])
                beacon_interval = {
                    "mean": bm * rng.uniform(0.95, 1.05),
                    "std": bm * _clamped(rng, 0.03, 0.02, 0.0, 0.09),
                }
                ia_std_factor = _clamped(rng, 0.15, 0.08, 0.02, 0.40)
            elif profile < 0.27:
                # Proxy / load balancer / browser opening many connections:
                # high fan-out without being a scan.
                fanout = max(8, int(_pos(rng, 45.0, 0.7, 8.0)))
                byte_ratio = _clamped(rng, 0.55, 0.20, 0.0, 1.0)
            elif profile < 0.38:
                # Backup, upload, video call: sustained high byte ratio and
                # large packets — the data_exfiltration signature.
                byte_ratio = _clamped(rng, 0.93, 0.05, 0.0, 1.0)
                packet_size_mean = _pos(rng, 1100.0, 0.20, 100.0)
                ia_std_factor = _clamped(rng, 0.20, 0.10, 0.02, 0.60)
            elif profile < 0.48:
                # Loopback / fast LAN chatter: sub-millisecond inter-arrival,
                # which on its own looks exactly like a flood.
                inter_arrival_mean = _pos(rng, 0.0008, 0.60, 1e-6)
                ia_std_factor = _clamped(rng, 0.30, 0.15, 0.05, 0.90)

            # Ordinary TLS is extremely common, and most of it has a domain SNI.
            if rng.random() < 0.45:
                ja4 = f"t13d{rng.randint(10,20):02d}{rng.randint(1,9):02d}h2_" \
                      f"{rng.getrandbits(48):012x}_{rng.getrandbits(48):012x}"
            elif rng.random() < 0.12:
                # Some legitimate TLS has no SNI (connections to a bare IP:
                # health checks, container-to-container, captive-portal probes).
                ja4 = f"t13i{rng.randint(10,20):02d}{rng.randint(1,9):02d}00_" \
                      f"{rng.getrandbits(48):012x}_{rng.getrandbits(48):012x}"
            # Benign DNS, including long CDN names that push bigram entropy up
            # into the lower part of the DGA range.
            if rng.random() < 0.25:
                dns_entropy = _clamped(rng, 6.2, 0.7, 3.5, 7.4)

        # TTL varies by OS and hop count; a single constant let the model treat
        # TTL as a free class label on any dataset where it differed.
        ttl = int(_clamped(rng, rng.choice([64, 128, 255]) - rng.randint(0, 8), 2.0, 1, 255))

        flow = FlowRecord(
            flow_id=flow_id,
            timestamp=base_time + timedelta(milliseconds=i * inter_arrival_mean * 1000),
            src_port=1024 + rng.randrange(64512),
            dst_port=port,
            # DNS tunnelling is predominantly UDP; everything else here is TCP.
            protocol="UDP" if threat_class == "dga_dns_tunneling" and rng.random() < 0.8 else "TCP",
            packet_size_stats={
                # Drawn around the mean rather than computed as an exact
                # multiple of it: a fixed 0.5x/1.5x relationship is itself a
                # learnable artefact, since real captures never produce one.
                "min": float(pkt_min if pkt_min is not None
                             else max(40.0, _pos(rng, packet_size_mean * 0.5, 0.25, 40.0))),
                "max": float(pkt_max if pkt_max is not None
                             else min(1500.0, _pos(rng, packet_size_mean * 1.5, 0.25, 60.0))),
                "mean": float(packet_size_mean),
                "std": float(packet_size_mean * pkt_std_factor),
            },
            inter_arrival_stats={
                "mean": inter_arrival_mean,
                # Timing regularity separates machine-generated floods/beacons
                # (near-zero jitter) from bursty human/background traffic.
                "std": inter_arrival_mean * ia_std_factor,
            },
            entropy=entropy,
            byte_ratio=byte_ratio,
            ttl=ttl,
            ja4=ja4,
            beacon_interval_stats=beacon_interval,
            dns_ngram_entropy=dns_entropy,
            fanout_count=fanout,
        )
        flows.append(flow)

    return flows
