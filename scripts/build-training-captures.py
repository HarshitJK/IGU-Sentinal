#!/usr/bin/env python3
"""Build varied, labelled offline PCAP captures for model training and evaluation.

This script generates synthetic PCAP files using the same raw-packet helpers as
validate-packet-lab.py, then extracts FlowRecord features through the *same*
streaming pipeline used for live ingest (iter_flows_from_pcap / _build_flow_records).
It does NOT fabricate features by filling fixture constants — every FlowRecord
is derived from packets through the real extractor.

Scenario taxonomy
-----------------
  benign_idle          — sparse irregular UDP, NTP-style
  benign_large_upload  — TCP bulk transfer (challenging: large packets, high byte_rate)
  benign_health_check  — regular TCP keepalives (challenging: regular interval ≠ C2)
  benign_dns_txt       — legitimate SPF/DKIM TXT queries (challenging: TXT record type)
  benign_bursty        — short TCP bursts separated by idle gaps

  volumetric_ddos_udp  — single-source UDP flood, large payloads, sub-ms spacing
  volumetric_ddos_syn  — TCP SYN flood, spoofed sources, sub-ms spacing
  volumetric_ddos_distributed — multi-source UDP flood (high src_ip_entropy)

  recon_scanning_syn   — TCP SYN scan across many ports, small payloads
  recon_scanning_udp   — UDP probe sweep across many destinations

  c2_beaconing_regular — periodic UDP callbacks every ~30s, sub-5% jitter
  c2_beaconing_jittered — callbacks at 60s ± 25s (still within threshold)

  dga_dns_tunneling    — high-entropy DNS queries over port 53

  data_exfiltration    — large sustained outbound (requires IGU_PROTECTED_CIDRS)

Provenance
----------
Each scenario's PCAP is written alongside a JSON sidecar recording:
  scenario, label, packet_count, description, parameter_hash

Features are extracted, NOT manufactured. Every output JSONL line is produced
by igu_sentinel.ingest.iter_flows_from_pcap and carries the scenario label as
a separate metadata field (not injected into the FlowRecord).

Usage
-----
  python scripts/build-training-captures.py --output data/training-captures/

The script prints a summary table and writes:
  data/training-captures/{scenario}.pcap
  data/training-captures/{scenario}.meta.json
  data/training-captures/flows.jsonl          (one JSON object per flow)
  data/training-captures/manifest.json        (all scenarios + provenance)

LIMITATIONS (synthetic-only)
-----------------------------
  - No real network hardware, OS stacks, or application behaviour.
  - Encrypted-session patterns (ja4, TLS metadata) are functional stubs only;
    do not report them as proof of encrypted-malware detection capability.
  - Results from this corpus are valid for regression testing; they are NOT
    representative real-world accuracy estimates.
"""
import argparse
import hashlib
import json
import os
import random
import socket
import struct
import sys
import time
from collections import Counter
from pathlib import Path
from typing import List, Tuple, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from igu_sentinel.ingest import iter_flows_from_pcap, FlowState

# ── Packet builders ───────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _eth_ip(src_ip: str, dst_ip: str) -> Tuple[bytes, bytes]:
    """Return (ethernet_header, ip_header_prefix) for the given addresses."""
    eth = bytes.fromhex("0200000000020200000000010800")  # loopback-style Ethernet
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    return eth, src, dst


def udp_packet(src_ip: str, sport: int, dst_ip: str, dport: int,
               payload: bytes, ttl: int = 64) -> bytes:
    eth = bytes.fromhex("0200000000020200000000010800")
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0, 20 + len(transport) + len(payload),
                     0, 0, ttl, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return eth + ip + transport + payload


def tcp_packet(src_ip: str, sport: int, dst_ip: str, dport: int,
               payload: bytes = b"", flags: int = 0x02, ttl: int = 64) -> bytes:
    """TCP packet. flags: 0x02=SYN, 0x10=ACK, 0x12=SYN-ACK, 0x18=PSH+ACK."""
    eth = bytes.fromhex("0200000000020200000000010800")
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 8192, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = _checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0, 20 + len(tcp) + len(payload),
                     0, 0, ttl, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return eth + ip + tcp + payload


def write_pcap(path: Path, events: List[Tuple[float, bytes]]) -> None:
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, raw in events:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            f.write(raw)


# ── Scenario generators ───────────────────────────────────────────────────────

BASE_TS = 1_700_000_000.0  # 2023-11-14 — fixed for reproducibility
INSIDE_IP = "10.0.0.100"
OUTSIDE_IP = "198.51.100.20"
DNS_SERVER = "8.8.8.8"


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def scenario_benign_idle(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Irregular NTP-style UDP, 80 packets, large gaps."""
    events = []
    t = BASE_TS
    for i in range(80):
        t += rng.uniform(0.3, 2.5)
        events.append((t, udp_packet(INSIDE_IP, 40000 + i, OUTSIDE_IP, 123,
                                     b"\x1b" + b"\x00" * 47)))
    return events


def scenario_benign_large_upload(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Large TCP upload — challenging: large packets, high byte_rate, looks like exfil."""
    events = []
    t = BASE_TS
    sport = 50000
    for i in range(200):
        t += rng.uniform(0.0005, 0.002)  # 500 µs – 2 ms gaps
        payload = bytes([rng.randint(0, 255) for _ in range(1400)])
        events.append((t, tcp_packet(INSIDE_IP, sport, OUTSIDE_IP, 443,
                                     payload, flags=0x18)))  # PSH+ACK
    return events


def scenario_benign_health_check(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Regular TCP keepalives every 10s — challenging: regular interval looks like C2."""
    events = []
    t = BASE_TS
    for i in range(20):
        t += 10.0 + rng.gauss(0, 0.05)  # jitter < 5%
        events.append((t, tcp_packet(INSIDE_IP, 60000 + i, OUTSIDE_IP, 443,
                                     b"\x00" * 4, flags=0x18)))
    return events


def scenario_benign_dns_txt(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Legitimate SPF/DKIM TXT queries — challenging: TXT record, moderate name length."""
    # Build minimal DNS query packets (type=TXT=16 over UDP/53)
    events = []
    t = BASE_TS
    names = [b"_dmarc.example.com", b"v=spf1.example.org", b"selector._domainkey.acme.io"]
    for i in range(15):
        t += rng.uniform(0.5, 3.0)
        name = names[i % len(names)]
        # Minimal DNS query wire format
        dns = (
            b"\x00\x01"  # transaction ID
            b"\x01\x00"  # flags: standard query
            b"\x00\x01"  # questions: 1
            b"\x00\x00\x00\x00\x00\x00"  # answers/authority/additional
        )
        # Encode name
        qname = b""
        for label in name.split(b"."):
            qname += bytes([len(label)]) + label
        qname += b"\x00"  # root
        dns += qname + b"\x00\x10\x00\x01"  # QTYPE=TXT, QCLASS=IN
        events.append((t, udp_packet(INSIDE_IP, 50000 + i, DNS_SERVER, 53, dns)))
    return events


def scenario_benign_bursty(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Short TCP bursts followed by idle, mimicking browser page loads."""
    events = []
    t = BASE_TS
    for burst in range(8):
        t += rng.uniform(1.0, 5.0)  # idle between bursts
        for pkt in range(rng.randint(5, 20)):
            t += rng.uniform(0.0001, 0.001)
            sz = rng.randint(64, 1460)
            events.append((t, tcp_packet(INSIDE_IP, 51000 + burst, OUTSIDE_IP, 443,
                                         bytes(sz), flags=0x18)))
    return events


def scenario_volumetric_ddos_udp(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Single-source UDP flood: 2000 large packets at 0.1ms spacing."""
    events = []
    t = BASE_TS
    for i in range(2000):
        t += 0.0001 + rng.gauss(0, 0.000005)
        events.append((t, udp_packet(INSIDE_IP, 43000, OUTSIDE_IP, 9999,
                                     b"x" * 1200)))
    return events


def scenario_volumetric_ddos_syn(rng: random.Random) -> List[Tuple[float, bytes]]:
    """TCP SYN flood: many short SYN packets, sub-ms spacing."""
    events = []
    t = BASE_TS
    for i in range(1000):
        t += 0.0002 + rng.gauss(0, 0.00001)
        events.append((t, tcp_packet(INSIDE_IP, 44000, OUTSIDE_IP, 80,
                                     flags=0x02)))  # SYN only
    return events


def scenario_volumetric_ddos_distributed(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Multi-source UDP flood — tests src_ip_entropy feature."""
    events = []
    t = BASE_TS
    src_pool = [f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
                for _ in range(50)]
    for i in range(1500):
        t += 0.0001 + rng.gauss(0, 0.000005)
        src = rng.choice(src_pool)
        events.append((t, udp_packet(src, rng.randint(1024, 65535), OUTSIDE_IP, 9999,
                                     b"A" * 900)))
    return events


def scenario_recon_scanning_syn(rng: random.Random) -> List[Tuple[float, bytes]]:
    """TCP SYN scan across many ports from one source."""
    events = []
    t = BASE_TS
    for port in range(1000, 1150):
        t += 0.005 + rng.gauss(0, 0.001)
        events.append((t, tcp_packet(INSIDE_IP, 41000, OUTSIDE_IP, port,
                                     flags=0x02)))
    return events


def scenario_recon_scanning_udp(rng: random.Random) -> List[Tuple[float, bytes]]:
    """UDP probe sweep to many distinct destinations."""
    events = []
    t = BASE_TS
    for i in range(150):
        t += 0.005 + rng.gauss(0, 0.001)
        dst = f"192.0.2.{1 + (i % 254)}"
        events.append((t, udp_packet(INSIDE_IP, 45000, dst, 161,  # SNMP
                                     b"\x00" * 40)))
    return events


def scenario_c2_beaconing_regular(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Periodic UDP callbacks every ~30s, jitter < 5%."""
    events = []
    t = BASE_TS
    for i in range(20):
        t += 30.0 + rng.gauss(0, 0.5)  # std/mean = 0.5/30 ≈ 1.7% < 5%
        events.append((t, udp_packet(INSIDE_IP, 42000 + i, OUTSIDE_IP, 8443,
                                     b"callback\x00" * 8)))
    return events


def scenario_c2_beaconing_jittered(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Callbacks at 60s ± 10% — still within beacon thresholds but near the edge."""
    events = []
    t = BASE_TS
    for i in range(20):
        t += 60.0 + rng.gauss(0, 3.0)  # std/mean = 3/60 = 5%
        events.append((t, udp_packet(INSIDE_IP, 42500 + i, OUTSIDE_IP, 4444,
                                     b"hb" * 12)))
    return events


def scenario_dga_dns_tunneling(rng: random.Random) -> List[Tuple[float, bytes]]:
    """High-entropy DNS queries — mimics DGA/DNS-tunnel hostnames."""
    events = []
    t = BASE_TS
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(50):
        t += rng.uniform(0.05, 0.3)
        label_len = rng.randint(20, 40)
        label = "".join(rng.choices(chars, k=label_len))
        name = f"{label}.tunnel.evil.example".encode()
        dns = b"\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in name.split(b"."):
            dns += bytes([len(part)]) + part
        dns += b"\x00\x00\x01\x00\x01"
        events.append((t, udp_packet(INSIDE_IP, 46000 + i, DNS_SERVER, 53, dns)))
    return events


def scenario_data_exfiltration(rng: random.Random) -> List[Tuple[float, bytes]]:
    """Slow sustained TCP upload — encrypted payload, large packet size.

    NOTE: This scenario is only meaningful as an exfiltration signal when
    IGU_PROTECTED_CIDRS is set so that INSIDE_IP is 'inside' and OUTSIDE_IP
    is 'outside'. Without directional context the rule engine relies on
    byte_rate + entropy, which is a weak signal.
    """
    events = []
    t = BASE_TS
    for i in range(300):
        t += rng.uniform(0.001, 0.003)  # 1-3ms — moderate rate
        # High-entropy payload (simulates encrypted data)
        payload = bytes([rng.randint(0, 255) for _ in range(1400)])
        events.append((t, tcp_packet(INSIDE_IP, 53000, OUTSIDE_IP, 443,
                                     payload, flags=0x18)))
        if i % 10 == 0:
            events.append((t + .00001, tcp_packet(OUTSIDE_IP, 443, INSIDE_IP, 53000, flags=0x10)))
    return events


# ── Registry ──────────────────────────────────────────────────────────────────

SCENARIOS = {
    # benign — must produce few or no alerts
    "benign_idle":          ("benign",           scenario_benign_idle),
    "benign_large_upload":  ("benign",           scenario_benign_large_upload),
    "benign_health_check":  ("benign",           scenario_benign_health_check),
    "benign_dns_txt":       ("benign",           scenario_benign_dns_txt),
    "benign_bursty":        ("benign",           scenario_benign_bursty),
    # attacks
    "volumetric_ddos_udp":  ("volumetric_ddos",  scenario_volumetric_ddos_udp),
    "volumetric_ddos_syn":  ("volumetric_ddos",  scenario_volumetric_ddos_syn),
    "volumetric_ddos_dist": ("volumetric_ddos",  scenario_volumetric_ddos_distributed),
    "recon_scanning_syn":   ("recon_scanning",   scenario_recon_scanning_syn),
    "recon_scanning_udp":   ("recon_scanning",   scenario_recon_scanning_udp),
    "c2_beaconing_regular": ("c2_beaconing",     scenario_c2_beaconing_regular),
    "c2_beaconing_jitter":  ("c2_beaconing",     scenario_c2_beaconing_jittered),
    "dga_dns_tunneling":    ("dga_dns_tunneling", scenario_dga_dns_tunneling),
    "data_exfiltration":    ("data_exfiltration", scenario_data_exfiltration),
}


# ── Extractor ─────────────────────────────────────────────────────────────────

def extract_flows_labelled(pcap_path: Path, label: str) -> List[dict]:
    """Run iter_flows_from_pcap and tag each FlowRecord with the scenario label.

    The label is stored as a top-level key *outside* the FlowRecord JSON so it
    is never visible to the feature extractor — the extractor sees only the same
    FlowRecord it would see from a live capture.
    """
    labelled = []
    state = FlowState()
    try:
        for window in iter_flows_from_pcap(str(pcap_path)):
            for flow in window:
                labelled.append({
                    "label": label,
                    "flow": json.loads(flow.model_dump_json()),
                })
    except Exception as exc:
        raise RuntimeError(f"Extraction failed for {pcap_path}") from exc
    return labelled


def _scenario_hash(name: str, seed: int) -> str:
    h = hashlib.sha256(f"{name}:{seed}".encode()).hexdigest()[:12]
    return h


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=Path("data/training-captures"),
                        help="Directory for PCAP files and flow JSONL")
    parser.add_argument("--seed", type=int, default=26145,
                        help="Master RNG seed for reproducibility")
    parser.add_argument("--scenarios", nargs="*", default=None,
                        help="Subset of scenarios to run (default: all)")
    parser.add_argument("--skip-tshark", action="store_true",
                        help="Write PCAPs but skip flow extraction (no tshark needed)")
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)

    which = args.scenarios or list(SCENARIOS.keys())
    unknown = set(which) - set(SCENARIOS.keys())
    if unknown:
        parser.error(f"Unknown scenarios: {sorted(unknown)}.  Available: {sorted(SCENARIOS)}")

    all_flows: List[dict] = []
    manifest = {
        "provenance": (
            "Synthetic PCAP captures extracted through igu_sentinel.ingest.iter_flows_from_pcap. "
            "Every FlowRecord is derived from packets; no features are fabricated. "
            "Results from this corpus are regression checks ONLY — not real-world accuracy."
        ),
        "feature_contract_version": __import__("igu_sentinel.schemas", fromlist=["FEATURE_CONTRACT_VERSION"]).FEATURE_CONTRACT_VERSION,
        "seed": args.seed,
        "scenarios": {},
    }

    header = f"{'Scenario':<28}  {'Label':<20}  {'Pkts':>6}  {'Flows':>6}  {'Hash'}"
    print(header)
    print("-" * len(header))

    for name in which:
        label, generator = SCENARIOS[name]
        rng = _rng(args.seed + int(hashlib.sha256(name.encode()).hexdigest()[:8], 16))
        events = generator(rng)
        pcap_path = args.output / f"{name}.pcap"
        write_pcap(pcap_path, events)

        param_hash = _scenario_hash(name, args.seed)
        meta = {
            "scenario": name,
            "label": label,
            "packet_count": len(events),
            "pcap": pcap_path.name,
            "param_hash": param_hash,
            "note": (
                "Synthetic only. Not representative of real attacks or traffic patterns. "
                "Encrypted-session patterns are functional stubs."
            ),
        }
        (args.output / f"{name}.meta.json").write_text(json.dumps(meta, indent=2))

        flow_count = 0
        if not args.skip_tshark:
            labelled = extract_flows_labelled(pcap_path, label)
            for row in labelled:
                row["group"] = f"{name}:{args.seed}"
                row["source_sha256"] = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
                row["provenance"] = "synthetic_packet_capture"
            all_flows.extend(labelled)
            flow_count = len(labelled)

        manifest["scenarios"][name] = {**meta, "flow_count": flow_count}
        print(f"{name:<28}  {label:<20}  {len(events):>6}  {flow_count:>6}  {param_hash}")

    # Write combined JSONL
    if not args.skip_tshark:
        flows_path = args.output / "flows.jsonl"
        with flows_path.open("w") as f:
            for row in all_flows:
                f.write(json.dumps(row) + "\n")
        label_counts = Counter(r["label"] for r in all_flows)
        print(f"\nFlows written: {len(all_flows)} to {flows_path}")
        print("Per-label counts:")
        for lbl, cnt in sorted(label_counts.items()):
            print(f"  {lbl:<25}  {cnt:>5}")
        print()
        _print_limitations()

    manifest_path = args.output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"Manifest: {manifest_path}")


def _print_limitations() -> None:
    print("""
LIMITATIONS — read before using these results
==============================================
  1. Synthetic only: no real OS stacks, NICs, applications, or adversary
     behaviour. Real attacks differ in TTL jitter, fragmentation, and
     protocol-level anomalies not captured here.
  2. Encrypted-session patterns (ja4, TLS metadata): functional stubs.
     Do not report JA4-based detection rates from this corpus as proof
     of encrypted-malware detection capability.
  3. data_exfiltration: only meaningful with IGU_PROTECTED_CIDRS set.
     Without directional context the rule engine uses a weak heuristic.
  4. No calibration from this data: use it to train, then hold out real
     captures (or a separate synthetic set) for Platt fitting.
  5. Do not publish accuracy figures from this corpus without a disclaimer.
""")


if __name__ == "__main__":
    main()
