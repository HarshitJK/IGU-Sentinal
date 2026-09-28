#!/usr/bin/env python3
"""Offline packet lab: independent of the training FlowRecord generator.

Creates PCAP files without opening a network socket. Measures replay detection,
not real-world accuracy, sustained live throughput, or dashboard latency.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import random
import socket
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from igu_sentinel.api import run_detection_pipeline_scored
from igu_sentinel.fusion import is_actionable_alert
from igu_sentinel.ingest import iter_flows_from_pcap


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(sport, dport, payload=b"", tcp=False):
    src, dst = socket.inet_aton("192.0.2.10"), socket.inet_aton("198.51.100.20")
    proto = 6 if tcp else 17
    if tcp:
        transport = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 80, 2, 8192, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, proto, len(transport) + len(payload))
        transport = transport[:16] + struct.pack("!H", checksum(pseudo + transport + payload)) + transport[18:]
    else:
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    header = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(transport) + len(payload),
                         1, 0, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + transport + payload


def write_pcap(path, events):
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for offset, raw in events:
            timestamp = 1700000000 + offset
            seconds = int(timestamp)
            stream.write(struct.pack("<IIII", seconds, int((timestamp - seconds) * 1e6), len(raw), len(raw)))
            stream.write(raw)


def scenarios():
    rng = random.Random(26145)
    benign = []
    elapsed = 0.0
    for i in range(80):
        elapsed += rng.uniform(0.3, 2.5)
        benign.append((elapsed, packet(40000 + i, 123, b"\x1b" + b"\0" * 47)))
    yield "benign", benign
    yield "recon_scanning", [(i * 0.005, packet(41000, 1000 + i, tcp=True)) for i in range(150)]
    yield "c2_beaconing", [(i * 30.0, packet(42000 + i, 8443, b"callback")) for i in range(20)]
    yield "volumetric_ddos", [(i * 0.0001, packet(43000, 9999, b"x" * 1200)) for i in range(2000)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/packet-lab"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"scope": "Offline synthetic packet replay; independent of training generator; no network traffic sent",
              "excluded_classes": ["dga_dns_tunneling", "encrypted_malware", "data_exfiltration"],
              "results": []}
    for label, events in scenarios():
        path = args.output / f"{label}.pcap"
        write_pcap(path, events)
        predictions = Counter()
        windows = 0
        started = time.perf_counter()
        for flows in iter_flows_from_pcap(str(path)):
            windows += 1
            for scores, alert in run_detection_pipeline_scored(flows):
                predictions[alert.threat_class if is_actionable_alert(scores, alert) else "benign"] += 1
        elapsed = time.perf_counter() - started
        count = sum(predictions.values())
        report["results"].append({"scenario": label, "packets": len(events), "windows": windows,
                                  "flows": count, "predictions": dict(predictions),
                                  "expected_label_fraction": predictions[label] / count if count else 0,
                                  "replay_wall_seconds": round(elapsed, 3)})
    target = args.output / "report.json"
    target.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
