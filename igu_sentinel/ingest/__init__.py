"""Flow ingest from tshark capture -> feature extraction."""
import json
import subprocess
import hashlib
import struct
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Tuple
from statistics import mean, stdev
from igu_sentinel.schemas import FlowRecord


def _extract_payload_entropy(packet_data: str) -> float:
    """Calculate Shannon entropy of packet payload."""
    import math

    if not packet_data:
        return 0.0

    # Convert hex string to bytes
    try:
        payload_bytes = bytes.fromhex(packet_data)
    except ValueError:
        return 0.0

    if len(payload_bytes) == 0:
        return 0.0

    # Calculate byte frequency
    frequency = defaultdict(int)
    for byte in payload_bytes:
        frequency[byte] += 1

    # Calculate Shannon entropy using log2
    entropy = 0.0
    payload_len = len(payload_bytes)
    for count in frequency.values():
        if count > 0:
            probability = count / payload_len
            entropy -= probability * math.log2(probability)

    return entropy


def _get_flow_key(packet: Dict[str, Any]) -> Tuple[str, int, str, int, str]:
    """Extract 5-tuple flow key from packet."""
    layers = packet.get("_source", {}).get("layers", {})

    src_ip = layers.get("ip", {}).get("ip_src", "0.0.0.0")
    dst_ip = layers.get("ip", {}).get("ip_dst", "0.0.0.0")
    protocol = layers.get("ip", {}).get("ip_proto", "")

    src_port = 0
    dst_port = 0

    if "tcp" in layers:
        src_port = int(layers["tcp"].get("tcp_srcport", 0))
        dst_port = int(layers["tcp"].get("tcp_dstport", 0))
        protocol = "TCP"
    elif "udp" in layers:
        src_port = int(layers["udp"].get("udp_srcport", 0))
        dst_port = int(layers["udp"].get("udp_dstport", 0))
        protocol = "UDP"

    return (src_ip, src_port, dst_ip, dst_port, protocol)


def _get_packet_size(packet: Dict[str, Any]) -> int:
    """Extract packet size from tshark packet."""
    frame = packet.get("_source", {}).get("layers", {}).get("frame", {})
    frame_len = frame.get("frame_len")
    if frame_len:
        return int(frame_len)
    return 0


def _get_ttl(packet: Dict[str, Any]) -> int:
    """Extract TTL from packet."""
    ip_layer = packet.get("_source", {}).get("layers", {}).get("ip", {})
    ttl = ip_layer.get("ip_ttl")
    if ttl:
        return int(ttl)
    return 64  # Default TTL


def _get_payload(packet: Dict[str, Any]) -> str:
    """Extract payload hex data from packet."""
    layers = packet.get("_source", {}).get("layers", {})

    # Try to get data layer
    if "data" in layers:
        return layers["data"].get("data_data", "")

    return ""


def extract_flows_from_pcap(pcap_path: str) -> List[FlowRecord]:
    """
    Extract flows from a pcap file using tshark.

    Args:
        pcap_path: Path to pcap file

    Returns:
        List of FlowRecord objects
    """
    # Run tshark to extract packets in JSON format
    try:
        result = subprocess.run(
            [
                "tshark",
                "-r", pcap_path,
                "-T", "json",
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"tshark timeout reading {pcap_path}")
    except FileNotFoundError:
        raise RuntimeError("tshark not found in PATH")

    if result.returncode != 0:
        raise RuntimeError(f"tshark failed: {result.stderr}")

    if not result.stdout.strip():
        return []

    # Parse JSON output
    try:
        packets = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse tshark JSON output: {e}")

    # Group packets by flow
    flows_data: Dict[Tuple, List] = defaultdict(list)
    packet_times: Dict[Tuple, List[float]] = defaultdict(list)

    for packet in packets:
        flow_key = _get_flow_key(packet)
        packet_size = _get_packet_size(packet)
        ttl = _get_ttl(packet)
        payload = _get_payload(packet)

        # Get packet timestamp
        frame = packet.get("_source", {}).get("layers", {}).get("frame", {})
        timestamp_str = frame.get("frame_time_epoch")
        timestamp = float(timestamp_str) if timestamp_str else 0.0

        flows_data[flow_key].append({
            "size": packet_size,
            "ttl": ttl,
            "payload": payload,
            "timestamp": timestamp
        })
        packet_times[flow_key].append(timestamp)

    # Create FlowRecord for each flow
    flow_records = []

    for flow_key, packets_info in flows_data.items():
        src_ip, src_port, dst_ip, dst_port, protocol = flow_key

        if not packets_info:
            continue

        # Calculate statistics
        packet_sizes = [p["size"] for p in packets_info if p["size"] > 0]
        ttls = [p["ttl"] for p in packets_info]
        timestamps = [p["timestamp"] for p in packets_info]

        if not packet_sizes or not timestamps:
            continue

        # Packet size statistics
        packet_size_stats = {
            "min": float(min(packet_sizes)),
            "max": float(max(packet_sizes)),
            "mean": float(mean(packet_sizes)) if len(packet_sizes) > 0 else 0.0,
            "std": float(stdev(packet_sizes)) if len(packet_sizes) > 1 else 0.0,
        }

        # Inter-arrival time statistics
        inter_arrivals = []
        for i in range(1, len(timestamps)):
            inter_arrival = timestamps[i] - timestamps[i - 1]
            if inter_arrival > 0:
                inter_arrivals.append(inter_arrival)

        if inter_arrivals:
            inter_arrival_stats = {
                "mean": float(mean(inter_arrivals)),
                "std": float(stdev(inter_arrivals)) if len(inter_arrivals) > 1 else 0.0,
            }
        else:
            inter_arrival_stats = {"mean": 0.0, "std": 0.0}

        # Entropy calculation
        all_payloads = "".join([p["payload"] for p in packets_info])
        entropy = _extract_payload_entropy(all_payloads)

        # Byte ratio (ratio of data bytes to total frame bytes)
        total_bytes = sum(packet_sizes)
        byte_ratio = 0.7  # Default for valid traffic
        if total_bytes > 0:
            byte_ratio = min(1.0, sum([len(p["payload"]) // 2 for p in packets_info]) / total_bytes)

        # TTL (use first packet's TTL as flow TTL)
        flow_ttl = ttls[0] if ttls else 64

        # Create flow_id based on flow tuple
        flow_id = hashlib.md5(
            f"{src_ip}:{src_port}:{dst_ip}:{dst_port}:{protocol}".encode()
        ).hexdigest()[:16]

        # Create FlowRecord
        flow_record = FlowRecord(
            flow_id=flow_id,
            timestamp=datetime.fromtimestamp(timestamps[0]) if timestamps[0] > 0 else datetime.now(),
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size_stats=packet_size_stats,
            inter_arrival_stats=inter_arrival_stats,
            entropy=entropy,
            byte_ratio=byte_ratio,
            ttl=int(flow_ttl),
            ja4=None,  # Would be extracted from TLS in real scenario
            beacon_interval_stats=None,
            dns_ngram_entropy=None,
            fanout_count=None,
        )

        flow_records.append(flow_record)

    return flow_records
