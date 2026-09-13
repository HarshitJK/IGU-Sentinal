"""Mock traffic generator for testing and synthetic data generation."""
from datetime import datetime, timedelta
from typing import List
from igu_sentinel.schemas import FlowRecord


def generate(
    threat_class: str,
    source_mode: str = "fixed",
    rate: int = 10,
    size: int = 128,
    port: int = 80,
    duration: int = 1,
) -> List[FlowRecord]:
    """
    Generate synthetic flows matching threat class characteristics.

    Args:
        threat_class: One of {volumetric_ddos, c2_beaconing, dga_dns_tunneling,
                     encrypted_malware, recon_scanning, data_exfiltration}
        source_mode: "fixed" or "rand" (randomize source IPs)
        rate: Flows per second
        size: Packet size in bytes
        port: Destination port
        duration: Duration in seconds

    Returns:
        List of synthetic FlowRecord objects.
    """
    num_flows = int(max(1, rate * duration))
    flows = []
    base_time = datetime.now()

    for i in range(num_flows):
        flow_id = f"{threat_class}_{source_mode}_{i}"

        # Generate characteristics based on threat class
        if threat_class == "volumetric_ddos":
            # High-rate, low inter-arrival
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.1  # Very fast
            packet_size_mean = size or 64
            entropy = 3.5
            byte_ratio = 0.6
            fanout = None
            dns_entropy = None
            beacon_interval = None
            ja4 = None

        elif threat_class == "c2_beaconing":
            # Regular intervals, consistent size
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.5  # Regular
            packet_size_mean = size or 128
            entropy = 5.5
            byte_ratio = 0.5
            fanout = None
            dns_entropy = None
            beacon_interval = {"mean": 10.0, "std": 0.5}  # Regular beacon
            ja4 = "t13d1618h0_002f,00-02-01_1301-1302-1303-1201-1200_000b-000a-0009-0008_0016,_45,1"

        elif threat_class == "dga_dns_tunneling":
            # DNS traffic with high entropy
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.2
            packet_size_mean = size or 100
            entropy = 7.8  # High entropy for DNS names
            byte_ratio = 0.4
            fanout = 20  # Multiple DNS queries
            dns_entropy = 7.9  # High DNS name entropy
            beacon_interval = None
            ja4 = None

        elif threat_class == "encrypted_malware":
            # TLS traffic, moderate entropy
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.3
            packet_size_mean = size or 256
            entropy = 7.2
            byte_ratio = 0.7
            fanout = None
            dns_entropy = None
            beacon_interval = None
            # Malware TLS fingerprint: no SNI ('i'), no ALPN ('00')
            ja4 = "t13i050200_e133e205ac38_000000000000"

        elif threat_class == "recon_scanning":
            # Rapid scanning, varied ports
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.05  # Fast scanning
            packet_size_mean = size or 100
            entropy = 4.0
            byte_ratio = 0.3
            fanout = 50  # Many connection attempts
            dns_entropy = None
            beacon_interval = None
            ja4 = None

        elif threat_class == "data_exfiltration":
            # Large packets, consistent flow
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.1
            packet_size_mean = size or 512
            entropy = 6.5
            byte_ratio = 0.9  # High byte ratio for data
            fanout = None
            dns_entropy = None
            beacon_interval = None
            ja4 = None

        else:  # benign
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.1
            packet_size_mean = size or 128
            entropy = 5.0
            byte_ratio = 0.5
            fanout = None
            dns_entropy = None
            beacon_interval = None
            ja4 = None

        # Create flow record
        flow = FlowRecord(
            flow_id=flow_id,
            timestamp=base_time + timedelta(milliseconds=i * inter_arrival_mean * 1000),
            src_port=1024 + (i % 64512),  # Random ephemeral port
            dst_port=port,
            protocol="TCP",
            packet_size_stats={
                "min": max(40, int(packet_size_mean * 0.5)),
                "max": int(packet_size_mean * 1.5),
                "mean": float(packet_size_mean),
                "std": float(packet_size_mean * 0.2),
            },
            inter_arrival_stats={
                "mean": inter_arrival_mean,
                "std": inter_arrival_mean * 0.1,
            },
            entropy=entropy,
            byte_ratio=byte_ratio,
            ttl=64,
            ja4=ja4,
            beacon_interval_stats=beacon_interval,
            dns_ngram_entropy=dns_entropy,
            fanout_count=fanout,
        )
        flows.append(flow)

    return flows
