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
        # Packet-size spread defaults; volumetric_ddos widens these below.
        pkt_std_factor = 0.2
        pkt_min = pkt_max = None
        flow_id = f"{threat_class}_{source_mode}_{i}"

        # Generate characteristics based on threat class
        if threat_class == "volumetric_ddos":
            # High-rate, low inter-arrival
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.1  # Very fast
            packet_size_mean = size or 64
            entropy = 3.5
            byte_ratio = 0.85  # flood pushes payload bytes hard
            # A flood concentrates on ONE target: huge volume, no fan-out.
            fanout = 1
            ia_std_factor = 0.05  # metronomic / machine-generated flood
            # Real floods mix tiny SYNs with MTU-sized payloads, so the size
            # spread is wide -- not the narrow band the generator used to emit.
            pkt_std_factor = 0.75
            pkt_min, pkt_max = 40, 1500
            dns_entropy = None
            beacon_interval = None
            ja4 = None

        elif threat_class == "c2_beaconing":
            # Regular intervals, consistent size
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.5  # Regular
            packet_size_mean = size or 128
            entropy = 5.5
            byte_ratio = 0.5
            fanout = 1  # beacon talks to one C2 endpoint
            ia_std_factor = 0.05  # highly regular callback
            dns_entropy = None
            beacon_interval = {"mean": 10.0, "std": 0.5}  # Regular beacon
            ja4 = "t13d1618h0_002f,00-02-01_1301-1302-1303-1201-1200_000b-000a-0009-0008_0016,_45,1"

        elif threat_class == "dga_dns_tunneling":
            # DNS traffic with high entropy
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.2
            packet_size_mean = size or 100
            # DNS tunnelling shows up in TWO shapes, and the model must know both:
            #  * plain UDP DNS queries - tshark parses these into a `dns` layer, so
            #    ingest extracts NO raw payload and reports entropy/byte_ratio ~0
            #    (measured on a real DGA capture: entropy 0.00, byte_ratio 0.00);
            #  * payload-bearing tunnels (iodine-style) that do carry raw bytes.
            # Either way the identifying signal is dns_ngram_entropy, not entropy.
            if i % 2:
                entropy = 0.0          # raw DNS query, no extractable payload
                byte_ratio = 0.02
            else:
                entropy = 7.8          # payload-bearing tunnel
                byte_ratio = 0.4
            fanout = 1  # one resolver: many QUERY NAMES, not many targets
            ia_std_factor = 0.3
            # Measured through real ingest: DGA/tunnelling names land 7.4-8.5.
            dns_entropy = 7.5 + (i % 5) * 0.25
            beacon_interval = None
            ja4 = None

        elif threat_class == "encrypted_malware":
            # TLS traffic, moderate entropy
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.3
            packet_size_mean = size or 256
            entropy = 7.2
            byte_ratio = 0.7
            fanout = 1  # single TLS callback endpoint
            ia_std_factor = 0.2
            dns_entropy = None
            beacon_interval = None
            # Malware TLS fingerprint: no SNI ('i'), no ALPN ('00')
            ja4 = "t13i050200_e133e205ac38_000000000000"

        elif threat_class == "recon_scanning":
            # Rapid scanning, varied ports
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.05  # Fast scanning
            packet_size_mean = size or 100
            entropy = 4.0
            byte_ratio = 0.15  # probes carry almost no payload
            # Scanning's defining signature: one source, MANY distinct targets.
            # Spread across configs so the model learns "high fan-out", not one value.
            fanout = max(40, int(rate) * 2)
            ia_std_factor = 0.15
            dns_entropy = None
            beacon_interval = None
            ja4 = None

        elif threat_class == "data_exfiltration":
            # Large packets, consistent flow
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.1
            packet_size_mean = size or 512
            entropy = 6.5
            byte_ratio = 0.97  # bulk outbound transfer
            fanout = 1  # one exfil destination
            ia_std_factor = 0.1
            dns_entropy = None
            beacon_interval = None
            ja4 = None

        else:  # benign
            inter_arrival_mean = 1.0 / rate if rate > 0 else 0.1
            packet_size_mean = size or 128
            entropy = 5.0
            byte_ratio = 0.5
            fanout = 1
            ia_std_factor = 0.8  # human/app traffic arrives in bursts, not evenly
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
                "min": float(pkt_min if pkt_min is not None else max(40, int(packet_size_mean * 0.5))),
                "max": float(pkt_max if pkt_max is not None else int(packet_size_mean * 1.5)),
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
            ttl=64,
            ja4=ja4,
            beacon_interval_stats=beacon_interval,
            dns_ngram_entropy=dns_entropy,
            fanout_count=fanout,
        )
        flows.append(flow)

    return flows
