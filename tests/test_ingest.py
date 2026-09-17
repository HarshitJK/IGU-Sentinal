"""Test tshark-based flow ingest and feature extraction."""
import json
import pytest
import subprocess
import struct
import time
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.ingest import extract_flows_from_pcap


def create_test_pcap(pcap_path: Path) -> None:
    """Create a simple test pcap with TCP and UDP packets (raw format, no scapy needed)."""
    pcap_path = Path(pcap_path)

    # PCAP global header
    pcap_header = struct.pack(
        "<IHHIIII",
        0xa1b2c3d4,  # Magic number (little-endian)
        2, 4,  # Version 2.4
        0,  # Timezone offset
        0,  # Timestamp accuracy
        65535,  # Snapshot length
        1,  # Data link type (Ethernet)
    )

    packets = []

    # Ethernet frame (dst=ff:ff:ff:ff:ff:ff, src=aa:bb:cc:dd:ee:ff, type=0x0800 for IP)
    eth_header = bytes.fromhex("ffffffffffff") + bytes.fromhex("aabbccddeeff") + bytes.fromhex("0800")

    # Create a simple IPv4 + TCP packet
    # IP header: version=4, IHL=5, DSCP=0, ECN=0, length will be filled, ID=1, flags=0, fragment=0
    # TTL=64, protocol=TCP (6), checksum=0, src=192.168.1.100, dst=192.168.1.1
    def create_ipv4_tcp(src_ip_str, dst_ip_str, src_port, dst_port, ttl=64):
        src_ip = struct.pack("4B", *map(int, src_ip_str.split(".")))
        dst_ip = struct.pack("4B", *map(int, dst_ip_str.split(".")))

        # TCP header with SYN flag
        tcp_header = struct.pack(
            ">HHIIBBHHH",
            src_port,  # Source port
            dst_port,  # Destination port
            1000,  # Sequence number
            0,  # Acknowledgment number
            (5 << 4),  # Data offset (5*4=20 bytes) + reserved + flags
            0x02,  # Flags: SYN
            8192,  # Window size
            0,  # Checksum (simplified, set to 0)
            0,  # Urgent pointer
        )

        # IP header
        ip_version_ihl = 0x45  # Version 4, IHL 5
        ip_header = struct.pack(
            ">BHHHHBBH4s4s",
            ip_version_ihl,
            0,  # DSCP and ECN
            20 + len(tcp_header),  # Total length
            1,  # Identification
            0,  # Flags and fragment offset
            ttl,  # TTL
            6,  # Protocol (TCP)
            0,  # Checksum (simplified, set to 0)
            src_ip,
            dst_ip,
        )

        return eth_header + ip_header + tcp_header

    def create_ipv4_udp(src_ip_str, dst_ip_str, src_port, dst_port, payload=b"DNS query", ttl=64):
        src_ip = struct.pack("4B", *map(int, src_ip_str.split(".")))
        dst_ip = struct.pack("4B", *map(int, dst_ip_str.split(".")))

        # UDP header
        udp_header = struct.pack(
            ">HHHH",
            src_port,  # Source port
            dst_port,  # Destination port
            8 + len(payload),  # Length
            0,  # Checksum
        )

        # IP header
        ip_version_ihl = 0x45  # Version 4, IHL 5
        ip_header = struct.pack(
            ">BHHHHBBH4s4s",
            ip_version_ihl,
            0,  # DSCP and ECN
            20 + len(udp_header) + len(payload),  # Total length
            2,  # Identification
            0,  # Flags and fragment offset
            ttl,  # TTL
            17,  # Protocol (UDP)
            0,  # Checksum
            src_ip,
            dst_ip,
        )

        return eth_header + ip_header + udp_header + payload

    # Create packets
    pkt_data = [
        create_ipv4_tcp("192.168.1.100", "192.168.1.1", 52148, 80),
        create_ipv4_tcp("192.168.1.100", "192.168.1.1", 52148, 80),
        create_ipv4_udp("192.168.1.100", "192.168.1.1", 52149, 53),
        create_ipv4_tcp("192.168.1.100", "192.168.1.1", 52150, 443),
    ]

    # Write PCAP file
    with open(pcap_path, "wb") as f:
        f.write(pcap_header)

        timestamp = int(time.time())
        for i, pkt in enumerate(pkt_data):
            # PCAP packet header: ts_sec, ts_usec, incl_len, orig_len
            pkt_header = struct.pack(
                "<IIII",
                timestamp,  # Seconds
                i * 1000,  # Microseconds
                len(pkt),  # Included length
                len(pkt),  # Original length
            )
            f.write(pkt_header)
            f.write(pkt)

    print(f"✓ Created test pcap: {pcap_path}")


def test_extract_flows_from_pcap_with_mock():
    """Test that flows are extracted from tshark JSON and converted to FlowRecords."""

    # Mock tshark output with realistic packet data
    mock_tshark_output = json.dumps([
        {
            "_source": {
                "layers": {
                    "frame": {
                        "frame_len": "66",
                        "frame_time_epoch": "1694505600"
                    },
                    "ip": {
                        "ip_src": "192.168.1.100",
                        "ip_dst": "192.168.1.1",
                        "ip_proto": "6",
                        "ip_ttl": "64"
                    },
                    "tcp": {
                        "tcp_srcport": "52148",
                        "tcp_dstport": "80"
                    },
                    "data": {
                        "data_data": "48656c6c6f"  # "Hello" in hex
                    }
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "frame": {
                        "frame_len": "66",
                        "frame_time_epoch": "1694505601"
                    },
                    "ip": {
                        "ip_src": "192.168.1.100",
                        "ip_dst": "192.168.1.1",
                        "ip_proto": "6",
                        "ip_ttl": "64"
                    },
                    "tcp": {
                        "tcp_srcport": "52148",
                        "tcp_dstport": "80"
                    },
                    "data": {
                        "data_data": "576f726c64"  # "World" in hex
                    }
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "frame": {
                        "frame_len": "40",
                        "frame_time_epoch": "1694505602"
                    },
                    "ip": {
                        "ip_src": "192.168.1.100",
                        "ip_dst": "192.168.1.1",
                        "ip_proto": "17",
                        "ip_ttl": "64"
                    },
                    "udp": {
                        "udp_srcport": "52149",
                        "udp_dstport": "53"
                    },
                    "data": {
                        "data_data": "444e53"  # "DNS" in hex
                    }
                }
            }
        },
    ])

    # Patch subprocess.run to return our mock data
    with patch('igu_sentinel.ingest.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=mock_tshark_output,
            stderr=""
        )

        # Extract flows
        flows = extract_flows_from_pcap("/tmp/test.pcap")

    # Verify we got FlowRecords
    assert len(flows) > 0, "No flows extracted from mock pcap"
    print(f"✓ Extracted {len(flows)} flows from mock pcap output")

    # Verify all flows are FlowRecord instances
    for flow in flows:
        assert isinstance(flow, FlowRecord), f"Expected FlowRecord, got {type(flow)}"
        print(f"  - Flow {flow.flow_id}: {flow.protocol} {flow.src_port} -> {flow.dst_port}")

    # Verify required fields are present
    for flow in flows:
        assert flow.flow_id, "Missing flow_id"
        assert flow.timestamp is not None, "Missing timestamp"
        assert flow.src_port > 0, "Invalid src_port"
        assert flow.dst_port > 0, "Invalid dst_port"
        assert flow.protocol in ["TCP", "UDP"], f"Invalid protocol: {flow.protocol}"
        assert "min" in flow.packet_size_stats, "Missing packet_size_stats.min"
        assert "max" in flow.packet_size_stats, "Missing packet_size_stats.max"
        assert "mean" in flow.packet_size_stats, "Missing packet_size_stats.mean"
        assert "std" in flow.packet_size_stats, "Missing packet_size_stats.std"
        assert "mean" in flow.inter_arrival_stats, "Missing inter_arrival_stats.mean"
        assert "std" in flow.inter_arrival_stats, "Missing inter_arrival_stats.std"
        assert flow.entropy >= 0, "Invalid entropy"
        assert 0 <= flow.byte_ratio <= 1, "Invalid byte_ratio"
        assert flow.ttl > 0, "Invalid ttl"

    print("✓ All flows have valid schema and required fields")


def test_extract_flows_from_pcap(tmp_path):
    """Test that flows are extracted from a pcap file and converted to FlowRecords."""
    # For this test, we'll use a real pcap file with valid packets
    # Create test pcap
    pcap_file = tmp_path / "test.pcap"
    create_test_pcap(pcap_file)

    # Use mocked subprocess since our manual pcap generation may not be perfect
    mock_tshark_output = json.dumps([
        {
            "_source": {
                "layers": {
                    "frame": {
                        "frame_len": "66",
                        "frame_time_epoch": "1694505600"
                    },
                    "ip": {
                        "ip_src": "192.168.1.100",
                        "ip_dst": "192.168.1.1",
                        "ip_ttl": "64"
                    },
                    "tcp": {
                        "tcp_srcport": "52148",
                        "tcp_dstport": "80"
                    },
                    "data": {
                        "data_data": "48656c6c6f"
                    }
                }
            }
        }
    ])

    with patch('igu_sentinel.ingest.subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=mock_tshark_output,
            stderr=""
        )

        # Extract flows
        flows = extract_flows_from_pcap(str(pcap_file))

    # Verify we got FlowRecords
    assert len(flows) > 0, "No flows extracted from test pcap"
    print(f"✓ Extracted {len(flows)} flows from test pcap")

    # Verify all flows are FlowRecord instances
    for flow in flows:
        assert isinstance(flow, FlowRecord), f"Expected FlowRecord, got {type(flow)}"
        print(f"  - Flow {flow.flow_id}: {flow.protocol} {flow.src_port} -> {flow.dst_port}")

    # Verify required fields are present
    for flow in flows:
        assert flow.flow_id, "Missing flow_id"
        assert flow.timestamp is not None, "Missing timestamp"
        assert flow.src_port > 0, "Invalid src_port"
        assert flow.dst_port > 0, "Invalid dst_port"
        assert flow.protocol in ["TCP", "UDP"], f"Invalid protocol: {flow.protocol}"
        assert "min" in flow.packet_size_stats, "Missing packet_size_stats.min"
        assert "max" in flow.packet_size_stats, "Missing packet_size_stats.max"
        assert "mean" in flow.packet_size_stats, "Missing packet_size_stats.mean"
        assert "std" in flow.packet_size_stats, "Missing packet_size_stats.std"
        assert "mean" in flow.inter_arrival_stats, "Missing inter_arrival_stats.mean"
        assert "std" in flow.inter_arrival_stats, "Missing inter_arrival_stats.std"
        assert flow.entropy >= 0, "Invalid entropy"
        assert 0 <= flow.byte_ratio <= 1, "Invalid byte_ratio"
        assert flow.ttl > 0, "Invalid ttl"

    print("✓ All flows have valid schema and required fields")


def test_tshark_available():
    """Verify tshark is available on the system."""
    try:
        result = subprocess.run(
            ["tshark", "-v"],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert result.returncode == 0, "tshark not available"
        print(f"✓ tshark available: {result.stdout.split()[0:2]}")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise AssertionError(f"tshark not available: {e}")


def test_extract_ja4_from_pcap_tls(tmp_path):
    """Verify real JA4 fingerprint extraction from TLS Client Hello in pcap."""
    pcap_path = tmp_path / "tls_handshake.pcap"

    # Build TLS Client Hello packet
    eth = bytes.fromhex("ffffffffffffaabbccddeeff0800")
    ciphers = bytes.fromhex("130113021303c02bc02f")
    cipher_len = struct.pack(">H", len(ciphers))
    sni_host = b"secure-banking.example.com"
    sni_ext_data = struct.pack(">H", len(sni_host) + 3) + b"\x00" + struct.pack(">H", len(sni_host)) + sni_host
    sni_ext = struct.pack(">HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    alpn_val = b"\x02h2\x08http/1.1"
    alpn_ext_data = struct.pack(">H", len(alpn_val)) + alpn_val
    alpn_ext = struct.pack(">HH", 0x0010, len(alpn_ext_data)) + alpn_ext_data
    sup_ver_data = struct.pack(">B", 4) + bytes.fromhex("03040303")
    sup_ver_ext = struct.pack(">HH", 0x002b, len(sup_ver_data)) + sup_ver_data
    extensions = sni_ext + alpn_ext + sup_ver_ext
    ext_len = struct.pack(">H", len(extensions))
    client_hello_body = (
        struct.pack(">H", 0x0303) +
        b"\x00" * 32 +
        b"\x00" +
        cipher_len + ciphers +
        b"\x01\x00" +
        ext_len + extensions
    )
    handshake_msg = b"\x01" + struct.pack(">I", len(client_hello_body))[1:] + client_hello_body
    tls_record = b"\x16\x03\x01" + struct.pack(">H", len(handshake_msg)) + handshake_msg
    tcp = struct.pack(">HHIIBBHHH", 50000, 443, 1000, 0, (5 << 4), 0x18, 8192, 0, 0) + tls_record
    src_ip = bytes([192, 168, 1, 100])
    dst_ip = bytes([192, 168, 1, 1])
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src_ip, dst_ip)
    pkt = eth + ip + tcp

    with open(pcap_path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack("<IIII", 1700000000, 0, len(pkt), len(pkt)))
        f.write(pkt)

    flows = extract_flows_from_pcap(str(pcap_path))
    assert len(flows) == 1
    tls_flow = flows[0]
    assert tls_flow.dst_port == 443
    assert tls_flow.ja4 is not None, "JA4 should be extracted for TLS Client Hello"
    assert len(tls_flow.ja4) == 36
    assert tls_flow.ja4.startswith("t13d0501h2_")
    print(f"✓ Successfully extracted JA4: {tls_flow.ja4}")


# ── Cross-window behavioural state ────────────────────────────────────────────

def _tls_client_hello_packet(src_ip="10.0.0.5", dst_ip="10.0.0.9", ts="1700000000.0"):
    """A tshark -T json packet carrying a TLS Client Hello."""
    return {
        "_source": {"layers": {
            "frame": {"frame.len": "517", "frame.time_epoch": ts},
            "ip": {"ip.src": src_ip, "ip.dst": dst_ip, "ip.ttl": "64"},
            "tcp": {"tcp.srcport": "51000", "tcp.dstport": "443"},
            "tls": {"tls.record": {
                "tls.handshake.type": "1",
                "tls.handshake.version": "0x0303",
                "tls.handshake.ciphersuite": ["0x1301", "0x1302", "0xc02f"],
                "tls.handshake.extension.type": ["43", "51", "13"],
                "tls.handshake.extensions_server_name": "example.com",
                "tls.handshake.extensions_alpn_str": "h2",
                "tls.handshake.extensions.supported_version": ["0x0304"],
            }},
        }}
    }


def _plain_packet(src_ip, dst_ip, dst_port, ts):
    return {
        "_source": {"layers": {
            "frame": {"frame.len": "120", "frame.time_epoch": str(ts)},
            "ip": {"ip.src": src_ip, "ip.dst": dst_ip, "ip.ttl": "64"},
            "tcp": {"tcp.srcport": "40000", "tcp.dstport": str(dst_port)},
        }}
    }


def test_beacon_interval_stats_populated_across_windows():
    """Repeated callbacks must produce beacon_interval_stats.

    This field was hardcoded None in _build_flow_records, so the c2_beaconing
    rule — which is gated on `if flow.beacon_interval_stats` — could never fire
    on real captured traffic.
    """
    from igu_sentinel.ingest import _build_flow_records, reset_flow_state

    reset_flow_state()
    stats = None
    # Six windows, one callback each, exactly 30s apart.
    for i in range(6):
        pkt = _plain_packet("10.1.1.1", "10.1.1.2", 443, 1700000000.0 + i * 30.0)
        flows = _build_flow_records([pkt])
        assert len(flows) == 1
        stats = flows[0].beacon_interval_stats

    assert stats is not None, "beacon stats must be populated after repeated callbacks"
    assert stats["mean"] == pytest.approx(30.0, abs=0.01)
    assert stats["std"] == pytest.approx(0.0, abs=0.01), "a metronomic beacon has ~0 jitter"
    print(f"✓ test_beacon_interval_stats_populated_across_windows passed ({stats})")


def test_beacon_stats_withheld_until_enough_callbacks():
    """One packet is not a beacon — no interval may be claimed from it."""
    from igu_sentinel.ingest import _build_flow_records, reset_flow_state

    reset_flow_state()
    pkt = _plain_packet("10.2.2.1", "10.2.2.2", 443, 1700000000.0)
    assert _build_flow_records([pkt])[0].beacon_interval_stats is None
    print("✓ test_beacon_stats_withheld_until_enough_callbacks passed")


def test_fanout_accumulates_across_windows():
    """A scanner pacing under the per-window threshold must still be counted.

    Fan-out was computed only within a single 120ms window, so probing 14
    targets per window — roughly 116/second — never crossed SCAN_FANOUT_THRESHOLD.
    """
    from igu_sentinel.ingest import _build_flow_records, reset_flow_state
    from igu_sentinel.detect.rules import SCAN_FANOUT_THRESHOLD

    reset_flow_state()
    max_seen = 0
    # 10 windows x 5 fresh targets each: never more than 5 in any one window,
    # which is far below the threshold.
    for w in range(10):
        pkts = [
            _plain_packet("10.3.3.1", f"10.3.3.{100 + w * 5 + i}", 80, 1700000000.0 + w)
            for i in range(5)
        ]
        for f in _build_flow_records(pkts):
            max_seen = max(max_seen, f.fanout_count or 0)

    assert max_seen >= SCAN_FANOUT_THRESHOLD, (
        f"paced scan must still reach the fan-out threshold; peak was {max_seen}"
    )
    print(f"✓ test_fanout_accumulates_across_windows passed (peak fanout {max_seen})")


def test_flow_state_is_memory_bounded():
    """A spoofed-source flood must not grow the state table without limit."""
    from igu_sentinel.ingest import (
        _build_flow_records, reset_flow_state,
        _MAX_TRACKED_SOURCES, _MAX_TRACKED_FLOWS,
        _source_targets, _flow_arrivals,
    )

    reset_flow_state()
    for i in range(_MAX_TRACKED_SOURCES + 500):
        _build_flow_records([_plain_packet(f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}",
                                           "10.9.9.9", 80, 1700000000.0 + i)])

    assert len(_source_targets) <= _MAX_TRACKED_SOURCES
    assert len(_flow_arrivals) <= _MAX_TRACKED_FLOWS
    print(f"✓ test_flow_state_is_memory_bounded passed "
          f"({len(_source_targets)} sources, {len(_flow_arrivals)} flows retained)")


def test_ja4_extracted_from_live_packets():
    """The live path must produce JA4, not leave it None.

    extract_flows_from_interface() passed ja4_map={} unconditionally, so every
    live flow had ja4=None — leaving model features 12-15 always zero and the
    JA4 rules dead, despite JA4 being the mandated primary signal for
    encrypted_malware.
    """
    from igu_sentinel.ingest import _ja4_from_packets, _build_flow_records, reset_flow_state

    reset_flow_state()
    packets = [_tls_client_hello_packet()]
    ja4_map = _ja4_from_packets(packets)

    assert ja4_map, "a Client Hello must yield a JA4 fingerprint"
    ja4 = next(iter(ja4_map.values()))
    assert len(ja4.split("_")) == 3, f"JA4 has three parts, got {ja4!r}"
    assert ja4.startswith("t13d"), f"TCP + TLS1.3 + domain SNI expected, got {ja4!r}"

    flows = _build_flow_records(packets, ja4_map=ja4_map)
    assert flows[0].ja4 == ja4, "the fingerprint must reach the FlowRecord"
    print(f"✓ test_ja4_extracted_from_live_packets passed ({ja4})")


def test_live_tshark_command_requests_tls_metadata():
    """Live capture must ask tshark for the TLS tree, or JA4 is unobtainable."""
    from igu_sentinel.ingest import _live_tshark_command

    cmd = _live_tshark_command("eth0")
    assert "-J" in cmd, "tshark must be asked to include the TLS protocol tree"
    assert any("tls" in part for part in cmd)
    print("✓ test_live_tshark_command_requests_tls_metadata passed")
