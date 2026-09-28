"""Regression tests for the packet-level training capture builder and dataset adapters.

These tests:
  1. Verify the capture builder writes valid PCAPs and meta files.
  2. Verify that feature extraction runs through the real streaming pipeline
     (no fabricated feature vectors).
  3. Verify the dataset adapters respect label mapping, drop unrelated labels,
     and never fabricate absent features.
  4. Verify the UDP-flood misclassification is fixed at the rules layer.

No datasets are downloaded; adapters use their built-in fixture rows.
"""
import io
import json
import os
import random
import tempfile
from pathlib import Path
from typing import List

import pytest

# ── Build-capture builder ─────────────────────────────────────────────────────

def test_udp_flood_rules_no_longer_exfil():
    """UDP flood with large payload must be labelled volumetric_ddos by rules engine."""
    from datetime import datetime
    from igu_sentinel.schemas import FlowRecord
    from igu_sentinel.detect.rules import detect_rules

    flow = FlowRecord(
        flow_id="flood_test",
        timestamp=datetime.now(),
        src_port=43000, dst_port=9999, protocol="UDP",
        packet_size_stats={"min": 1228.0, "max": 1228.0, "mean": 1228.0, "std": 0.0},
        inter_arrival_stats={"mean": 0.0001, "std": 0.00001},
        entropy=0.5,
        byte_ratio=1.0,   # payload/frame — was wrongly used as exfil signal
        ttl=64,
        fanout_count=1,
        pkt_rate=10000.0,
        byte_rate=12_280_000.0,
    )
    score = detect_rules(flow)
    assert score.threat_class_guess == "volumetric_ddos", (
        f"Expected volumetric_ddos but got {score.threat_class_guess!r}. "
        f"Evidence: {score.evidence}"
    )


def test_exfil_rule_does_not_fire_on_flood_without_directional_context():
    """Without outbound_bytes/inbound_bytes, exfil should not fire on a flood."""
    from datetime import datetime
    from igu_sentinel.schemas import FlowRecord
    from igu_sentinel.detect.rules import detect_rules

    # Flood: fast packets, large size, high byte_ratio, but NO directional context
    flow = FlowRecord(
        flow_id="flood_no_dir",
        timestamp=datetime.now(),
        src_port=43000, dst_port=9999, protocol="UDP",
        packet_size_stats={"min": 1228.0, "max": 1228.0, "mean": 1228.0, "std": 0.0},
        inter_arrival_stats={"mean": 0.0001, "std": 0.00001},
        entropy=0.5, byte_ratio=1.0, ttl=64, fanout_count=1,
        pkt_rate=10000.0, byte_rate=12_280_000.0,
        outbound_bytes=None, inbound_bytes=None,
    )
    score = detect_rules(flow)
    assert "data_exfiltration" not in (score.threat_class_guess or ""), (
        f"Exfil must not fire without directional context. Evidence: {score.evidence}"
    )


def test_exfil_rule_fires_with_directional_v2_context():
    """With outbound_bytes >> inbound_bytes, exfil rule should fire."""
    from datetime import datetime
    from igu_sentinel.schemas import FlowRecord
    from igu_sentinel.detect.rules import detect_rules

    flow = FlowRecord(
        flow_id="exfil_dir",
        timestamp=datetime.now(),
        src_port=53000, dst_port=443, protocol="TCP",
        packet_size_stats={"min": 1000.0, "max": 1500.0, "mean": 1400.0, "std": 100.0},
        inter_arrival_stats={"mean": 0.002, "std": 0.0005},
        entropy=7.5, byte_ratio=0.7, ttl=64, fanout_count=1,
        pkt_rate=500.0, byte_rate=700_000.0,
        outbound_bytes=140_000, inbound_bytes=200,  # 140 KB out, 200 B in
    )
    score = detect_rules(flow)
    assert score.threat_class_guess == "data_exfiltration", (
        f"Expected data_exfiltration, got {score.threat_class_guess!r}. "
        f"Evidence: {score.evidence}"
    )


def test_benign_health_check_not_labelled_c2():
    """Regular TCP keepalives at 10s intervals should NOT reach c2_beaconing."""
    from datetime import datetime
    from igu_sentinel.schemas import FlowRecord
    from igu_sentinel.detect.rules import detect_rules

    # Regular 10s keepalives — rules require beacon_interval_stats to be set
    # by the ingest cross-window state tracker. Without it the rule doesn't fire.
    flow = FlowRecord(
        flow_id="health_check",
        timestamp=datetime.now(),
        src_port=60000, dst_port=443, protocol="TCP",
        packet_size_stats={"min": 4.0, "max": 4.0, "mean": 4.0, "std": 0.0},
        inter_arrival_stats={"mean": 10.0, "std": 0.3},
        entropy=0.0, byte_ratio=0.0, ttl=64, fanout_count=1,
        pkt_rate=0.1, byte_rate=40.0,
        beacon_interval_stats=None,  # not enough history yet — no alert
    )
    score = detect_rules(flow)
    assert score.threat_class_guess != "c2_beaconing" or score.raw_score < 0.5, (
        "Health check with beacon_interval_stats=None should not produce a c2_beaconing alert"
    )


def _syn_packet(src_ip, sport, dst_ip, dport, length, ts):
    """Build a tshark-shaped TCP SYN packet dict (no ACK bit)."""
    layers = {
        "frame": {"frame.len": str(length), "frame.time_epoch": str(ts)},
        "ip": {"ip.src": src_ip, "ip.dst": dst_ip, "ip.ttl": "64"},
        # tcp.flags = 0x002 (SYN only, ACK bit clear)
        "tcp": {
            "tcp.srcport": str(sport), "tcp.dstport": str(dport),
            "tcp.flags": "0x002",
        },
    }
    return {"_source": {"layers": layers}}


def test_syn_flood_has_high_syn_fraction():
    """SYN flood packets should produce syn_fraction ≈ 1.0 from the ingest path."""
    import igu_sentinel.ingest as ingest

    pkts = [_syn_packet("10.0.0.1", 44000, "192.0.2.1", 80, 60, 12.0 + i * 0.0002)
            for i in range(100)]
    flows = ingest._build_flow_records(pkts, state=ingest.FlowState())
    assert flows, "Expected at least one flow"
    assert any(f.syn_fraction > 0.9 for f in flows), (
        f"Expected syn_fraction > 0.9 for a SYN flood; got {[f.syn_fraction for f in flows]}"
    )


def test_build_capture_writes_pcap_and_meta(tmp_path):
    """PCAP builder writes valid files for each scenario."""
    import scripts.build_training_captures as btc

    rng = random.Random(42)
    events = btc.scenario_benign_idle(rng)
    assert len(events) == 80

    pcap_path = tmp_path / "test.pcap"
    btc.write_pcap(pcap_path, events)
    assert pcap_path.exists()
    assert pcap_path.stat().st_size > 0

    # Verify PCAP magic number
    with pcap_path.open("rb") as f:
        magic = f.read(4)
    assert magic == b"\xd4\xc3\xb2\xa1", "PCAP file should start with little-endian magic"


def test_build_capture_extracts_flows_through_real_pipeline(tmp_path):
    """Extraction runs through iter_flows_from_pcap (not fabricated features)."""
    import scripts.build_training_captures as btc

    rng = random.Random(42)
    events = btc.scenario_volumetric_ddos_udp(rng)
    pcap_path = tmp_path / "ddos.pcap"
    btc.write_pcap(pcap_path, events)

    labelled = btc.extract_flows_labelled(pcap_path, "volumetric_ddos")
    assert labelled, "Expected at least one extracted flow"
    for row in labelled:
        assert row["label"] == "volumetric_ddos"
        flow_dict = row["flow"]
        # Verify it is a real FlowRecord (has required fields)
        assert "flow_id" in flow_dict
        assert "packet_size_stats" in flow_dict
        # pkt_rate must be populated by the real extractor
        assert flow_dict.get("pkt_rate", 0) > 0, "pkt_rate should be non-zero for a flood"


def test_ddos_udp_scenario_has_large_pkt_rate(tmp_path):
    """UDP flood extracted via real pipeline should have high pkt_rate."""
    import scripts.build_training_captures as btc

    rng = random.Random(26145)
    events = btc.scenario_volumetric_ddos_udp(rng)
    pcap_path = tmp_path / "flood.pcap"
    btc.write_pcap(pcap_path, events)

    labelled = btc.extract_flows_labelled(pcap_path, "volumetric_ddos")
    assert labelled
    rates = [r["flow"]["pkt_rate"] for r in labelled]
    assert max(rates) > 1000, (
        f"UDP flood should produce pkt_rate > 1000 pps; got max={max(rates):.1f}"
    )


# ── Dataset adapters ──────────────────────────────────────────────────────────

def test_cicddos2019_fixture_maps_correctly():
    """CICDDoS2019 fixture maps UDP→volumetric_ddos, Benign→benign."""
    import io, tempfile, os
    from igu_sentinel.eval.dataset_adapters import iter_cicddos2019, load_fixture

    fixture = load_fixture("cicddos2019")
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.csv"
        p.write_text(fixture)
        rows = list(iter_cicddos2019(Path(td)))
    assert len(rows) == 2
    labels = [label for _, label in rows]
    assert "volumetric_ddos" in labels
    assert "benign" in labels


def test_iot23_unlabelled_and_generic_c2_are_not_forced_into_classes(tmp_path):
    from igu_sentinel.eval.dataset_adapters import _iter_zeek_conn_log, load_fixture
    path = tmp_path / 'conn.log.labeled'
    path.write_text(load_fixture('iot23'))
    assert list(_iter_zeek_conn_log(path, 'iot23')) == []


def test_unmatched_labels_are_excluded():
    """Web-attack labels must not appear in adapter output."""
    import tempfile
    from igu_sentinel.eval.dataset_adapters import iter_cicids2017, load_fixture

    # Build a minimal CSV with unmatched labels
    csv_text = (
        " Destination Port, Protocol, Fwd Packet Length Mean, Fwd Packet Length Std,"
        " Fwd Packet Length Min, Fwd Packet Length Max, Fwd IAT Mean, Fwd IAT Std,"
        " Total Fwd Packets, Total Length of Fwd Packets, Flow Duration,"
        " Syn Flag Count, TTL, Label\n"
        " 80,6,64,0,64,64,1000,100,5,320,5000,0,64,Web Attack – Brute Force\n"
        " 80,6,64,0,64,64,1000,100,5,320,5000,0,64,BENIGN\n"
    )
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.csv"
        p.write_text(csv_text)
        rows = list(iter_cicids2017(Path(td)))
    labels = [label for _, label in rows]
    assert all(label != "UNMATCHED" for label in labels), (
        "UNMATCHED rows should be dropped, not yielded"
    )
    # Only the BENIGN row should survive
    assert labels == ["benign"], f"Expected only benign to survive, got {labels}"


def test_backward_columns_never_read():
    """Adapter must not reference Bwd columns even if present."""
    import tempfile
    from igu_sentinel.eval.dataset_adapters import iter_cicids2017

    # CSV with only Bwd columns for non-benign signals — adapter should not use them
    csv_text = (
        "Destination Port,Protocol,"
        "Bwd Packet Length Mean,Bwd Packet Length Max,Bwd IAT Mean,"  # Bwd-only
        "Total Fwd Packets,Total Length of Fwd Packets,Flow Duration,Label\n"
        "443,6,900,1500,5000,10,9000,10000,DDoS\n"
        "443,6,900,1500,5000,10,9000,10000,BENIGN\n"
    )
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "test.csv"
        p.write_text(csv_text)
        rows = list(iter_cicids2017(Path(td)))
    for observation, _ in rows:
        record = json.loads(observation.model_dump_json())
        assert record['model_ready'] is False
        assert 'entropy' not in record['measurements']
        assert 'fwd_len_mean' not in record['measurements']


def test_label_mapping_dry_run_covers_all_keys():
    """Every key in a label map should be either a PS class or UNMATCHED."""
    from igu_sentinel.eval.dataset_adapters import LABEL_MAPS

    VALID = {
        "benign", "volumetric_ddos", "c2_beaconing", "dga_dns_tunneling",
        "encrypted_malware", "recon_scanning", "data_exfiltration", "UNMATCHED",
    }
    for dataset, mapping in LABEL_MAPS.items():
        for raw_label, ps_label in mapping.items():
            assert ps_label in VALID, (
                f"Dataset {dataset!r}: label {raw_label!r} maps to {ps_label!r}, "
                f"which is not a valid PS class or UNMATCHED"
            )


def test_legacy_converter_refuses_fabricated_features():
    from igu_sentinel.eval.cicids_converter import convert_row_to_flow_record, map_cicids_label
    assert map_cicids_label('Web Attack – XSS') is None
    assert map_cicids_label('Infiltration') is None
    with pytest.raises(ValueError, match='proxy features'):
        convert_row_to_flow_record({'Label': 'BENIGN'}, {'label': 'Label'}, 1)
