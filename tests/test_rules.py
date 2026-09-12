"""Test detect/rules.py static IOC and protocol-violation detector."""
import json
from pathlib import Path
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.detect.rules import detect_rules


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture_flows(threat_class: str) -> list[FlowRecord]:
    """Load flows from a fixture file."""
    fixture_file = FIXTURES_DIR / f"{threat_class}_sample.jsonl"
    flows = []
    with open(fixture_file) as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                flows.append(FlowRecord(**data))
    return flows


def test_rules_detect_benign():
    """Rules detector should score benign traffic low."""
    benign_flows = load_fixture_flows("benign")
    for flow in benign_flows:
        score = detect_rules(flow)
        assert score.flow_id == flow.flow_id
        assert score.layer_name == "rules"
        assert 0 <= score.raw_score <= 1
        assert 0 <= score.calibrated_probability <= 1
        # Benign should be low confidence
        assert score.calibrated_probability < 0.5
    print(f"✓ test_rules_detect_benign passed ({len(benign_flows)} flows)")


def test_rules_detect_ddos():
    """Rules detector should detect volumetric DDoS."""
    ddos_flows = load_fixture_flows("volumetric_ddos")
    for flow in ddos_flows:
        score = detect_rules(flow)
        assert score.flow_id == flow.flow_id
        # DDoS should trigger rules (very low inter-arrival times)
        assert score.calibrated_probability > 0.5
        assert score.threat_class_guess == "volumetric_ddos"
    print(f"✓ test_rules_detect_ddos passed ({len(ddos_flows)} flows)")


def test_rules_detect_beaconing():
    """Rules detector should detect C2 beaconing."""
    c2_flows = load_fixture_flows("c2_beaconing")
    for flow in c2_flows:
        score = detect_rules(flow)
        assert score.flow_id == flow.flow_id
        # Beaconing should be detected by regular intervals
        assert score.calibrated_probability > 0.4
        if score.calibrated_probability > 0.5:
            assert score.threat_class_guess == "c2_beaconing"
    print(f"✓ test_rules_detect_beaconing passed ({len(c2_flows)} flows)")


def test_rules_detect_dga():
    """Rules detector should detect DGA/DNS tunneling."""
    dga_flows = load_fixture_flows("dga_dns_tunneling")
    for flow in dga_flows:
        score = detect_rules(flow)
        assert score.flow_id == flow.flow_id
        # High DNS entropy and fanout should trigger rules
        if flow.dns_ngram_entropy and flow.dns_ngram_entropy > 7.0:
            assert score.calibrated_probability > 0.4
    print(f"✓ test_rules_detect_dga passed ({len(dga_flows)} flows)")


def test_rules_detect_scanning():
    """Rules detector should detect recon scanning."""
    scan_flows = load_fixture_flows("recon_scanning")
    for flow in scan_flows:
        score = detect_rules(flow)
        assert score.flow_id == flow.flow_id
        # Port variety and short connections indicate scanning
        assert score.calibrated_probability > 0.5
        assert score.threat_class_guess == "recon_scanning"
    print(f"✓ test_rules_detect_scanning passed ({len(scan_flows)} flows)")


def test_rules_returns_layer_score():
    """Rules detector should return a valid LayerScore."""
    benign_flows = load_fixture_flows("benign")
    flow = benign_flows[0]
    score = detect_rules(flow)

    # Check LayerScore fields
    assert score.flow_id == flow.flow_id
    assert score.layer_name == "rules"
    assert score.raw_score is not None
    assert score.calibrated_probability is not None
    assert isinstance(score.evidence, (list, type(None)))
    print("✓ test_rules_returns_layer_score passed")


def test_rules_unusual_ports():
    """Rules detector should flag unusual port combinations."""
    # Create a benign flow with unusual port
    unusual_flow = FlowRecord(
        flow_id="unusual_port",
        timestamp="2026-09-12T00:00:00",
        src_port=8888,
        dst_port=6666,  # Unusual high port
        protocol="TCP",
        packet_size_stats={"min": 100, "max": 500, "mean": 300, "std": 100},
        inter_arrival_stats={"mean": 0.1, "std": 0.05},
        entropy=7.5,
        byte_ratio=0.8,
        ttl=64,
    )
    score = detect_rules(unusual_flow)
    # High entropy + unusual port should raise suspicion
    assert score.calibrated_probability > 0.3
    print("✓ test_rules_unusual_ports passed")
