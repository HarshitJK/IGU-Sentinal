"""Test detect/rules.py static IOC and protocol-violation detector."""
import json
from pathlib import Path
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.detect.rules import detect_rules


def _make_flow(**overrides) -> FlowRecord:
    """Build a FlowRecord with neutral defaults, overriding only what a test cares about."""
    from datetime import datetime

    base = dict(
        flow_id="test_flow",
        timestamp=datetime.now(),
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        packet_size_stats={"min": 100.0, "max": 300.0, "mean": 200.0, "std": 40.0},
        inter_arrival_stats={"mean": 0.5, "std": 0.1},
        entropy=5.0,
        byte_ratio=0.5,
        ttl=64,
    )
    base.update(overrides)
    return FlowRecord(**base)



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


def test_rules_detect_encrypted_malware_ja4():
    """Rules detector should flag flows bearing malicious JA4 fingerprints."""
    malware_flow = FlowRecord(
        flow_id="malware_tls_ja4",
        timestamp="2026-09-12T14:00:00",
        src_port=49876,
        dst_port=443,
        protocol="TCP",
        packet_size_stats={"min": 100, "max": 1500, "mean": 700, "std": 400},
        inter_arrival_stats={"mean": 0.05, "std": 0.03},
        entropy=7.9,
        byte_ratio=0.85,
        ttl=64,
        ja4="t13i050200_e133e205ac38_000000000000",  # No SNI, no ALPN malware profile
    )
    score = detect_rules(malware_flow)
    assert score.calibrated_probability > 0.6
    assert score.threat_class_guess == "encrypted_malware"
    assert any("ja4" in ev for ev in (score.evidence or []))
    print(f"✓ test_rules_detect_encrypted_malware_ja4 passed (calibrated: {score.calibrated_probability:.3f})")


# ── Rule verdict selection ────────────────────────────────────────────────────

def test_beacon_rule_fires_on_generator_output():
    """The c2_beaconing rule must fire on the traffic the project generates.

    Regression test for two stacked defects that made this rule score 0/105:
      1. The interval window was 25-65s while the generator emits a 10s beacon,
         and the jitter test was a strict `< 0.05` against a value of exactly
         0.05 — so both conditions failed arithmetically.
      2. Once it did fire, the JA4 block later in detect_rules() overwrote
         threat_class_guess, because the verdict was last-write-wins.
    """
    from igu_sentinel.traffic_gen.generators import mock

    flows = mock.generate("c2_beaconing", rate=20, duration=1, port=443)
    guesses = [detect_rules(f).threat_class_guess for f in flows]
    assert all(g == "c2_beaconing" for g in guesses), (
        f"beacon rule must win on beaconing flows, got {set(guesses)}"
    )
    print("✓ test_beacon_rule_fires_on_generator_output passed")


def test_beacon_jitter_boundary_is_inclusive():
    """A beacon at exactly the jitter limit is regular, not irregular."""
    from igu_sentinel.detect.rules import BEACON_JITTER_MAX

    flow = _make_flow(
        beacon_interval_stats={"mean": 60.0, "std": 60.0 * BEACON_JITTER_MAX},
        dst_port=443,
    )
    assert detect_rules(flow).threat_class_guess == "c2_beaconing"
    print("✓ test_beacon_jitter_boundary_is_inclusive passed")


def test_rule_verdict_is_strongest_evidence_not_source_order():
    """When several rules match, the verdict follows evidence weight.

    The verdict used to be whichever rule appeared last in the function body,
    so adding a rule could silently change the classification of flows that had
    nothing to do with it.
    """
    # A flow that trips BOTH the beacon rule and the malicious-JA4 rule.
    flow = _make_flow(
        beacon_interval_stats={"mean": 60.0, "std": 1.0},
        ja4="t13i050200_e133e205ac38_000000000000",   # on the IOC list
        dst_port=443,
        entropy=7.0,
    )
    score = detect_rules(flow)

    assert score.threat_class_guess == "c2_beaconing", (
        "behavioural beacon evidence must outweigh a JA4 toolkit match"
    )
    # Both matches must remain visible to fusion and to an analyst.
    joined = " ".join(score.evidence)
    assert "regular_beacon_interval" in joined
    assert "malicious_ja4_fingerprint" in joined
    assert "rule_candidates[" in joined, "runner-up classes must be reported"
    print("✓ test_rule_verdict_is_strongest_evidence_not_source_order passed")


def test_rule_verdict_is_deterministic_on_ties():
    """Equal-weight candidates must resolve the same way every call."""
    flow = _make_flow(
        beacon_interval_stats={"mean": 60.0, "std": 1.0},
        ja4="t13i050200_e133e205ac38_000000000000",
        dst_port=443,
        entropy=7.0,
    )
    verdicts = {detect_rules(flow).threat_class_guess for _ in range(20)}
    assert len(verdicts) == 1, f"verdict must be stable, saw {verdicts}"
    print("✓ test_rule_verdict_is_deterministic_on_ties passed")
