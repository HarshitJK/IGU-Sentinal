"""Test fusion/ cross-layer correlation and alert generation."""
from datetime import datetime
from igu_sentinel.schemas import LayerScore, Alert
from igu_sentinel.fusion import fuse_layers


def test_fusion_high_confidence_multi_layer():
    """Multi-layer agreement should produce high-confidence alert."""
    scores = [
        LayerScore(
            flow_id="flow_123",
            layer_name="rules",
            raw_score=0.75,
            calibrated_probability=0.82,
            threat_class_guess="volumetric_ddos",
            evidence=["high_packet_rate"],
        ),
        LayerScore(
            flow_id="flow_123",
            layer_name="stats",
            raw_score=0.70,
            calibrated_probability=0.80,
            threat_class_guess="volumetric_ddos",
            evidence=["unusual_inter_arrival"],
        ),
    ]

    alert = fuse_layers(scores)

    assert isinstance(alert, Alert)
    assert alert.flow_id == "flow_123"
    assert alert.threat_class == "volumetric_ddos"
    # Multi-layer agreement should be high confidence
    assert alert.confidence_score > 0.7
    print(f"✓ test_fusion_high_confidence_multi_layer passed (confidence: {alert.confidence_score:.2f})")


def test_fusion_low_confidence_single_layer():
    """Single-layer detection should be downgraded to lower confidence."""
    scores = [
        LayerScore(
            flow_id="flow_456",
            layer_name="rules",
            raw_score=0.75,
            calibrated_probability=0.82,
            threat_class_guess="c2_beaconing",
            evidence=["beacon_interval"],
        ),
    ]

    alert = fuse_layers(scores)

    assert isinstance(alert, Alert)
    assert alert.flow_id == "flow_456"
    # Single-layer detection should be downgraded
    assert alert.confidence_score < 0.7
    print(f"✓ test_fusion_low_confidence_single_layer passed (confidence: {alert.confidence_score:.2f})")


def test_fusion_multi_layer_disagreement():
    """Layers with disagreement should be downgraded."""
    scores = [
        LayerScore(
            flow_id="flow_789",
            layer_name="rules",
            raw_score=0.75,
            calibrated_probability=0.82,
            threat_class_guess="volumetric_ddos",
            evidence=["high_rate"],
        ),
        LayerScore(
            flow_id="flow_789",
            layer_name="stats",
            raw_score=0.20,
            calibrated_probability=0.30,
            threat_class_guess="benign",
            evidence=[],
        ),
    ]

    alert = fuse_layers(scores)

    assert isinstance(alert, Alert)
    # Disagreement should result in lower confidence
    assert alert.confidence_score < 0.65
    print(f"✓ test_fusion_multi_layer_disagreement passed (confidence: {alert.confidence_score:.2f})")


def test_fusion_combines_evidence():
    """Fused alert should include evidence from all layers."""
    scores = [
        LayerScore(
            flow_id="flow_111",
            layer_name="rules",
            raw_score=0.75,
            calibrated_probability=0.82,
            threat_class_guess="dga_dns_tunneling",
            evidence=["high_dns_entropy"],
        ),
        LayerScore(
            flow_id="flow_111",
            layer_name="isoforest",
            raw_score=0.65,
            calibrated_probability=0.75,
            threat_class_guess="dga_dns_tunneling",
            evidence=["anomalous_fanout"],
        ),
    ]

    alert = fuse_layers(scores)

    assert len(alert.evidence) >= 2
    print(f"✓ test_fusion_combines_evidence passed (evidence: {alert.evidence})")


def test_fusion_returns_valid_alert():
    """Fused result must be valid Alert."""
    scores = [
        LayerScore(
            flow_id="flow_222",
            layer_name="xgb",
            raw_score=0.80,
            calibrated_probability=0.85,
            threat_class_guess="encrypted_malware",
            evidence=["high_entropy"],
        ),
    ]

    alert = fuse_layers(scores)

    assert isinstance(alert, Alert)
    assert alert.flow_id == "flow_222"
    assert alert.threat_class in [
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]
    assert 0 <= alert.confidence_score <= 1
    print(f"✓ test_fusion_returns_valid_alert passed")


def test_fusion_three_layer_agreement():
    """Three-layer agreement should have even higher confidence."""
    scores = [
        LayerScore(
            flow_id="flow_333",
            layer_name="rules",
            raw_score=0.80,
            calibrated_probability=0.85,
            threat_class_guess="recon_scanning",
            evidence=["port_scan"],
        ),
        LayerScore(
            flow_id="flow_333",
            layer_name="stats",
            raw_score=0.75,
            calibrated_probability=0.82,
            threat_class_guess="recon_scanning",
            evidence=["many_ports"],
        ),
        LayerScore(
            flow_id="flow_333",
            layer_name="isoforest",
            raw_score=0.70,
            calibrated_probability=0.78,
            threat_class_guess="recon_scanning",
            evidence=["cluster_isolated"],
        ),
    ]

    alert = fuse_layers(scores)

    # Three-layer agreement should be very high confidence
    assert alert.confidence_score > 0.8
    print(f"✓ test_fusion_three_layer_agreement passed (confidence: {alert.confidence_score:.2f})")
