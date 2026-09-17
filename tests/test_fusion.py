"""Test fusion/ cross-layer correlation and alert generation."""
from datetime import datetime
import pytest

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


def test_fusion_single_layer_is_advisory_tier():
    """A single-layer detection is advisory — but its probability stays calibrated.

    This previously asserted `confidence_score < 0.7`, which encoded the old
    behaviour of multiplying the fused probability by 0.7 for single-layer
    detections. That multiplier destroyed the calibration the field is
    documented to carry: after scaling, a reported 0.8 no longer meant "80% of
    flows scored this way are threats". The downgrade is now expressed as a
    tier and enforced by is_actionable_alert()'s higher bar, leaving the
    probability itself untouched.
    """
    from igu_sentinel.fusion import ADVISORY_TIER

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
    # The probability is the calibrated value, not a tier-scaled one.
    assert alert.confidence_score == pytest.approx(0.82)
    # The downgrade is expressed as a tier, which is where that belongs.
    assert f"tier={ADVISORY_TIER}" in alert.evidence
    assert "corroborating_layers=1" in alert.evidence
    print(f"✓ test_fusion_single_layer_is_advisory_tier passed "
          f"(confidence {alert.confidence_score:.2f}, tier advisory)")


def test_single_layer_detection_must_clear_a_higher_bar():
    """Uncorroborated detections need more confidence to be surfaced."""
    from igu_sentinel.fusion import (
        ADVISORY_CONFIDENCE_THRESHOLD,
        ALERT_CONFIDENCE_THRESHOLD,
        is_actionable_alert,
    )

    assert ADVISORY_CONFIDENCE_THRESHOLD > ALERT_CONFIDENCE_THRESHOLD

    mid = (ALERT_CONFIDENCE_THRESHOLD + ADVISORY_CONFIDENCE_THRESHOLD) / 2

    one = [LayerScore(flow_id="f", layer_name="rules", raw_score=mid,
                      calibrated_probability=mid,
                      threat_class_guess="c2_beaconing", evidence=["e"])]
    assert not is_actionable_alert(one, fuse_layers(one)), (
        "a single layer at mid confidence must not raise an alert"
    )

    two = [
        LayerScore(flow_id="f", layer_name="rules", raw_score=mid,
                   calibrated_probability=mid, threat_class_guess="c2_beaconing",
                   evidence=["e"]),
        LayerScore(flow_id="f", layer_name="xgb", raw_score=mid,
                   calibrated_probability=mid, threat_class_guess="c2_beaconing",
                   evidence=["e"]),
    ]
    assert is_actionable_alert(two, fuse_layers(two)), (
        "two corroborating layers at the same confidence must raise an alert"
    )
    print("✓ test_single_layer_detection_must_clear_a_higher_bar passed")


def test_fused_confidence_stays_within_layer_range():
    """The fused score must never exceed what the layers actually reported.

    The old >=2-layer path multiplied the average by 1.1, so fusion could output
    a confidence higher than any individual layer's — inventing certainty that
    no detector expressed.
    """
    probs = [0.60, 0.64, 0.58, 0.62]
    names = ["rules", "stats", "isoforest", "xgb"]
    scores = [
        LayerScore(flow_id="f", layer_name=n, raw_score=p, calibrated_probability=p,
                   threat_class_guess="recon_scanning" if n in ("rules", "xgb") else None,
                   evidence=[n])
        for n, p in zip(names, probs)
    ]
    alert = fuse_layers(scores)
    assert min(probs) <= alert.confidence_score <= max(probs), (
        f"fused {alert.confidence_score} outside layer range "
        f"[{min(probs)}, {max(probs)}]"
    )
    print(f"✓ test_fused_confidence_stays_within_layer_range passed "
          f"({alert.confidence_score:.3f})")


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


def test_r7_unsupervised_layer_corroboration():
    """R7: Unsupervised layer (stats or isoforest with threat_class_guess=None)
    should corroborate a candidate supervised class when calibrated_probability >= 0.75."""
    from igu_sentinel.fusion import HIGH_CONFIDENCE_TIER, is_actionable_alert

    # Only 1 supervised layer named a class, but isoforest fires strongly without class guess
    scores = [
        LayerScore(
            flow_id="r7_flow",
            layer_name="rules",
            raw_score=0.80,
            calibrated_probability=0.82,
            threat_class_guess="c2_beaconing",
            evidence=["interval_std_low"],
        ),
        LayerScore(
            flow_id="r7_flow",
            layer_name="isoforest",
            raw_score=0.75,
            calibrated_probability=0.78,
            threat_class_guess=None,
            evidence=["isolated_point"],
        ),
    ]

    alert = fuse_layers(scores)
    assert alert.threat_class == "c2_beaconing"
    assert f"tier={HIGH_CONFIDENCE_TIER}" in alert.evidence
    assert "corroborating_layers=2" in alert.evidence
    assert any("isoforest_corroborates=" in e for e in alert.evidence)
    assert is_actionable_alert(scores, alert) is True
    print("✓ test_r7_unsupervised_layer_corroboration passed")


def test_r8_unclassified_anomaly_routing():
    """R8: Strong unsupervised anomalies with no supervised class should not be silently dropped."""
    from igu_sentinel.fusion import ADVISORY_TIER, is_actionable_alert

    # Neither rules nor xgb detected anything (both None), but stats and isoforest detected strong anomaly
    scores = [
        LayerScore(
            flow_id="r8_flow",
            layer_name="stats",
            raw_score=0.85,
            calibrated_probability=0.82,
            threat_class_guess=None,
            evidence=["high_fanout_detected", "fanout_count=45"],
        ),
        LayerScore(
            flow_id="r8_flow",
            layer_name="isoforest",
            raw_score=0.80,
            calibrated_probability=0.80,
            threat_class_guess=None,
            evidence=["severe_cluster_outlier"],
        ),
    ]

    alert = fuse_layers(scores)
    assert alert.threat_class == "recon_scanning"  # routed via evidence fanout cues
    assert "unclassified_anomaly=true" in alert.evidence
    assert f"tier={ADVISORY_TIER}" in alert.evidence
    assert is_actionable_alert(scores, alert) is True
    print("✓ test_r8_unclassified_anomaly_routing passed")

