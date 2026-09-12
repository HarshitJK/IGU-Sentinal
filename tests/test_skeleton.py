"""Test package layout and schema contracts."""
import pytest
from datetime import datetime
from pydantic import ValidationError

from igu_sentinel.schemas import FlowRecord, LayerScore, Alert


class TestFlowRecordSchema:
    """Test FlowRecord validation."""

    def test_valid_flow_record(self):
        """FlowRecord should accept valid data."""
        flow = FlowRecord(
            flow_id="flow_123",
            timestamp=datetime.now(),
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            packet_size_stats={"min": 64, "max": 1500, "mean": 512, "std": 100},
            inter_arrival_stats={"mean": 0.001, "std": 0.0005},
            entropy=7.2,
            byte_ratio=0.85,
            ttl=64,
            ja4=None,
            beacon_interval_stats=None,
            dns_ngram_entropy=None,
            fanout_count=None,
        )
        assert flow.flow_id == "flow_123"
        assert flow.protocol == "TCP"

    def test_missing_required_field(self):
        """FlowRecord should reject missing required fields."""
        with pytest.raises(ValidationError):
            FlowRecord(
                flow_id="flow_123",
                timestamp=datetime.now(),
                src_port=1234,
                # Missing dst_port and other required fields
            )

    def test_invalid_type(self):
        """FlowRecord should reject invalid types."""
        with pytest.raises(ValidationError):
            FlowRecord(
                flow_id="flow_123",
                timestamp=datetime.now(),
                src_port="not_a_number",  # Should be int
                dst_port=80,
                protocol="TCP",
                packet_size_stats={"min": 64, "max": 1500, "mean": 512, "std": 100},
                inter_arrival_stats={"mean": 0.001, "std": 0.0005},
                entropy=7.2,
                byte_ratio=0.85,
                ttl=64,
            )


class TestLayerScoreSchema:
    """Test LayerScore validation."""

    def test_valid_layer_score(self):
        """LayerScore should accept valid data."""
        score = LayerScore(
            flow_id="flow_123",
            layer_name="rules",
            raw_score=0.75,
            calibrated_probability=0.82,
            threat_class_guess="volumetric_ddos",
            evidence=["high_packet_rate", "large_flow_volume"],
        )
        assert score.flow_id == "flow_123"
        assert score.layer_name == "rules"

    def test_missing_required_field(self):
        """LayerScore should reject missing required fields."""
        with pytest.raises(ValidationError):
            LayerScore(
                flow_id="flow_123",
                layer_name="rules",
                # Missing raw_score
                calibrated_probability=0.82,
            )

    def test_optional_fields(self):
        """LayerScore should allow optional threat_class_guess and evidence."""
        score = LayerScore(
            flow_id="flow_123",
            layer_name="isoforest",
            raw_score=0.45,
            calibrated_probability=0.50,
            threat_class_guess=None,
            evidence=None,
        )
        assert score.threat_class_guess is None


class TestAlertSchema:
    """Test Alert validation (PS-mandated schema)."""

    def test_valid_alert(self):
        """Alert should accept valid data."""
        alert = Alert(
            timestamp=datetime.now(),
            flow_id="flow_123",
            threat_class="volumetric_ddos",
            confidence_score=0.88,
            evidence=["rules_triggered", "stats_anomaly"],
        )
        assert alert.threat_class == "volumetric_ddos"
        assert alert.confidence_score == 0.88

    def test_invalid_threat_class(self):
        """Alert should validate threat_class is one of the six mandated types."""
        with pytest.raises(ValidationError):
            Alert(
                timestamp=datetime.now(),
                flow_id="flow_123",
                threat_class="unknown_threat",  # Invalid
                confidence_score=0.88,
                evidence=[],
            )

    def test_valid_threat_classes(self):
        """All six PS-mandated threat classes should be valid."""
        threat_classes = [
            "volumetric_ddos",
            "c2_beaconing",
            "dga_dns_tunneling",
            "encrypted_malware",
            "recon_scanning",
            "data_exfiltration",
        ]
        for threat_class in threat_classes:
            alert = Alert(
                timestamp=datetime.now(),
                flow_id=f"flow_{threat_class}",
                threat_class=threat_class,
                confidence_score=0.75,
                evidence=[],
            )
            assert alert.threat_class == threat_class


class TestModuleImports:
    """Test that all modules are importable."""

    def test_ingest_module_exists(self):
        """ingest module should be importable."""
        import igu_sentinel.ingest

    def test_detect_modules_exist(self):
        """detect module and submodules should be importable."""
        import igu_sentinel.detect
        import igu_sentinel.detect.rules
        import igu_sentinel.detect.stats
        import igu_sentinel.detect.isoforest
        import igu_sentinel.detect.xgb

    def test_fusion_module_exists(self):
        """fusion module should be importable."""
        import igu_sentinel.fusion

    def test_alert_module_exists(self):
        """alert module should be importable."""
        import igu_sentinel.alert

    def test_drift_module_exists(self):
        """drift module should be importable."""
        import igu_sentinel.drift

    def test_traffic_gen_module_exists(self):
        """traffic_gen module should be importable."""
        import igu_sentinel.traffic_gen

    def test_api_module_exists(self):
        """api module should be importable."""
        import igu_sentinel.api
