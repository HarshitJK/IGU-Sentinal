#!/usr/bin/env python3
"""Simple test runner without pytest dependency."""
import sys
import json
import traceback
from datetime import datetime
from pathlib import Path
from pydantic import ValidationError

# Import schemas
from igu_sentinel.schemas import FlowRecord, LayerScore, Alert


def test_valid_flow_record():
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
    print("✓ test_valid_flow_record passed")


def test_missing_required_field():
    """FlowRecord should reject missing required fields."""
    try:
        FlowRecord(
            flow_id="flow_123",
            timestamp=datetime.now(),
            src_port=1234,
            # Missing dst_port and other required fields
        )
        print("✗ test_missing_required_field failed: should have raised ValidationError")
        return False
    except ValidationError:
        print("✓ test_missing_required_field passed")
        return True


def test_invalid_type():
    """FlowRecord should reject invalid types."""
    try:
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
        print("✗ test_invalid_type failed: should have raised ValidationError")
        return False
    except ValidationError:
        print("✓ test_invalid_type passed")
        return True


def test_valid_layer_score():
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
    print("✓ test_valid_layer_score passed")


def test_layer_score_optional_fields():
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
    print("✓ test_layer_score_optional_fields passed")


def test_valid_alert():
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
    print("✓ test_valid_alert passed")


def test_invalid_threat_class():
    """Alert should validate threat_class is one of the six mandated types."""
    try:
        Alert(
            timestamp=datetime.now(),
            flow_id="flow_123",
            threat_class="unknown_threat",  # Invalid
            confidence_score=0.88,
            evidence=[],
        )
        print("✗ test_invalid_threat_class failed: should have raised ValidationError")
        return False
    except ValidationError:
        print("✓ test_invalid_threat_class passed")
        return True


def test_valid_threat_classes():
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
    print("✓ test_valid_threat_classes passed")


def test_module_imports():
    """Test that all modules are importable."""
    modules_to_test = [
        "igu_sentinel.ingest",
        "igu_sentinel.detect",
        "igu_sentinel.detect.rules",
        "igu_sentinel.detect.stats",
        "igu_sentinel.detect.isoforest",
        "igu_sentinel.detect.xgb",
        "igu_sentinel.fusion",
        "igu_sentinel.alert",
        "igu_sentinel.drift",
        "igu_sentinel.traffic_gen",
        "igu_sentinel.api",
    ]
    for module in modules_to_test:
        try:
            __import__(module)
        except ImportError as e:
            print(f"✗ failed to import {module}: {e}")
            return False
    print("✓ test_module_imports passed")
    return True


def test_fixture_files_exist():
    """All fixture files should exist."""
    fixtures_dir = Path(__file__).parent / "tests" / "fixtures"
    threat_classes = [
        "benign",
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]
    for threat_class in threat_classes:
        fixture_file = fixtures_dir / f"{threat_class}_sample.jsonl"
        if not fixture_file.exists():
            print(f"✗ Fixture file {fixture_file} does not exist")
            return False
    print("✓ test_fixture_files_exist passed")
    return True


def test_fixtures_parse_as_flow_records():
    """All fixture files should parse into valid FlowRecords."""
    fixtures_dir = Path(__file__).parent / "tests" / "fixtures"
    threat_classes = [
        "benign",
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]
    for threat_class in threat_classes:
        fixture_file = fixtures_dir / f"{threat_class}_sample.jsonl"
        flows = []

        with open(fixture_file) as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    flow = FlowRecord(**data)
                    flows.append(flow)

        if len(flows) < 5:
            print(
                f"✗ {threat_class} has {len(flows)} flows, "
                f"expected at least 5"
            )
            return False
    print("✓ test_fixtures_parse_as_flow_records passed")
    return True


def test_fixture_schema_compliance():
    """All fixture flows should have correct required fields."""
    fixtures_dir = Path(__file__).parent / "tests" / "fixtures"
    threat_classes = [
        "benign",
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]
    required_fields = {
        "flow_id",
        "timestamp",
        "src_port",
        "dst_port",
        "protocol",
        "packet_size_stats",
        "inter_arrival_stats",
        "entropy",
        "byte_ratio",
        "ttl",
    }

    for threat_class in threat_classes:
        fixture_file = fixtures_dir / f"{threat_class}_sample.jsonl"

        with open(fixture_file) as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    data = json.loads(line)
                    missing_fields = required_fields - set(data.keys())
                    if missing_fields:
                        print(
                            f"✗ Line {line_num} in {threat_class} "
                            f"missing fields: {missing_fields}"
                        )
                        return False
    print("✓ test_fixture_schema_compliance passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_valid_flow_record,
        test_missing_required_field,
        test_invalid_type,
        test_valid_layer_score,
        test_layer_score_optional_fields,
        test_valid_alert,
        test_invalid_threat_class,
        test_valid_threat_classes,
        test_module_imports,
        test_fixture_files_exist,
        test_fixtures_parse_as_flow_records,
        test_fixture_schema_compliance,
    ]

    failed = 0
    for test in tests:
        try:
            result = test()
            if result is False:
                failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} raised unexpected error:")
            traceback.print_exc()
            failed += 1

    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
