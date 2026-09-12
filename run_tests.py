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


def load_and_run_tests(module_name: str, test_names: list[str]) -> tuple[int, int]:
    """Dynamically load and run tests from a module."""
    sys.path.insert(0, str(Path(__file__).parent))
    module = __import__(f"tests.{module_name}", fromlist=test_names)

    tests = [getattr(module, name) for name in test_names]

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

    return len(tests), failed


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

    # Run rules tests
    print("\n--- Rules Detector Tests ---")
    rules_total, rules_failed = load_and_run_tests(
        "test_rules",
        [
            "test_rules_detect_benign",
            "test_rules_detect_ddos",
            "test_rules_detect_beaconing",
            "test_rules_detect_dga",
            "test_rules_detect_scanning",
            "test_rules_returns_layer_score",
            "test_rules_unusual_ports",
        ],
    )
    failed += rules_failed

    # Run stats tests
    print("\n--- Stats Detector Tests ---")
    stats_total, stats_failed = load_and_run_tests(
        "test_stats",
        [
            "test_stats_train_baseline",
            "test_stats_detect_benign_low",
            "test_stats_detect_ddos_high",
            "test_stats_detect_beaconing_high",
            "test_stats_detect_exfil_high",
            "test_stats_returns_valid_score",
        ],
    )
    failed += stats_failed

    # Run isolation forest tests
    print("\n--- Isolation Forest Detector Tests ---")
    isoforest_total, isoforest_failed = load_and_run_tests(
        "test_isoforest",
        [
            "test_isoforest_train",
            "test_isoforest_scores_benign_low",
            "test_isoforest_scores_attacks_high",
            "test_isoforest_returns_valid_score",
        ],
    )
    failed += isoforest_failed

    # Run XGBoost tests
    print("\n--- XGBoost Classifier Tests ---")
    xgb_total, xgb_failed = load_and_run_tests(
        "test_xgb",
        [
            "test_xgb_train",
            "test_xgb_predict_returns_valid_score",
            "test_xgb_end_to_end_with_held_out",
        ],
    )
    failed += xgb_failed

    # Run fusion tests
    print("\n--- Fusion Layer Tests ---")
    fusion_total, fusion_failed = load_and_run_tests(
        "test_fusion",
        [
            "test_fusion_high_confidence_multi_layer",
            "test_fusion_low_confidence_single_layer",
            "test_fusion_multi_layer_disagreement",
            "test_fusion_combines_evidence",
            "test_fusion_returns_valid_alert",
            "test_fusion_three_layer_agreement",
        ],
    )
    failed += fusion_failed

    # Run alert tests
    print("\n--- Alert Logging Tests ---")
    alert_total, alert_failed = load_and_run_tests(
        "test_alert",
        [
            "test_alert_log_single",
            "test_alert_log_chain_integrity",
            "test_alert_verify_valid_chain",
            "test_alert_verify_detects_tampering",
            "test_alert_verify_detects_hash_tampering",
            "test_alert_empty_log_verification",
        ],
    )
    failed += alert_failed

    # Run drift tests
    print("\n--- Drift Detection Tests ---")
    drift_total, drift_failed = load_and_run_tests(
        "test_drift",
        [
            "test_drift_compute_psi_no_drift",
            "test_drift_compute_psi_with_drift",
            "test_drift_monitor_no_drift",
            "test_drift_monitor_detects_drift",
            "test_drift_trigger_retrain",
            "test_drift_bounded_retrain_preserves_baseline",
            "test_drift_rolling_window",
        ],
    )
    failed += drift_failed

    # Run API tests
    print("\n--- API Pipeline Tests ---")
    api_total, api_failed = load_and_run_tests(
        "test_api",
        [
            "test_api_pipeline_benign",
            "test_api_pipeline_attack",
            "test_api_pipeline_mixed",
            "test_api_pipeline_returns_valid_alerts",
            "test_api_pipeline_preserves_flow_ids",
            "test_api_pipeline_end_to_end",
        ],
    )
    failed += api_failed

    # Run benchmark tests
    print("\n--- Benchmark Performance Tests ---")
    bench_total, bench_failed = load_and_run_tests(
        "test_benchmark",
        [
            "test_benchmark_throughput",
            "test_benchmark_latency",
        ],
    )
    failed += bench_failed

    # Run traffic_gen tests
    print("\n--- Traffic Generator Tests ---")
    traffic_gen_total, traffic_gen_failed = load_and_run_tests(
        "test_traffic_gen",
        [
            "test_traffic_gen_loads_config",
            "test_traffic_gen_produces_labeled_flows",
            "test_traffic_gen_matches_intent_threat_class",
            "test_traffic_gen_config_params",
        ],
    )
    failed += traffic_gen_failed

    total = len(tests) + rules_total + stats_total + isoforest_total + xgb_total + fusion_total + alert_total + drift_total + api_total + bench_total + traffic_gen_total
    print(f"\n{total - failed}/{total} tests passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
