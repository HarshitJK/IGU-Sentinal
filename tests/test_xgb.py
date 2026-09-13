"""Test detect/xgb.py XGBoost multi-class threat classifier."""
import json
from pathlib import Path
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.detect.xgb import train_xgb, predict_xgb


FIXTURES_DIR = Path(__file__).parent / "fixtures"
THREAT_CLASSES = [
    "benign",
    "volumetric_ddos",
    "c2_beaconing",
    "dga_dns_tunneling",
    "encrypted_malware",
    "recon_scanning",
    "data_exfiltration",
]


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


def test_xgb_train():
    """XGBoost should successfully train on labeled flows."""
    flows = []
    labels = []

    for threat_class in THREAT_CLASSES:
        class_flows = load_fixture_flows(threat_class)
        flows.extend(class_flows)
        labels.extend([threat_class] * len(class_flows))

    train_xgb(flows, labels)
    print(f"✓ test_xgb_train passed (trained on {len(flows)} flows, {len(set(labels))} classes)")


def test_xgb_predict_returns_valid_score():
    """XGBoost should return valid LayerScore with threat class."""
    # Train
    flows = []
    labels = []
    for threat_class in THREAT_CLASSES:
        class_flows = load_fixture_flows(threat_class)
        flows.extend(class_flows)
        labels.extend([threat_class] * len(class_flows))

    train_xgb(flows, labels)

    # Predict
    benign_flow = load_fixture_flows("benign")[0]
    score = predict_xgb(benign_flow)

    assert score.flow_id == benign_flow.flow_id
    assert score.layer_name == "xgb"
    assert 0 <= score.raw_score <= 1
    assert 0 <= score.calibrated_probability <= 1
    # Threat class guess can be None (if benign) or a valid threat class
    assert score.threat_class_guess is None or score.threat_class_guess in [
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]
    print(f"✓ test_xgb_predict_returns_valid_score passed (predicted: {score.threat_class_guess})")


def test_xgb_end_to_end_with_held_out():
    """XGBoost end-to-end test with held-out evaluation set."""
    # Split data: 70% train, 30% test
    flows = []
    labels = []
    for threat_class in THREAT_CLASSES:
        class_flows = load_fixture_flows(threat_class)
        flows.extend(class_flows)
        labels.extend([threat_class] * len(class_flows))

    total_flows = len(flows)
    split_point = int(total_flows * 0.7)

    train_flows = flows[:split_point]
    train_labels = labels[:split_point]
    test_flows = flows[split_point:]
    test_labels = labels[split_point:]

    # Train
    train_xgb(train_flows, train_labels)

    # Evaluate on held-out test set
    predictions = []
    for flow in test_flows:
        score = predict_xgb(flow)
        predictions.append(score.threat_class_guess)

    # Compute per-class metrics
    per_class_metrics = {}
    for threat_class in THREAT_CLASSES:
        tp = sum(1 for pred, true in zip(predictions, test_labels)
                 if pred == threat_class and true == threat_class)
        fp = sum(1 for pred, true in zip(predictions, test_labels)
                 if pred == threat_class and true != threat_class)
        fn = sum(1 for pred, true in zip(predictions, test_labels)
                 if pred != threat_class and true == threat_class)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class_metrics[threat_class] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "samples": sum(1 for t in test_labels if t == threat_class),
        }

    # Report metrics (not asserted, just printed)
    print(f"\n✓ test_xgb_end_to_end_with_held_out passed")
    print(f"  Train set: {len(train_flows)} flows")
    print(f"  Test set: {len(test_flows)} flows")
    print(f"  Per-class metrics (Precision / Recall / F1):")
    for threat_class in THREAT_CLASSES:
        metrics = per_class_metrics[threat_class]
        if metrics["samples"] > 0:
            print(f"    {threat_class:20s}: {metrics['precision']:.2f} / {metrics['recall']:.2f} / {metrics['f1']:.2f} ({metrics['samples']} samples)")
