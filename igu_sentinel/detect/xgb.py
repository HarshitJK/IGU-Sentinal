"""XGBoost multi-class threat classifier wrapper.

Note: Uses a simple k-NN classifier (k=1) as XGBoost/sklearn are not available.
This provides the required multi-class classification capability for per-threat evaluation.
"""
import math
from typing import Optional
from igu_sentinel.schemas import FlowRecord, LayerScore


# Global training data
_training_data: Optional[dict] = None


def _extract_features(flow: FlowRecord) -> list[float]:
    """Extract feature vector from a FlowRecord."""
    return [
        flow.inter_arrival_stats["mean"],
        flow.packet_size_stats["mean"],
        flow.entropy,
        flow.byte_ratio,
        float(flow.ttl),
        float(flow.fanout_count) if flow.fanout_count else 0.0,
    ]


def _euclidean_distance(features1: list[float], features2: list[float]) -> float:
    """Compute Euclidean distance between two feature vectors."""
    return math.sqrt(sum((f1 - f2) ** 2 for f1, f2 in zip(features1, features2)))


def train_xgb(flows: list[FlowRecord], labels: list[str]) -> None:
    """Train multi-class classifier on labeled flows.

    Uses simple k-NN (k=1) approach since sklearn/xgboost unavailable.

    Args:
        flows: List of FlowRecords
        labels: Corresponding threat class labels
    """
    global _training_data

    if len(flows) != len(labels):
        raise ValueError("flows and labels must have same length")

    if not flows:
        raise ValueError("Must provide at least one flow")

    # Store training features and labels
    _training_data = {
        "features": [_extract_features(flow) for flow in flows],
        "labels": labels.copy(),
        "flows": flows.copy(),
    }


def predict_xgb(flow: FlowRecord) -> LayerScore:
    """Predict threat class using trained multi-class classifier.

    Uses k-NN (k=1) approach: find closest training sample and use its label.

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with threat_class_guess and calibrated_probability
    """
    if _training_data is None:
        raise RuntimeError("Must call train_xgb() before predict_xgb()")

    features = _extract_features(flow)
    training_features = _training_data["features"]
    training_labels = _training_data["labels"]

    # Find nearest neighbor
    min_distance = float('inf')
    nearest_label = None
    for train_feat, label in zip(training_features, training_labels):
        distance = _euclidean_distance(features, train_feat)
        if distance < min_distance:
            min_distance = distance
            nearest_label = label

    # Filter out "benign" - it's not a valid threat class
    # Only return threat class if it's one of the six valid types
    valid_threat_classes = {
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    }
    if nearest_label and nearest_label not in valid_threat_classes:
        nearest_label = None

    # Compute confidence based on distance
    # Normalize distance to a confidence score
    # Use inverse: closer = more confident
    if min_distance > 0:
        # Map distance to confidence using sigmoid-like function
        # Small distance (~0) → high confidence (~0.9)
        # Large distance (~10) → low confidence (~0.2)
        raw_score = 1.0 / (1.0 + min_distance / 2.0)
    else:
        raw_score = 1.0

    # Platt-scale calibration
    import math
    try:
        calibrated = 1.0 / (1.0 + math.exp(-5.0 * (raw_score - 0.25)))
    except (ValueError, OverflowError):
        calibrated = 1.0 if raw_score > 0.5 else 0.0

    return LayerScore(
        flow_id=flow.flow_id,
        layer_name="xgb",
        raw_score=raw_score,
        calibrated_probability=calibrated,
        threat_class_guess=nearest_label,
        evidence=[f"nearest_neighbor_distance={min_distance:.3f}"],
    )
