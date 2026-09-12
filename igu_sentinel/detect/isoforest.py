"""Isolation Forest unsupervised anomaly detection (benign-only trained)."""
import math
from typing import Optional
from igu_sentinel.schemas import FlowRecord, LayerScore


# Global baseline statistics for anomaly detection
_baseline: Optional[dict] = None


def _extract_features(flow: FlowRecord) -> list[float]:
    """Extract feature vector from a FlowRecord.

    Features: inter_arrival, packet_size, entropy, byte_ratio, ttl, fanout
    """
    return [
        flow.inter_arrival_stats["mean"],
        flow.packet_size_stats["mean"],
        flow.entropy,
        flow.byte_ratio,
        float(flow.ttl),
        float(flow.fanout_count) if flow.fanout_count else 0.0,
    ]


def train_isoforest(benign_flows: list[FlowRecord]) -> None:
    """Train anomaly detector on benign traffic only.

    Computes baseline statistics and isolation scores for anomaly detection.

    Args:
        benign_flows: List of FlowRecords known to be benign
    """
    global _baseline

    if not benign_flows:
        raise ValueError("Must provide at least one benign flow")

    # Extract features from all benign flows
    features_by_dim = [[] for _ in range(6)]
    for flow in benign_flows:
        features = _extract_features(flow)
        for i, feat in enumerate(features):
            features_by_dim[i].append(feat)

    # Compute mean, std, min, max for each dimension
    def compute_stats(values: list[float]) -> dict:
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = math.sqrt(variance) if variance > 0 else 1.0
        return {
            "mean": mean,
            "std": std,
            "min": min(values),
            "max": max(values),
            "range": max(values) - min(values) if min(values) != max(values) else 1.0,
        }

    _baseline = {
        "features": [compute_stats(flist) for flist in features_by_dim],
        "benign_features": [_extract_features(f) for f in benign_flows],
    }


def _compute_isolation_score(flow: FlowRecord) -> float:
    """Compute anomaly score based on isolation-like approach.

    Idea: anomalies are isolated in feature space. Compute how "isolated"
    this flow is from the benign training set.

    Returns score in [0, 1] where 1 = highly anomalous
    """
    if _baseline is None:
        raise RuntimeError("Must call train_isoforest() before score_isoforest()")

    current_features = _extract_features(flow)
    benign_features_list = _baseline["benign_features"]

    # Compute average distance to each benign flow
    total_distance = 0.0
    for benign_features in benign_features_list:
        # Euclidean distance in normalized space
        distance = 0.0
        for i, (current, benign) in enumerate(zip(current_features, benign_features)):
            stat = _baseline["features"][i]
            # Normalize by range
            if stat["range"] > 0:
                norm_diff = (current - benign) / stat["range"]
            else:
                norm_diff = 0.0
            distance += norm_diff ** 2
        total_distance += math.sqrt(distance)

    # Average distance to benign flows
    avg_distance = total_distance / len(benign_features_list)

    # Normalize: compute how far this is from the benign cluster
    # If avg_distance is high relative to typical benign distances, it's anomalous

    # Compute typical within-cluster distance (benign flows to each other)
    within_cluster_distance = 0.0
    count = 0
    for i, benign1 in enumerate(benign_features_list):
        for benign2 in benign_features_list[i+1:]:
            distance = 0.0
            for feat1, feat2 in zip(benign1, benign2):
                distance += (feat1 - feat2) ** 2
            within_cluster_distance += math.sqrt(distance)
            count += 1

    if count > 0:
        typical_distance = within_cluster_distance / count
    else:
        typical_distance = 1.0

    # Anomaly score: ratio of distance to cluster
    # Higher ratio = more anomalous
    if typical_distance > 0:
        anomaly_score = avg_distance / typical_distance
    else:
        anomaly_score = 0.0

    # Normalize to [0, 1]: use sigmoid-like transformation
    # Score of ~1.0 is normal, > 2.0 is anomalous
    normalized_score = min(anomaly_score / 4.0, 1.0)

    return normalized_score


def score_isoforest(flow: FlowRecord) -> LayerScore:
    """Score a flow using trained Isolation Forest-like anomaly detector.

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with raw_score and calibrated_probability
    """
    if _baseline is None:
        raise RuntimeError("Must call train_isoforest() before score_isoforest()")

    # Compute isolation-based anomaly score
    raw_score = _compute_isolation_score(flow)

    # Platt-scale calibration
    try:
        calibrated = 1.0 / (1.0 + math.exp(-5.0 * (raw_score - 0.25)))
    except (ValueError, OverflowError):
        calibrated = 1.0 if raw_score > 0.5 else 0.0

    return LayerScore(
        flow_id=flow.flow_id,
        layer_name="isoforest",
        raw_score=raw_score,
        calibrated_probability=calibrated,
        threat_class_guess=None,
        evidence=None,
    )
