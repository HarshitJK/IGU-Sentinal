"""Z-score baseline anomaly detection."""
import math
from typing import Optional
from igu_sentinel.schemas import FlowRecord, LayerScore


# Global baseline statistics (trained on benign traffic)
_baseline: Optional[dict] = None


def train_stats_baseline(benign_flows: list[FlowRecord]) -> None:
    """Train z-score baseline on benign flows.

    Args:
        benign_flows: List of benign FlowRecords to compute baseline statistics
    """
    global _baseline

    if not benign_flows:
        raise ValueError("Must provide at least one benign flow")

    # Extract features from all benign flows
    inter_arrivals = []
    packet_sizes = []
    entropies = []
    byte_ratios = []
    ttls = []
    fanouts = []

    for flow in benign_flows:
        inter_arrivals.append(flow.inter_arrival_stats["mean"])
        packet_sizes.append(flow.packet_size_stats["mean"])
        entropies.append(flow.entropy)
        byte_ratios.append(flow.byte_ratio)
        ttls.append(flow.ttl)
        if flow.fanout_count:
            fanouts.append(flow.fanout_count)

    # Compute mean and std for each feature
    def compute_stats(values: list[float]) -> tuple[float, float]:
        if not values:
            return 0.0, 1.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = math.sqrt(variance) if variance > 0 else 1.0
        return mean, std

    _baseline = {
        "inter_arrival_mean": compute_stats(inter_arrivals),
        "packet_size_mean": compute_stats(packet_sizes),
        "entropy": compute_stats(entropies),
        "byte_ratio": compute_stats(byte_ratios),
        "ttl": compute_stats(ttls),
        "fanout_count": compute_stats(fanouts) if fanouts else (1.0, 1.0),
    }


def detect_stats(flow: FlowRecord) -> LayerScore:
    """Detect anomalies using z-score baseline.

    Computes z-scores for various flow features against the trained baseline.
    Combines them into a composite anomaly score.

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with raw_score and calibrated_probability
    """
    if _baseline is None:
        raise RuntimeError("Must call train_stats_baseline() before detect_stats()")

    z_scores = []
    evidence = []

    # Compute z-score for inter-arrival time
    mean, std = _baseline["inter_arrival_mean"]
    z = abs((flow.inter_arrival_stats["mean"] - mean) / std)
    z_scores.append(z)
    if z > 2:
        evidence.append(f"unusual_inter_arrival_time (z={z:.2f})")

    # Compute z-score for packet size
    mean, std = _baseline["packet_size_mean"]
    z = abs((flow.packet_size_stats["mean"] - mean) / std)
    z_scores.append(z)
    if z > 2:
        evidence.append(f"unusual_packet_size (z={z:.2f})")

    # Compute z-score for entropy
    mean, std = _baseline["entropy"]
    z = abs((flow.entropy - mean) / std)
    z_scores.append(z)
    if z > 2:
        evidence.append(f"unusual_entropy (z={z:.2f})")

    # Compute z-score for byte ratio
    mean, std = _baseline["byte_ratio"]
    z = abs((flow.byte_ratio - mean) / std)
    z_scores.append(z)
    if z > 2:
        evidence.append(f"unusual_byte_ratio (z={z:.2f})")

    # Compute z-score for TTL
    mean, std = _baseline["ttl"]
    z = abs((flow.ttl - mean) / std)
    z_scores.append(z)
    if z > 2:
        evidence.append(f"unusual_ttl (z={z:.2f})")

    # Compute z-score for fanout (if present)
    if flow.fanout_count:
        mean, std = _baseline["fanout_count"]
        z = abs((flow.fanout_count - mean) / std)
        z_scores.append(z)
        if z > 2:
            evidence.append(f"unusual_fanout (z={z:.2f})")

    # Average absolute z-score as anomaly score
    raw_score = sum(z_scores) / len(z_scores) if z_scores else 0.0
    # Normalize to [0, 1] using sigmoid-like function
    # raw_score is typically in [0, 5] range; map to [0, 1]
    normalized_score = min(raw_score / 5.0, 1.0)

    # Platt-scale calibration
    try:
        calibrated = 1.0 / (1.0 + math.exp(-5.0 * (normalized_score - 0.25)))
    except (ValueError, OverflowError):
        calibrated = 1.0 if normalized_score > 0.5 else 0.0

    return LayerScore(
        flow_id=flow.flow_id,
        layer_name="stats",
        raw_score=normalized_score,
        calibrated_probability=calibrated,
        threat_class_guess=None,
        evidence=evidence if evidence else None,
    )
