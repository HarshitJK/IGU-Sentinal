"""Z-score baseline anomaly detection."""
from igu_sentinel.schemas import FlowRecord, LayerScore


def detect_stats(flow: FlowRecord) -> LayerScore:
    """Detect anomalies using z-score baseline.

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with raw_score and calibrated_probability
    """
    pass
