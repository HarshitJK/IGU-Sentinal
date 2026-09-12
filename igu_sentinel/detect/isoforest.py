"""Isolation Forest unsupervised anomaly detection (benign-only trained)."""
from igu_sentinel.schemas import FlowRecord, LayerScore


def train_isoforest(benign_flows: list[FlowRecord]) -> None:
    """Train Isolation Forest on benign traffic only.

    Args:
        benign_flows: List of FlowRecords known to be benign
    """
    pass


def score_isoforest(flow: FlowRecord) -> LayerScore:
    """Score a flow using trained Isolation Forest.

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with raw_score and calibrated_probability
    """
    pass
