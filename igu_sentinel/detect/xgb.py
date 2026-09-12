"""XGBoost multi-class threat classifier."""
from igu_sentinel.schemas import FlowRecord, LayerScore


def train_xgb(flows: list[FlowRecord], labels: list[str]) -> None:
    """Train XGBoost multi-class classifier.

    Args:
        flows: List of FlowRecords
        labels: Corresponding threat class labels
    """
    pass


def predict_xgb(flow: FlowRecord) -> LayerScore:
    """Predict threat class using trained XGBoost.

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with raw_score, threat_class_guess, and calibrated_probability
    """
    pass
