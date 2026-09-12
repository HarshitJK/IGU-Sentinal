"""Static IOC and protocol-violation rule engine."""
from igu_sentinel.schemas import FlowRecord, LayerScore


def detect_rules(flow: FlowRecord) -> LayerScore:
    """Detect threats using static rules.

    Args:
        flow: FlowRecord to analyze

    Returns:
        LayerScore with raw_score and calibrated_probability
    """
    pass
