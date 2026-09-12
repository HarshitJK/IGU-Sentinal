"""Cross-layer fusion: Platt calibration + correlation logic."""
from igu_sentinel.schemas import LayerScore, Alert


def fuse_layers(scores: list[LayerScore]) -> Alert:
    """Fuse multiple LayerScores into an Alert.

    Cross-layer correlation: require agreement across >=2 independent layers
    for high-confidence tier; single-layer-only detections downgrade to advisory.

    Args:
        scores: List of LayerScore objects from different detection layers

    Returns:
        Alert with fused confidence and evidence
    """
    pass
