"""Cross-layer fusion: Platt calibration + correlation logic."""
from datetime import datetime
from igu_sentinel.schemas import LayerScore, Alert


def fuse_layers(scores: list[LayerScore]) -> Alert:
    """Fuse multiple LayerScores into an Alert.

    Cross-layer correlation logic:
    - Require agreement across >=2 independent layers for high-confidence tier
    - Single-layer-only detections are downgraded to advisory/lower confidence
    - Combine evidence from all layers
    - Calibrated probabilities already applied by detection layers

    Args:
        scores: List of LayerScore objects from different detection layers

    Returns:
        Alert with fused confidence and evidence

    Raises:
        ValueError: If scores list is empty or flow_ids don't match
    """
    if not scores:
        raise ValueError("Must provide at least one LayerScore")

    # Verify all scores are for the same flow
    flow_id = scores[0].flow_id
    for score in scores:
        if score.flow_id != flow_id:
            raise ValueError(f"All scores must have same flow_id, got {score.flow_id} != {flow_id}")

    # Collect threat class guesses and probabilities
    threat_guesses = {}
    layer_probabilities = []
    all_evidence = []

    for score in scores:
        layer_probabilities.append(score.calibrated_probability)
        if score.threat_class_guess:
            if score.threat_class_guess not in threat_guesses:
                threat_guesses[score.threat_class_guess] = []
            threat_guesses[score.threat_class_guess].append(score.calibrated_probability)
        if score.evidence:
            all_evidence.extend(score.evidence)

    # Determine consensus threat class
    # Pick the one with most layer agreement, weighted by confidence
    if threat_guesses:
        # Sort by number of layers agreeing (desc), then by avg confidence (desc)
        sorted_guesses = sorted(
            threat_guesses.items(),
            key=lambda x: (len(x[1]), sum(x[1]) / len(x[1])),
            reverse=True,
        )
        threat_class = sorted_guesses[0][0]
        agreement_count = len(sorted_guesses[0][1])
    else:
        # No threat class consensus, use highest probability
        threat_class = "volumetric_ddos"  # Default fallback
        agreement_count = 0

    # Compute fused confidence score
    # Base: average calibrated probability across all layers
    avg_probability = sum(layer_probabilities) / len(layer_probabilities)

    # Adjust based on layer agreement
    # >=2 layers agreeing: boost confidence
    # 1 layer: downgrade confidence (advisory tier)
    if agreement_count >= 2:
        # High-confidence tier: multiple layers agree
        # Boost toward upper range
        fused_confidence = min(0.95, avg_probability * 1.1)
    elif agreement_count == 1:
        # Lower-confidence (advisory): only one layer detected threat
        # Downgrade to lower range
        fused_confidence = avg_probability * 0.7
    else:
        # No specific threat class guess, use base average
        fused_confidence = avg_probability * 0.6

    # Ensure confidence is in valid range
    fused_confidence = max(0.0, min(1.0, fused_confidence))

    # Build alert
    alert = Alert(
        timestamp=datetime.now(),
        flow_id=flow_id,
        threat_class=threat_class,
        confidence_score=fused_confidence,
        evidence=all_evidence if all_evidence else ["fused_from_multiple_layers"],
    )

    return alert
