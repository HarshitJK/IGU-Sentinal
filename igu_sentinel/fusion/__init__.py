"""Cross-layer fusion: Platt calibration + correlation logic."""
from datetime import datetime
from igu_sentinel.schemas import LayerScore, Alert


# A layer may explicitly vote "benign"; that is NOT an accusation and must never
# be treated as a threat-class vote in the consensus.
BENIGN_LABEL = "benign"

# Minimum fused confidence for an alert to be worth surfacing to an analyst.
# Combined with the existing single-layer downgrade (x0.7), this suppresses
# "one layer twitched on quiet traffic" without touching the >=2-layer
# consensus logic that gates the high-confidence tier.
ALERT_CONFIDENCE_THRESHOLD = 0.5

# Marker added when no layer named any threat class at all.
NO_CONSENSUS_EVIDENCE = "no_layer_named_a_threat_class"


def is_actionable_alert(scores: list[LayerScore], alert: Alert) -> bool:
    """Decide whether a fused Alert is worth emitting to an analyst.

    The Alert schema is PS-fixed and its ``threat_class`` must be one of the six
    mandated classes — there is no "benign" alert to emit. So a flow that nothing
    accused of anything must be dropped rather than labelled. Without this gate
    every observed flow becomes an alert (and, with no threat vote, inherits the
    placeholder class), which is exactly the idle-traffic false-positive flood.

    An alert is actionable only when BOTH hold:
      1. At least one layer actually named a threat class (not None, not benign).
      2. The fused confidence clears ALERT_CONFIDENCE_THRESHOLD.

    This does not alter the >=2-layer consensus mechanism — it only decides
    whether the already-fused verdict is surfaced.

    Args:
        scores: The LayerScores that produced this alert.
        alert:  The fused Alert from fuse_layers().

    Returns:
        True if the alert should be logged/broadcast, False to suppress it.
    """
    named_threat = any(
        s.threat_class_guess and s.threat_class_guess != BENIGN_LABEL for s in scores
    )
    if not named_threat:
        return False
    return alert.confidence_score >= ALERT_CONFIDENCE_THRESHOLD


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
        # An explicit "benign" verdict is not an accusation — it must not be
        # counted as a threat-class vote in the consensus below.
        if score.threat_class_guess and score.threat_class_guess != BENIGN_LABEL:
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
        # No layer named a threat class. The Alert schema requires one of the six
        # mandated classes, so a placeholder is unavoidable here — but this alert
        # is NOT actionable and is_actionable_alert() drops it before it reaches
        # the log or the dashboard. The marker makes that visible if it is ever
        # inspected directly. (Previously this silently mislabelled quiet traffic
        # as volumetric_ddos.)
        threat_class = "volumetric_ddos"  # placeholder only — suppressed downstream
        agreement_count = 0
        all_evidence.append(NO_CONSENSUS_EVIDENCE)

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
