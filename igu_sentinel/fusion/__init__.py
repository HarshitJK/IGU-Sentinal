"""Cross-layer fusion: Platt calibration + correlation logic."""
import logging
from datetime import datetime
from igu_sentinel.schemas import LayerScore, Alert

log = logging.getLogger(__name__)

# A layer may explicitly vote "benign"; that is NOT an accusation and must never
# be treated as a threat-class vote in the consensus.
BENIGN_LABEL = "benign"

# Zero trust at the data level (CLAUDE.md): fusion does not assume an upstream
# detector emitted a class the Alert schema accepts. A stale model artifact or a
# new detector can emit anything; an unrecognised label reaching Alert() raises
# ValidationError per flow, taking down the scoring path rather than degrading.
VALID_THREAT_CLASSES = frozenset({
    "volumetric_ddos",
    "c2_beaconing",
    "dga_dns_tunneling",
    "encrypted_malware",
    "recon_scanning",
    "data_exfiltration",
})

# Confidence tiers. Reported in `evidence`, never multiplied into the score.
HIGH_CONFIDENCE_TIER = "high"          # >=2 independent layers named the same class
ADVISORY_TIER = "advisory"             # exactly one layer named a class
UNCORROBORATED_TIER = "uncorroborated"  # no layer named a class

# Minimum calibrated probability for an alert to be worth surfacing.
#
# Retuned when the tier multipliers were removed: a single-layer detection used
# to be scaled by 0.7 before meeting this threshold, so the effective bar for
# one layer was ~0.71 and for two layers ~0.45. Those effective bars are now
# stated directly, per tier, instead of being an artefact of arithmetic.
ALERT_CONFIDENCE_THRESHOLD = 0.5
ADVISORY_CONFIDENCE_THRESHOLD = 0.70

# Minimum calibrated probability for an unsupervised layer to corroborate or alert (R7, R8)
UNSUPERVISED_CORROBORATION_THRESHOLD = 0.75

# Marker added when no layer named any threat class at all.
NO_CONSENSUS_EVIDENCE = "no_layer_named_a_threat_class"


def is_actionable_alert(scores: list[LayerScore], alert: Alert) -> bool:
    """Decide whether a fused Alert is worth emitting to an analyst.

    The Alert schema is PS-fixed and its ``threat_class`` must be one of the six
    mandated classes — there is no "benign" alert to emit. So a flow that nothing
    accused of anything must be dropped rather than labelled. Without this gate
    every observed flow becomes an alert (and, with no threat vote, inherits the
    placeholder class), which is exactly the idle-traffic false-positive flood.

    An alert is actionable when:
      1. At least one layer named a threat class (or an unclassified anomaly was
         surfaced by strong unsupervised layers per R8).
      2. The fused confidence clears the applicable threshold (ALERT_CONFIDENCE_THRESHOLD
         for corroborated alerts, ADVISORY_CONFIDENCE_THRESHOLD for single-layer
         or unclassified anomaly alerts).

    Args:
        scores: The LayerScores that produced this alert.
        alert:  The fused Alert from fuse_layers().

    Returns:
        True if the alert should be logged/broadcast, False to suppress it.
    """
    named = [
        s.threat_class_guess for s in scores
        if s.threat_class_guess and s.threat_class_guess != BENIGN_LABEL
    ]
    if not named:
        # R8: Allow strong unsupervised anomalies to surface at advisory threshold
        if "unclassified_anomaly=true" in alert.evidence:
            return alert.confidence_score >= ADVISORY_CONFIDENCE_THRESHOLD
        return False

    # A single-layer detection has no corroboration, so it must clear a higher
    # bar than a cross-layer one. Corroboration includes both supervised agreement
    # and strong unsupervised corroboration (R7).
    corroborated = len([c for c in set(named) if named.count(c) >= 2]) > 0
    if not corroborated and any("corroborates=" in e for e in alert.evidence):
        corroborated = True

    threshold = (
        ALERT_CONFIDENCE_THRESHOLD if corroborated else ADVISORY_CONFIDENCE_THRESHOLD
    )
    return alert.confidence_score >= threshold


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
        guess = score.threat_class_guess
        if guess and guess != BENIGN_LABEL:
            if guess in VALID_THREAT_CLASSES:
                if guess not in threat_guesses:
                    threat_guesses[guess] = []
                threat_guesses[guess].append(score.calibrated_probability)
            else:
                # Drop the vote, keep the layer's evidence: the observation may
                # still be useful to an analyst even when the label is not one
                # the Alert schema accepts.
                log.warning(
                    "fusion: layer %r proposed out-of-schema class %r — ignoring vote",
                    score.layer_name, guess,
                )
        if score.evidence:
            all_evidence.extend(score.evidence)

    # R7: Cross-layer corroboration from unsupervised layers
    # If exactly one candidate threat class was proposed by supervised layers, allow
    # high-confidence unsupervised layers (calibrated probability >= 0.75) to corroborate
    named_candidates = list(threat_guesses.keys())
    if len(named_candidates) == 1:
        candidate = named_candidates[0]
        for score in scores:
            if (
                score.threat_class_guess is None
                and score.calibrated_probability >= UNSUPERVISED_CORROBORATION_THRESHOLD
            ):
                threat_guesses[candidate].append(score.calibrated_probability)
                all_evidence.append(
                    f"{score.layer_name}_corroborates={score.calibrated_probability:.3f}"
                )

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
        # R8: Strong unclassified anomalies from unsupervised layers
        strong_unsupervised = [
            s for s in scores
            if s.threat_class_guess is None
            and s.calibrated_probability >= UNSUPERVISED_CORROBORATION_THRESHOLD
        ]
        if strong_unsupervised:
            # Route to nearest plausible class by evidence cues to keep schema valid
            combined_evidence_str = " ".join(all_evidence).lower()
            if any(k in combined_evidence_str for k in ("fanout", "port", "scan", "targets")):
                threat_class = "recon_scanning"
            elif any(k in combined_evidence_str for k in ("byte", "exfil", "upload", "outbound")):
                threat_class = "data_exfiltration"
            elif any(k in combined_evidence_str for k in ("dns", "tunnel", "entropy", "query")):
                threat_class = "dga_dns_tunneling"
            elif any(k in combined_evidence_str for k in ("rate", "packet_count", "pps", "flood")):
                threat_class = "volumetric_ddos"
            else:
                threat_class = "recon_scanning"
            agreement_count = len(strong_unsupervised)
            all_evidence.append("unclassified_anomaly=true")
            all_evidence.append(f"unsupervised_layers_alerted={len(strong_unsupervised)}")
        else:
            threat_class = "volumetric_ddos"  # placeholder only — suppressed downstream
            agreement_count = 0
            all_evidence.append(NO_CONSENSUS_EVIDENCE)

    # Compute fused confidence score
    # Base: average calibrated probability across all layers
    avg_probability = sum(layer_probabilities) / len(layer_probabilities)

    # confidence_score stays a CALIBRATED PROBABILITY — it is not rescaled by
    # tier.
    #
    # It used to be multiplied by 1.1 (>=2 layers), 0.7 (1 layer) or 0.6 (none).
    # Those factors are tier weighting, and they destroy calibration: after a
    # x1.1 a reported 0.8 no longer means "80% of flows scored this way are
    # threats", which is exactly what CLAUDE.md says the field means. The tier
    # is real information, so it is reported alongside rather than multiplied in.
    fused_confidence = max(0.0, min(1.0, avg_probability))

    if "unclassified_anomaly=true" in all_evidence:
        tier = ADVISORY_TIER
    else:
        tier = (
            HIGH_CONFIDENCE_TIER if agreement_count >= 2
            else ADVISORY_TIER if agreement_count == 1
            else UNCORROBORATED_TIER
        )
    # The Alert schema is PS-fixed, so the tier cannot become a field. Putting
    # it in evidence keeps the schema exact while preserving the information
    # that the multipliers used to encode (lossily).
    all_evidence.append(f"tier={tier}")
    all_evidence.append(f"corroborating_layers={agreement_count}")

    # Build alert
    alert = Alert(
        timestamp=datetime.now(),
        flow_id=flow_id,
        threat_class=threat_class,
        confidence_score=fused_confidence,
        evidence=all_evidence if all_evidence else ["fused_from_multiple_layers"],
    )

    return alert
