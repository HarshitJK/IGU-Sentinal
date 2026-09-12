"""Score drift detection and bounded retrain trigger."""


def monitor_drift(scores: list[float]) -> bool:
    """Monitor rolling-window score distribution for drift.

    Uses KS test or PSI (PSI > 0.2 = significant drift threshold).

    Args:
        scores: List of recent anomaly scores

    Returns:
        True if drift detected, False otherwise
    """
    pass


def trigger_bounded_retrain() -> None:
    """Trigger retrain with bounds.

    Ensures single retrain does not shift decision boundary excessively.
    Never discards original baseline model (kept as permanent fallback).
    """
    pass
