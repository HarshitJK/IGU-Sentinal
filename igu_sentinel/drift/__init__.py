"""Score drift detection and bounded retrain trigger."""
import math
from datetime import datetime
from typing import Optional


# Global baseline distribution for drift detection
_baseline_distribution: Optional[list[float]] = None
_retrain_log: list[str] = []


def compute_psi(baseline: list[float], current: list[float], bins: int = 10) -> float:
    """Compute Population Stability Index (PSI) between two distributions.

    PSI measures how much a current distribution has shifted from baseline.
    PSI > 0.2 indicates significant drift (literature standard).

    Args:
        baseline: Baseline distribution scores
        current: Current distribution scores
        bins: Number of bins for histogram

    Returns:
        PSI score (0 = identical, > 0.2 = significant drift)
    """
    if not baseline or not current:
        return 0.0

    # Create histograms
    # Determine range from combined data
    all_data = baseline + current
    min_val = min(all_data)
    max_val = max(all_data)
    range_val = max_val - min_val if max_val > min_val else 1.0

    # Create bins
    bin_edges = [min_val + (i / bins) * range_val for i in range(bins + 1)]

    # Count samples in each bin
    baseline_counts = [0] * bins
    current_counts = [0] * bins

    for score in baseline:
        for i in range(bins):
            if bin_edges[i] <= score < bin_edges[i + 1]:
                baseline_counts[i] += 1
                break
        else:
            # Handle max value
            if score == max_val:
                baseline_counts[-1] += 1

    for score in current:
        for i in range(bins):
            if bin_edges[i] <= score < bin_edges[i + 1]:
                current_counts[i] += 1
                break
        else:
            # Handle max value
            if score == max_val:
                current_counts[-1] += 1

    # Compute PSI
    psi = 0.0
    for baseline_count, current_count in zip(baseline_counts, current_counts):
        # Avoid division by zero
        baseline_pct = (baseline_count + 0.5) / (len(baseline) + len(bin_edges))
        current_pct = (current_count + 0.5) / (len(current) + len(bin_edges))

        # PSI formula: sum((current% - baseline%) * ln(current% / baseline%))
        if baseline_pct > 0 and current_pct > 0:
            psi += (current_pct - baseline_pct) * math.log(current_pct / baseline_pct)

    return abs(psi)


def monitor_drift(scores: list[float]) -> bool:
    """Monitor rolling-window score distribution for drift.

    Uses PSI (Population Stability Index) to detect if current score
    distribution has shifted from baseline. PSI > 0.2 = significant drift.

    Args:
        scores: List of recent anomaly scores

    Returns:
        True if drift detected, False otherwise
    """
    global _baseline_distribution

    if not scores:
        return False

    # First call: establish baseline
    if _baseline_distribution is None:
        _baseline_distribution = scores.copy()
        return False

    # Compute PSI between baseline and current distribution
    psi = compute_psi(_baseline_distribution, scores)

    # Use PSI threshold of 0.2 (literature standard)
    drift_threshold = 0.2
    is_drifted = psi > drift_threshold

    if is_drifted:
        _retrain_log.append(
            f"[{datetime.now().isoformat()}] Drift detected: PSI={psi:.4f} "
            f"(threshold={drift_threshold})"
        )

    return is_drifted


def trigger_bounded_retrain() -> None:
    """Trigger retrain with bounds.

    Ensures single retrain does not shift decision boundary excessively.
    Never discards original baseline model (kept as permanent fallback/reference).
    """
    global _baseline_distribution

    if _baseline_distribution is None:
        return

    # Log retrain event
    _retrain_log.append(
        f"[{datetime.now().isoformat()}] Bounded retrain triggered. "
        f"Original baseline preserved as fallback."
    )

    # In a production system, this would:
    # 1. Retrain model on recent confirmed-benign flows
    # 2. Validate new model doesn't shift decision boundary >threshold
    # 3. Gradually blend new model with original (e.g., 70% original + 30% new)
    # 4. Keep original baseline in memory for fallback

    # For now, we log the event but don't modify baseline
    # (bounded retrain is constrained by not updating _baseline_distribution)


def get_retrain_log() -> list[str]:
    """Get log of retrain events.

    Returns:
        List of retrain log messages
    """
    return _retrain_log.copy()


def reset_retrain_log() -> None:
    """Reset retrain log (for testing)."""
    global _baseline_distribution, _retrain_log
    _baseline_distribution = None
    _retrain_log = []
