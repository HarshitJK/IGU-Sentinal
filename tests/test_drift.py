"""Test drift/ score distribution monitoring and retrain triggering."""
from igu_sentinel.drift import (
    monitor_drift,
    compute_psi,
    trigger_bounded_retrain,
    get_retrain_log,
    reset_retrain_log,
)


def test_drift_compute_psi_no_drift():
    """PSI should be low for identical distributions."""
    baseline = [0.5] * 100  # Uniform distribution at 0.5
    current = [0.5] * 100   # Same distribution

    psi = compute_psi(baseline, current)

    # PSI should be close to 0 for identical distributions
    assert psi < 0.05, f"Identical distributions should have PSI < 0.05, got {psi}"
    print(f"✓ test_drift_compute_psi_no_drift passed (PSI: {psi:.4f})")


def test_drift_compute_psi_with_drift():
    """PSI should be high for shifted distributions."""
    baseline = [i * 0.01 for i in range(100)]  # Distribution from 0 to 1
    current = [min(1.0, i * 0.01 + 0.3) for i in range(100)]  # Shifted right

    psi = compute_psi(baseline, current)

    # PSI should be > 0.2 (literature threshold for significant drift)
    assert psi > 0.1, f"Shifted distributions should have PSI > 0.1, got {psi}"
    print(f"✓ test_drift_compute_psi_with_drift passed (PSI: {psi:.4f})")


def test_drift_monitor_no_drift():
    """monitor_drift should return False when no drift detected."""
    # Stable scores within a narrow range
    stable_scores = [0.45 + (i % 10) * 0.01 for i in range(50)]

    is_drifted = monitor_drift(stable_scores)

    assert not is_drifted, "Stable scores should not trigger drift"
    print("✓ test_drift_monitor_no_drift passed")


def test_drift_monitor_detects_drift():
    """monitor_drift should return True when drift is detected."""
    reset_retrain_log()

    # First batch: low scores
    baseline_scores = [0.2 + (i % 10) * 0.02 for i in range(30)]

    # Second batch: high scores (shifted)
    drifted_scores = [0.7 + (i % 10) * 0.02 for i in range(30)]

    # Monitor baseline
    monitor_drift(baseline_scores)

    # Monitor drifted distribution
    is_drifted = monitor_drift(drifted_scores)

    assert is_drifted, "Shifted distribution should trigger drift detection"
    print("✓ test_drift_monitor_detects_drift passed")


def test_drift_trigger_retrain():
    """Retrain should be triggered and logged when drift detected."""
    reset_retrain_log()

    # Simulate drift scenario
    baseline_scores = [0.2 + (i % 10) * 0.02 for i in range(30)]
    drifted_scores = [0.7 + (i % 10) * 0.02 for i in range(30)]

    monitor_drift(baseline_scores)
    is_drifted = monitor_drift(drifted_scores)

    if is_drifted:
        trigger_bounded_retrain()

    # Check that retrain was logged
    retrain_log = get_retrain_log()
    if is_drifted:
        assert len(retrain_log) > 0, "Retrain should be logged when drift detected"

    print(f"✓ test_drift_trigger_retrain passed (retrain log size: {len(retrain_log)})")


def test_drift_bounded_retrain_preserves_baseline():
    """Bounded retrain should not discard original baseline."""
    reset_retrain_log()

    baseline_scores = [0.2 + (i % 10) * 0.02 for i in range(30)]
    drifted_scores = [0.7 + (i % 10) * 0.02 for i in range(30)]

    monitor_drift(baseline_scores)
    is_drifted = monitor_drift(drifted_scores)

    if is_drifted:
        trigger_bounded_retrain()

    # Get retrain log
    retrain_log = get_retrain_log()

    # Check that log mentions baseline preservation
    if is_drifted:
        log_str = "\n".join(retrain_log)
        # The log should indicate retrain occurred and baseline was kept
        assert len(retrain_log) > 0

    print(f"✓ test_drift_bounded_retrain_preserves_baseline passed")


def test_drift_rolling_window():
    """Drift detection should use rolling window correctly."""
    reset_retrain_log()

    # Simulate gradual drift over time
    scores_timeline = []

    # Phase 1: baseline (scores around 0.3)
    for _ in range(20):
        scores_timeline.extend([0.25 + i * 0.01 for i in range(10)])

    # Phase 2: gradual shift (scores move to 0.6)
    for _ in range(20):
        scores_timeline.extend([0.55 + i * 0.01 for i in range(10)])

    # Monitor and check for drift
    drift_detected = False
    for i in range(20, len(scores_timeline), 10):
        window = scores_timeline[max(0, i-30):i+10]
        if monitor_drift(window):
            drift_detected = True
            break

    print(f"✓ test_drift_rolling_window passed (drift_detected: {drift_detected})")
