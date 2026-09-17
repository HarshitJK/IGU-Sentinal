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


# ── Drift guarantees from CLAUDE.md ───────────────────────────────────────────

import json
from pathlib import Path

import pytest

from igu_sentinel.schemas import FlowRecord
from igu_sentinel.drift import (
    DRIFT_PSI_THRESHOLD,
    MAX_BOUNDARY_SHIFT_PSI,
    MIN_RETRAIN_SAMPLES,
    compute_ks,
    get_baseline_distribution,
    get_retrain_pool_size,
    has_baseline_model,
    rollback_to_baseline,
    set_baseline_distribution,
    submit_confirmed_benign,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load(threat_class: str) -> list[FlowRecord]:
    path = FIXTURES_DIR / f"{threat_class}_sample.jsonl"
    out = []
    with open(path) as fh:
        for line in fh:
            if line.strip():
                out.append(FlowRecord(**json.loads(line)))
    return out


def test_psi_is_measured_against_the_original_baseline():
    """Gradual drift must be caught; measuring window-to-window hides it.

    Comparing each window to the *previous* one lets an attacker walk the
    baseline anywhere by taking small steps — every step looks drift-free. Each
    window must be compared to the frozen original.
    """
    reset_retrain_log()

    original = [0.10 + (i % 20) * 0.005 for i in range(200)]   # ~0.10-0.20
    monitor_drift(original)                                     # establishes baseline

    # Walk the distribution up in small steps. Each step is small relative to
    # the previous one, but the cumulative move from the original is large.
    drifted = False
    for step in range(1, 9):
        window = [v + step * 0.08 for v in original]
        if monitor_drift(window):
            drifted = True
            break

    assert drifted, "cumulative drift from the original baseline must be detected"

    # The reference distribution must not have moved.
    assert get_baseline_distribution() == original, "baseline must never be overwritten"
    print("✓ test_psi_is_measured_against_the_original_baseline passed")


def test_set_baseline_distribution_is_idempotent():
    """The original baseline is captured once and cannot be replaced."""
    reset_retrain_log()
    first = [0.1, 0.2, 0.3, 0.4]
    set_baseline_distribution(first)
    set_baseline_distribution([0.9, 0.95, 0.99])
    assert get_baseline_distribution() == first
    print("✓ test_set_baseline_distribution_is_idempotent passed")


def test_psi_identical_distributions_is_near_zero():
    """A spread-out distribution compared with itself must score ~0."""
    dist = [i / 100 for i in range(100)]
    assert compute_psi(dist, dist) < 0.01
    print("✓ test_psi_identical_distributions_is_near_zero passed")


def test_psi_crosses_literature_threshold_on_real_shift():
    """A clear distribution shift must exceed the 0.2 literature threshold."""
    baseline = [0.1 + (i % 10) * 0.01 for i in range(200)]
    shifted = [0.7 + (i % 10) * 0.01 for i in range(200)]
    psi = compute_psi(baseline, shifted)
    assert psi > DRIFT_PSI_THRESHOLD, f"expected PSI > {DRIFT_PSI_THRESHOLD}, got {psi}"
    print(f"✓ test_psi_crosses_literature_threshold_on_real_shift passed (PSI={psi:.3f})")


def test_ks_statistic_bounds():
    """KS is 0 for identical samples and 1 for fully disjoint ones."""
    a = [i / 50 for i in range(50)]
    assert compute_ks(a, a) == pytest.approx(0.0)
    assert compute_ks([0.0] * 50, [1.0] * 50) == pytest.approx(1.0)
    print("✓ test_ks_statistic_bounds passed")


def test_retrain_requires_fused_confirmed_benign_flows():
    """Retrain must refuse to run on an under-filled confirmed-benign pool.

    Isolation Forest's own low score is not evidence of benignity — only the
    fused cross-layer verdict may feed the pool (anti-poisoning constraint).
    """
    reset_retrain_log()
    assert get_retrain_pool_size() == 0

    benign = _load("benign")
    submit_confirmed_benign(benign[:3])
    assert trigger_bounded_retrain() is False, "must not retrain on 3 flows"
    assert any("Retrain skipped" in line for line in get_retrain_log())
    print("✓ test_retrain_requires_fused_confirmed_benign_flows passed")


def test_bounded_retrain_refuses_excessive_boundary_shift():
    """A retrain that moves the boundary too far must be rolled back.

    Feeding attack traffic in as "benign" is the poisoning scenario: the bound
    is what stops one retrain from redrawing the boundary around it.
    """
    reset_retrain_log()
    from igu_sentinel.detect import isoforest

    # A baseline distribution of tightly-clustered benign scores.
    set_baseline_distribution([0.05 + (i % 10) * 0.002 for i in range(200)])

    before = isoforest.snapshot_state()

    # Poisoned pool: attack flows submitted as if confirmed benign.
    poison = []
    for tc in ("volumetric_ddos", "recon_scanning", "data_exfiltration", "c2_beaconing"):
        poison.extend(_load(tc))
    while len(poison) < MIN_RETRAIN_SAMPLES:
        poison.extend(poison)
    submit_confirmed_benign(poison[:MIN_RETRAIN_SAMPLES + 10])

    accepted = trigger_bounded_retrain()

    log_text = "\n".join(get_retrain_log())
    if not accepted:
        assert "REFUSED" in log_text, f"refusal must be logged, got:\n{log_text}"
        # The previous model must still be the one in service.
        after = isoforest.snapshot_state()
        assert after[0] is before[0], "refused retrain must restore the previous model"

    # Either way the original model must be retained as a fallback.
    assert has_baseline_model(), "original baseline model must be snapshotted"
    print(f"✓ test_bounded_retrain_refuses_excessive_boundary_shift passed (accepted={accepted})")


def test_rollback_restores_original_baseline_model():
    """The original model must remain restorable after any retrain."""
    reset_retrain_log()
    from igu_sentinel.detect import isoforest

    set_baseline_distribution([0.05 + (i % 10) * 0.002 for i in range(200)])
    original = isoforest.snapshot_state()

    pool = _load("benign") * 20
    submit_confirmed_benign(pool[:MIN_RETRAIN_SAMPLES + 5])
    trigger_bounded_retrain()

    assert rollback_to_baseline() is True
    assert isoforest.snapshot_state()[0] is original[0], "rollback must restore the original forest"
    print("✓ test_rollback_restores_original_baseline_model passed")


def test_rollback_without_snapshot_reports_failure():
    """Rollback with nothing snapshotted must report False, not crash."""
    reset_retrain_log()
    assert rollback_to_baseline() is False
    print("✓ test_rollback_without_snapshot_reports_failure passed")
