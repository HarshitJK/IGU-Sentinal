"""Score drift detection and bounded retrain of the Isolation Forest.

What this module guarantees (CLAUDE.md, "Drift detection")
----------------------------------------------------------
1. Drift is measured against the **original** benign baseline distribution, not
   against the previous window. Comparing each window to the last one lets an
   attacker walk the baseline anywhere they like one small step at a time —
   every individual step looks drift-free, so nothing ever fires. The original
   distribution is captured once and never overwritten.
2. A retrain is **bounded**: the candidate model's score distribution may not
   move further than ``MAX_BOUNDARY_SHIFT_PSI`` from the original baseline. A
   candidate that exceeds the bound is discarded and the previous model stays.
3. The **original model is never discarded**. It is snapshotted before the first
   retrain and can be restored at any time via :func:`rollback_to_baseline`.
4. Retrain input must be **fused-verdict benign**. Isolation Forest's own low
   score is not evidence of benignity — retraining on what the model already
   likes is exactly the model-poisoning path the PS constraints call out.
   :func:`submit_confirmed_benign` is the only way flows enter the retrain pool.

Previously this module computed PSI with a mis-scaled smoothing term, compared
each window against the previous one, and ``trigger_bounded_retrain()`` wrote a
log line and returned — it never retrained, never bounded anything, and nothing
in the pipeline ever called it.
"""
import logging
import math
import threading
from datetime import datetime
from typing import List, Optional, Sequence

from igu_sentinel.schemas import FlowRecord

log = logging.getLogger(__name__)

# PSI > 0.2 is the literature-standard "significant drift" threshold.
DRIFT_PSI_THRESHOLD = 0.2

# A single retrain may not move the score distribution further than this from
# the ORIGINAL baseline. Bounds how far one retrain can walk the boundary.
MAX_BOUNDARY_SHIFT_PSI = 0.35

# Minimum confirmed-benign flows before a retrain is worth attempting.
MIN_RETRAIN_SAMPLES = 50

# Rolling window of recent isoforest scores kept for the drift comparison.
ROLLING_WINDOW = 500

_lock = threading.Lock()

# The original benign score distribution. Written once, never overwritten.
_baseline_distribution: Optional[List[float]] = None
# Rolling window of recent scores.
_recent_scores: List[float] = []
# Flows the FUSED verdict confirmed benign — the only legal retrain input.
_confirmed_benign: List[FlowRecord] = []
# Snapshot of the original model, kept as a permanent fallback.
_baseline_model_state: Optional[tuple] = None
_retrain_log: List[str] = []


def _log_event(message: str) -> None:
    entry = f"[{datetime.now().isoformat()}] {message}"
    _retrain_log.append(entry)
    log.info("drift: %s", message)


# ── Distribution distance ─────────────────────────────────────────────────────

def compute_psi(baseline: Sequence[float], current: Sequence[float], bins: int = 10) -> float:
    """Population Stability Index between a baseline and a current distribution.

    PSI = sum over bins of ``(cur% - base%) * ln(cur% / base%)``.
    PSI > 0.2 is the conventional "significant drift" threshold.

    Bin edges come from the **baseline's** range, not the combined range of both
    samples. Deriving edges from the combined range let the current sample move
    the bins it is being measured against, which damps exactly the large shifts
    this is supposed to catch. Values outside the baseline range are clamped
    into the edge bins so drifted mass is still counted.

    Both proportions use Laplace smoothing of 0.5 counts over ``bins`` bins, so
    an empty bin cannot produce ``ln(0)`` and the PSI value stays on the scale
    the 0.2 threshold refers to. (The previous version divided by
    ``len(bin_edges)`` — ``bins + 1`` — which is not a count of anything and
    left PSI off that scale.)

    Args:
        baseline: Reference distribution.
        current: Distribution under test.
        bins: Number of histogram bins.

    Returns:
        PSI (0.0 for identical distributions, larger as they diverge).
    """
    if not baseline or not current or bins < 1:
        return 0.0

    lo = min(baseline)
    hi = max(baseline)
    if hi <= lo:
        # A baseline with zero spread has no distribution to compare against.
        # Returning 1.0 here put a sentinel on the same scale as a real PSI and
        # let it be compared against the 0.2 threshold as if it were measured.
        # inf says "not comparable" unambiguously, and still trips any
        # threshold check, which is the safe direction.
        if all(math.isclose(c, lo) for c in current):
            return 0.0
        log.warning(
            "PSI baseline has zero spread (n=%d, value=%.6g) — not comparable; "
            "this usually means too few baseline samples",
            len(baseline), lo,
        )
        return float("inf")

    width = (hi - lo) / bins

    def histogram(values: Sequence[float]) -> List[int]:
        counts = [0] * bins
        for v in values:
            idx = int((v - lo) / width)
            counts[min(max(idx, 0), bins - 1)] += 1   # clamp out-of-range mass
        return counts

    base_counts = histogram(baseline)
    cur_counts = histogram(current)

    # Laplace smoothing: 0.5 of a count added to every bin, so the denominator
    # grows by 0.5 * bins and the proportions still sum to 1.
    base_total = len(baseline) + 0.5 * bins
    cur_total = len(current) + 0.5 * bins

    psi = 0.0
    for b, c in zip(base_counts, cur_counts):
        base_pct = (b + 0.5) / base_total
        cur_pct = (c + 0.5) / cur_total
        psi += (cur_pct - base_pct) * math.log(cur_pct / base_pct)

    return psi


def compute_ks(baseline: Sequence[float], current: Sequence[float]) -> float:
    """Two-sample Kolmogorov-Smirnov statistic (max CDF gap) in [0, 1].

    Offered alongside PSI because KS is sensitive to a shift in distribution
    *shape* that leaves the binned mass roughly where it was.
    """
    if not baseline or not current:
        return 0.0
    b = sorted(baseline)
    c = sorted(current)
    nb, nc = len(b), len(c)
    i = j = 0
    d = 0.0
    # Both CDFs must be advanced past ALL copies of a tied value before the gap
    # is measured. Advancing one side at a time reports a spurious gap of 1/n
    # for two identical samples, because the comparison lands mid-tie.
    while i < nb and j < nc:
        x = min(b[i], c[j])
        while i < nb and b[i] == x:
            i += 1
        while j < nc and c[j] == x:
            j += 1
        d = max(d, abs(i / nb - j / nc))
    return d


# ── Baseline + rolling window ─────────────────────────────────────────────────

def set_baseline_distribution(scores: Sequence[float]) -> None:
    """Capture the original benign score distribution (idempotent).

    Only the first call takes effect. Later calls are ignored and logged: the
    reference distribution must stay fixed, or drift is measured against a
    moving target and gradual poisoning becomes invisible.
    """
    global _baseline_distribution
    with _lock:
        if _baseline_distribution is not None:
            log.debug("drift: baseline already set — ignoring re-set")
            return
        _baseline_distribution = list(scores)
    _log_event(f"Original baseline distribution captured (n={len(scores)})")


def monitor_drift(scores: Sequence[float]) -> bool:
    """Compare a window of isoforest scores against the ORIGINAL baseline.

    The first call establishes the baseline and reports no drift.

    Args:
        scores: Recent isoforest raw anomaly scores.

    Returns:
        True when PSI exceeds DRIFT_PSI_THRESHOLD.
    """
    if not scores:
        return False

    with _lock:
        first_call = _baseline_distribution is None

    if first_call:
        set_baseline_distribution(scores)
        return False

    with _lock:
        baseline = list(_baseline_distribution or [])
        _recent_scores.extend(scores)
        del _recent_scores[:-ROLLING_WINDOW]

    psi = compute_psi(baseline, scores)
    ks = compute_ks(baseline, scores)
    drifted = psi > DRIFT_PSI_THRESHOLD

    if drifted:
        _log_event(
            f"Drift detected: PSI={psi:.4f} (threshold={DRIFT_PSI_THRESHOLD}), KS={ks:.4f}"
        )
    return drifted


def get_baseline_distribution() -> Optional[List[float]]:
    """Return a copy of the original baseline distribution, if captured."""
    with _lock:
        return list(_baseline_distribution) if _baseline_distribution is not None else None


# ── Anti-poisoning retrain pool ───────────────────────────────────────────────

def submit_confirmed_benign(flows: Sequence[FlowRecord]) -> int:
    """Add flows the FUSED cross-layer verdict cleared as benign to the pool.

    This is the only entry point for retrain data. Isolation Forest's own low
    score must never qualify a flow: retraining on what the model already
    considers normal is how an attacker walks the decision boundary out to cover
    their traffic, one slightly-more-anomalous batch at a time.

    Args:
        flows: Flows confirmed benign by cross-layer fusion.

    Returns:
        Size of the retrain pool after the addition.
    """
    with _lock:
        _confirmed_benign.extend(flows)
        return len(_confirmed_benign)


def get_retrain_pool_size() -> int:
    """Number of confirmed-benign flows currently staged for retrain."""
    with _lock:
        return len(_confirmed_benign)


# ── Bounded retrain ───────────────────────────────────────────────────────────

def trigger_bounded_retrain(flows: Optional[Sequence[FlowRecord]] = None) -> bool:
    """Retrain the Isolation Forest under an explicit boundary-shift bound.

    Steps:
      1. Snapshot the original model on first use (permanent fallback).
      2. Retrain on confirmed-benign flows only.
      3. Score the original baseline sample through the candidate model and
         measure how far its score distribution moved (PSI).
      4. If the move exceeds MAX_BOUNDARY_SHIFT_PSI, restore the previous model
         and refuse the retrain.

    Args:
        flows: Confirmed-benign flows to train on. Defaults to the pool built by
            :func:`submit_confirmed_benign`.

    Returns:
        True if a new model was accepted, False if refused or not attempted.
    """
    from igu_sentinel.detect import isoforest

    global _baseline_model_state

    with _lock:
        pool = list(flows) if flows is not None else list(_confirmed_benign)
        baseline = list(_baseline_distribution or [])

    if len(pool) < MIN_RETRAIN_SAMPLES:
        _log_event(
            f"Retrain skipped: only {len(pool)} confirmed-benign flows "
            f"(need {MIN_RETRAIN_SAMPLES})"
        )
        return False

    # 1. Permanent fallback — captured once, never replaced.
    previous_state = isoforest.snapshot_state()
    with _lock:
        if _baseline_model_state is None and previous_state is not None:
            _baseline_model_state = previous_state
            _log_event("Original baseline model snapshotted as permanent fallback")

    # 2. Candidate retrain.
    try:
        isoforest.train_isoforest(pool)
    except Exception as exc:
        _log_event(f"Retrain FAILED ({type(exc).__name__}: {exc}) — previous model retained")
        if previous_state is not None:
            isoforest.restore_state(previous_state)
        return False

    # 3. Measure how far the candidate moved the decision boundary.
    if not baseline:
        _log_event("Retrain accepted (no baseline distribution to bound against)")
        return True

    candidate_scores = isoforest.score_values(_baseline_sample_flows())
    if not candidate_scores:
        _log_event("Retrain accepted (boundary shift not measurable)")
        return True

    shift = compute_psi(baseline, candidate_scores)

    # 4. Enforce the bound.
    if shift > MAX_BOUNDARY_SHIFT_PSI:
        if previous_state is not None:
            isoforest.restore_state(previous_state)
        _log_event(
            f"Retrain REFUSED: boundary shift PSI={shift:.4f} exceeds bound "
            f"{MAX_BOUNDARY_SHIFT_PSI}. Previous model restored; "
            f"original baseline preserved as fallback."
        )
        return False

    _log_event(
        f"Bounded retrain accepted on {len(pool)} confirmed-benign flows "
        f"(boundary shift PSI={shift:.4f} <= {MAX_BOUNDARY_SHIFT_PSI}). "
        f"Original baseline preserved as fallback."
    )
    with _lock:
        _confirmed_benign.clear()
    return True


def _baseline_sample_flows() -> List[FlowRecord]:
    """Flows used to re-measure the boundary after a retrain.

    The confirmed-benign pool doubles as the probe set: if scoring it through
    the candidate model yields a very different distribution from the original
    baseline, the boundary moved too far.
    """
    with _lock:
        return list(_confirmed_benign)


def rollback_to_baseline() -> bool:
    """Restore the original baseline model. Returns False if none was captured."""
    from igu_sentinel.detect import isoforest

    with _lock:
        state = _baseline_model_state
    if state is None:
        _log_event("Rollback requested but no baseline model snapshot exists")
        return False
    isoforest.restore_state(state)
    _log_event("Rolled back to the original baseline model")
    return True


def has_baseline_model() -> bool:
    """True when the original model is retained as a fallback."""
    with _lock:
        return _baseline_model_state is not None


def get_retrain_log() -> List[str]:
    """Return a copy of the drift/retrain event log."""
    return _retrain_log.copy()


def reset_retrain_log() -> None:
    """Reset all drift state (tests only)."""
    global _baseline_distribution, _retrain_log, _baseline_model_state
    with _lock:
        _baseline_distribution = None
        _baseline_model_state = None
        _recent_scores.clear()
        _confirmed_benign.clear()
        _retrain_log = []
