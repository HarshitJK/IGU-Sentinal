"""Isolation Forest unsupervised anomaly detector (benign-only trained).

Uses sklearn.ensemble.IsolationForest:
- train_isoforest(flows): fits on benign-only FlowRecords; persists to
  models/isoforest_v{n}.pkl via joblib.
- score_isoforest(flow): uses decision_function() output converted to a
  calibrated probability consistent with what fusion expects.

Score semantics (important — do not change without updating fusion thresholds):
  raw_score          : float in [0, 1], 0=benign, 1=maximally anomalous
  calibrated_probability: Platt-scaled from raw_score → [0, 1]
    fusion uses calibrated_probability directly; it does NOT re-calibrate.

Model lifecycle:
  - Loaded once at module import (lazy: only if file exists).
  - train_isoforest() saves a new versioned file and hot-swaps in memory.
  - drift/ module calls train_isoforest() for bounded retrains; it inherits
    the version-bump guarantee so the original file is never overwritten.
"""

import hmac
import math
import logging
import threading
from pathlib import Path
from typing import Optional

from igu_sentinel.schemas import FlowRecord, LayerScore
from igu_sentinel.detect.features import extract_features, FEATURE_DIM

log = logging.getLogger(__name__)

# ── model storage ────────────────────────────────────────────────────────────
_MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
_MODEL_STEM = "isoforest_v"

# ── in-memory state ──────────────────────────────────────────────────────────
# The four pieces of scoring state (model, scaler, platt midpoint, df scale) are
# only meaningful TOGETHER: a scaler fitted for one forest produces garbage for
# another. They were separate module globals, so a retrain could swap the model
# in between a scorer reading _scaler and reading _model — a torn read that
# silently corrupts every score until the next swap. They now live in one
# immutable tuple rebound under a lock, which is what makes the "atomic swap"
# claim in CLAUDE.md actually true.
_state_lock = threading.Lock()
_state: Optional[tuple] = None   # (model, scaler, platt_b, df_scale)
_platt_a: float = 5.0            # logistic steepness for calibration

# ── Platt calibration notes ──────────────────────────────────────────────────
# decision_function() returns negative scores for anomalies (more negative =
# more anomalous).  We negate so "more anomalous → higher value", then scale
# to [0, 1] with a Platt sigmoid tuned at training time. The scale factor and
# midpoint travel inside _state so they can never drift apart from the model
# they were fitted for.


def _model_files() -> list[Path]:
    """Return all valid saved model paths sorted by version number."""
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in _MODELS_DIR.glob(f"{_MODEL_STEM}*.pkl"):
        try:
            ver = int(p.stem.replace(_MODEL_STEM, ""))
            items.append((ver, p))
        except ValueError:
            continue
    items.sort(key=lambda x: x[0])
    return [p for _, p in items]


def _next_version() -> int:
    """Return the next unused version number for saved models."""
    existing = _model_files()
    if not existing:
        return 1
    last = existing[-1].stem  # e.g. "isoforest_v3"
    try:
        return int(last.replace(_MODEL_STEM, "")) + 1
    except ValueError:
        return len(existing) + 1


_CURRENT_POINTER = "CURRENT"
_MANIFEST = "MANIFEST.json"


def _pinned_model_name(key: str) -> Optional[str]:
    """Read the artifact name pinned for ``key`` in models/CURRENT, if present.

    Format is one ``key = filename`` per line; ``#`` starts a comment.
    """
    pointer = _MODELS_DIR / _CURRENT_POINTER
    if not pointer.exists():
        return None
    try:
        for line in pointer.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            name, _, value = line.partition("=")
            if name.strip() == key:
                return value.strip() or None
    except OSError as exc:
        log.warning("could not read %s: %s", pointer, exc)
    return None


def verify_artifact(path: Path) -> bool:
    """Check ``path`` against models/MANIFEST.json before it is deserialized.

    joblib.load() unpickles, which executes arbitrary code — so models/ is a
    trust boundary equivalent to executable code, and "the highest version
    number wins" was an invitation to drop in an isoforest_v999.pkl. When a
    manifest exists, an artifact missing from it (or whose digest does not
    match) is refused.

    No manifest means no enforcement, which keeps a fresh checkout working;
    train_models.py writes one, and a deployment should ship it.
    """
    manifest_path = _MODELS_DIR / _MANIFEST
    if not manifest_path.exists():
        log.debug("no %s — artifact digests not enforced", _MANIFEST)
        return True
    try:
        import json as _json
        expected = _json.loads(manifest_path.read_text()).get(path.name)
    except (OSError, ValueError) as exc:
        log.error("could not read %s (%s) — refusing to load %s", _MANIFEST, exc, path.name)
        return False
    if not expected:
        log.error("%s is not listed in %s — refusing to load", path.name, _MANIFEST)
        return False
    import hashlib as _hashlib
    actual = _hashlib.sha256(path.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, expected):
        log.error("%s digest mismatch — refusing to load (expected %s, got %s)",
                  path.name, expected[:16], actual[:16])
        return False
    return True


def _latest_model_path() -> Optional[Path]:
    """Return the artifact to serve: the pinned one, else highest version.

    Pinning matters: the highest-version rule silently served a degraded
    5-class XGBoost model for isoforest's counterpart, and nothing declared
    which artifact was intended.
    """
    pinned = _pinned_model_name("isoforest")
    if pinned:
        candidate = _MODELS_DIR / pinned
        if candidate.exists() and candidate.resolve().parent == _MODELS_DIR.resolve():
            return candidate
        log.error("models/CURRENT pins %r which is missing — falling back", pinned)
    existing = _model_files()
    return existing[-1] if existing else None


_REQUIRED_BUNDLE_KEYS = {"model", "scaler"}


def _load_model_from_disk() -> bool:
    """Try to load the latest persisted model; return True on success.

    Security note: joblib.load() unpickles, which executes arbitrary code from
    the artifact. The models/ directory is therefore a trust boundary — treat it
    like executable code, not data. We at minimum refuse to load anything from
    outside _MODELS_DIR (so a traversal-style version name cannot redirect the
    load) and validate the bundle's shape before adopting it, so a truncated or
    foreign artifact fails loudly here instead of producing nonsense scores.
    """
    path = _latest_model_path()
    if path is None:
        return False
    try:
        resolved = path.resolve()
        if resolved.parent != _MODELS_DIR.resolve():
            log.error("isoforest: refusing to load model outside models/: %s", resolved)
            return False
        if not verify_artifact(resolved):
            return False
        import joblib
        bundle = joblib.load(resolved)
        if not isinstance(bundle, dict) or not _REQUIRED_BUNDLE_KEYS <= bundle.keys():
            log.error("isoforest: %s is not a valid model bundle", path.name)
            return False
        dim = bundle.get("feature_dim")
        if dim is not None and int(dim) != FEATURE_DIM:
            log.error(
                "isoforest: %s was trained on %s features but this build extracts %d "
                "— refusing to load (scores would be meaningless)",
                path.name, dim, FEATURE_DIM,
            )
            return False
        _swap_state(
            bundle["model"],
            bundle["scaler"],
            float(bundle.get("platt_b", 0.0)),
            float(bundle.get("df_scale", 1.0)),
        )
        log.info("isoforest: loaded %s", path.name)
        return True
    except Exception as exc:
        log.warning("isoforest: could not load %s: %s", path, exc)
        return False


def _swap_state(model, scaler, platt_b: float, df_scale: float) -> None:
    """Atomically install a new (model, scaler, calibration) set."""
    global _state
    with _state_lock:
        _state = (model, scaler, platt_b, df_scale)


def _current_state() -> Optional[tuple]:
    """Read the active scoring state as one consistent snapshot."""
    with _state_lock:
        return _state


# Attempt to load persisted model at import time (warm-start on service boot).
_load_model_from_disk()


# ── public API ────────────────────────────────────────────────────────────────

def train_isoforest(benign_flows: list[FlowRecord]) -> None:
    """Fit IsolationForest on benign-only flows and persist model to disk.

    Args:
        benign_flows: List of FlowRecords confirmed benign (from fused verdict,
            not self-assessed by isoforest alone — see CLAUDE.md anti-poisoning
            constraint).

    Raises:
        ValueError: If benign_flows is empty.
        ImportError: If scikit-learn or joblib are not installed.
    """
    if not benign_flows:
        raise ValueError("Must provide at least one benign flow to train on.")

    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import joblib
        import numpy as np
    except ImportError as exc:
        raise ImportError(
            "scikit-learn and joblib are required for real IsolationForest. "
            f"Install with: pip install scikit-learn joblib  ({exc})"
        ) from exc

    X = np.array([extract_features(f) for f in benign_flows], dtype=float)

    # Standardise features so all dimensions contribute equally.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # n_estimators=200 gives stable scores even on small training sets;
    # contamination=0.05 → IsoForest treats ~5% of training as anomalous
    # (benign fixture may still contain mildly unusual flows).
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    # Calibrate the Platt sigmoid midpoint using the benign training distribution.
    # decision_function > 0 → inlier, < 0 → outlier.
    df_scores = model.decision_function(X_scaled)   # shape (n,)
    # Negate so "more anomalous = larger positive value"
    neg_scores = -df_scores
    df_scale = float(max(abs(neg_scores.max()), abs(neg_scores.min()), 1e-6))
    raw_benign = np.clip((neg_scores / df_scale + 1.0) / 2.0, 0.0, 1.0)
    # 95th percentile of benign distribution: scores above this indicate true anomalies
    platt_b = float(np.percentile(raw_benign, 95))

    # Persist (versioned — never overwrites previous).
    version = _next_version()
    save_path = _MODELS_DIR / f"{_MODEL_STEM}{version}.pkl"
    bundle = {
        "model": model,
        "scaler": scaler,
        "platt_b": platt_b,
        "df_scale": df_scale,
        "n_train": len(benign_flows),
        "feature_dim": FEATURE_DIM,
    }
    joblib.dump(bundle, save_path)
    log.info("isoforest: saved %s (trained on %d flows)", save_path.name, len(benign_flows))

    # Hot-swap in memory as one atomic rebind — see _state.
    _swap_state(model, scaler, platt_b, df_scale)


def score_isoforest_batch(flows: list[FlowRecord]) -> list[LayerScore]:
    """Score a batch of flows in a single model call.

    Why this exists: sklearn's ``decision_function`` carries a fixed per-call
    cost (input validation, tree-ensemble dispatch, and with ``n_jobs=-1`` a
    thread hand-off) that dwarfs the work of scoring one 16-feature row. Measured
    on the fixture corpus, scoring one flow at a time runs at ~146 flows/sec —
    6.8 ms per flow — and was the single bottleneck of the whole pipeline, which
    topped out around 130 flows/sec end to end. The same rows scored as one
    matrix run at ~14,000 flows/sec, a ~97x improvement, because the per-call
    cost is paid once for the window instead of once per flow.

    The pipeline is already batched by construction — one fixed 120ms capture
    window yields one batch — so this is the natural shape for the hot path.
    :func:`score_isoforest` remains the per-flow contract from CLAUDE.md and is
    now implemented in terms of this function.

    Args:
        flows: FlowRecords to evaluate.

    Returns:
        One LayerScore per input flow, in the same order.

    Raises:
        RuntimeError: If no model has been trained or loaded.
    """
    if not flows:
        return []

    state = _current_state()
    if state is None:
        if not _load_model_from_disk():
            raise RuntimeError(
                "IsolationForest model not available. "
                "Call train_isoforest() or run train_models.py first."
            )
        state = _current_state()

    model, scaler, platt_b, df_scale = state

    try:
        import numpy as np
    except ImportError as exc:
        raise ImportError("numpy required for scoring: pip install numpy") from exc

    feats = np.array([extract_features(f) for f in flows], dtype=float)
    dfs = model.decision_function(scaler.transform(feats))
    raw_scores = np.clip((-dfs / df_scale + 1.0) / 2.0, 0.0, 1.0)

    results: list[LayerScore] = []
    for flow, raw in zip(flows, raw_scores):
        raw_score = float(raw)
        try:
            calibrated = 1.0 / (1.0 + math.exp(-_platt_a * (raw_score - platt_b)))
        except OverflowError:
            calibrated = 1.0 if raw_score > platt_b else 0.0
        calibrated = float(max(0.0, min(1.0, calibrated)))

        evidence = []
        if raw_score > 0.6:
            evidence.append(f"isoforest_anomaly_score={raw_score:.3f}")
        if raw_score > 0.8:
            evidence.append("high_anomaly_confidence")

        results.append(
            LayerScore(
                flow_id=flow.flow_id,
                layer_name="isoforest",
                raw_score=raw_score,
                calibrated_probability=calibrated,
                threat_class_guess=None,  # unsupervised — no class label
                evidence=evidence if evidence else None,
            )
        )
    return results


def score_isoforest(flow: FlowRecord) -> LayerScore:
    """Score a flow with the trained IsolationForest.

    This is the per-flow contract from CLAUDE.md (FlowRecord -> LayerScore).
    It delegates to :func:`score_isoforest_batch`, so there is exactly one
    scoring implementation. Prefer the batch form on the hot path: the per-call
    model overhead is what limits pipeline throughput.

    Args:
        flow: FlowRecord to evaluate.

    Returns:
        LayerScore:
          raw_score              float in [0, 1] (0=benign, 1=anomalous)
          calibrated_probability Platt-sigmoid of raw_score → [0, 1]
          threat_class_guess     always None (unsupervised — no class labels)
          evidence               human-readable anomaly indication

    Raises:
        RuntimeError: If no model has been trained or loaded.
    """
    return score_isoforest_batch([flow])[0]


# ── Model lifecycle hooks used by drift/ ──────────────────────────────────────

def snapshot_state() -> Optional[tuple]:
    """Return the current scoring state so it can be restored later.

    drift/ uses this to keep the ORIGINAL benign-trained model as a permanent
    fallback (CLAUDE.md: "Never discard the original baseline model") and to roll
    back a retrain whose decision-boundary shift exceeded the allowed bound.
    """
    return _current_state()


def restore_state(state: tuple) -> None:
    """Reinstall a previously snapshotted scoring state atomically.

    Note this restores the in-memory model only; the versioned artifacts under
    models/ are never overwritten, so the on-disk history stays intact.
    """
    if not state or len(state) != 4:
        raise ValueError("state must be a 4-tuple from snapshot_state()")
    _swap_state(*state)


def score_values(flows: list[FlowRecord]) -> list[float]:
    """Return raw anomaly scores for a batch, without building LayerScores.

    drift/ compares score *distributions*, so it needs the numbers rather than
    the per-flow detection records.
    """
    return [score_isoforest(f).raw_score for f in flows]
