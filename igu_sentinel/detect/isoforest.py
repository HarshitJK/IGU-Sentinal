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

import math
import logging
from pathlib import Path
from typing import Optional

from igu_sentinel.schemas import FlowRecord, LayerScore
from igu_sentinel.detect.features import extract_features, FEATURE_DIM

log = logging.getLogger(__name__)

# ── model storage ────────────────────────────────────────────────────────────
_MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
_MODEL_STEM = "isoforest_v"

# ── in-memory state ──────────────────────────────────────────────────────────
_model = None           # sklearn IsolationForest instance (or None)
_scaler = None          # sklearn StandardScaler fitted on benign training data
_platt_a: float = 5.0  # logistic steepness for calibration
_platt_b: float = 0.0  # logistic midpoint for calibration (set during training)

# ── Platt calibration constants ──────────────────────────────────────────────
# decision_function() returns negative scores for anomalies (more negative =
# more anomalous).  We negate so "more anomalous → higher value", then scale
# to [0, 1] with a Platt sigmoid tuned at training time.
_DF_SCALE: float = 1.0   # updated at training time from empirical range


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


def _latest_model_path() -> Optional[Path]:
    """Return path to the highest-numbered saved model, or None."""
    existing = _model_files()
    return existing[-1] if existing else None


def _load_model_from_disk() -> bool:
    """Try to load the latest persisted model; return True on success."""
    global _model, _scaler, _platt_b, _DF_SCALE
    path = _latest_model_path()
    if path is None:
        return False
    try:
        import joblib
        bundle = joblib.load(path)
        _model = bundle["model"]
        _scaler = bundle["scaler"]
        _platt_b = bundle.get("platt_b", 0.0)
        _DF_SCALE = bundle.get("df_scale", 1.0)
        log.info("isoforest: loaded %s", path.name)
        return True
    except Exception as exc:
        log.warning("isoforest: could not load %s: %s", path, exc)
        return False


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
    global _model, _scaler, _platt_b, _DF_SCALE

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

    # Hot-swap in memory.
    _model = model
    _scaler = scaler
    _platt_b = platt_b
    _DF_SCALE = df_scale


def score_isoforest(flow: FlowRecord) -> LayerScore:
    """Score a flow with the trained IsolationForest.

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
    global _model, _scaler

    # Lazy load attempt if module was imported before training ran.
    if _model is None:
        if not _load_model_from_disk():
            raise RuntimeError(
                "IsolationForest model not available. "
                "Call train_isoforest() or run train_models.py first."
            )

    try:
        import numpy as np
    except ImportError as exc:
        raise ImportError("numpy required for scoring: pip install numpy") from exc

    feat = np.array([extract_features(flow)], dtype=float)
    feat_scaled = _scaler.transform(feat)

    # decision_function: positive = inlier, negative = outlier.
    df = float(_model.decision_function(feat_scaled)[0])

    # Map to [0, 1]: more negative → more anomalous → higher raw_score.
    neg_df = -df
    raw_score = float(np.clip((neg_df / _DF_SCALE + 1.0) / 2.0, 0.0, 1.0))

    # Platt sigmoid calibration (midpoint tuned to benign training distribution).
    try:
        calibrated = 1.0 / (1.0 + math.exp(-_platt_a * (raw_score - _platt_b)))
    except OverflowError:
        calibrated = 1.0 if raw_score > _platt_b else 0.0

    calibrated = float(max(0.0, min(1.0, calibrated)))

    evidence = []
    if raw_score > 0.6:
        evidence.append(f"isoforest_anomaly_score={raw_score:.3f}")
    if raw_score > 0.8:
        evidence.append("high_anomaly_confidence")

    return LayerScore(
        flow_id=flow.flow_id,
        layer_name="isoforest",
        raw_score=raw_score,
        calibrated_probability=calibrated,
        threat_class_guess=None,  # unsupervised — no class label
        evidence=evidence if evidence else None,
    )
