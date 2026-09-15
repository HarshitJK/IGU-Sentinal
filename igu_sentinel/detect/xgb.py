"""XGBoost multi-class threat classifier.

Uses xgboost.XGBClassifier with objective="multi:softprob" over 7 classes:
  benign + 6 PS-mandated threat classes.

Score semantics (must be consistent with what fusion/ expects):
  raw_score              : max probability across the 6 *threat* classes [0, 1]
                           (i.e. 1 − P(benign), approximately)
  calibrated_probability : same as raw_score (softprob output IS already a
                           calibrated probability; no Platt-scaling needed on top)
  threat_class_guess     : argmax threat class, or None when benign wins

Model lifecycle:
  - Loaded once at module import (lazy: only if file exists in models/).
  - train_xgb() saves a new versioned JSON file and hot-swaps in memory.
"""

import logging
from pathlib import Path
from typing import Optional, List

from igu_sentinel.schemas import FlowRecord, LayerScore
from igu_sentinel.detect.features import extract_features, FEATURE_DIM

log = logging.getLogger(__name__)

# ── constants ────────────────────────────────────────────────────────────────
THREAT_CLASSES: List[str] = [
    "benign",
    "volumetric_ddos",
    "c2_beaconing",
    "dga_dns_tunneling",
    "encrypted_malware",
    "recon_scanning",
    "data_exfiltration",
]
VALID_THREAT_CLASSES = set(THREAT_CLASSES) - {"benign"}

# ── model storage ────────────────────────────────────────────────────────────
_MODELS_DIR = Path(__file__).resolve().parents[2] / "models"
_MODEL_STEM = "xgb_v"

# ── in-memory state ──────────────────────────────────────────────────────────
_model = None            # XGBClassifier instance (or None)
_label_encoder = None    # maps int indices ↔ class name strings


def _model_files() -> List[Path]:
    """Return all valid saved model paths sorted by version number."""
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in _MODELS_DIR.glob(f"{_MODEL_STEM}*.json"):
        if p.name.endswith(".labels.json"):
            continue
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
    last = existing[-1].stem
    try:
        return int(last.replace(_MODEL_STEM, "")) + 1
    except ValueError:
        return len(existing) + 1


def _latest_model_path() -> Optional[Path]:
    """Return path to the highest-numbered saved model JSON, or None."""
    existing = _model_files()
    return existing[-1] if existing else None


def _load_model_from_disk() -> bool:
    """Try to load latest persisted XGB model + label map; return True on success."""
    global _model, _label_encoder
    model_path = _latest_model_path()
    if model_path is None:
        return False
    # Companion label-map lives next to the model JSON.
    label_path = model_path.with_suffix(".labels.json")
    try:
        import xgboost as xgb
        import json as _json

        model = xgb.XGBClassifier()
        model.load_model(str(model_path))
        if label_path.exists():
            with open(label_path) as fh:
                _label_encoder = _json.load(fh)
        else:
            _label_encoder = {i: c for i, c in enumerate(THREAT_CLASSES)}
        _model = model
        log.info("xgb: loaded %s", model_path.name)
        return True
    except Exception as exc:
        log.warning("xgb: could not load %s: %s", model_path, exc)
        return False


# Attempt to load persisted model at import time (warm-start on service boot).
_load_model_from_disk()


# ── public API ────────────────────────────────────────────────────────────────

def train_xgb(flows: list[FlowRecord], labels: list[str]) -> None:
    """Train XGBClassifier on labeled flows and persist model to disk.

    Args:
        flows:  List of FlowRecords (any mix of classes including benign).
        labels: Parallel list of class strings from THREAT_CLASSES.

    Raises:
        ValueError: If inputs are inconsistent.
        ImportError: If xgboost or numpy are not installed.
    """
    global _model, _label_encoder

    if len(flows) != len(labels):
        raise ValueError("flows and labels must have equal length.")
    if not flows:
        raise ValueError("Must provide at least one flow.")

    try:
        import xgboost as xgb
        import numpy as np
        import json as _json
    except ImportError as exc:
        raise ImportError(
            "xgboost and numpy are required. "
            f"Install with: pip install xgboost  ({exc})"
        ) from exc

    # Build label encoder: stable ordering so saved model indices are reproducible.
    present_classes = sorted(set(labels))
    # Always put benign first so class 0 = benign across all versions.
    ordered = ["benign"] + [c for c in THREAT_CLASSES if c != "benign" and c in present_classes]
    for c in present_classes:
        if c not in ordered:
            ordered.append(c)
    label_to_int = {c: i for i, c in enumerate(ordered)}
    int_to_label = {i: c for c, i in label_to_int.items()}

    X = np.array([extract_features(f) for f in flows], dtype=float)
    y = np.array([label_to_int[lb] for lb in labels], dtype=int)

    num_classes = len(ordered)

    # Class weights: benign is over-represented; weight each class inversely
    # proportional to its frequency.
    from collections import Counter
    counts = Counter(y)
    n_total = len(y)
    sample_weight = np.array(
        [n_total / (num_classes * counts[yi]) for yi in y], dtype=float
    )

    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=num_classes,
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(X, y, sample_weight=sample_weight)

    # Persist model (versioned JSON — XGBoost native format).
    version = _next_version()
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model_path = _MODELS_DIR / f"{_MODEL_STEM}{version}.json"
    label_path = model_path.with_suffix(".labels.json")

    model.save_model(str(model_path))
    with open(label_path, "w") as fh:
        _json.dump(int_to_label, fh)

    log.info("xgb: saved %s (classes=%s, n=%d)", model_path.name, ordered, len(flows))

    # Hot-swap in memory.
    _model = model
    _label_encoder = int_to_label


def predict_xgb(flow: FlowRecord) -> LayerScore:
    """Classify a flow using the trained XGBClassifier.

    Args:
        flow: FlowRecord to evaluate.

    Returns:
        LayerScore:
          raw_score              max probability across the 6 threat classes
          calibrated_probability same as raw_score (softprob is already calibrated)
          threat_class_guess     predicted class, or None if benign wins
          evidence               top-2 candidate classes with probabilities

    Raises:
        RuntimeError: If no model has been trained or loaded.
    """
    global _model, _label_encoder

    if _model is None:
        if not _load_model_from_disk():
            raise RuntimeError(
                "XGBoost model not available. "
                "Call train_xgb() or run train_models.py first."
            )

    try:
        import numpy as np
    except ImportError as exc:
        raise ImportError("numpy required for scoring: pip install numpy") from exc

    X = np.array([extract_features(flow)], dtype=float)
    proba = _model.predict_proba(X)[0]  # shape: (num_classes,)

    # Build class→probability map.
    class_probs = {
        _label_encoder[str(i)] if str(i) in _label_encoder else _label_encoder.get(i, f"class_{i}"): float(p)
        for i, p in enumerate(proba)
    }

    # Separate benign probability from threat class probabilities.
    benign_prob = class_probs.get("benign", 0.0)
    threat_probs = {k: v for k, v in class_probs.items() if k != "benign"}

    # The "threat score" is the total probability NOT assigned to benign.
    raw_score = float(1.0 - benign_prob)
    raw_score = max(0.0, min(1.0, raw_score))

    # Predicted threat class: argmax over threat classes.
    if threat_probs:
        best_threat = max(threat_probs, key=lambda k: threat_probs[k])
        best_threat_prob = threat_probs[best_threat]
    else:
        best_threat = None
        best_threat_prob = 0.0

    # Only emit a threat_class_guess when the model positively prefers a
    # threat class over benign (i.e. benign is not the winner).
    threat_class_guess = best_threat if benign_prob < 0.5 else None

    # Evidence: top-2 classes for interpretability.
    sorted_classes = sorted(class_probs.items(), key=lambda kv: kv[1], reverse=True)
    evidence = [f"{cls}={prob:.3f}" for cls, prob in sorted_classes[:2]]

    return LayerScore(
        flow_id=flow.flow_id,
        layer_name="xgb",
        raw_score=raw_score,
        calibrated_probability=raw_score,  # softprob already calibrated
        threat_class_guess=threat_class_guess,
        evidence=evidence,
    )
