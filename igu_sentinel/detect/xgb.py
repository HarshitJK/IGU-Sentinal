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
import threading
from pathlib import Path
from typing import Optional, List

from igu_sentinel.schemas import FlowRecord, LayerScore
from igu_sentinel.detect.features import extract_features, FEATURE_DIM
# Shared with isoforest so there is one definition of how an artifact is
# pinned and how its digest is checked.
from igu_sentinel.detect.isoforest import _pinned_model_name, verify_artifact

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
# Model and label map are only meaningful as a pair — a model swapped in while
# the previous label map is still installed mislabels every prediction. They are
# rebound together under a lock (see isoforest for the same reasoning).
_state_lock = threading.Lock()
_state: Optional[tuple] = None   # (model, label_encoder)


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
    """Return the artifact to serve: the one pinned in models/CURRENT, else
    the highest version.

    The highest-version rule is what caused the worst defect found in this
    codebase: xgb_v14.json, a degraded 5-class model written by a test run,
    outranked the healthy 7-class v13 and became what the service loaded.
    recon_scanning and data_exfiltration were absent from the model entirely,
    and overall accuracy was 0.332 against v13's 1.000. The pointer makes the
    served version a declaration instead of an accident.
    """
    pinned = _pinned_model_name("xgb")
    if pinned:
        candidate = _MODELS_DIR / pinned
        if candidate.exists() and candidate.resolve().parent == _MODELS_DIR.resolve():
            return candidate
        log.error("models/CURRENT pins %r which is missing — falling back", pinned)
    existing = _model_files()
    return existing[-1] if existing else None


def _swap_state(model, label_encoder) -> None:
    """Atomically install a new (model, label map) pair."""
    global _state
    with _state_lock:
        _state = (model, label_encoder)


def _current_state() -> Optional[tuple]:
    """Read the active model and label map as one consistent snapshot."""
    with _state_lock:
        return _state


def _load_model_from_disk() -> bool:
    """Try to load latest persisted XGB model + label map; return True on success.

    The label map is validated against THREAT_CLASSES on load. A corrupt or
    stale map used to survive here and surface later as a threat_class_guess
    like "class_4", which fusion then handed to Alert() — and Alert rejects any
    class outside the six mandated ones, so a bad artifact crashed the scoring
    path per flow instead of failing once, loudly, at load time.
    """
    model_path = _latest_model_path()
    if model_path is None:
        return False
    # Companion label-map lives next to the model JSON.
    label_path = model_path.with_suffix(".labels.json")
    try:
        import xgboost as xgb
        import json as _json

        resolved = model_path.resolve()
        if resolved.parent != _MODELS_DIR.resolve():
            log.error("xgb: refusing to load model outside models/: %s", resolved)
            return False

        if not verify_artifact(resolved):
            return False
        model = xgb.XGBClassifier()
        model.load_model(str(resolved))
        if label_path.exists():
            with open(label_path) as fh:
                label_encoder = _json.load(fh)
        else:
            label_encoder = {i: c for i, c in enumerate(THREAT_CLASSES)}

        unknown = {c for c in label_encoder.values() if c not in THREAT_CLASSES}
        if unknown:
            log.error(
                "xgb: %s maps to unknown classes %s — refusing to load",
                label_path.name, sorted(unknown),
            )
            return False

        _swap_state(model, label_encoder)
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

    # num_class and use_label_encoder were removed from the public contract in
    # xgboost 2.0 (num_class is inferred; use_label_encoder is a no-op). They
    # were still being passed, implying a version constraint that no longer
    # applies.
    model = xgb.XGBClassifier(
        objective="multi:softprob",
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
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

    # Hot-swap in memory as one atomic rebind — see _state.
    _swap_state(model, int_to_label)


def predict_xgb_batch(flows: list[FlowRecord]) -> list[LayerScore]:
    """Classify a batch of flows in a single model call.

    XGBoost's ``predict_proba`` has a fixed per-call cost that dominates the
    work of classifying one 16-feature row: measured on the fixture corpus, one
    flow at a time runs at ~1,080 flows/sec while the same rows as one matrix
    run at ~397,000 flows/sec. Since a fixed 120ms capture window already
    produces a batch, this is the natural shape for the hot path.

    Args:
        flows: FlowRecords to classify.

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
                "XGBoost model not available. "
                "Call train_xgb() or run train_models.py first."
            )
        state = _current_state()

    # One consistent snapshot so a concurrent retrain cannot pair this model
    # with the previous label map.
    model, label_encoder = state

    try:
        import numpy as np
    except ImportError as exc:
        raise ImportError("numpy required for scoring: pip install numpy") from exc

    X = np.array([extract_features(f) for f in flows], dtype=float)
    probas = model.predict_proba(X)

    # Resolve the index -> class-name mapping once for the whole batch. The
    # label map survives a JSON round-trip with string keys but is built with
    # int keys in-process, so try both. An index with no label is dropped rather
    # than invented as "class_<i>": an invented name would propagate through
    # fusion into Alert(threat_class=...), which only accepts the six mandated
    # classes, and crash the scoring path.
    index_to_class = {}
    for i in range(probas.shape[1]):
        cls = label_encoder.get(str(i), label_encoder.get(i))
        if cls is None:
            log.warning("xgb: model output index %d has no label — ignoring", i)
            continue
        index_to_class[i] = cls

    results: list[LayerScore] = []
    for flow, proba in zip(flows, probas):
        class_probs = {cls: float(proba[i]) for i, cls in index_to_class.items()}

        # Separate benign probability from threat class probabilities.
        benign_prob = class_probs.get("benign", 0.0)
        threat_probs = {k: v for k, v in class_probs.items() if k != "benign"}

        # The "threat score" is the total probability NOT assigned to benign.
        raw_score = max(0.0, min(1.0, float(1.0 - benign_prob)))

        best_threat = max(threat_probs, key=threat_probs.get) if threat_probs else None

        # Only emit a threat_class_guess when the model positively prefers a
        # threat class over benign, and only for a class Alert will accept.
        threat_class_guess = best_threat if benign_prob < 0.5 else None
        if threat_class_guess is not None and threat_class_guess not in VALID_THREAT_CLASSES:
            log.warning("xgb: dropping out-of-schema class guess %r", threat_class_guess)
            threat_class_guess = None

        # Evidence: top-2 classes for interpretability.
        top2 = sorted(class_probs.items(), key=lambda kv: kv[1], reverse=True)[:2]
        evidence = [f"{cls}={prob:.3f}" for cls, prob in top2]

        results.append(
            LayerScore(
                flow_id=flow.flow_id,
                layer_name="xgb",
                raw_score=raw_score,
                calibrated_probability=raw_score,  # softprob already calibrated
                threat_class_guess=threat_class_guess,
                evidence=evidence,
            )
        )
    return results


def predict_xgb(flow: FlowRecord) -> LayerScore:
    """Classify a flow using the trained XGBClassifier.

    This is the per-flow contract from CLAUDE.md (FlowRecord -> LayerScore). It
    delegates to :func:`predict_xgb_batch`, so there is exactly one prediction
    implementation. Prefer the batch form on the hot path.

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
    return predict_xgb_batch([flow])[0]
