"""Held-out calibration of fused class correctness; never fitted on live traffic."""
import hashlib
import json
import math
import os
from functools import lru_cache
from pathlib import Path

from igu_sentinel.schemas import FEATURE_CONTRACT_VERSION


def inputs(scores, alert):
    layers = {score.layer_name: score for score in scores}
    return [alert.confidence_score] + [layers[name].raw_score for name in ('rules', 'stats', 'isoforest', 'xgb')]


def fit(rows, targets):
    from sklearn.linear_model import LogisticRegression
    if len(rows) < 20 or len(set(targets)) != 2:
        raise ValueError('Calibration requires >=20 held-out examples and both correct and incorrect predictions')
    model = LogisticRegression(random_state=26145, max_iter=1000).fit(rows, targets)
    return {'coefficients': model.coef_[0].tolist(), 'intercept': float(model.intercept_[0]),
            'feature_contract_version': FEATURE_CONTRACT_VERSION, 'n_calibration': len(rows),
            'target': 'probability that the proposed threat class is correct'}


def predict(calibration, row):
    value = calibration['intercept'] + sum(a * b for a, b in zip(calibration['coefficients'], row))
    return 1 / (1 + math.exp(-max(-700, min(700, value))))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pipeline_fingerprint():
    from igu_sentinel.detect import isoforest, xgb
    from igu_sentinel.detect import features, rules, stats
    from igu_sentinel import fusion
    baseline = Path(os.environ.get('IGU_STATS_BASELINE_PATH', Path(__file__).resolve().parents[2] / 'tests/fixtures/benign_sample.jsonl'))
    paths = [isoforest._latest_model_path(), xgb._latest_model_path()]
    if any(path is None for path in paths):
        raise ValueError('Serving models are missing')
    paths += [paths[1].with_suffix('.labels.json'), baseline]
    return {'artifacts': {path.name: digest(path) for path in paths},
            'code': {module.__name__: digest(module.__file__) for module in (isoforest, xgb, features, rules, stats, fusion)}}


@lru_cache(maxsize=1)
def configured(path):
    from igu_sentinel.detect.isoforest import verify_artifact
    artifact = Path(path)
    if not verify_artifact(artifact):
        raise ValueError('Calibration integrity verification failed')
    calibration = json.loads(artifact.read_text())
    if calibration['feature_contract_version'] != FEATURE_CONTRACT_VERSION:
        raise ValueError('Calibration feature version mismatch')
    if calibration['pipeline_fingerprint'] != pipeline_fingerprint():
        raise ValueError('Calibration was fitted for a different model, baseline or pipeline')
    return calibration


def apply_configured(scores, alert):
    path = os.environ.get('IGU_CONFIDENCE_CALIBRATION')
    if not path:
        alert.evidence.append('confidence=uncalibrated_heuristic')
        return alert
    calibration = configured(path)
    alert.confidence_score = predict(calibration, inputs(scores, alert))
    alert.evidence.append('confidence=held_out_calibrated')
    return alert
