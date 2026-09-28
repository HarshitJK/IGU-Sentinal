"""Offline candidate training/calibration/test. Never promotes serving artifacts.

python -m igu_sentinel.eval.candidate --train train.jsonl --calibration cal.jsonl
    --test test.jsonl --output data/candidate
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path

from igu_sentinel.schemas import FlowRecord, FEATURE_CONTRACT_VERSION
from igu_sentinel.detect import isoforest, xgb, stats
from igu_sentinel.fusion import is_actionable_alert
from igu_sentinel.fusion.calibration import fit, predict, inputs, pipeline_fingerprint, digest


def read_partition(path):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for row in rows:
        if not row.get('group') or not row.get('provenance'):
            raise ValueError('Every row needs capture group and provenance')
        row['record'] = FlowRecord.model_validate(row['flow'])
    return rows


def check_partitions(partitions):
    for i, left in enumerate(partitions):
        for right in partitions[i + 1:]:
            if {row['group'] for row in left} & {row['group'] for row in right}:
                raise ValueError('Capture groups overlap across partitions')
            hashes_left = {row['source_sha256'] for row in left if row.get('source_sha256')}
            hashes_right = {row['source_sha256'] for row in right if row.get('source_sha256')}
            if hashes_left & hashes_right:
                raise ValueError('Identical captures appear in different partitions')


def score(rows):
    from igu_sentinel.api import _score_batch
    records = [row['record'] for row in rows]
    result = []
    for offset in range(0, len(records), 256):
        result.extend(_score_batch(records[offset:offset + 256]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('train', 'calibration', 'test', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('IGU_CONFIDENCE_CALIBRATION'):
        parser.error('Unset IGU_CONFIDENCE_CALIBRATION during offline fitting')
    partitions = [read_partition(path) for path in (args.train, args.calibration, args.test)]
    check_partitions(partitions)
    training, calibration, testing = partitions
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('Candidate output directory must be empty')
    args.output.mkdir(parents=True, exist_ok=True)
    isoforest._MODELS_DIR = xgb._MODELS_DIR = args.output.resolve()
    benign = [row['record'] for row in training if row['label'] == 'benign']
    if not benign:
        parser.error('Training requires labelled benign records')
    isoforest.train_isoforest(benign)
    xgb.train_xgb([row['record'] for row in training], [row['label'] for row in training])
    stats.train_stats_baseline(benign)
    baseline_path = args.output / 'stats-baseline.jsonl'
    baseline_path.write_text(''.join(flow.model_dump_json() + '\n' for flow in benign))
    os.environ['IGU_STATS_BASELINE_PATH'] = str(baseline_path.resolve())
    cal_scores = score(calibration)
    cal = fit([inputs(scores, alert) for scores, alert in cal_scores],
              [int(alert.threat_class == row['label']) for row, (_, alert) in zip(calibration, cal_scores)])
    cal['pipeline_fingerprint'] = pipeline_fingerprint()
    cal['partition_sha256'] = digest(args.calibration)
    calibration_path = args.output / 'confidence-calibration.json'
    calibration_path.write_text(json.dumps(cal, indent=2))
    isoforest.record_artifact_digests([calibration_path, baseline_path])
    predictions, confidences, correct = [], [], []
    for row, (scores, alert) in zip(testing, score(testing)):
        alert.confidence_score = predict(cal, inputs(scores, alert))
        predictions.append(alert.threat_class if is_actionable_alert(scores, alert) else 'benign')
        confidences.append(alert.confidence_score)
        correct.append(int(alert.threat_class == row['label']))
    from sklearn.metrics import classification_report, confusion_matrix, brier_score_loss
    labels = xgb.THREAT_CLASSES
    truth = [row['label'] for row in testing]
    benign_count = sum(label == 'benign' for label in truth)
    false_positives = sum(t == 'benign' and p != 'benign' for t, p in zip(truth, predictions))
    report = {'scope': 'Held-out capture groups; synthetic results do not establish real-world accuracy',
              'feature_contract_version': FEATURE_CONTRACT_VERSION,
              'counts': {name: dict(Counter(row['label'] for row in rows)) for name, rows in zip(('train', 'calibration', 'test'), partitions)},
              'partition_sha256': {name: digest(path) for name, path in zip(('train', 'calibration', 'test'), (args.train, args.calibration, args.test))},
              'class_order': labels, 'classification_report': classification_report(truth, predictions, labels=labels, output_dict=True, zero_division=0),
              'confusion_matrix': confusion_matrix(truth, predictions, labels=labels).tolist(),
              'benign_false_positive_rate': false_positives / benign_count if benign_count else None,
              'brier_class_correctness': brier_score_loss(correct, confidences),
              'unvalidated_classes': sorted(set(labels) - {'benign'} - set(truth)),
              'promoted': False}
    (args.output / 'evaluation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
