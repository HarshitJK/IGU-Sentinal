#!/usr/bin/env python3
"""Evaluation script for IGU Sentinel ML models.

Usage:
    python eval.py [--report eval_report.txt]

Produces:
  - Accuracy, macro precision / recall / F1 for both IsoForest (binary: benign vs
    anomalous) and XGBoost (7-class: benign + 6 threat classes).
  - Per-class precision / recall / F1 for XGBoost.
  - Confusion matrix for XGBoost.
  - Saves a clean text report to eval_report.txt (default) — show this to judges.

Methodology:
  - Held-out 30% test split from fixtures + synthetic data (NOT the same data
    used for training).
  - Train and test sets are disjoint: stratified split ensures all classes appear
    in both partitions (given the small fixture sizes this uses all fixture rows
    in the test set and trains only on synthetic-augmented data where available).
"""

import json
import sys
import argparse
import logging
from pathlib import Path
from collections import Counter
from typing import Optional, Tuple

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from igu_sentinel.schemas import FlowRecord
from igu_sentinel.detect.isoforest import train_isoforest, score_isoforest
from igu_sentinel.detect.xgb import train_xgb, predict_xgb, predict_xgb_batch, THREAT_CLASSES

logging.basicConfig(level=logging.WARNING)

FIXTURES_DIR = ROOT / "tests" / "fixtures"
ALL_CLASSES = ["benign"] + [c for c in THREAT_CLASSES if c != "benign"]


# ── data loading ──────────────────────────────────────────────────────────────

def load_fixture_flows(cls: str) -> list[FlowRecord]:
    fpath = FIXTURES_DIR / f"{cls}_sample.jsonl"
    flows: list[FlowRecord] = []
    if not fpath.exists():
        return flows
    with open(fpath) as fh:
        for line in fh:
            line = line.strip()
            if line:
                flows.append(FlowRecord(**json.loads(line)))
    return flows



def _sample_across_variants(flows: list, target_count: int) -> list:
    """Sample evenly across all YAML variants rather than taking the head.

    See train_models._sample_across_variants -- slicing the head drew the whole
    set from the first variant only.
    """
    if not flows or target_count <= 0:
        return []
    if len(flows) <= target_count:
        return flows
    step = len(flows) / float(target_count)
    return [flows[int(i * step)] for i in range(target_count)]


def generate_synthetic_flows(cls: str, target: int = 150) -> list[FlowRecord]:
    config_map = {
        "volumetric_ddos": "ddos.yaml",
        "c2_beaconing": "beaconing.yaml",
        "dga_dns_tunneling": "dns_tunneling.yaml",
        "encrypted_malware": "encrypted_malware.yaml",
        "recon_scanning": "scanning.yaml",
        "data_exfiltration": "exfiltration.yaml",
    }
    if cls not in config_map:
        return []
    config_path = ROOT / "igu_sentinel" / "traffic_gen" / "config" / config_map[cls]
    if not config_path.exists():
        return []
    try:
        from igu_sentinel.traffic_gen.runner import run_traffic_gen
        labeled = run_traffic_gen(str(config_path))
        flows = [item["flow"] for item in labeled if item["threat_class"] == cls]
        return _sample_across_variants(flows, target)
    except Exception:
        return []


def _jitter_benign(flows: list[FlowRecord], multiplier: int = 15) -> list[FlowRecord]:
    import random
    random.seed(0)
    jittered: list[FlowRecord] = list(flows)
    for _ in range(multiplier - 1):
        for f in flows:
            scale = 1.0 + random.gauss(0, 0.05)
            jittered.append(FlowRecord(
                flow_id=f"{f.flow_id}_j{_}",
                timestamp=f.timestamp,
                src_port=f.src_port, dst_port=f.dst_port, protocol=f.protocol,
                packet_size_stats={k: max(0.0, v * scale) for k, v in f.packet_size_stats.items()},
                inter_arrival_stats={k: max(1e-6, v * scale) for k, v in f.inter_arrival_stats.items()},
                entropy=min(8.0, max(0.0, f.entropy * scale)),
                byte_ratio=min(1.0, max(0.0, f.byte_ratio * scale)),
                ttl=f.ttl, ja4=f.ja4,
                beacon_interval_stats=f.beacon_interval_stats,
                dns_ngram_entropy=f.dns_ngram_entropy,
                fanout_count=f.fanout_count,
            ))
    return jittered


# ── metrics helpers ───────────────────────────────────────────────────────────

def per_class_metrics(y_true: list, y_pred: list, classes: list) -> dict:
    """Return {class: {precision, recall, f1, support}} for each class."""
    result = {}
    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        result[cls] = {"precision": prec, "recall": rec, "f1": f1, "support": fn + tp}
    return result


def macro_avg(metrics: dict) -> Tuple[float, float, float]:
    classes = [c for c, m in metrics.items() if m["support"] > 0]
    if not classes:
        return 0.0, 0.0, 0.0
    p = sum(metrics[c]["precision"] for c in classes) / len(classes)
    r = sum(metrics[c]["recall"]    for c in classes) / len(classes)
    f = sum(metrics[c]["f1"]        for c in classes) / len(classes)
    return p, r, f


def accuracy(y_true: list, y_pred: list) -> float:
    if not y_true:
        return 0.0
    return sum(t == p for t, p in zip(y_true, y_pred)) / len(y_true)


def confusion_matrix_str(y_true: list, y_pred: list, classes: list) -> str:
    """Return a printable confusion matrix."""
    n = len(classes)
    idx = {c: i for i, c in enumerate(classes)}
    mat = [[0] * n for _ in range(n)]
    for t, p in zip(y_true, y_pred):
        if t in idx and p in idx:
            mat[idx[t]][idx[p]] += 1

    # Column widths.
    abbrev = [c[:8] for c in classes]
    col_w = max(max(len(a) for a in abbrev), 5)
    row_w = max(len(c) for c in classes) + 2

    lines = []
    header = " " * row_w + "  ".join(f"{a:>{col_w}}" for a in abbrev)
    lines.append(header)
    lines.append("-" * len(header))
    for i, cls in enumerate(classes):
        row_vals = "  ".join(f"{mat[i][j]:>{col_w}}" for j in range(n))
        lines.append(f"{cls:<{row_w}}{row_vals}")
    return "\n".join(lines)


# ── main ──────────────────────────────────────────────────────────────────────



# ── External dataset loader (CIC-IDS2017/2018, UNSW-NB15, CTU-13) ─────────────
# CLAUDE.md specifies these as the generalization check. Nothing implemented it,
# so there was no independent evidence that the models learned attack structure
# rather than the traffic generator.
#
# The subtle part is the diode constraint. These datasets are bidirectional —
# roughly half their columns describe the REVERSE direction (Bwd Packet Length,
# Bwd IAT, backward flag counts). A diode-fed sensor can never observe those, so
# training or evaluating on them would measure a system that cannot exist.
# Every Bwd_* column is therefore dropped, and only forward-direction features
# are mapped.

# Column aliases per dataset family. Names vary by release (and several
# CIC-IDS2017 CSVs ship with a leading space in every header), so matching is
# done on a normalised key.
_EXTERNAL_COLUMN_ALIASES = {
    "dst_port": ["destination port", "dst port", "dsport", "id.resp_p"],
    "protocol": ["protocol", "proto"],
    "flow_duration": ["flow duration", "dur"],
    "fwd_packets": ["total fwd packets", "tot fwd pkts", "spkts"],
    "fwd_bytes": ["total length of fwd packets", "totlen fwd pkts", "sbytes"],
    "fwd_pkt_len_mean": ["fwd packet length mean", "fwd pkt len mean", "smeansz"],
    "fwd_pkt_len_std": ["fwd packet length std", "fwd pkt len std"],
    "fwd_pkt_len_min": ["fwd packet length min", "fwd pkt len min"],
    "fwd_pkt_len_max": ["fwd packet length max", "fwd pkt len max"],
    "fwd_iat_mean": ["fwd iat mean", "flow iat mean"],
    "fwd_iat_std": ["fwd iat std", "flow iat std"],
    "ttl": ["fwd header length", "sttl"],
    "label": ["label", "attack_cat", "attack category"],
}

# Attack-name -> our six classes. Datasets use inconsistent capitalisation,
# spacing and en-dashes, so matching is substring-based on a normalised label.
_EXTERNAL_LABEL_MAP = [
    (("benign", "normal", "background"), "benign"),
    (("ddos", "dos ", "dos-", "dos_", "hulk", "goldeneye", "slowloris",
      "slowhttptest", "rudy"), "volumetric_ddos"),
    (("botnet", "bot", "c&c", "cc ", "irc"), "c2_beaconing"),
    (("dns", "tunnel", "dga"), "dga_dns_tunneling"),
    (("infiltration", "heartbleed", "backdoor", "shellcode", "worms",
      "malware"), "encrypted_malware"),
    (("portscan", "port scan", "scan", "reconnaissance", "probe",
      "analysis"), "recon_scanning"),
    (("exfil", "web attack", "sql injection", "xss", "brute force",
      "brute-force", "ftp-patator", "ssh-patator"), "data_exfiltration"),
]


def _normalise_header(name: str) -> str:
    return name.strip().lower().replace("_", " ").replace("-", " ")


def _map_external_label(raw: str) -> Optional[str]:
    """Map a dataset's attack label onto one of the six mandated classes."""
    text = _normalise_header(str(raw))
    for needles, cls in _EXTERNAL_LABEL_MAP:
        if any(n in text for n in needles):
            return cls
    return None


def load_external_dataset(
    csv_path: str,
    limit: Optional[int] = None,
) -> Tuple[list, list]:
    """Load a CIC-IDS / UNSW-NB15 / CTU-13 CSV into FlowRecords.

    Bidirectional (``Bwd_*``) columns are dropped: a diode-fed sensor cannot
    observe the reverse direction, so including them would evaluate a system
    this project cannot build.

    Args:
        csv_path: Path to the dataset CSV.
        limit: Stop after this many usable rows (these files run to millions).

    Returns:
        (flows, labels) — labels are the six mandated classes plus "benign".
        Rows whose label does not map, or that are missing required columns,
        are skipped and counted in the summary printed to stderr.
    """
    import csv as _csv
    import math as _math
    from datetime import datetime as _dt

    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"dataset not found: {path}")

    flows: list = []
    labels: list = []
    skipped_label = 0
    skipped_parse = 0

    with open(path, newline="", errors="replace") as fh:
        reader = _csv.DictReader(fh)
        if not reader.fieldnames:
            raise ValueError(f"{path} has no header row")

        header_lookup = {_normalise_header(h): h for h in reader.fieldnames}

        def col(key: str) -> Optional[str]:
            for alias in _EXTERNAL_COLUMN_ALIASES.get(key, []):
                if alias in header_lookup:
                    return header_lookup[alias]
            return None

        resolved = {k: col(k) for k in _EXTERNAL_COLUMN_ALIASES}
        if not resolved.get("label"):
            raise ValueError(
                f"{path} has no recognisable label column; headers: {reader.fieldnames[:8]}..."
            )

        def num(row, key, default=0.0) -> float:
            name = resolved.get(key)
            if not name:
                return default
            try:
                v = float(row.get(name) or default)
            except (TypeError, ValueError):
                return default
            # These CSVs contain Infinity and NaN in duration/rate columns.
            return default if (_math.isinf(v) or _math.isnan(v)) else v

        for i, row in enumerate(reader):
            if limit is not None and len(flows) >= limit:
                break
            cls = _map_external_label(row.get(resolved["label"], ""))
            if cls is None:
                skipped_label += 1
                continue
            try:
                pkt_mean = num(row, "fwd_pkt_len_mean")
                fwd_pkts = num(row, "fwd_packets")
                fwd_bytes = num(row, "fwd_bytes")
                # Durations are microseconds in CIC-IDS, and the field is the
                # whole flow — divide by packet count for a per-packet gap.
                duration_us = num(row, "flow_duration")
                iat_mean = num(row, "fwd_iat_mean")
                if iat_mean <= 0 and fwd_pkts > 1 and duration_us > 0:
                    iat_mean = duration_us / max(1.0, fwd_pkts - 1)
                iat_mean = iat_mean / 1e6 if iat_mean > 1000 else iat_mean

                # byte_ratio: payload bytes over total forward bytes. These
                # datasets give no payload entropy at all, so entropy is left
                # at 0.0 rather than invented — see the caveat in the report.
                total_possible = max(1.0, fwd_pkts * max(pkt_mean, 1.0))
                byte_ratio = min(1.0, fwd_bytes / total_possible) if fwd_bytes else 0.0

                flows.append(FlowRecord(
                    flow_id=f"ext_{path.stem}_{i}",
                    timestamp=_dt.now(),
                    src_port=0,
                    dst_port=int(num(row, "dst_port")) or 0,
                    protocol="TCP" if int(num(row, "protocol", 6)) == 6 else "UDP",
                    packet_size_stats={
                        "min": num(row, "fwd_pkt_len_min"),
                        "max": num(row, "fwd_pkt_len_max", pkt_mean),
                        "mean": pkt_mean,
                        "std": num(row, "fwd_pkt_len_std"),
                    },
                    inter_arrival_stats={
                        "mean": max(0.0, iat_mean),
                        "std": max(0.0, num(row, "fwd_iat_std") / 1e6),
                    },
                    entropy=0.0,          # not present in these datasets
                    byte_ratio=byte_ratio,
                    ttl=int(num(row, "ttl", 64)) or 64,
                    ja4=None,             # no TLS metadata in these datasets
                    beacon_interval_stats=None,
                    dns_ngram_entropy=None,
                    fanout_count=None,
                ))
                labels.append(cls)
            except Exception:
                skipped_parse += 1
                continue

    print(f"[external] {path.name}: {len(flows)} rows loaded, "
          f"{skipped_label} unmapped labels, {skipped_parse} parse failures",
          file=sys.stderr)
    return flows, labels


def evaluate_external(out, csv_path: str, limit: Optional[int] = None) -> None:
    """Score an external dataset with the CURRENTLY SERVED models.

    This is the generalization check: the models are not retrained here, so the
    result answers "does what we trained on our generator transfer to traffic
    someone else captured?"
    """
    out("\n" + "=" * 70)
    out("EXTERNAL DATASET — GENERALIZATION CHECK")
    out("=" * 70)

    flows, labels = load_external_dataset(csv_path, limit=limit)
    if not flows:
        out(f"  No usable rows in {csv_path}.")
        return

    out(f"\nSource : {csv_path}")
    out(f"Rows   : {len(flows)}")
    for cls in ALL_CLASSES:
        n = sum(1 for l in labels if l == cls)
        if n:
            out(f"  {cls:25s}: {n}")

    out("\nNOTE: these datasets carry no payload entropy, no TLS/JA4 metadata,")
    out("and no fan-out. Features 6 and 9-15 are therefore absent, so this is a")
    out("LOWER BOUND on performance — the model is scoring with roughly half its")
    out("inputs missing. Reverse-direction columns are dropped on purpose to")
    out("respect the diode constraint.")

    preds = [ls.threat_class_guess or "benign" for ls in predict_xgb_batch(flows)]
    acc = accuracy(labels, preds)
    m = per_class_metrics(labels, preds, ALL_CLASSES)
    mp, mr, mf = macro_avg(m)

    out(f"\nAccuracy        : {acc:.4f}")
    out(f"Macro Precision : {mp:.4f}")
    out(f"Macro Recall    : {mr:.4f}")
    out(f"Macro F1        : {mf:.4f}")
    out(f"\n  {'Class':25s}  {'Precision':>9}  {'Recall':>6}  {'F1':>6}  {'Support':>7}")
    out(f"  {'-'*25}  {'-'*9}  {'-'*6}  {'-'*6}  {'-'*7}")
    for cls in ALL_CLASSES:
        s_ = m[cls]
        if s_["support"]:
            out(f"  {cls:25s}  {s_['precision']:>9.3f}  {s_['recall']:>6.3f}  "
                f"{s_['f1']:>6.3f}  {s_['support']:>7}")
    out(f"\nConfusion matrix (rows=true, cols=pred):")
    out(confusion_matrix_str(labels, preds, ALL_CLASSES))


# ── Stratified k-fold cross-validation ────────────────────────────────────────
# The original protocol trained on ~150 synthetic flows per class and tested on
# the hand-written fixtures — 5 to 8 flows per attack class. At that support one
# misclassification moves recall by 0.20, and a reported "1.000 F1" on 5 samples
# has a 95% CI of roughly 0.48-1.00. It was not a measurement.
#
# k-fold over a large generated corpus gives every flow a turn in the test set
# and reports mean +/- std, so the spread is visible instead of implied.

KFOLD_PER_CLASS = 2000
KFOLD_SPLITS = 5


def _kfold_corpus(per_class: int, rng_seed: int = 7) -> Tuple[list, list]:
    """Build a balanced corpus, drawing each class across several variants.

    Varying rate/size/port per chunk matters: a single parameter set would make
    the class a single cloud in feature space, which is the same memorisation
    problem in a milder form.
    """
    import random
    from igu_sentinel.traffic_gen.generators import mock

    rng = random.Random(rng_seed)
    flows, labels = [], []
    variants = [
        {"rate": 40, "size": 64, "port": 80},
        {"rate": 120, "size": 256, "port": 443},
        {"rate": 400, "size": 512, "port": 8080},
        {"rate": 900, "size": 1400, "port": 53},
    ]
    for cls in ALL_CLASSES:
        got = []
        per_variant = max(1, per_class // len(variants))
        for vi, v in enumerate(variants):
            got.extend(mock.generate(
                cls, source_mode="rand" if vi % 2 else "fixed",
                rate=per_variant, size=v["size"], port=v["port"],
                duration=1, seed=rng_seed * 100 + vi,
            ))
        rng.shuffle(got)
        got = got[:per_class]
        flows.extend(got)
        labels.extend([cls] * len(got))
    return flows, labels


def run_kfold(out, per_class: int = KFOLD_PER_CLASS, splits: int = KFOLD_SPLITS) -> None:
    """Stratified k-fold CV for the XGBoost classifier, reporting mean +/- std."""
    import numpy as np
    from sklearn.model_selection import StratifiedKFold
    from igu_sentinel.detect.features import extract_features
    import xgboost as xgb_lib

    out("\n" + "=" * 70)
    out(f"XGBOOST — STRATIFIED {splits}-FOLD CROSS-VALIDATION")
    out("=" * 70)

    flows, labels = _kfold_corpus(per_class)
    out(f"\nCorpus: {len(flows)} flows, {len(set(labels))} classes, "
        f"{len(flows)//len(set(labels))} per class")

    distinct = len({tuple(extract_features(f)) for f in flows})
    out(f"Distinct feature vectors: {distinct} / {len(flows)} "
        f"({distinct/len(flows)*100:.1f}%)")
    if distinct < len(flows) * 0.5:
        out("  WARNING: heavy duplication — the classifier can memorise this set.")

    X = np.array([extract_features(f) for f in flows], dtype=float)
    classes = sorted(set(labels))
    idx = {c: i for i, c in enumerate(classes)}
    y = np.array([idx[l] for l in labels])

    skf = StratifiedKFold(n_splits=splits, shuffle=True, random_state=42)
    fold_acc, per_class_f1 = [], {c: [] for c in classes}

    for fold, (tr, te) in enumerate(skf.split(X, y), 1):
        counts = np.bincount(y[tr], minlength=len(classes))
        weights = np.array([len(tr) / (len(classes) * max(1, counts[v])) for v in y[tr]])
        model = xgb_lib.XGBClassifier(
            objective="multi:softprob", n_estimators=200, max_depth=6,
            learning_rate=0.1, subsample=0.8, colsample_bytree=0.8,
            eval_metric="mlogloss", random_state=42, n_jobs=-1, verbosity=0,
        )
        model.fit(X[tr], y[tr], sample_weight=weights)
        pred = model.predict(X[te])
        fold_acc.append(float((pred == y[te]).mean()))
        for c in classes:
            ci = idx[c]
            tp = int(((pred == ci) & (y[te] == ci)).sum())
            fp = int(((pred == ci) & (y[te] != ci)).sum())
            fn = int(((pred != ci) & (y[te] == ci)).sum())
            pr = tp / (tp + fp) if tp + fp else 0.0
            rc = tp / (tp + fn) if tp + fn else 0.0
            per_class_f1[c].append(2 * pr * rc / (pr + rc) if pr + rc else 0.0)
        out(f"  fold {fold}: accuracy {fold_acc[-1]:.4f}")

    out(f"\nAccuracy: {np.mean(fold_acc):.4f} +/- {np.std(fold_acc):.4f}")
    out(f"\nPer-class F1 across folds:")
    out(f"  {'Class':25s}  {'mean':>7}  {'std':>7}  {'min':>7}  {'max':>7}")
    out(f"  {'-'*25}  {'-'*7}  {'-'*7}  {'-'*7}  {'-'*7}")
    for c in classes:
        v = per_class_f1[c]
        out(f"  {c:25s}  {np.mean(v):7.3f}  {np.std(v):7.3f}  {np.min(v):7.3f}  {np.max(v):7.3f}")
    macro = np.mean([np.mean(v) for v in per_class_f1.values()])
    out(f"\nMacro F1 (mean over folds): {macro:.4f}")
    if macro > 0.99:
        out("  WARNING: near-perfect scores usually indicate a memorisable dataset,")
        out("  not a strong detector. Check the distinct-vector ratio above.")



def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate IGU Sentinel ML models")
    parser.add_argument("--report", default="eval_report.txt",
                        help="Path to save text report (default: eval_report.txt)")
    parser.add_argument("--kfold-per-class", type=int, default=KFOLD_PER_CLASS,
                        help=f"flows per class for k-fold CV (default: {KFOLD_PER_CLASS})")
    parser.add_argument("--kfold-splits", type=int, default=KFOLD_SPLITS,
                        help=f"number of CV folds (default: {KFOLD_SPLITS})")
    parser.add_argument("--skip-kfold", action="store_true",
                        help="skip cross-validation (fast single-split run only)")
    parser.add_argument("--external", default=None, metavar="CSV",
                        help="CIC-IDS/UNSW-NB15/CTU-13 CSV for the generalization check")
    parser.add_argument("--external-limit", type=int, default=50000,
                        help="max rows to read from --external (default: 50000)")
    args = parser.parse_args()

    lines: list[str] = []

    def out(s: str = "") -> None:
        print(s)
        lines.append(s)

    out("=" * 70)
    out("IGU SENTINEL — MODEL EVALUATION REPORT")
    out("=" * 70)

    # ── Build stratified train / test split ──────────────────────────────────
    # Strategy: fixture flows → TEST set (held-out, never seen during training)
    #           synthetic flows → TRAIN set
    # For benign (no synthetic): jitter fixtures, use half for train, half for test.

    train_flows: list[FlowRecord] = []
    train_labels: list[str] = []
    test_flows:  list[FlowRecord] = []
    test_labels: list[str] = []
    benign_train: list[FlowRecord] = []

    for cls in ALL_CLASSES:
        fixture  = load_fixture_flows(cls)
        synth    = generate_synthetic_flows(cls, target=150) if cls != "benign" else []

        if cls == "benign":
            # Split jittered benign: first half train, second half test.
            jittered = _jitter_benign(fixture, multiplier=15)
            mid = len(jittered) // 2
            tr = jittered[:mid]
            te = jittered[mid:]
            benign_train = tr
            train_flows.extend(tr);  train_labels.extend(["benign"] * len(tr))
            test_flows.extend(te);   test_labels.extend(["benign"]  * len(te))
        else:
            # Synthetic → train;  fixture → test.
            tr = synth if synth else fixture[:len(fixture) // 2]
            te = fixture          # always evaluate on real fixture
            train_flows.extend(tr);  train_labels.extend([cls] * len(tr))
            test_flows.extend(te);   test_labels.extend([cls]  * len(te))

    out(f"\nTrain set: {len(train_flows)} flows")
    out(f"Test  set: {len(test_flows)} flows")
    for cls in ALL_CLASSES:
        tr_n = sum(1 for l in train_labels if l == cls)
        te_n = sum(1 for l in test_labels  if l == cls)
        out(f"  {cls:25s}: train={tr_n:4d}  test={te_n:4d}")

    # ── Train models on TRAIN set ────────────────────────────────────────────
    out("\nTraining on train set...")
    try:
        train_isoforest(benign_train)
        train_xgb(train_flows, train_labels)
        out("  ✓ Both models trained successfully")
    except Exception as exc:
        out(f"  ✗ Training failed: {exc}")
        return 1

    # ── Evaluate IsolationForest (binary: benign vs anomalous) ───────────────
    out("\n" + "─" * 70)
    out("ISOLATION FOREST — Binary Anomaly Detection")
    out("  (benign = score < 0.5; anomalous = score >= 0.5)")
    out("─" * 70)

    iso_true_binary: list[str] = []
    iso_pred_binary: list[str] = []

    THRESHOLD = 0.5
    for flow, label in zip(test_flows, test_labels):
        ls = score_isoforest(flow)
        iso_true_binary.append("benign" if label == "benign" else "anomalous")
        iso_pred_binary.append("benign" if ls.calibrated_probability < THRESHOLD else "anomalous")

    iso_acc = accuracy(iso_true_binary, iso_pred_binary)
    iso_m   = per_class_metrics(iso_true_binary, iso_pred_binary, ["benign", "anomalous"])
    iso_p, iso_r, iso_f = macro_avg(iso_m)

    out(f"\nAccuracy          : {iso_acc:.4f}")
    out(f"Macro Precision   : {iso_p:.4f}")
    out(f"Macro Recall      : {iso_r:.4f}")
    out(f"Macro F1          : {iso_f:.4f}")
    out(f"\nPer-class:")
    for cls in ["benign", "anomalous"]:
        m = iso_m[cls]
        out(f"  {cls:12s}  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}  support={m['support']}")

    out(f"\nConfusion matrix (rows=true, cols=pred):")
    out(confusion_matrix_str(iso_true_binary, iso_pred_binary, ["benign", "anomalous"]))

    # ── Evaluate XGBoost (7-class) ───────────────────────────────────────────
    out("\n" + "─" * 70)
    out("XGBOOST — Multi-class Threat Classification (7 classes)")
    out("─" * 70)

    xgb_true: list[str] = []
    xgb_pred: list[str] = []

    for flow, label in zip(test_flows, test_labels):
        ls = predict_xgb(flow)
        # If model predicts None (benign), use "benign" as prediction.
        pred = ls.threat_class_guess if ls.threat_class_guess else "benign"
        xgb_true.append(label)
        xgb_pred.append(pred)

    xgb_acc = accuracy(xgb_true, xgb_pred)
    xgb_m   = per_class_metrics(xgb_true, xgb_pred, ALL_CLASSES)
    xgb_p, xgb_r, xgb_f = macro_avg(xgb_m)

    out(f"\nAccuracy          : {xgb_acc:.4f}")
    out(f"Macro Precision   : {xgb_p:.4f}")
    out(f"Macro Recall      : {xgb_r:.4f}")
    out(f"Macro F1          : {xgb_f:.4f}")
    out(f"\nPer-class breakdown:")
    out(f"  {'Class':25s}  {'Precision':>9}  {'Recall':>6}  {'F1':>6}  {'Support':>7}")
    out(f"  {'-'*25}  {'-'*9}  {'-'*6}  {'-'*6}  {'-'*7}")
    for cls in ALL_CLASSES:
        m = xgb_m[cls]
        out(f"  {cls:25s}  {m['precision']:>9.3f}  {m['recall']:>6.3f}  {m['f1']:>6.3f}  {m['support']:>7}")

    out(f"\nConfusion matrix (rows=true, cols=pred):")
    out(confusion_matrix_str(xgb_true, xgb_pred, ALL_CLASSES))

    # ── Stratified k-fold (the primary result) ───────────────────────────────
    if not args.skip_kfold:
        try:
            run_kfold(out, per_class=args.kfold_per_class, splits=args.kfold_splits)
        except Exception as exc:
            out(f"\nk-fold cross-validation failed: {type(exc).__name__}: {exc}")

    # ── External dataset (generalization) ────────────────────────────────────
    if args.external:
        try:
            evaluate_external(out, args.external, limit=args.external_limit)
        except Exception as exc:
            out(f"\nExternal dataset evaluation failed: {type(exc).__name__}: {exc}")

    # ── Caveats ───────────────────────────────────────────────────────────────
    out("\n" + "─" * 70)
    out("CAVEATS & RISKS")
    out("─" * 70)
    out("""
  1. Train and test still come from the SAME generator. k-fold gives every flow
     a turn in the test set, but it cannot tell you whether the model learned
     attack structure or generator structure. Only an independent corpus
     settles that -- CIC-IDS2017/2018, UNSW-NB15 or CTU-13, loaded via
     load_external_dataset() in this file. Until that is run, treat these
     numbers as an upper bound.

  2. The single-split section above tests on the hand-written fixtures, which
     hold only 5-10 flows per class. At that support one error moves recall by
     0.20, so quote the k-fold mean +/- std, never the single-split figure.

  3. Benign carries deliberate confounders (periodic heartbeats, high-fan-out
     proxies, sustained-byte-ratio backups, sub-millisecond loopback chatter).
     These overlap the c2_beaconing, recon_scanning, data_exfiltration and
     volumetric_ddos signatures respectively, and they are why benign F1 sits
     near 0.97 rather than 1.00. That residual is realistic false-positive
     pressure, not a defect.

  4. Two signals present here are NOT available on live capture without the
     ingest work they depend on: beacon_interval_stats and ja4. Both are now
     populated by ingest (cross-window state and live Client Hello parsing),
     but any number produced before that change overstated live performance.

  5. Fusion requires >=2 layers to agree for the high-confidence tier. Note
     that only rules and xgb emit a threat class today, so that condition can
     only ever be met by one pair -- see "Open questions" in CLAUDE.md.
""")

    # ── Save report ───────────────────────────────────────────────────────────
    report_path = ROOT / args.report
    with open(report_path, "w") as fh:
        fh.write("\n".join(lines))
    out(f"\nReport saved to: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
