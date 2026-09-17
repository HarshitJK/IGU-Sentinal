"""Tests for eval.py — the external-dataset loader and k-fold corpus builder.

eval.py produces the numbers the project's claims rest on and had no test
coverage at all, so a silent break there corrupted the reported metrics.
"""
import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval import (  # noqa: E402
    _kfold_corpus,
    _map_external_label,
    load_external_dataset,
)

# Real CIC-IDS2017 headers, including the leading space the released CSVs carry
# on nearly every column — a loader that strips nothing fails on the real files.
_CIC_HEADERS = [
    " Destination Port", " Protocol", " Flow Duration", " Total Fwd Packets",
    "Total Length of Fwd Packets", " Fwd Packet Length Max",
    " Fwd Packet Length Min", " Fwd Packet Length Mean",
    " Fwd Packet Length Std", " Fwd IAT Mean", " Fwd IAT Std",
    " Bwd Packet Length Mean", " Bwd IAT Mean", " Fwd Header Length", " Label",
]


def _row(label, **over):
    base = {h: 0 for h in _CIC_HEADERS}
    base.update({
        " Destination Port": 443, " Protocol": 6, " Flow Duration": 100000,
        " Total Fwd Packets": 10, "Total Length of Fwd Packets": 5000,
        " Fwd Packet Length Max": 1200, " Fwd Packet Length Min": 60,
        " Fwd Packet Length Mean": 500, " Fwd Packet Length Std": 200,
        " Fwd IAT Mean": 1000, " Fwd IAT Std": 50,
        " Bwd Packet Length Mean": 999, " Bwd IAT Mean": 999,
        " Fwd Header Length": 64, " Label": label,
    })
    base.update(over)
    return base


def _write_csv(tmp_path, rows):
    p = tmp_path / "cicids.csv"
    with open(p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_CIC_HEADERS)
        w.writeheader()
        w.writerows(rows)
    return str(p)


def test_external_label_mapping_covers_the_six_classes():
    """Dataset attack names must map onto the six mandated classes."""
    cases = {
        "BENIGN": "benign",
        "DDoS": "volumetric_ddos",
        "DoS Hulk": "volumetric_ddos",
        "Bot": "c2_beaconing",
        "PortScan": "recon_scanning",
        "Reconnaissance": "recon_scanning",
        "Infiltration": "encrypted_malware",
        "Backdoor": "encrypted_malware",
        "Web Attack – Brute Force": "data_exfiltration",
    }
    for raw, expected in cases.items():
        assert _map_external_label(raw) == expected, f"{raw!r} -> {expected}"
    assert _map_external_label("something totally unknown") is None
    print("✓ test_external_label_mapping_covers_the_six_classes passed")


def test_external_loader_reads_cic_ids_headers(tmp_path):
    """Headers with the released files' leading spaces must resolve."""
    path = _write_csv(tmp_path, [_row("BENIGN"), _row("DDoS"), _row("PortScan")])
    flows, labels = load_external_dataset(path)

    assert len(flows) == 3
    assert labels == ["benign", "volumetric_ddos", "recon_scanning"]
    assert flows[0].dst_port == 443
    assert flows[0].packet_size_stats["mean"] == 500
    print("✓ test_external_loader_reads_cic_ids_headers passed")


def test_external_loader_drops_bidirectional_fields(tmp_path):
    """Reverse-direction columns must never reach a FlowRecord.

    A diode-fed sensor cannot observe the reverse direction. Using Bwd_* columns
    would evaluate a system this project cannot build.
    """
    path = _write_csv(tmp_path, [_row("BENIGN", **{" Bwd Packet Length Mean": 123456})])
    flows, _ = load_external_dataset(path)

    dumped = flows[0].model_dump_json()
    assert "123456" not in dumped, "a Bwd_* value leaked into the FlowRecord"
    print("✓ test_external_loader_drops_bidirectional_fields passed")


def test_external_loader_survives_infinity_and_nan(tmp_path):
    """CIC-IDS CSVs really do contain Infinity and NaN in numeric columns."""
    path = _write_csv(tmp_path, [
        _row("BENIGN", **{" Flow Duration": "Infinity"}),
        _row("DDoS", **{" Fwd IAT Mean": "NaN"}),
        _row("PortScan", **{" Fwd Packet Length Mean": ""}),
    ])
    flows, labels = load_external_dataset(path)

    assert len(flows) == 3, "rows with Infinity/NaN/blank must still load"
    for f in flows:
        for v in (f.inter_arrival_stats["mean"], f.packet_size_stats["mean"]):
            assert v == v and abs(v) != float("inf"), "non-finite value reached a FlowRecord"
    print("✓ test_external_loader_survives_infinity_and_nan passed")


def test_external_loader_skips_unmappable_labels(tmp_path):
    """Rows whose label has no mapping are skipped, not guessed at."""
    path = _write_csv(tmp_path, [_row("BENIGN"), _row("Some Future Attack"), _row("DDoS")])
    flows, labels = load_external_dataset(path)
    assert len(flows) == 2
    assert "Some Future Attack" not in labels
    print("✓ test_external_loader_skips_unmappable_labels passed")


def test_external_loader_honours_limit(tmp_path):
    """These files run to millions of rows; the limit must be respected."""
    path = _write_csv(tmp_path, [_row("BENIGN") for _ in range(50)])
    flows, _ = load_external_dataset(path, limit=7)
    assert len(flows) == 7
    print("✓ test_external_loader_honours_limit passed")


def test_external_loader_rejects_file_without_labels(tmp_path):
    """A CSV with no label column is an error, not an empty result."""
    p = tmp_path / "nolabel.csv"
    with open(p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["a", "b"])
        w.writeheader()
        w.writerow({"a": 1, "b": 2})
    with pytest.raises(ValueError, match="label"):
        load_external_dataset(str(p))
    print("✓ test_external_loader_rejects_file_without_labels passed")


def test_external_loader_missing_file():
    with pytest.raises(FileNotFoundError):
        load_external_dataset("/nonexistent/path/to.csv")
    print("✓ test_external_loader_missing_file passed")


def test_kfold_corpus_is_balanced_and_varied():
    """The CV corpus must be balanced and must not repeat feature vectors.

    Duplicate vectors are what made the original 99.7% meaningless: with a
    handful of distinct points, train and test rows are the same rows.
    """
    from igu_sentinel.detect.features import extract_features

    flows, labels = _kfold_corpus(per_class=200)
    counts = {c: labels.count(c) for c in set(labels)}
    assert len(set(counts.values())) == 1, f"corpus must be balanced, got {counts}"

    distinct = len({tuple(extract_features(f)) for f in flows})
    ratio = distinct / len(flows)
    assert ratio > 0.95, (
        f"only {ratio:.1%} of feature vectors are distinct — the classifier "
        f"can memorise this corpus"
    )
    print(f"✓ test_kfold_corpus_is_balanced_and_varied passed ({ratio:.1%} distinct)")
