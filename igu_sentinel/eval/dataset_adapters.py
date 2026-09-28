"""Inspect external CSV/Zeek datasets without fabricating model inputs.

Outputs partial observations retaining available source values. They cannot be
passed to inference. PCAP extraction is required to match the streaming feature
contract. Label mappings are conservative; unidentified traffic is not benign.
"""
import csv
import hashlib
import json
import logging
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from igu_sentinel.schemas import FlowRecord

log = logging.getLogger(__name__)

# ── Label mapping tables ──────────────────────────────────────────────────────
# Keys are lowercase, stripped dataset label strings.
# Values are the PS-mandated threat class or "benign" or "UNMATCHED".
# "UNMATCHED" rows are logged and excluded from training; we do NOT force-map
# Web attacks, Brute Force, Infiltration, or Botnet into any of the six classes.

_CICDDOS2019_LABEL_MAP: Dict[str, str] = {
    "benign":                     "benign",
    "dns":                        "volumetric_ddos",
    "ldap":                       "volumetric_ddos",
    "mssql":                      "volumetric_ddos",
    "netbios":                    "volumetric_ddos",
    "ntp":                        "volumetric_ddos",
    "portmap":                    "volumetric_ddos",
    "snmp":                       "volumetric_ddos",
    "syn":                        "volumetric_ddos",
    "tftp":                       "volumetric_ddos",
    "udp":                        "volumetric_ddos",
    "udplag":                     "volumetric_ddos",
    "webddos":                    "volumetric_ddos",
    "drdo":                       "volumetric_ddos",  # Reflection DDoS
}

_CICIDS2017_LABEL_MAP: Dict[str, str] = {
    "benign":                     "benign",
    "ddos":                       "volumetric_ddos",
    "dos hulk":                   "volumetric_ddos",
    "dos goldeneye":              "volumetric_ddos",
    "dos slowloris":              "volumetric_ddos",
    "dos slowhttptest":           "volumetric_ddos",
    "heartbleed":                 "UNMATCHED",   # protocol vuln, not a PS class
    "web attack – brute force":   "UNMATCHED",   # web-app brute force
    "web attack – xss":           "UNMATCHED",   # injection, not a PS class
    "web attack – sql injection": "UNMATCHED",
    "infiltration":               "UNMATCHED",   # forward-exfil stage only
    "bot":                        "UNMATCHED",
    "ftp-patator":                "UNMATCHED",   # credential attack
    "ssh-patator":                "UNMATCHED",
    "portscan":                   "recon_scanning",
}

_IOT23_LABEL_MAP: Dict[str, str] = {
    "benign":                     "benign",
    "-":                          "UNMATCHED",       # unknown is not benign
    "c&c":                        "UNMATCHED",
    "c&c-filedownload":           "UNMATCHED",
    "c&c-heartbeat":              "c2_beaconing",
    "c&c-mirai":                  "UNMATCHED",
    "c&c-torii":                  "UNMATCHED",
    "ddos":                       "volumetric_ddos",
    "filedownload":               "UNMATCHED",
    "okiru":                      "UNMATCHED",
    "partofahorizontalportscan": "recon_scanning",
    "scanning":                   "recon_scanning",
    "attack":                     "UNMATCHED",    # generic — not mappable
    "tunelling":                  "dga_dns_tunneling",  # dataset typo preserved
    "tunneling":                  "dga_dns_tunneling",
}

_DNS_LABEL_MAP: Dict[str, str] = {
    "benign":                     "benign",
    "normal":                     "benign",
    "dga":                        "dga_dns_tunneling",
    "tunneling":                  "dga_dns_tunneling",
    "tunnelling":                 "dga_dns_tunneling",
    "dns tunnel":                 "dga_dns_tunneling",
    "malware":                    "UNMATCHED",
}

LABEL_MAPS = {
    "cicddos2019": _CICDDOS2019_LABEL_MAP,
    "cicids2017":  _CICIDS2017_LABEL_MAP,
    "iot23":       _IOT23_LABEL_MAP,
    "dns":         _DNS_LABEL_MAP,
}


def map_label(raw: str, dataset: str) -> str:
    """Map a raw dataset label to a PS class, 'benign', or 'UNMATCHED'."""
    key = raw.strip().lower()
    mapping = LABEL_MAPS.get(dataset, {})
    return mapping.get(key, "UNMATCHED")


# ── Column alias resolver ─────────────────────────────────────────────────────

# Common header variants across dataset releases.
_ALIASES: Dict[str, List[str]] = {
    # forward-only columns (backward columns are never included)
    "dst_port":       ["destination port", "dst port", "dsport", "id.resp_p"],
    "protocol":       ["protocol", "proto"],
    "fwd_pkts":       ["total fwd packets", "tot fwd pkts", "spkts"],
    "fwd_bytes":      ["total length of fwd packets", "totlen fwd pkts", "sbytes"],
    "fwd_iat_mean":   ["fwd iat mean"],
    "fwd_iat_std":    ["fwd iat std"],
    "flow_iat_mean":  ["flow iat mean"],
    "flow_iat_std":   ["flow iat std"],
    "fwd_len_mean":   ["fwd packet length mean", "fwd pkt len mean"],
    "fwd_len_std":    ["fwd packet length std", "fwd pkt len std"],
    "fwd_len_min":    ["fwd packet length min", "fwd pkt len min"],
    "fwd_len_max":    ["fwd packet length max", "fwd pkt len max"],
    "flow_duration":  ["flow duration", "dur"],
    "ttl":            ["sttl", "fwd ttl"],
    "syn_count":      ["syn flag count", "syn flag cnt"],
    "label":          ["label", "attack_cat", "attack category", "class"],
    # DNS-specific
    "dns_query":      ["query", "qname", "dns.qry.name"],
    "dns_type":       ["qtype", "dns.qry.type", "type"],
}


def _resolve(headers: List[str]) -> Dict[str, int]:
    """Build column-name→index map, resolving aliases. Case-insensitive."""
    lower = {h.strip().lower(): i for i, h in enumerate(headers)}
    resolved: Dict[str, int] = {}
    for canonical, variants in _ALIASES.items():
        for variant in variants:
            if variant in lower:
                resolved[canonical] = lower[variant]
                break
    return resolved


def _f(row: List[str], col_map: Dict[str, int], key: str,
        default: Optional[float] = None) -> Optional[float]:
    """Safely read a float from a row; return default on missing/invalid."""
    idx = col_map.get(key)
    if idx is None or idx >= len(row):
        return default
    try:
        v = float(row[idx])
        return v if math.isfinite(v) else default
    except (ValueError, TypeError):
        return default


def _s(row: List[str], col_map: Dict[str, int], key: str) -> Optional[str]:
    """Safely read a string from a row."""
    idx = col_map.get(key)
    if idx is None or idx >= len(row):
        return None
    return row[idx].strip() or None


# ── Generic CSV → FlowRecord converter ───────────────────────────────────────

class ExternalObservation:
    """Partial source measurements, deliberately not a model-ready FlowRecord."""
    def __init__(self, fields, row_index):
        self.fields = fields
        self.row_index = row_index
        self.source = {}

    def model_dump_json(self):
        return json.dumps({"record_type": "external_observation", "row": self.row_index,
                           "measurements": self.fields, "source": self.source,
                           "model_ready": False,
                           "missing_features": ["entropy", "byte_ratio", "ja4"],
                           "note": "Re-extract PCAP for inference; CSV definitions differ from 120ms windows"})


def _csv_row_to_flow(row: List[str], col_map: Dict[str, int],
                     row_index: int) -> ExternalObservation:
    # Preserve source values and missingness. No proxy payload fraction, fake
    # TTL, current timestamp, or guessed duration units are supplied to models.
    fields = {name: _s(row, col_map, name) for name in col_map if name != "label"}
    return ExternalObservation(fields, row_index)


# ── Dataset-specific iterators ────────────────────────────────────────────────

def iter_cicddos2019(csv_dir: Path) -> Iterator[Tuple[FlowRecord, str]]:
    """Yield (FlowRecord, label) for every forward-direction-compatible row in CICDDoS2019."""
    return _iter_generic_csv(csv_dir, "cicddos2019",
                              required_cols={"label"},
                              note="Drop Bwd columns; src_port absent")


def iter_cicids2017(csv_dir: Path) -> Iterator[Tuple[FlowRecord, str]]:
    """Yield (FlowRecord, label) for CICIDS2017.  See also igu_sentinel/eval/cicids_converter.py."""
    return _iter_generic_csv(csv_dir, "cicids2017",
                              required_cols={"label"},
                              note="Partial observations; unrelated labels excluded")


def iter_iot23(csv_dir: Path) -> Iterator[Tuple[FlowRecord, str]]:
    """Yield (FlowRecord, label) for IoT-23 Zeek conn.log TSV."""
    # IoT-23 uses tab-separated Zeek conn.log format
    for csv_path in sorted(csv_dir.rglob("*.log*")):
        yield from _iter_zeek_conn_log(csv_path, "iot23")
    for csv_path in sorted(csv_dir.rglob("*.csv")):
        yield from _iter_generic_csv_file(csv_path, "iot23")


def iter_dns(csv_dir: Path) -> Iterator[Tuple[FlowRecord, str]]:
    """Yield (FlowRecord, label) for labelled DNS CSV datasets."""
    return _iter_generic_csv(csv_dir, "dns",
                              required_cols={"label"},
                              note="dns_ngram_entropy not computed from CSV query names here")


def _iter_generic_csv(csv_dir: Path, dataset: str, *,
                       required_cols=None,
                       note: str = "") -> Iterator[Tuple[FlowRecord, str]]:
    for path in sorted(csv_dir.rglob("*.csv")):
        yield from _iter_generic_csv_file(path, dataset)


def _iter_generic_csv_file(path: Path, dataset: str) -> Iterator[Tuple[FlowRecord, str]]:
    stats = {"rows": 0, "ok": 0, "unmatched": 0, "invalid": 0}
    try:
        with path.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            try:
                headers = next(reader)
            except StopIteration:
                return
            col_map = _resolve(headers)
            source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if "label" not in col_map:
                log.warning("%s: no label column found in %s — skipping", dataset, path.name)
                return
            for i, row in enumerate(reader):
                stats["rows"] += 1
                raw_label = _s(row, col_map, "label") or ""
                ps_label = map_label(raw_label, dataset)
                if ps_label == "UNMATCHED":
                    stats["unmatched"] += 1
                    continue
                flow = _csv_row_to_flow(row, col_map, i)
                if flow is None:
                    stats["invalid"] += 1
                    continue
                flow.source = {"path": str(path), "sha256": source_hash,
                               "row": i + 2, "raw_fields": dict(zip(headers, row))}
                stats["ok"] += 1
                yield flow, ps_label
    except Exception as exc:
        log.warning("Failed to read %s: %s", path, exc)
        return
    log.info("%s %s: %d rows, %d ok, %d unmatched, %d invalid",
             dataset, path.name, stats["rows"], stats["ok"],
             stats["unmatched"], stats["invalid"])


def _iter_zeek_conn_log(path: Path, dataset: str) -> Iterator[Tuple[FlowRecord, str]]:
    """Parse Zeek conn.log format (tab-separated with #fields header)."""
    col_map: Dict[str, int] = {}
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for row_number, line in enumerate(fh, 1):
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    headers = line.split()[1:]
                    # Map Zeek field names to our canonical names
                    zeek_map = {
                        "id.resp_p": "dst_port",
                        "proto": "protocol",
                        "duration": "flow_duration",
                        "orig_pkts": "fwd_pkts",
                        "orig_bytes": "fwd_bytes",
                        "label": "label",
                        "detailed-label": "label",
                    }
                    for idx, h in enumerate(headers):
                        canon = zeek_map.get(h)
                        if canon:
                            col_map[canon] = idx
                    continue
                if line.startswith("#"):
                    continue
                if not col_map:
                    continue
                row = line.split()
                raw_label = _s(row, col_map, "label") or ""
                ps_label = map_label(raw_label, dataset)
                if ps_label == "UNMATCHED":
                    continue
                flow = _csv_row_to_flow(row, col_map, row_number)
                if flow is not None:
                    yield flow, ps_label
    except Exception as exc:
        log.warning("Failed to read Zeek log %s: %s", path, exc)


# ── Fixture for tests (no download required) ──────────────────────────────────

# Tiny synthetic CSV rows exercising each adapter path.
CICDDOS2019_FIXTURE = """\
 Destination Port, Protocol, Fwd Packet Length Mean, Fwd Packet Length Std, Fwd Packet Length Min, Fwd Packet Length Max, Fwd IAT Mean, Fwd IAT Std, Total Fwd Packets, Total Length of Fwd Packets, Flow Duration, Syn Flag Count,  TTL, Label
 9999, 17, 1200.0, 0.0, 1200.0, 1200.0, 100.0, 5.0, 2000, 2400000, 200000, 0, 64, UDP
 443, 6, 800.0, 200.0, 64.0, 1500.0, 5000.0, 1000.0, 100, 80000, 500000, 1, 64, Benign
"""

IOT23_FIXTURE = """\
#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_pkts\torig_bytes\tlabel
1234567890.0\t192.168.1.1\t54321\t10.0.0.1\t80\ttcp\t1.5\t10\t1400\tC&C
1234567891.0\t192.168.1.2\t54322\t10.0.0.1\t443\ttcp\t0.5\t3\t200\t-
"""

DNS_FIXTURE = """\
query,qtype,label
aaaaabbbbbcccccdddddeeeeeffffff.evil.example,A,DGA
www.google.com,A,benign
"""


def load_fixture(dataset: str) -> str:
    """Return a tiny fixture CSV/log string for the given dataset."""
    return {
        "cicddos2019": CICDDOS2019_FIXTURE,
        "iot23":       IOT23_FIXTURE,
        "dns":         DNS_FIXTURE,
    }.get(dataset, "")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dataset", choices=list(LABEL_MAPS.keys()),
                        help="Dataset to convert")
    parser.add_argument("--csv-dir", type=Path, required=False,
                        help="Directory containing dataset CSV/log files")
    parser.add_argument("--output", type=Path,
                        help="Output JSONL file (default: stdout)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print label mapping and exit without writing output")
    parser.add_argument("--fixture", action="store_true",
                        help="Use built-in fixture rows (no download needed)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.dry_run:
        print(f"\nLabel mapping for '{args.dataset}':")
        for raw, ps in sorted(LABEL_MAPS[args.dataset].items()):
            marker = "  (UNMATCHED — excluded)" if ps == "UNMATCHED" else ""
            print(f"  {raw!r:<40} → {ps}{marker}")
        return

    if args.fixture:
        import io, tempfile, os
        fixture_text = load_fixture(args.dataset)
        if not fixture_text:
            print(f"No fixture for dataset '{args.dataset}'", file=sys.stderr)
            sys.exit(1)
        with tempfile.TemporaryDirectory() as directory:
            csv_dir = Path(directory)
            tmp = csv_dir / ("conn.log" if args.dataset == "iot23" else "fixture.csv")
            tmp.write_text(fixture_text)
            iterator = iter_iot23 if args.dataset == "iot23" else lambda d: _iter_generic_csv(d, args.dataset)
            rows = [{"label": label, "observation": json.loads(flow.model_dump_json())}
                    for flow, label in iterator(csv_dir)]
    else:
        if not args.csv_dir:
            parser.error("--csv-dir is required unless --fixture is set")
        if not args.csv_dir.is_dir():
            parser.error(f"--csv-dir {args.csv_dir} is not a directory")
        iterators = {"cicddos2019": iter_cicddos2019, "cicids2017": iter_cicids2017,
                     "iot23": iter_iot23, "dns": iter_dns}
        rows = []
        for flow, label in iterators[args.dataset](args.csv_dir):
            rows.append({"label": label, "observation": json.loads(flow.model_dump_json())})

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
        print(f"Wrote {len(rows)} rows to {args.output}")
    else:
        for row in rows:
            print(json.dumps(row))

    counts = {}
    for row in rows:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    print("\nLabel counts:")
    for lbl, cnt in sorted(counts.items()):
        print(f"  {lbl:<30} {cnt:>6}")


if __name__ == "__main__":
    main()
