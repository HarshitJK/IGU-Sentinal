#!/usr/bin/env python3
"""Extract public PCAPs through the streaming feature path, without inventing labels."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from igu_sentinel.ingest import iter_flows_from_pcap
from igu_sentinel.schemas import FEATURE_CONTRACT_VERSION

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--pcap', type=Path, required=True)
parser.add_argument('--labels', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
started = time.perf_counter()
count, counters = 0, {}
with (args.output / 'flows.jsonl').open('w') as output:
    for window in iter_flows_from_pcap(str(args.pcap), counters=counters):
        for flow in window:
            output.write(flow.model_dump_json() + '\n')
            count += 1
with args.labels.open() as source:
    labels = Counter(row['Label'] for row in csv.DictReader(source))
report = {'dataset': 'CTU-13 scenario 7 (CTU-Malware-Capture-Botnet-48)',
          'source': 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/',
          'citation': 'Garcia, Sebastian. Malware Capture Facility Project. https://stratosphereips.org; Garcia et al., An empirical comparison of botnet detection methods, Computers & Security 45 (2014), 100–123.',
          'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.pcap, args.labels)},
          'bytes': {p.name: p.stat().st_size for p in (args.pcap, args.labels)},
          'feature_contract_version': FEATURE_CONTRACT_VERSION,
          'extracted_flows': count, 'extraction_seconds': time.perf_counter() - started,
          'ingest_counters': counters, 'original_label_counts': dict(labels),
          'label_join_status': 'Not joined: full-network flow labels and botnet-only PCAP cover different populations; timestamps/timezone and interval joins need validation',
          'training_eligible': False}
(args.output / 'provenance.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
