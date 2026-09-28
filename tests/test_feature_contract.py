"""Regression checks for measured v2 features, independent of model predictions."""
import ipaddress
import pytest
import igu_sentinel.ingest as ingest
from tests.test_live_ingest import _packet


def build(packets):
    return ingest._build_flow_records(packets, state=ingest.FlowState())


def test_rates_use_fixed_window_not_packet_spacing():
    flows = build([_packet('10.0.0.1', 1, '192.0.2.1', 443, 100, ts)
                   for ts in (12.01, 12.010001)])
    assert flows[0].pkt_rate == pytest.approx(2 / .12)
    assert flows[0].byte_rate == pytest.approx(200 / .12)


def test_entropy_aggregates_sources_to_same_target_only():
    flows = build([_packet(src, 1, dst, 443, 100, 12.01)
                   for src, dst in [('10.0.0.1', '192.0.2.1'),
                                    ('10.0.0.2', '192.0.2.1'),
                                    ('10.0.0.3', '192.0.2.2')]])
    assert [f.src_ip_entropy for f in flows] == [1.0, 1.0, 0.0]


def test_reverse_missing_is_unknown_and_observed_reverse_is_counted(monkeypatch):
    monkeypatch.setattr(ingest, 'PROTECTED_NETWORKS', [ipaddress.ip_network('10.0.0.0/8')])
    out = _packet('10.0.0.1', 1000, '192.0.2.1', 443, 100, 12.01)
    incoming = _packet('192.0.2.1', 443, '10.0.0.1', 1000, 60, 12.02)
    assert build([out])[0].inbound_bytes is None
    for flow in build([out, incoming]):
        assert flow.outbound_bytes == 100
        assert flow.inbound_bytes == 60


def test_nested_tshark_dns_and_syn_are_extracted():
    packet = _packet('10.0.0.1', 1000, '192.0.2.1', 53, 100, 12.01)
    layers = packet['_source']['layers']
    layers['tcp']['tcp.flags_tree'] = {'tcp.flags.syn': '1', 'tcp.flags.ack': '0'}
    layers['dns'] = {'Queries': {'example.test: type TXT': {
        'dns.qry.name': 'example.test', 'dns.qry.type': '16'}}}
    flow = build([packet])[0]
    assert flow.syn_count == 1
    assert flow.dns_record_type == 'TXT'
    assert flow.dns_query_len is not None


def test_v2_rejects_legacy_models_in_fresh_process():
    import os
    import subprocess
    import sys
    code = '''from igu_sentinel.detect import isoforest, xgb
from igu_sentinel.detect.features import FEATURE_DIM
assert FEATURE_DIM == 27
assert isoforest._current_state() is None
assert xgb._current_state() is None
'''
    result = subprocess.run([sys.executable, '-c', code], capture_output=True,
                            text=True, env={**os.environ, 'IGU_FEATURE_CONTRACT_VERSION': '2'})
    assert result.returncode == 0, result.stderr


def test_v2_training_roundtrip_isolated_from_serving_artifacts(tmp_path):
    import os
    import subprocess
    import sys
    code = '''import json, sys
from pathlib import Path
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.detect import isoforest, xgb
from igu_sentinel.detect.features import extract_features
root = Path(sys.argv[1])
isoforest._MODELS_DIR = xgb._MODELS_DIR = root
flows, labels = [], []
for name in ("benign", "volumetric_ddos"):
    for line in Path(f"tests/fixtures/{name}_sample.jsonl").read_text().splitlines():
        flows.append(FlowRecord.model_validate_json(line))
        labels.append(name)
isoforest.train_isoforest(flows[:5])
xgb.train_xgb(flows, labels)
assert isoforest._load_model_from_disk()
assert xgb._load_model_from_disk()
assert len(xgb.predict_xgb_batch(flows)) == len(flows)
assert len(isoforest.score_isoforest_batch(flows)) == len(flows)
f = flows[0].model_copy(update={"dns_query_len": 40})
assert extract_features(f)[26] == 40
# Absent version metadata must not authorize a v2 artifact.
p = next(root.glob("*.labels.json"))
metadata = json.loads(p.read_text())
del metadata["_feature_contract_version"]
p.write_text(json.dumps(metadata))
assert not xgb._load_model_from_disk()
'''
    result = subprocess.run([sys.executable, '-c', code, str(tmp_path)], capture_output=True,
                            text=True, env={**os.environ, 'IGU_FEATURE_CONTRACT_VERSION': '2'})
    assert result.returncode == 0, result.stderr
