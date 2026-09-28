"""Test detect/stats.py z-score baseline anomaly detector."""
import json
from pathlib import Path
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.detect.stats import train_stats_baseline, detect_stats


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture_flows(threat_class: str) -> list[FlowRecord]:
    """Load flows from a fixture file."""
    fixture_file = FIXTURES_DIR / f"{threat_class}_sample.jsonl"
    flows = []
    with open(fixture_file) as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                flows.append(FlowRecord(**data))
    return flows


def test_stats_train_baseline():
    """Stats detector should successfully train on benign flows."""
    benign_flows = load_fixture_flows("benign")
    train_stats_baseline(benign_flows)
    print(f"✓ test_stats_train_baseline passed (trained on {len(benign_flows)} flows)")


def test_stats_detect_benign_low():
    """Stats detector should score benign flows low."""
    benign_flows = load_fixture_flows("benign")
    train_stats_baseline(benign_flows)

    scores = []
    for flow in benign_flows:
        score = detect_stats(flow)
        assert score.flow_id == flow.flow_id
        assert score.layer_name == "stats"
        scores.append(score.calibrated_probability)

    # Average benign score should be low
    avg_benign_score = sum(scores) / len(scores)
    assert avg_benign_score < 0.5, f"Benign avg score {avg_benign_score} should be < 0.5"
    print(f"✓ test_stats_detect_benign_low passed (avg benign score: {avg_benign_score:.3f})")


def test_stats_detect_ddos_high():
    """Stats detector should score volumetric DDoS attacks high."""
    benign_flows = load_fixture_flows("benign")
    train_stats_baseline(benign_flows)

    ddos_flows = load_fixture_flows("volumetric_ddos")
    scores = []
    for flow in ddos_flows:
        score = detect_stats(flow)
        assert score.flow_id == flow.flow_id
        scores.append(score.calibrated_probability)

    # Average DDoS score should be high
    avg_ddos_score = sum(scores) / len(scores)
    assert avg_ddos_score > 0.5, f"DDoS avg score {avg_ddos_score} should be > 0.5"
    print(f"✓ test_stats_detect_ddos_high passed (avg DDoS score: {avg_ddos_score:.3f})")


def test_stats_detect_beaconing_high():
    """Stats detector should score C2 beaconing high."""
    benign_flows = load_fixture_flows("benign")
    train_stats_baseline(benign_flows)

    c2_flows = load_fixture_flows("c2_beaconing")
    scores = []
    for flow in c2_flows:
        score = detect_stats(flow)
        scores.append(score.calibrated_probability)

    # Average C2 score should be moderate to high
    avg_c2_score = sum(scores) / len(scores)
    assert avg_c2_score > 0.3, f"C2 avg score {avg_c2_score} should be > 0.3"
    print(f"✓ test_stats_detect_beaconing_high passed (avg C2 score: {avg_c2_score:.3f})")


def test_stats_detect_exfil_high():
    """Stats detector should score data exfiltration high."""
    benign_flows = load_fixture_flows("benign")
    train_stats_baseline(benign_flows)

    exfil_flows = load_fixture_flows("data_exfiltration")
    scores = []
    for flow in exfil_flows:
        score = detect_stats(flow)
        scores.append(score.calibrated_probability)

    # Exfiltration has large bytes and high byte_ratio, should score high
    avg_exfil_score = sum(scores) / len(scores)
    assert avg_exfil_score > 0.5, f"Exfiltration avg score {avg_exfil_score} should be > 0.5"
    print(f"✓ test_stats_detect_exfil_high passed (avg exfil score: {avg_exfil_score:.3f})")


def test_stats_returns_valid_score():
    """Stats detector should return valid LayerScore."""
    benign_flows = load_fixture_flows("benign")
    train_stats_baseline(benign_flows)

    flow = benign_flows[0]
    score = detect_stats(flow)

    assert score.flow_id == flow.flow_id
    assert score.layer_name == "stats"
    assert 0 <= score.raw_score <= 1
    assert 0 <= score.calibrated_probability <= 1
    print("✓ test_stats_returns_valid_score passed")


def test_stats_baseline_thread_safe():
    """train_stats_baseline and detect_stats must not race under concurrent access.

    This is a regression test for the RLock added in detect/stats.py.  Without
    the lock a concurrent retrain that swaps _baseline mid-read in detect_stats
    can either produce a KeyError (partial dict) or use a mix of old/new values.
    """
    import threading
    from igu_sentinel.detect import stats as stats_mod

    benign_flows = load_fixture_flows("benign")
    train_stats_baseline(benign_flows)

    errors = []

    def _detect_loop():
        for flow in benign_flows * 20:
            try:
                detect_stats(flow)
            except Exception as exc:
                errors.append(f"detect: {exc}")

    def _retrain_loop():
        for _ in range(10):
            try:
                train_stats_baseline(benign_flows)
            except Exception as exc:
                errors.append(f"retrain: {exc}")

    threads = [threading.Thread(target=_detect_loop) for _ in range(4)]
    threads += [threading.Thread(target=_retrain_loop) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not errors, f"Thread-safety errors: {errors}"
    print("✓ test_stats_baseline_thread_safe passed")
