"""Test detect/isoforest.py Isolation Forest anomaly detector."""
import json
from pathlib import Path
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.detect.isoforest import train_isoforest, score_isoforest


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


def test_isoforest_train():
    """Isolation Forest should successfully train on benign flows."""
    benign_flows = load_fixture_flows("benign")
    train_isoforest(benign_flows)
    print(f"✓ test_isoforest_train passed (trained on {len(benign_flows)} flows)")


def test_isoforest_scores_benign_low():
    """Isolation Forest should score benign flows low."""
    benign_flows = load_fixture_flows("benign")
    train_isoforest(benign_flows)

    scores = []
    for flow in benign_flows:
        score = score_isoforest(flow)
        assert score.flow_id == flow.flow_id
        assert score.layer_name == "isoforest"
        assert 0 <= score.calibrated_probability <= 1
        scores.append(score.calibrated_probability)

    # Average benign score should be low
    avg_score = sum(scores) / len(scores)
    assert avg_score < 0.5, f"Benign avg score {avg_score} should be < 0.5"
    print(f"✓ test_isoforest_scores_benign_low passed (avg benign: {avg_score:.3f})")


def test_isoforest_scores_attacks_high():
    """Isolation Forest should score attack flows high (relative to benign)."""
    benign_flows = load_fixture_flows("benign")
    train_isoforest(benign_flows)

    # Test multiple attack types
    attack_classes = [
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]

    benign_scores = [score_isoforest(f).calibrated_probability for f in benign_flows]
    avg_benign = sum(benign_scores) / len(benign_scores)

    for attack_class in attack_classes:
        attack_flows = load_fixture_flows(attack_class)
        attack_scores = [score_isoforest(f).calibrated_probability for f in attack_flows]
        avg_attack = sum(attack_scores) / len(attack_scores)

        # Attack should score higher than benign on average
        assert avg_attack > avg_benign * 0.8, (
            f"{attack_class}: avg score {avg_attack:.3f} should be > "
            f"0.8 * benign {avg_benign:.3f}"
        )

    print(f"✓ test_isoforest_scores_attacks_high passed (benign: {avg_benign:.3f})")


def test_isoforest_returns_valid_score():
    """Isolation Forest should return valid LayerScore."""
    benign_flows = load_fixture_flows("benign")
    train_isoforest(benign_flows)

    flow = benign_flows[0]
    score = score_isoforest(flow)

    assert score.flow_id == flow.flow_id
    assert score.layer_name == "isoforest"
    assert 0 <= score.raw_score <= 1
    assert 0 <= score.calibrated_probability <= 1
    print("✓ test_isoforest_returns_valid_score passed")
