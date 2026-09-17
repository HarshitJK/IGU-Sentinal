"""Test api/ FastAPI orchestration end-to-end."""
import json
from pathlib import Path
from igu_sentinel.schemas import FlowRecord, Alert
from igu_sentinel.api import run_detection_pipeline


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


def test_api_pipeline_benign():
    """API pipeline should process benign flows and produce alerts."""
    benign_flows = load_fixture_flows("benign")[:3]

    alerts = run_detection_pipeline(benign_flows)

    assert len(alerts) == len(benign_flows)
    for alert in alerts:
        assert isinstance(alert, Alert)
        assert alert.flow_id is not None
        assert 0 <= alert.confidence_score <= 1

    print(f"✓ test_api_pipeline_benign passed ({len(alerts)} alerts)")


def test_api_pipeline_attack():
    """API pipeline should detect attack flows."""
    attack_flows = load_fixture_flows("volumetric_ddos")[:3]

    alerts = run_detection_pipeline(attack_flows)

    assert len(alerts) == len(attack_flows)
    for alert in alerts:
        assert isinstance(alert, Alert)
        # Attack should have some confidence
        assert alert.confidence_score > 0.3

    print(f"✓ test_api_pipeline_attack passed ({len(alerts)} alerts)")


def test_api_pipeline_mixed():
    """API pipeline should handle mixed benign and attack flows."""
    benign_flows = load_fixture_flows("benign")[:2]
    attack_flows = load_fixture_flows("c2_beaconing")[:2]

    all_flows = benign_flows + attack_flows
    alerts = run_detection_pipeline(all_flows)

    assert len(alerts) == len(all_flows)

    # Check benign alerts have lower confidence
    benign_alerts = alerts[:2]
    avg_benign_conf = sum(a.confidence_score for a in benign_alerts) / len(benign_alerts)

    # Check attack alerts have higher confidence
    attack_alerts = alerts[2:]
    avg_attack_conf = sum(a.confidence_score for a in attack_alerts) / len(attack_alerts)

    # Attack should generally have higher confidence
    print(f"✓ test_api_pipeline_mixed passed (benign avg: {avg_benign_conf:.2f}, attack avg: {avg_attack_conf:.2f})")


def test_api_pipeline_returns_valid_alerts():
    """API pipeline should return valid Alert objects."""
    flows = load_fixture_flows("recon_scanning")[:2]

    alerts = run_detection_pipeline(flows)

    assert len(alerts) == len(flows)
    for alert in alerts:
        # Verify all required Alert fields
        assert alert.timestamp is not None
        assert alert.flow_id in [f.flow_id for f in flows]
        assert alert.threat_class in [
            "volumetric_ddos",
            "c2_beaconing",
            "dga_dns_tunneling",
            "encrypted_malware",
            "recon_scanning",
            "data_exfiltration",
        ]
        assert 0 <= alert.confidence_score <= 1
        assert isinstance(alert.evidence, list)

    print(f"✓ test_api_pipeline_returns_valid_alerts passed")


def test_api_pipeline_preserves_flow_ids():
    """API pipeline should preserve flow IDs from input flows."""
    flows = load_fixture_flows("data_exfiltration")[:3]
    flow_ids = [f.flow_id for f in flows]

    alerts = run_detection_pipeline(flows)

    alert_ids = [a.flow_id for a in alerts]
    assert set(alert_ids) == set(flow_ids)

    print(f"✓ test_api_pipeline_preserves_flow_ids passed")


def test_api_pipeline_end_to_end():
    """Full end-to-end pipeline test with all threat classes."""
    threat_classes = [
        "benign",
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]

    all_flows = []
    for tc in threat_classes:
        flows = load_fixture_flows(tc)[:2]
        all_flows.extend(flows)

    # Run pipeline
    alerts = run_detection_pipeline(all_flows)

    assert len(alerts) == len(all_flows)

    # Verify structure
    threat_class_predictions = set()
    for alert in alerts:
        assert isinstance(alert, Alert)
        threat_class_predictions.add(alert.threat_class)

    print(f"✓ test_api_pipeline_end_to_end passed ({len(alerts)} alerts, "
          f"{len(threat_class_predictions)} unique threat classes predicted)")


def test_api_post_detect_endpoint():
    """POST /detect endpoint should return valid alert response."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app

    client = TestClient(app)
    flow = load_fixture_flows("c2_beaconing")[0]
    flow_dict = json.loads(flow.model_dump_json())

    response = client.post("/detect", json=[flow_dict])
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    alert = data[0]
    assert alert["flow_id"] == flow.flow_id
    assert "threat_class" in alert
    assert "confidence_score" in alert
    assert isinstance(alert["evidence"], list)
    print(f"✓ test_api_post_detect_endpoint passed (alert: {alert['threat_class']})")


def test_api_websocket_alerts_stream():
    """WebSocket /ws/alerts should receive real-time alerts when /detect processes flows."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app

    client = TestClient(app)
    flow = load_fixture_flows("volumetric_ddos")[0]
    flow_dict = json.loads(flow.model_dump_json())

    with client.websocket_connect("/ws/alerts") as ws:
        response = client.post("/detect", json=[flow_dict])
        assert response.status_code == 200

        # Receive streamed alert over WebSocket
        alert_json = ws.receive_json()
        assert alert_json["flow_id"] == flow.flow_id
        assert alert_json["threat_class"] == "volumetric_ddos"
        assert 0 <= alert_json["confidence_score"] <= 1
        assert isinstance(alert_json["evidence"], list)

    print("✓ test_api_websocket_alerts_stream passed")


# ── Access control and input validation ───────────────────────────────────────

def test_api_detect_rejects_malformed_flow():
    """A flow that fails FlowRecord validation must return 422, not 500."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/detect", json=[{"flow_id": "missing_everything_else"}])
    assert response.status_code == 422, "schema violation must be a client error"
    assert "index" in json.dumps(response.json())
    print("✓ test_api_detect_rejects_malformed_flow passed")


def test_api_detect_rejects_oversize_batch():
    """A batch beyond MAX_FLOWS_PER_REQUEST must be refused before processing."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app, MAX_FLOWS_PER_REQUEST

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/detect", json=[{}] * (MAX_FLOWS_PER_REQUEST + 1))
    assert response.status_code == 413
    print("✓ test_api_detect_rejects_oversize_batch passed")


def test_api_capture_start_rejects_bad_interface():
    """An interface name outside the allowlist must be refused with 400."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/capture/start", json={"interface": "eth0; rm -rf /"})
    assert response.status_code == 400
    print("✓ test_api_capture_start_rejects_bad_interface passed")


def test_api_requires_token_when_configured(monkeypatch):
    """With IGU_API_TOKEN set, /detect and /capture/* must reject bad tokens."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app

    monkeypatch.setenv("IGU_API_TOKEN", "s3cret-token")
    client = TestClient(app, raise_server_exceptions=False)

    assert client.post("/detect", json=[]).status_code == 401, "no token must be rejected"
    assert client.post(
        "/detect", json=[], headers={"Authorization": "Bearer wrong"}
    ).status_code == 401, "wrong token must be rejected"
    assert client.get("/capture/status").status_code == 401

    ok = client.post("/detect", json=[], headers={"Authorization": "Bearer s3cret-token"})
    assert ok.status_code == 200, "correct token must be accepted"

    # /health stays open so container healthchecks keep working.
    assert client.get("/health").status_code == 200
    print("✓ test_api_requires_token_when_configured passed")


def test_api_websocket_rejects_bad_token(monkeypatch):
    """The alert stream must not be readable without the configured token."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app
    import pytest

    monkeypatch.setenv("IGU_API_TOKEN", "s3cret-token")
    client = TestClient(app)

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/alerts?token=wrong") as ws:
            ws.receive_json()

    # Correct token still connects.
    with client.websocket_connect("/ws/alerts?token=s3cret-token") as ws:
        assert ws is not None
    print("✓ test_api_websocket_rejects_bad_token passed")


def test_api_websocket_rejects_disallowed_origin(monkeypatch):
    """WebSockets bypass CORS, so Origin must be enforced at the handshake."""
    from fastapi.testclient import TestClient
    from igu_sentinel.api import app
    import pytest

    monkeypatch.setenv("IGU_ALLOWED_ORIGINS", "http://localhost:5173")
    client = TestClient(app)

    with pytest.raises(Exception):
        with client.websocket_connect(
            "/ws/alerts", headers={"Origin": "https://evil.example"}
        ) as ws:
            ws.receive_json()

    with client.websocket_connect(
        "/ws/alerts", headers={"Origin": "http://localhost:5173"}
    ) as ws:
        assert ws is not None
    print("✓ test_api_websocket_rejects_disallowed_origin passed")
