"""Tests for live-interface ingest (P5B).

These tests mock the tshark subprocess so they verify the windowing/batching
logic and the live flow -> detect -> fusion -> alert -> /ws/alerts wiring WITHOUT
requiring real packet capture, a live interface, or root/setcap permissions in CI.
"""
import json
import time
import threading

import pytest

import igu_sentinel.ingest as ingest
from igu_sentinel.ingest import (
    _iter_json_objects,
    _build_flow_records,
    extract_flows_from_interface,
    extract_flows_from_pcap,
    LiveCaptureError,
)
from igu_sentinel.schemas import FlowRecord, Alert


# ── Helpers: a fake tshark process emitting -T json array text ────────────────

def _packet(src_ip, sport, dst_ip, dport, length, ts, proto="tcp"):
    layers = {
        "frame": {"frame.len": str(length), "frame.time_epoch": str(ts)},
        "ip": {"ip.src": src_ip, "ip.dst": dst_ip, "ip.ttl": "64"},
        proto: {f"{proto}.srcport": str(sport), f"{proto}.dstport": str(dport)},
    }
    return {"_source": {"layers": layers}}


def _tshark_json_lines(packets):
    """Render packet dicts as pretty-printed -T json array lines (as tshark does)."""
    text = json.dumps(packets, indent=2)
    return text.splitlines(keepends=True)


class _FakeProc:
    """Minimal stand-in for a subprocess.Popen returned by tshark."""

    def __init__(self, stdout_lines=None, stderr_text="", returncode=None, alive=True):
        self.stdout = iter(stdout_lines) if stdout_lines is not None else iter([])
        self.stderr = _FakeStderr(stderr_text)
        self._returncode = returncode
        self._alive = alive
        self.terminated = False

    def poll(self):
        return None if self._alive else self._returncode

    @property
    def returncode(self):
        return self._returncode

    def terminate(self):
        self.terminated = True
        self._alive = False
        self._returncode = 0

    def wait(self, timeout=None):
        return self._returncode

    def kill(self):
        self._alive = False


class _FakeStderr:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text


@pytest.fixture(autouse=True)
def _fast_startup(monkeypatch):
    """Shrink the live-capture startup grace so tests run quickly."""
    monkeypatch.setattr(ingest, "_LIVE_STARTUP_GRACE_S", 0.02)


# ── _iter_json_objects: incremental JSON array parsing ─────────────────────────

def test_iter_json_objects_parses_streamed_array():
    packets = [
        _packet("10.0.0.5", 1234, "10.0.0.9", 80, 64, 1700000000.0),
        _packet("10.0.0.5", 1235, "10.0.0.9", 443, 128, 1700000000.05),
    ]
    lines = _tshark_json_lines(packets)
    parsed = list(_iter_json_objects(lines))
    assert len(parsed) == 2
    assert parsed[0]["_source"]["layers"]["tcp"]["tcp.dstport"] == "80"
    assert parsed[1]["_source"]["layers"]["tcp"]["tcp.dstport"] == "443"


def test_iter_json_objects_ignores_braces_inside_strings():
    # A field value containing braces must not confuse the brace counter.
    pkt = _packet("10.0.0.5", 1234, "10.0.0.9", 80, 64, 1700000000.0)
    pkt["_source"]["layers"]["frame"]["frame.comment"] = "weird {value} with } braces"
    parsed = list(_iter_json_objects(_tshark_json_lines([pkt])))
    assert len(parsed) == 1
    assert parsed[0]["_source"]["layers"]["frame"]["frame.comment"] == "weird {value} with } braces"


# ── Shared flow construction: pcap and live use the same builder ───────────────

def test_build_flow_records_shared_path():
    packets = [
        _packet("10.0.0.5", 1234, "10.0.0.9", 80, 64, 1700000000.0),
        _packet("10.0.0.5", 1234, "10.0.0.9", 80, 66, 1700000000.01),  # same flow
        _packet("10.0.0.5", 1235, "10.0.0.9", 443, 128, 1700000000.02),  # different flow
    ]
    flows = _build_flow_records(packets, ja4_map={})
    assert len(flows) == 2
    for f in flows:
        assert isinstance(f, FlowRecord)
        assert f.protocol == "TCP"
        assert f.packet_size_stats["min"] > 0


# ── Windowing / batching of the live path ──────────────────────────────────────

def test_extract_flows_from_interface_windows_and_batches():
    packets = [
        _packet("10.0.0.5", 1234, "10.0.0.9", 80, 64, 1700000000.0),
        _packet("10.0.0.5", 1234, "10.0.0.9", 80, 66, 1700000000.01),
        _packet("10.0.0.5", 1235, "10.0.0.9", 443, 128, 1700000000.02),
    ]
    fake = _FakeProc(stdout_lines=_tshark_json_lines(packets), alive=True)

    def fake_popen(cmd, **kwargs):
        # verify the live command shape (live interface, line-buffered json)
        assert cmd[0] == "tshark"
        assert "-i" in cmd and "en_test" in cmd
        assert "-T" in cmd and "json" in cmd
        return fake

    windows = []
    for window_flows in extract_flows_from_interface("en_test", window_ms=60, _popen=fake_popen):
        windows.append(window_flows)
        if any(window_flows):  # got the batched flows; stop
            break

    all_flows = [f for w in windows for f in w]
    assert len(all_flows) == 2, f"expected 2 batched flows, got {len(all_flows)}"
    assert fake.terminated is True, "tshark process should be terminated on generator close"


# ── Graceful failure: bad interface / no permission ────────────────────────────

def test_extract_flows_from_interface_permission_error():
    # tshark exits immediately with a permission error on stderr.
    fake = _FakeProc(
        stdout_lines=[],
        stderr_text='tshark: You do not have permission to capture on device "en0".',
        returncode=2,
        alive=False,
    )
    gen = extract_flows_from_interface("en0", window_ms=60, _popen=lambda *a, **k: fake)
    with pytest.raises(LiveCaptureError) as exc:
        list(gen)
    assert "permission" in str(exc.value).lower()


def test_extract_flows_from_interface_tshark_missing():
    def raise_fnf(*a, **k):
        raise FileNotFoundError("tshark")

    gen = extract_flows_from_interface("en0", window_ms=60, _popen=raise_fnf)
    with pytest.raises(LiveCaptureError) as exc:
        list(gen)
    assert "tshark not found" in str(exc.value).lower()


# ── End-to-end wiring: live window -> detect -> alert -> /ws/alerts ────────────

def _load_fixture(threat_class, n=None):
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / f"{threat_class}_sample.jsonl"
    flows = [FlowRecord(**json.loads(l)) for l in open(path) if l.strip()]
    return flows[:n] if n else flows


def test_live_capture_broadcasts_alert_over_websocket(monkeypatch):
    """A live-captured window must produce an alert on the SAME /ws/alerts path."""
    from fastapi.testclient import TestClient
    import igu_sentinel.api as api

    attack_window = _load_fixture("volumetric_ddos", 2)

    def fake_live(interface, window_ms=120, stop_event=None, _popen=None):
        # First window: real attack flows. Then idle windows until stopped.
        yield attack_window
        while stop_event is None or not stop_event.is_set():
            yield []
            time.sleep(0.01)

    # Patch the name the worker resolves at call time.
    monkeypatch.setattr(api, "extract_flows_from_interface", fake_live)

    # NOTE: TestClient must be entered as a context manager so it keeps ONE
    # persistent event loop for the client's lifetime. The capture worker
    # broadcasts from a background thread onto the loop captured in
    # /capture/start; without a persistent loop TestClient closes it after each
    # request and the cross-thread broadcast would target a closed loop. Under a
    # real uvicorn server the loop lives for the whole process, so this matters
    # only for the in-process test harness.
    with TestClient(api.app) as client:
        with client.websocket_connect("/ws/alerts") as ws:
            resp = client.post("/capture/start", json={"interface": "en_test", "window_ms": 60})
            assert resp.status_code == 200, resp.text
            assert resp.json()["running"] in (True, False)  # running or already stopped

            alert = ws.receive_json()
            assert alert["flow_id"] == attack_window[0].flow_id
            assert alert["threat_class"] in {
                "volumetric_ddos", "c2_beaconing", "dga_dns_tunneling",
                "encrypted_malware", "recon_scanning", "data_exfiltration",
            }
            assert 0 <= alert["confidence_score"] <= 1
            assert isinstance(alert["evidence"], list)

        stop = client.post("/capture/stop")
        assert stop.status_code == 200
        assert stop.json()["alerts_emitted"] >= 1


def test_capture_start_rejects_missing_interface():
    from fastapi.testclient import TestClient
    import igu_sentinel.api as api

    client = TestClient(api.app)
    resp = client.post("/capture/start", json={})
    assert resp.status_code == 400
    assert "interface" in resp.json()["error"].lower()


def test_capture_start_reports_error_without_crashing(monkeypatch):
    """A capture that fails to start returns an error but leaves the API alive."""
    from fastapi.testclient import TestClient
    import igu_sentinel.api as api

    def failing_live(interface, window_ms=120, stop_event=None, _popen=None):
        raise LiveCaptureError(f"tshark could not capture on interface '{interface}': permission denied")
        yield  # pragma: no cover  (make it a generator)

    monkeypatch.setattr(api, "extract_flows_from_interface", failing_live)

    client = TestClient(api.app)
    resp = client.post("/capture/start", json={"interface": "bad0"})
    assert resp.status_code == 400
    assert resp.json()["status"] == "error"
    assert "permission denied" in resp.json()["error"]

    # Service still responds normally afterwards.
    assert client.get("/health").status_code == 200
