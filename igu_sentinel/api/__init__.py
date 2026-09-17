"""FastAPI app orchestrating the detection pipeline with concurrent layer execution and WebSocket streaming.

Pipeline Architecture:
  - Detection layers are evaluated per capture window, not per flow. rules and
    stats run straight through (pure Python, >350k flows/sec); isoforest and xgb
    are called ONCE for the whole window via their batch entry points, because
    their fixed per-call model overhead — not the per-row work — is what limits
    throughput. See _score_batch() for the measurements.
  - The whole batch is scored in a worker thread (asyncio.to_thread) so the
    event loop stays responsive to WebSocket clients while a window is scored.
  - Fusion correlates LayerScores into an Alert with confidence scoring.
  - Alert logging applies SHA-256 hash chaining.
  - Real-time streaming broadcasts alerts over WebSocket at /ws/alerts to connected dashboards.
"""
import asyncio
import hmac
import json
import logging
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import ValidationError
from igu_sentinel.schemas import FlowRecord, Alert, LayerScore
from igu_sentinel.detect.rules import detect_rules
from igu_sentinel.detect.stats import train_stats_baseline, detect_stats
from igu_sentinel.detect.isoforest import score_isoforest, score_isoforest_batch  # loaded at import
from igu_sentinel.detect.xgb import predict_xgb, predict_xgb_batch                # loaded at import
from igu_sentinel.fusion import fuse_layers, is_actionable_alert
from igu_sentinel.alert import log_alert
from igu_sentinel.drift import monitor_drift, submit_confirmed_benign
from igu_sentinel.ingest import (
    extract_flows_from_interface,
    LiveCaptureError,
    DEFAULT_WINDOW_MS,
)

log = logging.getLogger(__name__)
app = FastAPI(title="IGU Sentinel", description="Passive Diode-Fed Threat Detection System")

# ── Access control ────────────────────────────────────────────────────────────
# This service exposes packet capture control and a live threat-alert feed. Both
# were originally unauthenticated, which meant anyone who could reach the port
# could start a capture on any interface of the host, or subscribe to the alert
# stream. WebSockets are NOT covered by the browser same-origin policy, so any
# web page the operator visited could open ws://<host>/ws/alerts and read the
# feed — hence the explicit Origin check below in addition to CORS.
#
# Auth is enabled by setting IGU_API_TOKEN. It is off by default so the local
# demo still runs with no setup; _warn_if_unauthenticated() makes that loud.
_TOKEN_ENV = "IGU_API_TOKEN"
_ORIGINS_ENV = "IGU_ALLOWED_ORIGINS"

# Upper bound on a single /detect request. Without it, one request could pin
# arbitrary memory and occupy the thread pool indefinitely.
MAX_FLOWS_PER_REQUEST = int(os.environ.get("IGU_MAX_FLOWS_PER_REQUEST", "10000"))

# A slow or wedged WebSocket client must not stall the broadcast to everyone
# else, nor the capture thread feeding it.
_WS_SEND_TIMEOUT_S = 2.0

# The alert stream is server-push; clients have nothing to say. Anything larger
# than a keepalive is refused rather than buffered.
_WS_MAX_CLIENT_MESSAGE_BYTES = 4096

# Interface names are passed to tshark. argv is a list (no shell), so this is
# not command injection, but the allowlist keeps the surface tight and gives a
# clear 400 instead of an opaque tshark failure.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _configured_token() -> Optional[str]:
    token = os.environ.get(_TOKEN_ENV)
    return token if token else None


def _allowed_origins() -> List[str]:
    raw = os.environ.get(_ORIGINS_ENV, "")
    return [o.strip() for o in raw.split(",") if o.strip()]


def _warn_if_unauthenticated() -> None:
    if _configured_token() is None:
        log.warning(
            "%s is not set: /detect, /capture/* and /ws/alerts are UNAUTHENTICATED. "
            "Set %s before exposing this service beyond localhost.",
            _TOKEN_ENV,
            _TOKEN_ENV,
        )


_warn_if_unauthenticated()

# CORS is deny-by-default: with no IGU_ALLOWED_ORIGINS the browser blocks
# cross-origin calls, which is what we want for a same-origin dashboard. The
# Vite dev server proxies /detect, /capture and /ws, so development needs no
# entry here either.
if _allowed_origins():
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )


def require_token(authorization: Optional[str] = Header(default=None)) -> None:
    """Reject the request when IGU_API_TOKEN is set and the bearer token is wrong.

    Compared with :func:`hmac.compare_digest` so a wrong token cannot be
    recovered by timing the response.
    """
    expected = _configured_token()
    if expected is None:
        return
    supplied = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization.split(" ", 1)[1].strip()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")


def _websocket_authorized(websocket: WebSocket) -> bool:
    """Authorize a WebSocket handshake by Origin and, if configured, token.

    The browser same-origin policy does not apply to WebSockets, so the Origin
    header must be checked here or any site could subscribe to the alert feed.
    """
    allowed = _allowed_origins()
    origin = websocket.headers.get("origin")
    # A browser always sends Origin; non-browser clients (tests, CLI) do not.
    if origin is not None and allowed and origin not in allowed:
        log.warning("rejected WebSocket from disallowed origin %s", origin)
        return False

    expected = _configured_token()
    if expected is None:
        return True
    supplied = websocket.query_params.get("token", "")
    auth = websocket.headers.get("authorization", "")
    if not supplied and auth.lower().startswith("bearer "):
        supplied = auth.split(" ", 1)[1].strip()
    return hmac.compare_digest(supplied, expected)


# ── WebSocket connection manager ──────────────────────────────────────────────
class ConnectionManager:
    """Manages active WebSocket connections for streaming real-time alerts."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        log.info("WebSocket client connected. Active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        log.info("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast_alert(self, alert: Alert):
        """Broadcast an Alert as JSON to all active WebSocket connections.

        Sends run concurrently with a per-connection timeout. Sending serially
        without a timeout let one wedged client stall the broadcast for every
        other client — and, on the live-capture path, stall the capture thread
        that was waiting on this coroutine. A client that times out is treated
        as dead and dropped.
        """
        if not self.active_connections:
            return

        payload = {
            "timestamp": alert.timestamp.isoformat(),
            "flow_id": alert.flow_id,
            "threat_class": alert.threat_class,
            "confidence_score": alert.confidence_score,
            "evidence": alert.evidence,
        }

        connections = list(self.active_connections)

        async def _send(conn: WebSocket) -> bool:
            try:
                await asyncio.wait_for(conn.send_json(payload), timeout=_WS_SEND_TIMEOUT_S)
                return True
            except Exception:
                return False

        results = await asyncio.gather(
            *(_send(c) for c in connections), return_exceptions=True
        )
        for conn, ok in zip(connections, results):
            if ok is not True:
                self.disconnect(conn)


manager = ConnectionManager()


def _feed_drift_monitor(
    scored: List[tuple], flows: List[FlowRecord]
) -> None:
    """Route each batch's isoforest scores and benign verdicts into drift/.

    Two separate jobs, both required by CLAUDE.md and neither of which was
    connected to anything before — drift/ existed but nothing ever called it:

      * Drift monitoring reads the isoforest anomaly-score distribution.
      * The retrain pool accepts only flows the FUSED cross-layer verdict
        cleared, never flows isoforest merely scored low. Retraining on what the
        model already likes is the poisoning path the PS constraints rule out.

    Never allowed to break scoring: a drift bookkeeping error must not drop a
    detection.
    """
    try:
        iso_scores = [
            s.raw_score
            for layer_scores, _alert in scored
            for s in layer_scores
            if s.layer_name == "isoforest"
        ]
        if iso_scores and monitor_drift(iso_scores):
            log.warning(
                "drift detected in isoforest score distribution — "
                "retrain is gated on the confirmed-benign pool and the boundary bound"
            )

        confirmed_benign = [
            flow
            for flow, (layer_scores, alert) in zip(flows, scored)
            if not is_actionable_alert(layer_scores, alert)
        ]
        if confirmed_benign:
            submit_confirmed_benign(confirmed_benign)
    except Exception:
        log.exception("drift monitoring failed (scoring unaffected)")


def _log_broadcast_failure(fut) -> None:
    """Surface a failed fire-and-forget broadcast without blocking the caller."""
    try:
        fut.result()
    except Exception:
        log.exception("live capture: alert broadcast failed")


# ── Live capture controller ───────────────────────────────────────────────────
class CaptureController:
    """Runs a live tshark capture in a background thread and feeds each fixed
    window's flows through the SAME detection pipeline used by POST /detect,
    hash-logging every alert and broadcasting it to the SAME /ws/alerts clients.

    The worker isolates all capture failures: a bad interface or missing capture
    permission is recorded as an error state and never crashes the API process.
    """

    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._stop_event: Optional[threading.Event] = None
        self._lock = threading.Lock()
        self.state: dict = {
            "status": "idle",          # idle | starting | running | stopped | error
            "interface": None,
            "window_ms": None,
            "windows_processed": 0,
            "alerts_emitted": 0,
            "alerts_suppressed": 0,
            "flows_scored": 0,
            "error": None,
            "started_at": None,
        }

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> dict:
        s = dict(self.state)
        s["running"] = self.is_running()
        return s

    def start(self, interface: str, window_ms: int, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            if self.is_running():
                raise RuntimeError(f"capture already running on '{self.state.get('interface')}'")
            self._stop_event = threading.Event()
            self.state = {
                "status": "starting",
                "interface": interface,
                "window_ms": window_ms,
                "windows_processed": 0,
                "alerts_emitted": 0,
                "alerts_suppressed": 0,
                "flows_scored": 0,
                "error": None,
                "started_at": datetime.now().isoformat(),
            }
            self._thread = threading.Thread(
                target=self._worker,
                args=(interface, window_ms, loop, self._stop_event),
                name="live-capture",
                daemon=True,
            )
            self._thread.start()

    def _worker(
        self,
        interface: str,
        window_ms: int,
        loop: asyncio.AbstractEventLoop,
        stop_event: threading.Event,
    ) -> None:
        try:
            _ensure_stats_baseline()
            for window_flows in extract_flows_from_interface(interface, window_ms, stop_event):
                if stop_event.is_set():
                    break
                # First yielded window (even empty) confirms capture is live.
                self.state["status"] = "running"
                self.state["windows_processed"] += 1
                if not window_flows:
                    continue
                # Same pipeline as POST /detect: rules+stats+isoforest+xgb -> fusion.
                scored = run_detection_pipeline_scored(window_flows)
                self.state["flows_scored"] += len(scored)
                for scores, alert in scored:
                    # Only surface alerts the layers actually stand behind.
                    # Without this every observed flow — including idle
                    # background chatter — became an alert.
                    if not is_actionable_alert(scores, alert):
                        self.state["alerts_suppressed"] += 1
                        continue
                    log_alert(alert)
                    self.state["alerts_emitted"] += 1
                    # Broadcast on the main event loop where the WS clients live.
                    # Fire-and-forget: blocking the capture thread on each
                    # broadcast made dashboard latency backpressure the capture
                    # itself, so a slow client dropped packets. Delivery errors
                    # are reported by the callback; the broadcast has its own
                    # per-connection timeout.
                    try:
                        fut = asyncio.run_coroutine_threadsafe(
                            manager.broadcast_alert(alert), loop
                        )
                        fut.add_done_callback(_log_broadcast_failure)
                    except Exception:
                        log.exception("live capture: could not schedule alert broadcast")
        except LiveCaptureError as exc:
            self.state["status"] = "error"
            self.state["error"] = str(exc)
            log.warning("live capture error: %s", exc)
            return
        except Exception as exc:  # never let capture crash the service
            self.state["status"] = "error"
            self.state["error"] = f"{type(exc).__name__}: {exc}"
            log.exception("live capture worker crashed")
            return
        if self.state.get("status") != "error":
            self.state["status"] = "stopped"

    def stop(self) -> None:
        with self._lock:
            if self._stop_event is not None:
                self._stop_event.set()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=6)
            if thread.is_alive():
                # Reporting "stopped" while the worker is still running told the
                # operator the capture had ended when it had not.
                self.state["status"] = "stopping"
                self.state["error"] = "capture thread did not stop within 6s"
                return
        if self.state.get("status") == "idle":
            # Nothing was ever started; "stopped" would imply otherwise.
            return
        if self.state.get("status") != "error":
            self.state["status"] = "stopped"


capture = CaptureController()


# ── One-time startup state ────────────────────────────────────────────────────
_stats_trained: bool = False
# The capture worker thread and request handlers both reach this, so the
# "train once" flag needs a lock: two threads could both observe False and both
# call train_stats_baseline(), which rebinds detect/stats.py's module-global
# baseline while another thread is reading it.
_stats_lock = threading.Lock()


def _ensure_stats_baseline() -> None:
    """Train stats baseline from benign fixture once on first use (thread-safe)."""
    global _stats_trained
    if _stats_trained:
        return
    with _stats_lock:
        if _stats_trained:      # re-check: another thread may have won the race
            return
        _train_stats_baseline_once()


def _train_stats_baseline_once() -> None:
    """Load the benign corpus and fit the z-score baseline. Caller holds the lock."""
    global _stats_trained

    fixtures_dir = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
    benign_file = fixtures_dir / "benign_sample.jsonl"
    benign_flows: list[FlowRecord] = []
    if benign_file.exists():
        with open(benign_file) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    benign_flows.append(FlowRecord(**json.loads(line)))

    if benign_flows:
        train_stats_baseline(benign_flows)
        log.info("stats baseline trained on %d benign flows", len(benign_flows))
    else:
        log.warning("benign fixture not found — stats baseline not trained")

    _stats_trained = True


# ── Concurrent Detection Pipeline ─────────────────────────────────────────────

async def detect_flow_scored_async(flow: FlowRecord) -> tuple[List[LayerScore], Alert]:
    """Run all 4 detection layers concurrently, returning the scores AND the alert.

    The per-layer scores are returned alongside the fused Alert because the
    emission gate (fusion.is_actionable_alert) needs to know whether any layer
    actually named a threat class — an Alert alone cannot express "benign".

    CPU-bound scoring functions (sklearn IsolationForest, XGBoost) are executed
    in worker threads via asyncio.to_thread() to avoid blocking the asyncio event loop.
    """
    scores = list(await asyncio.gather(
        asyncio.to_thread(detect_rules, flow),
        asyncio.to_thread(detect_stats, flow),
        asyncio.to_thread(score_isoforest, flow),
        asyncio.to_thread(predict_xgb, flow),
    ))
    return scores, fuse_layers(scores)


async def detect_flow_async(flow: FlowRecord) -> Alert:
    """Run all 4 detection layers concurrently on a single FlowRecord."""
    _scores, alert = await detect_flow_scored_async(flow)
    return alert


def _score_batch(flows: List[FlowRecord]) -> List[tuple[List[LayerScore], Alert]]:
    """Score a whole window of flows, batching the two model layers.

    The ML layers dominate cost and both carry a large fixed per-call overhead,
    so they are called once for the batch rather than once per flow. Measured on
    the fixture corpus, per-flow scoring ran the pipeline at ~130 flows/sec with
    Isolation Forest alone costing 6.8 ms per flow; batching the same work lifts
    it by roughly two orders of magnitude. rules and stats are pure Python at
    >350k flows/sec, so they stay per-flow where they are already free.

    Ordering is preserved: each layer returns one score per input flow, in
    input order, and fusion is applied per flow afterwards.
    """
    if not flows:
        return []

    rules_scores = [detect_rules(f) for f in flows]
    stats_scores = [detect_stats(f) for f in flows]
    iso_scores = score_isoforest_batch(flows)
    xgb_scores = predict_xgb_batch(flows)

    results: List[tuple[List[LayerScore], Alert]] = []
    for r, st, iso, xg in zip(rules_scores, stats_scores, iso_scores, xgb_scores):
        scores = [r, st, iso, xg]
        results.append((scores, fuse_layers(scores)))
    return results


async def run_detection_pipeline_scored_async(
    flows: List[FlowRecord],
) -> List[tuple[List[LayerScore], Alert]]:
    """Run the pipeline over a batch, keeping each flow's LayerScores.

    The CPU-bound scoring runs in a worker thread so the event loop stays free
    to serve WebSocket clients and other requests while a window is scored.
    """
    if not flows:
        return []
    _ensure_stats_baseline()
    scored = await asyncio.to_thread(_score_batch, flows)
    _feed_drift_monitor(scored, flows)
    return scored


async def run_detection_pipeline_async(flows: List[FlowRecord]) -> List[Alert]:
    """Run the detection pipeline concurrently over a batch of FlowRecords."""
    return [alert for _scores, alert in await run_detection_pipeline_scored_async(flows)]


def run_detection_pipeline_scored(
    flows: List[FlowRecord],
) -> List[tuple[List[LayerScore], Alert]]:
    """Synchronous pipeline entry point keeping each flow's LayerScores.

    Scores the batch directly. The previous implementation spun up a fresh
    ThreadPoolExecutor per call (or a whole event loop via asyncio.run()) and
    dispatched four tasks per flow. That cost more than the work it parallelised:
    the layers are either trivial pure-Python or single model calls that hold the
    GIL, so the fan-out bought nothing and the setup was pure overhead —
    measurably slower than scoring the same flows straight through.
    """
    if not flows:
        return []

    _ensure_stats_baseline()
    results = _score_batch(flows)
    _feed_drift_monitor(results, flows)
    return results


def run_detection_pipeline(flows: List[FlowRecord]) -> List[Alert]:
    """Synchronous pipeline entry point (used by tests, scripts, benchmarks).

    Returns one Alert per input flow — scoring every flow is the contract here.
    Whether an alert is worth surfacing is a separate decision made by
    fusion.is_actionable_alert() at the emission points.
    """
    return [alert for _scores, alert in run_detection_pipeline_scored(flows)]


# ── FastAPI Endpoints ─────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "IGU Sentinel"}


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint streaming alerts in real-time as flows are processed.

    The handshake is authorized before the socket is accepted: Origin is checked
    against IGU_ALLOWED_ORIGINS (WebSockets bypass the browser same-origin
    policy) and, when IGU_API_TOKEN is set, a bearer token is required via the
    Authorization header or a ``token`` query parameter.
    """
    if not _websocket_authorized(websocket):
        # 1008 = policy violation.
        await websocket.close(code=1008)
        return
    await manager.connect(websocket)
    try:
        while True:
            # The alert feed is server-push only; this read exists solely to
            # keep the connection open and to notice disconnects. Client input
            # is bounded and discarded — an unbounded receive_text() let a
            # client make the server buffer arbitrary data it never reads.
            message = await websocket.receive_text()
            if len(message) > _WS_MAX_CLIENT_MESSAGE_BYTES:
                log.warning("WebSocket client sent %d bytes — closing", len(message))
                await websocket.close(code=1009)   # message too big
                break
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.post("/detect", dependencies=[Depends(require_token)])
async def detect(flows: list[dict]) -> list[dict]:
    """Run detection pipeline on flows.

    Layers are evaluated concurrently for each flow. Produced alerts are logged
    with SHA-256 hash chaining and broadcast in real-time to all connected WebSocket clients.

    Args:
        flows: List of flow dicts matching FlowRecord schema.

    Returns:
        List of Alert dicts.

    Raises:
        HTTPException: 413 if the batch exceeds MAX_FLOWS_PER_REQUEST,
            422 if any flow fails FlowRecord validation.
    """
    if len(flows) > MAX_FLOWS_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"batch of {len(flows)} exceeds limit of {MAX_FLOWS_PER_REQUEST} flows",
        )

    # Zero trust at the data level (CLAUDE.md): validate every record against
    # the schema and reject the batch with a precise 422. Letting the
    # ValidationError escape turned malformed input into an opaque HTTP 500.
    flow_records: List[FlowRecord] = []
    for idx, f in enumerate(flows):
        try:
            flow_records.append(FlowRecord(**f))
        except (ValidationError, TypeError) as exc:
            raise HTTPException(
                status_code=422,
                detail={"error": "invalid FlowRecord", "index": idx, "reason": str(exc)},
            ) from exc

    scored = await run_detection_pipeline_scored_async(flow_records)
    alerts = [alert for _s, alert in scored]

    # Hash-chained logging and WebSocket real-time broadcast happen only for
    # alerts the detection layers actually stand behind. The response still
    # carries a scored verdict for every submitted flow.
    for layer_scores, a in scored:
        if not is_actionable_alert(layer_scores, a):
            continue
        log_alert(a)
        await manager.broadcast_alert(a)

    return [
        {
            "timestamp": a.timestamp.isoformat(),
            "flow_id": a.flow_id,
            "threat_class": a.threat_class,
            "confidence_score": a.confidence_score,
            "evidence": a.evidence,
        }
        for a in alerts
    ]


# ── Live capture control endpoints ────────────────────────────────────────────

@app.post("/capture/start", dependencies=[Depends(require_token)])
async def capture_start(config: dict):
    """Start continuous live capture on an interface.

    Body: {"interface": "<name>", "window_ms": 120 (optional)}

    Captured flows are batched per fixed window and pushed through the same
    detect -> fusion -> alert -> /ws/alerts path as POST /detect. Returns a clear
    error (HTTP 400) — without crashing the service — if the interface does not
    exist or cannot be captured on (e.g. missing permission).
    """
    config = config or {}
    interface = config.get("interface")
    if not interface or not isinstance(interface, str):
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error": "'interface' (string) is required"},
        )
    if not _IFACE_RE.match(interface):
        # tshark is invoked with an argv list, so this is not a shell-injection
        # fix — it rejects nonsense early with a clear error instead of spawning
        # a doomed capture process per request.
        return JSONResponse(
            status_code=400,
            content={
                "status": "error",
                "error": "'interface' must match [A-Za-z0-9_.:-]{1,64}",
            },
        )
    try:
        window_ms = int(config.get("window_ms", DEFAULT_WINDOW_MS))
    except (TypeError, ValueError):
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error": "'window_ms' must be an integer"},
        )
    if window_ms <= 0:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "error": "'window_ms' must be positive"},
        )

    loop = asyncio.get_running_loop()
    try:
        capture.start(interface, window_ms, loop)
    except RuntimeError as exc:
        return JSONResponse(status_code=409, content={**capture.snapshot(), "error": str(exc)})

    # Wait briefly for the worker to confirm it is live or report a startup error,
    # so the caller gets a definitive answer (interface valid / permission ok).
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if capture.state.get("status") in ("running", "error"):
            break
        await asyncio.sleep(0.05)

    if capture.state.get("status") == "error":
        return JSONResponse(status_code=400, content=capture.snapshot())
    return capture.snapshot()


@app.post("/capture/stop", dependencies=[Depends(require_token)])
async def capture_stop():
    """Stop the active live capture (idempotent)."""
    if not capture.is_running():
        return {**capture.snapshot(), "detail": "no active capture"}
    await asyncio.to_thread(capture.stop)
    return capture.snapshot()


@app.get("/capture/status", dependencies=[Depends(require_token)])
async def capture_status():
    """Return the current live-capture status and counters."""
    return capture.snapshot()


@app.get("/dashboard")
async def dashboard():
    """Serve the live demo dashboard HTML.

    When IGU_API_TOKEN is configured the HTML is patched to include a
    ``<meta name="iguToken">`` tag that the dashboard's JavaScript reads to
    authenticate its WebSocket connection.  Without the token the dashboard
    is served as-is and the WebSocket handshake skips auth (consistent with
    IGU_API_TOKEN being unset on the backend).

    FileResponse is not used here because it streams the file directly
    without giving the server a chance to modify it.  HTMLResponse accepts a
    string, which is cheap for a ~18 KB HTML file.
    """
    dashboard_file = Path(__file__).parent / "dashboard.html"
    html = dashboard_file.read_text(encoding="utf-8")
    token = _configured_token()
    if token:
        # Inject the token as a meta tag right after <head> so the JS can
        # read it without any template engine dependency.
        meta_tag = f'\n    <meta name="iguToken" content="{token}">'
        html = html.replace("<head>", f"<head>{meta_tag}", 1)
    return HTMLResponse(content=html)

