"""FastAPI app orchestrating the detection pipeline with concurrent layer execution and WebSocket streaming.

Pipeline Architecture:
  - Detection layers (rules, stats, isoforest, xgb) run CONCURRENTLY per flow via asyncio.gather()
    and asyncio.to_thread() to offload CPU-bound ML scoring without blocking the event loop.
  - Fusion correlates LayerScores into an Alert with confidence scoring.
  - Alert logging applies SHA-256 hash chaining.
  - Real-time streaming broadcasts alerts over WebSocket at /ws/alerts to connected dashboards.
"""
import asyncio
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from igu_sentinel.schemas import FlowRecord, Alert
from igu_sentinel.detect.rules import detect_rules
from igu_sentinel.detect.stats import train_stats_baseline, detect_stats
from igu_sentinel.detect.isoforest import score_isoforest   # loaded at import
from igu_sentinel.detect.xgb import predict_xgb             # loaded at import
from igu_sentinel.fusion import fuse_layers
from igu_sentinel.alert import log_alert

log = logging.getLogger(__name__)
app = FastAPI(title="IGU Sentinel", description="Passive Diode-Fed Threat Detection System")

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
        """Broadcast an Alert as JSON to all active WebSocket connections."""
        if not self.active_connections:
            return

        payload = {
            "timestamp": alert.timestamp.isoformat(),
            "flow_id": alert.flow_id,
            "threat_class": alert.threat_class,
            "confidence_score": alert.confidence_score,
            "evidence": alert.evidence,
        }

        dead_connections = set()
        for connection in list(self.active_connections):
            try:
                await connection.send_json(payload)
            except Exception:
                dead_connections.add(connection)

        for dead in dead_connections:
            self.disconnect(dead)


manager = ConnectionManager()


# ── One-time startup state ────────────────────────────────────────────────────
_stats_trained: bool = False


def _ensure_stats_baseline() -> None:
    """Train stats baseline from benign fixture once on first use."""
    global _stats_trained
    if _stats_trained:
        return

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

async def detect_flow_async(flow: FlowRecord) -> Alert:
    """Run all 4 detection layers concurrently on a single FlowRecord.

    CPU-bound scoring functions (sklearn IsolationForest, XGBoost) are executed
    in worker threads via asyncio.to_thread() to avoid blocking the asyncio event loop.
    """
    scores = await asyncio.gather(
        asyncio.to_thread(detect_rules, flow),
        asyncio.to_thread(detect_stats, flow),
        asyncio.to_thread(score_isoforest, flow),
        asyncio.to_thread(predict_xgb, flow),
    )
    return fuse_layers(list(scores))


async def run_detection_pipeline_async(flows: List[FlowRecord]) -> List[Alert]:
    """Run the detection pipeline concurrently over a batch of FlowRecords."""
    if not flows:
        return []
    _ensure_stats_baseline()
    tasks = [detect_flow_async(f) for f in flows]
    return list(await asyncio.gather(*tasks))


def run_detection_pipeline(flows: List[FlowRecord]) -> List[Alert]:
    """Synchronous pipeline entry point (used by tests, scripts, benchmarks).

    Dispatches detection layers concurrently using ThreadPoolExecutor if an event
    loop is already running, or via asyncio.run() otherwise.
    """
    if not flows:
        return []

    _ensure_stats_baseline()

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Inside existing event loop: run layers concurrently across threads
        with ThreadPoolExecutor(max_workers=min(32, (len(flows) * 4) or 1)) as executor:
            alerts: List[Alert] = []
            for flow in flows:
                f_rules = executor.submit(detect_rules, flow)
                f_stats = executor.submit(detect_stats, flow)
                f_iso = executor.submit(score_isoforest, flow)
                f_xgb = executor.submit(predict_xgb, flow)
                scores = [f_rules.result(), f_stats.result(), f_iso.result(), f_xgb.result()]
                alerts.append(fuse_layers(scores))
            return alerts
    else:
        return asyncio.run(run_detection_pipeline_async(flows))


# ── FastAPI Endpoints ─────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "IGU Sentinel"}


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint streaming alerts in real-time as flows are processed."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection open; receive client pings/messages if any
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.post("/detect")
async def detect(flows: list[dict]) -> list[dict]:
    """Run detection pipeline on flows.

    Layers are evaluated concurrently for each flow. Produced alerts are logged
    with SHA-256 hash chaining and broadcast in real-time to all connected WebSocket clients.

    Args:
        flows: List of flow dicts matching FlowRecord schema.

    Returns:
        List of Alert dicts.
    """
    flow_records = [FlowRecord(**f) for f in flows]
    alerts = await run_detection_pipeline_async(flow_records)

    # Hash-chained logging and WebSocket real-time broadcast
    for a in alerts:
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
