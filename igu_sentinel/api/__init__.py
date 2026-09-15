"""FastAPI app orchestrating the detection pipeline."""
import asyncio
import json
from datetime import datetime
from collections import defaultdict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from igu_sentinel.schemas import FlowRecord, Alert
from igu_sentinel.detect.rules import detect_rules
from igu_sentinel.detect.stats import train_stats_baseline, detect_stats
from igu_sentinel.detect.isoforest import train_isoforest, score_isoforest
from igu_sentinel.detect.xgb import train_xgb, predict_xgb
from igu_sentinel.fusion import fuse_layers


app = FastAPI(title="IGU Sentinel")

# Global state for detectors
_detectors_trained = False
_training_flows = None

# Global state for WebSocket broadcasting
_alert_broadcast_clients = set()
_alert_lock = asyncio.Lock()
_alert_stats = {
    "total_flows": 0,
    "alert_history": [],
    "threat_class_counts": defaultdict(int),
    "last_alert_time": None,
}


async def broadcast_alert(alert: Alert):
    """Broadcast an alert to all connected WebSocket clients."""
    global _alert_broadcast_clients, _alert_stats

    async with _alert_lock:
        # Update stats
        _alert_stats["total_flows"] += 1
        _alert_stats["threat_class_counts"][alert.threat_class] += 1
        _alert_stats["last_alert_time"] = datetime.now()

        # Keep only last 100 alerts in history
        _alert_stats["alert_history"].append(alert)
        if len(_alert_stats["alert_history"]) > 100:
            _alert_stats["alert_history"].pop(0)

        # Prepare message
        message = {
            "type": "alert",
            "timestamp": alert.timestamp.isoformat(),
            "flow_id": alert.flow_id,
            "threat_class": alert.threat_class,
            "confidence_score": alert.confidence_score,
            "evidence": alert.evidence,
            "stats": {
                "total_flows": _alert_stats["total_flows"],
                "threat_class_counts": dict(_alert_stats["threat_class_counts"]),
            }
        }

        # Broadcast to all connected clients
        disconnected = set()
        for client in _alert_broadcast_clients:
            try:
                await client.send_json(message)
            except Exception:
                disconnected.add(client)

        # Clean up disconnected clients
        _alert_broadcast_clients -= disconnected


def run_detection_pipeline(flows: list[FlowRecord]) -> list[Alert]:
    """Run the full detection pipeline on flows.

    Pipeline:
    1. Extract features and run all detection layers (rules, stats, isoforest, xgb)
    2. Fuse scores from all layers
    3. Generate Alert with combined confidence

    Args:
        flows: List of FlowRecords to process

    Returns:
        List of Alert objects (one per flow)
    """
    global _detectors_trained, _training_flows

    if not flows:
        return []

    # Train detectors on first call (using all flows as if they're benign for baseline)
    if not _detectors_trained:
        _training_flows = flows
        train_stats_baseline(flows)
        train_isoforest(flows)
        train_xgb(flows, ["benign"] * len(flows))  # Assume all training data is benign
        _detectors_trained = True

    alerts = []

    for flow in flows:
        # Run all detection layers
        scores = [
            detect_rules(flow),
            detect_stats(flow),
            score_isoforest(flow),
            predict_xgb(flow),
        ]

        # Fuse scores into alert
        alert = fuse_layers(scores)
        alerts.append(alert)

    return alerts


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "IGU Sentinel"}


@app.post("/detect")
async def detect(flows: list[dict]) -> list[dict]:
    """Run detection pipeline on flows.

    Args:
        flows: List of flow dicts matching FlowRecord schema

    Returns:
        List of Alert dicts
    """
    # Convert dicts to FlowRecords
    flow_records = [FlowRecord(**f) for f in flows]

    # Run pipeline
    alerts = run_detection_pipeline(flow_records)

    # Broadcast each alert to WebSocket clients
    for alert in alerts:
        await broadcast_alert(alert)

    # Convert Alerts back to dicts
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


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for live alert streaming."""
    await websocket.accept()
    _alert_broadcast_clients.add(websocket)

    try:
        # Send initial state
        async with _alert_lock:
            initial_state = {
                "type": "init",
                "total_flows": _alert_stats["total_flows"],
                "threat_class_counts": dict(_alert_stats["threat_class_counts"]),
                "alert_history": [
                    {
                        "timestamp": a.timestamp.isoformat(),
                        "flow_id": a.flow_id,
                        "threat_class": a.threat_class,
                        "confidence_score": a.confidence_score,
                    }
                    for a in _alert_stats["alert_history"]
                ]
            }
        await websocket.send_json(initial_state)

        # Keep connection open
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _alert_broadcast_clients.discard(websocket)


@app.get("/dashboard")
async def dashboard():
    """Serve the live demo dashboard HTML."""
    dashboard_file = Path(__file__).parent / "dashboard.html"
    return FileResponse(dashboard_file, media_type="text/html")
