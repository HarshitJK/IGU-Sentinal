"""FastAPI app orchestrating the detection pipeline."""
from fastapi import FastAPI
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
