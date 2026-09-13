"""FastAPI app orchestrating the detection pipeline.

Model lifecycle (changed from the old per-request retrain approach):
  - IsolationForest and XGBoost are loaded ONCE at module import from the
    persisted files in models/.  If no persisted models exist yet, the service
    will raise RuntimeError on the first /detect call — run train_models.py
    before starting the service.
  - detect/stats.py baseline still needs to be trained on benign flows at
    startup (it's a rolling z-score baseline, not a persisted model).  We
    train it once from the benign fixture file.
"""
import json
import logging
from pathlib import Path

from fastapi import FastAPI
from igu_sentinel.schemas import FlowRecord, Alert
from igu_sentinel.detect.rules import detect_rules
from igu_sentinel.detect.stats import train_stats_baseline, detect_stats
from igu_sentinel.detect.isoforest import score_isoforest   # model loaded at import
from igu_sentinel.detect.xgb import predict_xgb             # model loaded at import
from igu_sentinel.fusion import fuse_layers

log = logging.getLogger(__name__)
app = FastAPI(title="IGU Sentinel")

# ── one-time startup state ────────────────────────────────────────────────────
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


# ── pipeline ──────────────────────────────────────────────────────────────────

def run_detection_pipeline(flows: list[FlowRecord]) -> list[Alert]:
    """Run the full detection pipeline on a list of FlowRecords.

    All models are loaded at module import time (isoforest, xgb).
    The stats z-score baseline is initialised lazily on first call.

    Args:
        flows: List of FlowRecords to process.

    Returns:
        List of Alert objects, one per input flow.
    """
    if not flows:
        return []

    _ensure_stats_baseline()

    alerts: list[Alert] = []
    for flow in flows:
        scores = [
            detect_rules(flow),
            detect_stats(flow),
            score_isoforest(flow),
            predict_xgb(flow),
        ]
        alerts.append(fuse_layers(scores))

    return alerts


# ── FastAPI endpoints ─────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "IGU Sentinel"}


@app.post("/detect")
async def detect(flows: list[dict]) -> list[dict]:
    """Run detection pipeline on flows.

    Args:
        flows: List of flow dicts matching FlowRecord schema.

    Returns:
        List of Alert dicts.
    """
    flow_records = [FlowRecord(**f) for f in flows]
    alerts = run_detection_pipeline(flow_records)
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
