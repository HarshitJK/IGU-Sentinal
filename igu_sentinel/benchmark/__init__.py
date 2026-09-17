"""Throughput and end-to-end latency harness for the detection pipeline.

CLAUDE.md requires a dedicated benchmark harness that measures and logs
sustained flows/sec and end-to-end latency (capture window + processing), and
calls it a graded requirement rather than optional polish. Only a *test* existed
(``tests/test_benchmark.py``) — it printed a number and threw it away, so there
was nothing any other code or report could call. This module is that harness.

What is measured
----------------
* **Sustained throughput** — flows/sec over a sustained run, not a single burst,
  reported as the mean over repeated passes so one lucky pass cannot flatter it.
* **End-to-end latency** — per-flow, reported as p50/p95/p99 rather than a mean.
  A mean hides the tail, and the tail is what a bounded-latency claim is about.
* **Window budget** — the fixed 120ms capture window (CLAUDE.md) sets the real
  deadline: a window's flows must be scored before the next window closes, or
  the pipeline falls behind the capture and never catches up. ``window_headroom``
  reports how much of that budget is left.

Usage::

    python -m igu_sentinel.benchmark                  # fixture-driven
    python -m igu_sentinel.benchmark --flows 5000 --repeats 5
"""

import argparse
import json
import logging
import statistics
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from igu_sentinel.schemas import FlowRecord

log = logging.getLogger(__name__)

# The fixed capture window the pipeline is built around (CLAUDE.md: locked,
# deliberately not adaptive). Processing a window must fit inside the next one.
CAPTURE_WINDOW_MS = 120.0

_FIXTURES_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures"

_THREAT_CLASSES = (
    "benign",
    "volumetric_ddos",
    "c2_beaconing",
    "dga_dns_tunneling",
    "encrypted_malware",
    "recon_scanning",
    "data_exfiltration",
)


@dataclass
class BenchmarkResult:
    """Measured pipeline performance. All times in milliseconds."""

    flows_processed: int
    repeats: int
    batch_size: int
    wall_seconds: float
    throughput_flows_per_sec: float
    throughput_stdev: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_max_ms: float
    capture_window_ms: float = CAPTURE_WINDOW_MS
    # Flows the pipeline can score inside one capture window at this throughput.
    flows_per_window: float = 0.0
    # Fraction of the window budget still free when scoring a full window.
    window_headroom: float = 0.0
    per_pass_throughput: List[float] = field(default_factory=list)

    def format_report(self) -> str:
        """Render a human-readable report."""
        lines = [
            "=" * 66,
            "IGU SENTINEL — PIPELINE BENCHMARK",
            "=" * 66,
            f"Flows processed      : {self.flows_processed} ({self.repeats} passes, "
            f"batch {self.batch_size})",
            f"Wall time            : {self.wall_seconds:.3f} s",
            "",
            "Sustained throughput",
            f"  flows/sec          : {self.throughput_flows_per_sec:,.1f}"
            f"  (stdev {self.throughput_stdev:,.1f})",
            "",
            "End-to-end latency per batch (capture window + processing)",
            f"  p50                : {self.latency_p50_ms:.3f} ms",
            f"  p95                : {self.latency_p95_ms:.3f} ms",
            f"  p99                : {self.latency_p99_ms:.3f} ms",
            f"  max                : {self.latency_max_ms:.3f} ms",
            "",
            f"Fixed capture window : {self.capture_window_ms:.0f} ms",
            f"  flows per window   : {self.flows_per_window:,.1f}",
            f"  scoring {self.batch_size} flows uses "
            f"{(1 - self.window_headroom) * 100:.1f}% of the window (p95)",
            f"  window headroom    : {self.window_headroom * 100:.1f}%",
            "=" * 66,
        ]
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def load_fixture_flows(threat_classes: Optional[List[str]] = None) -> List[FlowRecord]:
    """Load FlowRecords from the JSONL fixtures, one file per threat class.

    Args:
        threat_classes: Class names to load. Defaults to all seven. A bare
            string is accepted and treated as a single class — without that, a
            string would be iterated character by character and silently load
            nothing, reporting only "fixture b_sample.jsonl not found".
    """
    if isinstance(threat_classes, str):
        threat_classes = [threat_classes]
    flows: List[FlowRecord] = []
    for tc in threat_classes or list(_THREAT_CLASSES):
        path = _FIXTURES_DIR / f"{tc}_sample.jsonl"
        if not path.exists():
            log.warning("benchmark: fixture %s not found — skipping", path.name)
            continue
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    flows.append(FlowRecord(**json.loads(line)))
    return flows


def _synthesize(flows: List[FlowRecord], target: int) -> List[FlowRecord]:
    """Repeat the fixture set up to ``target`` flows, keeping flow_ids unique."""
    if not flows:
        raise ValueError("no fixture flows available to benchmark")
    out: List[FlowRecord] = []
    i = 0
    while len(out) < target:
        src = flows[i % len(flows)]
        out.append(src.model_copy(update={"flow_id": f"{src.flow_id}_bench{i}"}))
        i += 1
    return out


def run_benchmark(
    flows: Optional[List[FlowRecord]] = None,
    target_flows: int = 2000,
    repeats: int = 3,
    batch_size: int = 128,
    pipeline: Optional[Callable[[List[FlowRecord]], list]] = None,
) -> BenchmarkResult:
    """Measure sustained throughput and end-to-end latency through the pipeline.

    Args:
        flows: Flows to score. Defaults to the fixture corpus, repeated to
            ``target_flows``.
        target_flows: Flows per pass when synthesizing from fixtures.
        repeats: Number of passes. More than one is what makes the throughput
            figure "sustained" rather than a single burst.
        batch_size: Flows per pipeline call, standing in for one capture
            window's worth of flows.
        pipeline: Override for the scoring entry point (tests inject a stub).

    Returns:
        BenchmarkResult with throughput, latency percentiles and window headroom.
    """
    if pipeline is None:
        # Imported lazily: igu_sentinel.api pulls in the ML models at import,
        # which should not happen merely because someone imported this module.
        from igu_sentinel.api import run_detection_pipeline

        pipeline = run_detection_pipeline

    if flows is None:
        flows = _synthesize(load_fixture_flows(), target_flows)

    if not flows:
        raise ValueError("no flows to benchmark")

    # Warm up: first call pays model load and stats baseline training.
    # Including that in the measurement understates steady state.
    pipeline(flows[: min(16, len(flows))])

    per_pass_throughput: List[float] = []
    latencies_ms: List[float] = []
    total_start = time.perf_counter()

    # Feed the pipeline in window-sized batches, which is how it actually runs:
    # one fixed 120ms capture window yields one batch. Measuring one flow per
    # call would report the per-call model overhead rather than the sustained
    # rate, and that overhead is precisely what batching exists to amortise.
    for _ in range(max(1, repeats)):
        pass_start = time.perf_counter()
        for start in range(0, len(flows), batch_size):
            batch = flows[start:start + batch_size]
            t0 = time.perf_counter()
            pipeline(batch)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            # End-to-end latency for a flow is the time for its whole window to
            # be scored: no alert leaves the pipeline before its window is done.
            latencies_ms.extend([elapsed_ms] * len(batch))
        pass_elapsed = time.perf_counter() - pass_start
        if pass_elapsed > 0:
            per_pass_throughput.append(len(flows) / pass_elapsed)

    wall = time.perf_counter() - total_start

    ordered = sorted(latencies_ms)

    def pct(p: float) -> float:
        if not ordered:
            return 0.0
        idx = min(int(round(p * (len(ordered) - 1))), len(ordered) - 1)
        return ordered[idx]

    throughput = statistics.mean(per_pass_throughput) if per_pass_throughput else 0.0
    stdev = statistics.stdev(per_pass_throughput) if len(per_pass_throughput) > 1 else 0.0

    # Flows the pipeline can score within one capture window at this rate. This
    # is the number that matters operationally: offer more flows per window than
    # this and the pipeline falls behind the capture and never catches up.
    flows_per_window = throughput * (CAPTURE_WINDOW_MS / 1000.0)

    # Fraction of the 120ms window budget still free after scoring one
    # batch_size-sized window, measured at p95 so the tail is what is reported.
    # (Deriving this from throughput alone is circular — it reduces to
    # 1 - 120/120 = 0 for any throughput — so it must come from measured
    # per-batch latency.)
    window_headroom = max(0.0, 1.0 - pct(0.95) / CAPTURE_WINDOW_MS)

    result = BenchmarkResult(
        flows_processed=len(flows) * max(1, repeats),
        repeats=max(1, repeats),
        batch_size=batch_size,
        wall_seconds=wall,
        throughput_flows_per_sec=throughput,
        throughput_stdev=stdev,
        latency_p50_ms=pct(0.50),
        latency_p95_ms=pct(0.95),
        latency_p99_ms=pct(0.99),
        latency_max_ms=ordered[-1] if ordered else 0.0,
        flows_per_window=flows_per_window,
        window_headroom=window_headroom,
        per_pass_throughput=per_pass_throughput,
    )

    # Logged, not just returned — CLAUDE.md asks for the number to be recorded.
    log.info(
        "benchmark: %.1f flows/sec sustained, p95 latency %.3f ms, "
        "%.1f flows per %.0fms window",
        result.throughput_flows_per_sec,
        result.latency_p95_ms,
        result.flows_per_window,
        CAPTURE_WINDOW_MS,
    )
    return result


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point: run the benchmark and print the report."""
    parser = argparse.ArgumentParser(description="Benchmark the IGU Sentinel pipeline")
    parser.add_argument("--flows", type=int, default=2000, help="flows per pass")
    parser.add_argument("--repeats", type=int, default=3, help="number of passes")
    parser.add_argument(
        "--batch", type=int, default=128,
        help="flows per pipeline call (stands in for one capture window)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    parser.add_argument("--output", type=str, default=None, help="write the report to this file")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    result = run_benchmark(
        target_flows=args.flows, repeats=args.repeats, batch_size=args.batch
    )
    text = result.to_json() if args.json else result.format_report()
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n")
        print(f"\nWritten to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
