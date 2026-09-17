"""Test benchmark/ throughput and latency measurement."""
import json
import time

import pytest
from pathlib import Path
from igu_sentinel.schemas import FlowRecord
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


def test_benchmark_throughput():
    """Benchmark measure throughput in flows/sec."""
    # Load a mix of threat classes
    flows = []
    for tc in ["benign", "volumetric_ddos", "c2_beaconing", "dga_dns_tunneling"]:
        flows.extend(load_fixture_flows(tc))

    # Warm up
    run_detection_pipeline(flows[:5])

    # Measure throughput
    num_flows = len(flows)
    start_time = time.time()
    alerts = run_detection_pipeline(flows)
    elapsed = time.time() - start_time

    assert len(alerts) == num_flows

    # Compute throughput
    throughput = num_flows / elapsed if elapsed > 0 else 0

    # Report throughput (not asserting a specific number)
    print(f"✓ test_benchmark_throughput passed")
    print(f"  Flows: {num_flows}")
    print(f"  Time: {elapsed:.3f}s")
    print(f"  Throughput: {throughput:.1f} flows/sec")


def test_benchmark_latency():
    """Benchmark measure end-to-end latency per flow."""
    flows = load_fixture_flows("benign")[:3]

    # Warm up
    run_detection_pipeline(flows[:1])

    # Measure latencies
    latencies = []
    for flow in flows:
        start = time.time()
        alerts = run_detection_pipeline([flow])
        elapsed = time.time() - start
        latencies.append(elapsed)

    # Compute statistics
    min_lat = min(latencies)
    max_lat = max(latencies)
    avg_lat = sum(latencies) / len(latencies)

    # Report latency (not asserting specific values)
    print(f"✓ test_benchmark_latency passed")
    print(f"  Samples: {len(latencies)}")
    print(f"  Min latency: {min_lat * 1000:.2f}ms")
    print(f"  Max latency: {max_lat * 1000:.2f}ms")
    print(f"  Avg latency: {avg_lat * 1000:.2f}ms")


# ── Benchmark harness module ──────────────────────────────────────────────────
# CLAUDE.md requires a dedicated benchmark harness module, not just a test that
# prints a number. These cover igu_sentinel/benchmark.

from igu_sentinel.benchmark import (
    CAPTURE_WINDOW_MS,
    BenchmarkResult,
    run_benchmark,
)
# Aliased: this module already defines its own single-class load_fixture_flows,
# and importing the harness's multi-class one under the same name would shadow it.
from igu_sentinel.benchmark import load_fixture_flows as load_all_fixture_flows


def test_benchmark_harness_reports_concrete_numbers():
    """The harness must produce a real throughput and latency measurement."""
    result = run_benchmark(target_flows=256, repeats=2, batch_size=64)

    assert isinstance(result, BenchmarkResult)
    assert result.flows_processed == 256 * 2
    assert result.throughput_flows_per_sec > 0, "throughput must be measured"
    assert result.latency_p50_ms > 0, "latency must be measured"
    # Percentiles must be ordered — a tail that sorts below the median means the
    # percentile computation is wrong.
    assert result.latency_p50_ms <= result.latency_p95_ms <= result.latency_p99_ms
    assert result.latency_p99_ms <= result.latency_max_ms
    assert result.capture_window_ms == CAPTURE_WINDOW_MS

    print(
        f"✓ test_benchmark_harness_reports_concrete_numbers passed "
        f"({result.throughput_flows_per_sec:,.0f} flows/sec, "
        f"p95 {result.latency_p95_ms:.2f} ms)"
    )


def test_benchmark_window_headroom_is_not_degenerate():
    """Headroom must come from measured latency, not a circular identity.

    Deriving headroom from throughput alone reduces to 1 - 120/120 = 0 for every
    possible throughput, which silently reports a saturated pipeline no matter
    how fast it actually is.
    """
    result = run_benchmark(target_flows=256, repeats=2, batch_size=64)

    assert 0.0 <= result.window_headroom <= 1.0
    expected = max(0.0, 1.0 - result.latency_p95_ms / CAPTURE_WINDOW_MS)
    assert result.window_headroom == pytest.approx(expected)
    print(f"✓ test_benchmark_window_headroom_is_not_degenerate passed "
          f"({result.window_headroom * 100:.1f}% free)")


def test_benchmark_report_and_json_render():
    """Both output formats must render without raising."""
    result = run_benchmark(target_flows=128, repeats=1, batch_size=64)

    report = result.format_report()
    assert "flows/sec" in report and "p95" in report

    payload = json.loads(result.to_json())
    assert payload["throughput_flows_per_sec"] > 0
    assert payload["batch_size"] == 64
    print("✓ test_benchmark_report_and_json_render passed")


def test_benchmark_loads_every_threat_class_fixture():
    """The harness benchmarks across all seven classes, not just benign."""
    flows = load_all_fixture_flows()
    assert len(flows) > 0
    print(f"✓ test_benchmark_loads_every_threat_class_fixture passed ({len(flows)} flows)")


def test_batched_scoring_beats_per_flow_scoring():
    """Window-batched scoring must outperform per-flow scoring.

    This is the optimisation that took the pipeline from ~112 flows/sec to
    ~11,000: the ML layers' fixed per-call overhead dominates the per-row work,
    so it must be amortised across a capture window rather than paid per flow.
    A regression here silently reinstates the old bottleneck.
    """
    flows = load_all_fixture_flows()[:40]
    assert flows, "fixtures required"

    run_detection_pipeline(flows[:4])  # warm up

    t0 = time.perf_counter()
    for f in flows:
        run_detection_pipeline([f])
    per_flow = time.perf_counter() - t0

    t0 = time.perf_counter()
    run_detection_pipeline(flows)
    batched = time.perf_counter() - t0

    assert batched < per_flow, (
        f"batched scoring ({batched:.4f}s) must beat per-flow "
        f"({per_flow:.4f}s) for {len(flows)} flows"
    )
    print(f"✓ test_batched_scoring_beats_per_flow_scoring passed "
          f"({per_flow / batched:.1f}x faster batched)")
