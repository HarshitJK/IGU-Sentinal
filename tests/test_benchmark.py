"""Test benchmark/ throughput and latency measurement."""
import json
import time
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
