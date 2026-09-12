"""Test traffic_gen/ config-driven generator harness."""
import json
import tempfile
from pathlib import Path
import yaml
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.runner import run_traffic_gen


def create_test_config() -> Path:
    """Create a minimal yaml config for testing."""
    config = {
        "variants": [
            {
                "threat_class": "volumetric_ddos",
                "tool": "mock",
                "source_mode": "fixed",
                "rate": 100,
                "size": 64,
                "port": 80,
                "duration": 1,
            },
            {
                "threat_class": "c2_beaconing",
                "tool": "mock",
                "source_mode": "fixed",
                "rate": 10,
                "size": 128,
                "port": 443,
                "duration": 1,
            },
            {
                "threat_class": "recon_scanning",
                "tool": "mock",
                "source_mode": "rand",
                "rate": 50,
                "size": 100,
                "port": 22,
                "duration": 1,
            },
        ]
    }

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(config, f)
        return Path(f.name)


def test_traffic_gen_loads_config():
    """traffic_gen runner should load and parse yaml config."""
    config_path = create_test_config()
    try:
        # Run traffic gen - should return list of labeled flows
        flows = run_traffic_gen(str(config_path))
        assert isinstance(flows, list)
        assert len(flows) > 0
        print(f"✓ test_traffic_gen_loads_config passed ({len(flows)} flows generated)")
    finally:
        config_path.unlink()


def test_traffic_gen_produces_labeled_flows():
    """traffic_gen should produce flows labeled with threat class."""
    config_path = create_test_config()
    try:
        flows = run_traffic_gen(str(config_path))

        # Collect flows by threat class
        flows_by_class = {}
        for flow_data in flows:
            # Each flow should be a dict with threat_class and flow (FlowRecord)
            assert isinstance(flow_data, dict)
            assert "threat_class" in flow_data
            assert "flow" in flow_data

            threat_class = flow_data["threat_class"]
            if threat_class not in flows_by_class:
                flows_by_class[threat_class] = []
            flows_by_class[threat_class].append(flow_data["flow"])

        # Verify each threat class was generated
        expected_classes = {"volumetric_ddos", "c2_beaconing", "recon_scanning"}
        assert set(flows_by_class.keys()) == expected_classes

        # Verify all flows are valid FlowRecords
        for threat_class, class_flows in flows_by_class.items():
            assert len(class_flows) > 0
            for flow in class_flows:
                assert isinstance(flow, FlowRecord)
                assert flow.flow_id
                assert flow.timestamp
                assert flow.protocol

        print(f"✓ test_traffic_gen_produces_labeled_flows passed")
        for threat_class, class_flows in flows_by_class.items():
            print(f"  - {threat_class}: {len(class_flows)} flows")
    finally:
        config_path.unlink()


def test_traffic_gen_matches_intent_threat_class():
    """Flows should match their declared threat class."""
    config_path = create_test_config()
    try:
        flows = run_traffic_gen(str(config_path))

        for flow_data in flows:
            threat_class = flow_data["threat_class"]
            flow = flow_data["flow"]

            # For each threat class, flows should have characteristic patterns
            if threat_class == "volumetric_ddos":
                # DDoS: very low inter-arrival times (high rate)
                assert flow.inter_arrival_stats["mean"] < 0.1  # 100 flows/sec
            elif threat_class == "c2_beaconing":
                # Beaconing: regular intervals, small packets
                assert flow.packet_size_stats["mean"] <= 200
            elif threat_class == "recon_scanning":
                # Scanning: varied packet sizes, multiple ports
                assert flow.fanout_count and flow.fanout_count > 1

        print("✓ test_traffic_gen_matches_intent_threat_class passed")
    finally:
        config_path.unlink()


def test_traffic_gen_config_params():
    """Generated flows should reflect config parameters."""
    config_path = create_test_config()
    try:
        flows = run_traffic_gen(str(config_path))

        # Group by threat class
        flows_by_class = {}
        for flow_data in flows:
            threat_class = flow_data["threat_class"]
            if threat_class not in flows_by_class:
                flows_by_class[threat_class] = []
            flows_by_class[threat_class].append(flow_data["flow"])

        # volumetric_ddos: port 80, size ~64
        ddos_flows = flows_by_class.get("volumetric_ddos", [])
        if ddos_flows:
            # At least some flows should use port 80
            ports = {f.dst_port for f in ddos_flows}
            assert 80 in ports

        # c2_beaconing: port 443
        c2_flows = flows_by_class.get("c2_beaconing", [])
        if c2_flows:
            ports = {f.dst_port for f in c2_flows}
            assert 443 in ports

        print("✓ test_traffic_gen_config_params passed")
    finally:
        config_path.unlink()
