"""Config-driven traffic generator harness."""
from pathlib import Path
from typing import List, Dict, Any
import yaml
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock, ddos, beaconing, scanning


# Mapping from tool name to generator function
GENERATOR_MAP = {
    "mock": mock.generate,
    "ddos": ddos.generate,
    "beaconing": beaconing.generate,
    "scanning": scanning.generate,
}


def run_traffic_gen(config_path: str) -> List[Dict[str, Any]]:
    """
    Run config-driven traffic generation.

    Args:
        config_path: Path to yaml config file with variants.

    Returns:
        List of {threat_class, flow} dicts for each generated flow.
    """
    config_path = Path(config_path)
    with open(config_path) as f:
        config = yaml.safe_load(f)

    labeled_flows = []

    for variant in config.get("variants", []):
        threat_class = variant["threat_class"]
        tool = variant.get("tool", "mock")
        source_mode = variant.get("source_mode", "fixed")
        rate = variant.get("rate", 10)
        size = variant.get("size", 128)
        port = variant.get("port", 80)
        duration = variant.get("duration", 1)

        # Get generator function
        if tool not in GENERATOR_MAP:
            tool = "mock"  # Fallback to mock
        generator_fn = GENERATOR_MAP[tool]

        # Call generator with variant params
        flows = generator_fn(
            threat_class=threat_class,
            source_mode=source_mode,
            rate=rate,
            size=size,
            port=port,
            duration=duration,
        )

        # Label each flow with its threat class
        for flow in flows:
            labeled_flows.append({
                "threat_class": threat_class,
                "flow": flow,
            })

    return labeled_flows
