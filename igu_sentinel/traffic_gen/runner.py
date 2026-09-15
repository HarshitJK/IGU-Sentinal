"""Config-driven traffic generator harness."""
from pathlib import Path
from typing import List, Dict, Any
import yaml
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import (
    mock,
    ddos,
    beaconing,
    scanning,
    dns_tunneling,
    encrypted_malware,
    exfiltration,
)


# Mapping from tool name to generator function
GENERATOR_MAP = {
    "mock": mock.generate,
    "ddos": ddos.generate,
    "beaconing": beaconing.generate,
    "scanning": scanning.generate,
    "dns_tunneling": dns_tunneling.generate,
    "encrypted_malware": encrypted_malware.generate,
    "exfiltration": exfiltration.generate,
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
            rate=max(1, int(rate)),
            size=int(size),
            port=int(port),
            duration=int(duration),
        )

        # Label each flow with its threat class
        for flow in flows:
            labeled_flows.append({
                "threat_class": threat_class,
                "flow": flow,
            })

    return labeled_flows


def run_all_configs(config_dir: str | None = None) -> List[Dict[str, Any]]:
    """
    Run traffic generation for every YAML config in the config directory.

    Args:
        config_dir: Path to directory containing YAML configs.
                    Defaults to the package's config/ directory.

    Returns:
        Combined list of {threat_class, flow} dicts from all configs.
    """
    if config_dir is None:
        config_dir = str(Path(__file__).parent / "config")

    config_path = Path(config_dir)
    yaml_files = sorted(config_path.glob("*.yaml"))

    if not yaml_files:
        raise FileNotFoundError(f"No YAML configs found in {config_path}")

    all_flows: List[Dict[str, Any]] = []
    for yaml_file in yaml_files:
        print(f"[traffic-gen] Running config: {yaml_file.name}")
        flows = run_traffic_gen(str(yaml_file))
        all_flows.extend(flows)
        print(f"[traffic-gen]   Generated {len(flows)} flows")

    print(f"[traffic-gen] Total: {len(all_flows)} flows from {len(yaml_files)} configs")
    return all_flows


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m igu_sentinel.traffic_gen.runner <config.yaml | --all>")
        sys.exit(1)

    arg = sys.argv[1]

    if arg == "--all":
        run_all_configs()
    else:
        run_traffic_gen(arg)

