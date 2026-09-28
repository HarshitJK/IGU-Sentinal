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

# Variant keys the runner consumes itself; everything else in a lab variant is
# forwarded to the generator as an extra lab parameter (attack, iface, port,
# max_sockets, domain, lab_suffix, ...).
_RESERVED_KEYS = {
    "threat_class", "tool", "source_mode", "rate", "size", "port", "duration",
    "mode", "target",
}

# Only these generators know how to drive real lab traffic. A lab variant that
# routes anywhere else is a config error, not a silent mock fallback.
_LAB_CAPABLE_TOOLS = {"ddos", "dns_tunneling"}


def run_traffic_gen(config_path: str, allow_lab: bool = False) -> List[Dict[str, Any]]:
    """
    Run config-driven traffic generation.

    Args:
        config_path: Path to yaml config file with variants.
        allow_lab: When False (default), any variant with ``mode: lab`` is SKIPPED
            rather than run. This keeps the mock aggregate paths (``make gen-data``,
            :func:`run_all_configs`, eval/train helpers) CI-safe: they will never
            spawn real traffic just because a lab config sits in the config
            directory. Set True only from an explicit lab invocation
            (``make gen-data-lab`` / the CLI on a single config).

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
        mode = variant.get("mode", "mock")

        # Lab variants generate REAL traffic; never run them from a mock/aggregate
        # caller. Skip (don't error) so a lab config can coexist in config/.
        if mode == "lab" and not allow_lab:
            print(
                f"[traffic-gen] skipping lab variant "
                f"(threat_class={threat_class}, attack={variant.get('attack')}): "
                f"run `make gen-data-lab` to execute it"
            )
            continue

        # Get generator function
        if tool not in GENERATOR_MAP:
            tool = "mock"  # Fallback to mock
        generator_fn = GENERATOR_MAP[tool]

        if mode == "lab":
            # Real-traffic path: only the lab-capable generators support it, and
            # a lab run needs an explicit target.
            if tool not in _LAB_CAPABLE_TOOLS:
                raise ValueError(
                    f"mode: lab is only supported by tools {sorted(_LAB_CAPABLE_TOOLS)}, "
                    f"not {tool!r} (threat_class={threat_class!r})"
                )
            extra = {k: v for k, v in variant.items() if k not in _RESERVED_KEYS}
            flows = generator_fn(
                threat_class=threat_class,
                source_mode=source_mode,
                rate=max(1, int(rate)),
                size=int(size),
                port=int(port),
                duration=int(duration),
                mode="lab",
                target=variant.get("target"),
                **extra,
            )
        else:
            # mock mode (default): unchanged call — no new kwargs are passed, so
            # every existing generator and config behaves exactly as before.
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


def run_all_configs(config_dir: str | None = None, allow_lab: bool = False) -> List[Dict[str, Any]]:
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
        flows = run_traffic_gen(str(yaml_file), allow_lab=allow_lab)
        all_flows.extend(flows)
        print(f"[traffic-gen]   Generated {len(flows)} flows")

    print(f"[traffic-gen] Total: {len(all_flows)} flows from {len(yaml_files)} configs")
    return all_flows


def main(argv=None):
    import argparse
    import socket
    import time

    parser = argparse.ArgumentParser(description="Generate mock flows or explicitly selected lab traffic")
    parser.add_argument("config", nargs="?")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--allow-lab", action="store_true", help="Enable real traffic in the selected config only")
    parser.add_argument("--send-to", help="Send flow JSON datagrams to IPv4:port (no return path)")
    parser.add_argument("--rate", type=float, default=20, help="Flow export rate per second")
    parser.add_argument("--repeat", action="store_true", help="Repeat the generated flow corpus")
    args = parser.parse_args(argv)
    if args.all == bool(args.config):
        parser.error("choose either a config or --all")
    if args.allow_lab and args.all:
        parser.error("--allow-lab requires a single explicit config")
    if args.rate <= 0:
        parser.error("--rate must be positive")
    rows = run_all_configs(allow_lab=False) if args.all else run_traffic_gen(args.config, allow_lab=args.allow_lab)
    if args.send_to and rows:
        host, port = args.send_to.rsplit(":", 1)
        # Interleave classes for a short demonstration rather than spending
        # many minutes exporting the first class in the config directory.
        from itertools import zip_longest
        groups = {}
        for row in rows:
            groups.setdefault(row["threat_class"], []).append(row)
        rows = [r for group in zip_longest(*groups.values()) for r in group if r is not None]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            while True:
                for row in rows:
                    sender.sendto(row["flow"].model_dump_json().encode(), (host, int(port)))
                    time.sleep(1 / args.rate)
                if not args.repeat:
                    break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
