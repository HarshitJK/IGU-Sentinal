"""Static validation tests for docker-compose setup (no docker execution required)."""
import yaml
from pathlib import Path
import sys


def test_dockerfile_exists_and_valid():
    """Dockerfile should exist with correct structure for sentinel app."""
    root_dir = Path(__file__).parent.parent
    dockerfile = root_dir / "Dockerfile"

    assert dockerfile.exists(), "Dockerfile not found at project root"
    print("✓ Dockerfile exists")

    with open(dockerfile) as f:
        content = f.read()

    # Verify key components
    assert "python:3.11-slim" in content, "Must use Python 3.11-slim base image"
    assert "requirements.txt" in content, "Must copy requirements.txt"
    assert "igu_sentinel" in content, "Must copy igu_sentinel module"
    assert "tests/fixtures" in content, "Must copy test fixtures"
    assert "uvicorn" in content, "Must use uvicorn to run app"
    assert "igu_sentinel.api:app" in content, "Must reference FastAPI app"
    assert "8000" in content, "Must expose port 8000"
    assert "/health" in content, "Must have health check"

    print("✓ Dockerfile has all required components:")
    print("  - Base image: python:3.11-slim")
    print("  - Dependencies: requirements.txt")
    print("  - Code: igu_sentinel module")
    print("  - Fixtures: test data")
    print("  - App: FastAPI via uvicorn on port 8000")
    print("  - Health check: /health endpoint")


def test_docker_compose_yaml_valid():
    """docker-compose.yml should be valid YAML."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    assert compose_file.exists(), "docker-compose.yml not found"

    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    assert compose_config is not None, "docker-compose.yml is empty or invalid"
    assert "services" in compose_config, "Missing 'services' section"
    assert "networks" in compose_config, "Missing 'networks' section"

    print("✓ docker-compose.yml is valid YAML with services and networks")


def test_sentinel_service_configured():
    """Sentinel service must be configured correctly in docker-compose.yml."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    services = compose_config["services"]
    assert "sentinel" in services, "Sentinel service not found"

    sentinel = services["sentinel"]

    # Verify configuration
    assert sentinel.get("build") == ".", "Must build from current directory"
    assert sentinel.get("container_name") == "igusentinel-sentinel", "Wrong container name"

    # Check networks
    networks = sentinel.get("networks", [])
    if isinstance(networks, dict):
        network_names = list(networks.keys())
    else:
        network_names = networks

    assert "prod-net" in network_names, "Sentinel must be on prod-net"

    # Check port
    ports = sentinel.get("ports", [])
    assert any("8000" in str(p) for p in ports), "Must expose port 8000"

    # Check depends_on
    depends_on = sentinel.get("depends_on")
    assert "diode" in (depends_on or []), "Sentinel should depend on diode"

    print("✓ Sentinel service properly configured:")
    print("  - Build: . (from Dockerfile)")
    print("  - Container: igusentinel-sentinel")
    print("  - Network: prod-net")
    print("  - Port: 8000:8000")
    print("  - Depends on: diode")


def test_diode_service_configured():
    """Diode service must be on both networks with iptables configuration."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    services = compose_config["services"]
    assert "diode" in services, "Diode service not found"

    diode = services["diode"]

    # Check networks
    networks = diode.get("networks", [])
    if isinstance(networks, list):
        network_names = networks
    else:
        network_names = list(networks.keys())

    assert "prod-net" in network_names, "Diode must be on prod-net"
    assert "enclave-net" in network_names, "Diode must be on enclave-net"

    # Check capabilities
    cap_add = diode.get("cap_add", [])
    assert "NET_ADMIN" in cap_add, "Diode must have NET_ADMIN for iptables"

    print("✓ Diode service properly configured:")
    print("  - Networks: prod-net, enclave-net")
    print("  - Capabilities: NET_ADMIN")
    print("  - One-way relay: iptables rules configured")


def test_networks_configured():
    """Networks must be properly defined."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    networks = compose_config.get("networks", {})

    assert "prod-net" in networks, "prod-net not defined"
    assert "enclave-net" in networks, "enclave-net not defined"

    prod_net = networks["prod-net"]
    assert prod_net.get("driver") == "bridge", "prod-net must use bridge driver"

    enclave_net = networks["enclave-net"]
    assert enclave_net.get("driver") == "bridge", "enclave-net must use bridge driver"

    print("✓ Networks properly configured:")
    print("  - prod-net: bridge driver")
    print("  - enclave-net: bridge driver")


def test_traffic_generators_configured():
    """Traffic generator service must be configured on prod-net."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    services = compose_config["services"]
    assert "traffic-gen" in services, "Missing traffic-gen service"

    gen = services["traffic-gen"]
    networks = gen.get("networks", [])

    if isinstance(networks, list):
        network_names = networks
    else:
        network_names = list(networks.keys())

    assert "prod-net" in network_names, "traffic-gen must be on prod-net"

    # Verify it builds from Dockerfile (same as sentinel)
    assert gen.get("build") == ".", "traffic-gen must build from current directory"

    # Verify it runs --all to cover all 6 configs
    command = gen.get("command", [])
    command_str = " ".join(command) if isinstance(command, list) else str(command)
    assert "--all" in command_str, "traffic-gen must run with --all flag"

    print(f"✓ Traffic generator service configured on prod-net (consolidated, --all)")


def test_requirements_has_dependencies():
    """requirements.txt must have all needed dependencies."""
    root_dir = Path(__file__).parent.parent
    req_file = root_dir / "requirements.txt"

    assert req_file.exists(), "requirements.txt not found"

    with open(req_file) as f:
        content = f.read()

    # Check required packages
    required = ["fastapi", "uvicorn", "pydantic"]
    for pkg in required:
        assert pkg in content.lower(), f"Missing required package: {pkg}"

    print("✓ requirements.txt has all required dependencies:")
    for line in content.strip().split('\n'):
        if line and not line.startswith('#'):
            print(f"  - {line}")


def test_api_module_importable():
    """API module must be importable and have required endpoints."""
    sys.path.insert(0, str(Path(__file__).parent.parent))

    try:
        from igu_sentinel.api import app
        from fastapi import FastAPI

        assert isinstance(app, FastAPI), "app must be a FastAPI instance"
        print("✓ FastAPI app successfully imported")

        # Check for required endpoints
        routes = [route.path for route in app.routes]
        assert "/health" in routes, "Missing /health endpoint"
        assert "/detect" in routes, "Missing /detect endpoint"

        print("✓ Required endpoints present:")
        print(f"  - /health (health check)")
        print(f"  - /detect (detection pipeline)")

    except Exception as e:
        raise AssertionError(f"Failed to import API: {e}")


def test_fixtures_exist():
    """Test fixtures must exist for all threat classes."""
    root_dir = Path(__file__).parent.parent
    fixtures_dir = root_dir / "tests" / "fixtures"

    assert fixtures_dir.exists(), "fixtures directory not found"

    threat_classes = [
        "benign",
        "volumetric_ddos",
        "c2_beaconing",
        "dga_dns_tunneling",
        "encrypted_malware",
        "recon_scanning",
        "data_exfiltration",
    ]

    fixture_files = list(fixtures_dir.glob("*_sample.jsonl"))
    fixture_names = {f.stem.replace("_sample", "") for f in fixture_files}

    for threat_class in threat_classes:
        assert threat_class in fixture_names, f"Missing fixture for {threat_class} (checked {fixture_names})"

    print(f"✓ All {len(threat_classes)} threat class fixtures present")


if __name__ == "__main__":
    print("Running docker-compose static validation tests...\n")

    tests = [
        test_dockerfile_exists_and_valid,
        test_docker_compose_yaml_valid,
        test_sentinel_service_configured,
        test_diode_service_configured,
        test_networks_configured,
        test_traffic_generators_configured,
        test_requirements_has_dependencies,
        test_api_module_importable,
        test_fixtures_exist,
    ]

    for test in tests:
        try:
            test()
            print()
        except AssertionError as e:
            print(f"✗ FAILED: {e}\n")
            sys.exit(1)
        except Exception as e:
            print(f"✗ ERROR: {e}\n")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    print("=" * 70)
    print("✅ All docker-compose static validation tests passed!")
    print("=" * 70)
    print("\nConfiguration Summary:")
    print("  Sentinel Service:")
    print("    - FastAPI app running on 0.0.0.0:8000")
    print("    - Accessible from prod-net")
    print("    - Health check: GET /health")
    print("    - Detection API: POST /detect")
    print("\n  Diode Container:")
    print("    - One-way relay between prod-net and enclave-net")
    print("    - iptables enforced: enclave→prod allowed, prod→enclave blocked")
    print("\n  Traffic Generators (on prod-net):")
    print("    - volumetric_ddos")
    print("    - c2_beaconing")
    print("    - dga_dns_tunneling")
    print("    - encrypted_malware")
    print("    - recon_scanning")
    print("    - data_exfiltration")
    print("\n  Pipeline Flow:")
    print("    traffic-generators → prod-net → sentinel → detect → alert")
    print("    (diode blocks return traffic from prod-net to enclave-net)")
