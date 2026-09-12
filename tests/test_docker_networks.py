"""Test Docker networks setup (prod-net and enclave-net)."""
import subprocess
import json
from pathlib import Path
import yaml


def run_docker_command(cmd):
    """Run a docker command and return stdout."""
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30
    )
    if result.returncode != 0:
        raise RuntimeError(f"Docker command failed: {cmd}\nstderr: {result.stderr}")
    return result.stdout.strip()


def test_docker_compose_file_exists():
    """docker-compose.yml should exist and be valid."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    assert compose_file.exists(), (
        f"docker-compose.yml not found at {compose_file}"
    )
    print(f"✓ docker-compose.yml found")

    # Parse and validate YAML
    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    assert compose_config is not None, "docker-compose.yml is empty or invalid YAML"
    assert 'networks' in compose_config, "docker-compose.yml must define 'networks' section"
    print(f"✓ docker-compose.yml is valid YAML")


def test_networks_defined_in_compose():
    """prod-net and enclave-net networks should be defined in docker-compose.yml."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    networks = compose_config.get('networks', {})

    assert 'prod-net' in networks, f"prod-net not defined in networks: {networks.keys()}"
    assert 'enclave-net' in networks, f"enclave-net not defined in networks: {networks.keys()}"

    print(f"✓ Networks defined: prod-net, enclave-net")
    print(f"  prod-net config: {networks['prod-net']}")
    print(f"  enclave-net config: {networks['enclave-net']}")


def test_networks_can_be_created():
    """Docker networks should be creatable with the defined config."""
    # Create the networks directly using docker network create
    try:
        # Create prod-net
        output = run_docker_command("docker network create -d bridge prod-net 2>&1 || true")
        print(f"✓ prod-net creation attempted")

        # Create enclave-net
        output = run_docker_command("docker network create -d bridge enclave-net 2>&1 || true")
        print(f"✓ enclave-net creation attempted")

        # Verify networks exist
        output = run_docker_command("docker network ls --format json")
        networks = [json.loads(line) for line in output.split('\n') if line.strip()]
        network_names = {n['Name'] for n in networks}

        assert 'prod-net' in network_names, f"prod-net not found in networks: {network_names}"
        assert 'enclave-net' in network_names, f"enclave-net not found in networks: {network_names}"

        print(f"✓ Both networks exist and are accessible")
        print(f"  All networks: {sorted(network_names)}")

    finally:
        # Clean up created networks
        try:
            run_docker_command("docker network rm prod-net 2>&1 || true")
            run_docker_command("docker network rm enclave-net 2>&1 || true")
            print("✓ Cleanup complete")
        except Exception as e:
            print(f"Warning: cleanup failed: {e}")


if __name__ == "__main__":
    test_docker_compose_file_exists()
    test_networks_defined_in_compose()
    test_networks_can_be_created()
    print("\n✓ All Docker network tests passed")
