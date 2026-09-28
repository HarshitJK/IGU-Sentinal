"""Test Docker networks setup (prod-net and enclave-net)."""
import subprocess
import json
from pathlib import Path
import yaml


def run_docker_command(cmd: list[str]) -> str:
    """Run a docker command (argument list) and return stdout."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Docker command failed: {cmd}\nstderr: {result.stderr}")
    return result.stdout.strip()


def run_docker_command_optional(cmd: list[str]) -> str:
    """Run a docker command that is allowed to fail (e.g. 'network rm' on a missing network)."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )
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
    try:
        # Create prod-net (ignore error if it already exists)
        run_docker_command_optional(["docker", "network", "create", "-d", "bridge", "prod-net"])
        print(f"✓ prod-net creation attempted")

        # Create enclave-net (ignore error if it already exists)
        run_docker_command_optional(["docker", "network", "create", "-d", "bridge", "enclave-net"])
        print(f"✓ enclave-net creation attempted")

        # Verify networks exist
        output = run_docker_command(["docker", "network", "ls", "--format", "json"])
        networks = [json.loads(line) for line in output.split('\n') if line.strip()]
        network_names = {n['Name'] for n in networks}

        assert 'prod-net' in network_names, f"prod-net not found in networks: {network_names}"
        assert 'enclave-net' in network_names, f"enclave-net not found in networks: {network_names}"

        print(f"✓ Both networks exist and are accessible")
        print(f"  All networks: {sorted(network_names)}")

    finally:
        # Clean up created networks (ignore errors on missing networks)
        try:
            run_docker_command_optional(["docker", "network", "rm", "prod-net"])
            run_docker_command_optional(["docker", "network", "rm", "enclave-net"])
            print("✓ Cleanup complete")
        except Exception as e:
            print(f"Warning: cleanup failed: {e}")


if __name__ == "__main__":
    test_docker_compose_file_exists()
    test_networks_defined_in_compose()
    test_networks_can_be_created()
    print("\n✓ All Docker network tests passed")

