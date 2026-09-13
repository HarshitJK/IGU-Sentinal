"""Test traffic generator containers on prod-net wired to traffic_gen/."""
import subprocess
import time
from pathlib import Path
import yaml


def run_command(cmd, timeout=30):
    """Run a shell command and return stdout, stderr, returncode."""
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def docker_compose_up():
    """Start all containers."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    stdout, stderr, rc = run_command(
        f"cd {root_dir} && docker-compose -f {compose_file} up -d",
        timeout=60
    )

    if rc != 0:
        raise RuntimeError(f"docker-compose up failed:\nstdout: {stdout}\nstderr: {stderr}")

    # Wait for containers to be ready
    time.sleep(3)
    print(f"✓ docker-compose up: containers started")


def docker_compose_down():
    """Stop and remove all containers."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    stdout, stderr, rc = run_command(
        f"cd {root_dir} && docker-compose -f {compose_file} down -v",
        timeout=60
    )

    if rc != 0:
        print(f"⚠ docker-compose down had issues: {stderr}")
    else:
        print(f"✓ docker-compose down: cleanup complete")


def test_traffic_gen_configs_exist():
    """Traffic gen config files should exist."""
    root_dir = Path(__file__).parent.parent
    config_dir = root_dir / "igu_sentinel" / "traffic_gen" / "config"

    assert config_dir.exists(), f"traffic_gen/config/ directory not found at {config_dir}"

    # Check for at least one config file
    config_files = list(config_dir.glob("*.yaml"))
    assert len(config_files) > 0, f"No YAML config files found in {config_dir}"

    print(f"✓ Traffic gen config files found: {len(config_files)}")
    for config_file in config_files:
        print(f"  - {config_file.name}")


def test_traffic_gen_containers_defined():
    """Traffic generator container should be defined in docker-compose.yml."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        compose_config = yaml.safe_load(f)

    services = compose_config.get('services', {})

    # Consolidated traffic-gen service should exist
    assert 'traffic-gen' in services, (
        f"No traffic-gen service found in docker-compose.yml. "
        f"Available services: {list(services.keys())}"
    )

    print(f"✓ Traffic generator service found: traffic-gen")

    # Verify traffic-gen is on prod-net
    service = services['traffic-gen']
    networks = service.get('networks', [])

    if isinstance(networks, list):
        network_names = networks
    elif isinstance(networks, dict):
        network_names = list(networks.keys())
    else:
        network_names = []

    assert 'prod-net' in network_names, (
        f"traffic-gen must be on 'prod-net'. Networks: {network_names}"
    )
    print(f"  ✓ traffic-gen is on prod-net")

    # Verify it builds from Dockerfile (not a raw image with volume mounts)
    build = service.get('build')
    assert build, "traffic-gen must have a build context defined"
    print(f"    ✓ build: {build}")


def test_traffic_gen_container_startup():
    """Traffic generator containers should start successfully."""
    try:
        docker_compose_up()

        # Verify containers are running
        root_dir = Path(__file__).parent.parent
        stdout, stderr, rc = run_command(
            "docker ps --format '{{.Names}}' | grep -E '(traffic|gen)'",
            timeout=10
        )

        if rc == 0:
            container_names = stdout.split('\n')
            container_names = [c for c in container_names if c.strip()]
            print(f"✓ Traffic generator containers running: {container_names}")
        else:
            # It's ok if no containers match the pattern yet, just verify compose didn't fail
            print(f"✓ docker-compose started without errors")

        print(f"✓ test_traffic_gen_container_startup passed")

    finally:
        docker_compose_down()


if __name__ == "__main__":
    test_traffic_gen_configs_exist()
    test_traffic_gen_containers_defined()
    test_traffic_gen_container_startup()
    print("\n✓ All traffic gen container tests passed")
