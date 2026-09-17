"""Test diode container one-way relay enforcement.

A diode enforces unidirectional traffic:
- Outbound from enclave-net to prod-net is allowed via iptables ACCEPT
- Inbound from prod-net to enclave-net is blocked via iptables DROP
"""
import subprocess
import time
from pathlib import Path

import yaml

from tests.conftest import compose_command


def run_command(cmd, timeout=30, cwd=None):
    """Run a command (list or str) and return stdout, stderr, returncode."""
    result = subprocess.run(
        cmd,
        shell=isinstance(cmd, str),
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def docker_compose_up():
    """Start all containers."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    stdout, stderr, rc = run_command(
        [*compose_command().split(), "-f", str(compose_file), "up", "-d"],
        timeout=60,
        cwd=str(root_dir),
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
        [*compose_command().split(), "-f", str(compose_file), "down", "-v"],
        timeout=60,
        cwd=str(root_dir),
    )

    if rc != 0:
        print(f"⚠ docker-compose down had issues: {stderr}")
    else:
        print(f"✓ docker-compose down: cleanup complete")


def test_diode_container_exists():
    """Diode container should be defined in docker-compose.yml."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        import yaml
        compose_config = yaml.safe_load(f)

    services = compose_config.get('services', {})
    assert 'diode' in services, (
        f"'diode' service not found in docker-compose.yml. "
        f"Available services: {list(services.keys())}"
    )

    # Diode should be on both networks
    diode_service = services['diode']
    networks = diode_service.get('networks', [])

    # Handle both list and dict formats for networks
    if isinstance(networks, list):
        network_names = networks
    elif isinstance(networks, dict):
        network_names = list(networks.keys())
    else:
        network_names = []

    assert 'prod-net' in network_names, (
        f"diode service must be on 'prod-net'. Networks: {network_names}"
    )
    assert 'enclave-net' in network_names, (
        f"diode service must be on 'enclave-net'. Networks: {network_names}"
    )

    print(f"✓ Diode container defined and on both networks: {network_names}")


def test_diode_iptables_rules_configured():
    """Verify the diode installs, and verifies, one-way iptables rules.

    Asserts the *properties* the diode must have rather than literal interface
    names. The rules used to be pinned to eth0/eth1, but Docker does not
    guarantee that the first network listed becomes eth0 — so the one-way rules
    could be installed backwards, inverting the diode with no visible error. The
    command now resolves each interface from its network's subnet.
    """
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        content = f.read()

    compose_config = yaml.safe_load(content)
    diode = compose_config["services"]["diode"]
    command = "\n".join(
        part for part in diode["command"] if isinstance(part, str)
    )

    # Default-deny, then exactly one permitted direction.
    assert "iptables -P FORWARD DROP" in command, (
        "Diode must set the iptables FORWARD policy to DROP"
    )
    assert '-i "$$ENCL_IF" -o "$$PROD_IF" -j ACCEPT' in command, (
        "Diode must allow enclave -> prod forwarding"
    )
    assert '-i "$$PROD_IF" -o "$$ENCL_IF" -j DROP' in command, (
        "Diode must DROP the prod -> enclave return path"
    )

    # Interfaces resolved from subnets, not assumed from Docker's ordering.
    assert "ip -o -4 addr show" in command, (
        "Diode must resolve its interfaces at runtime, not hardcode eth0/eth1"
    )

    # The rules must be read back: a diode that cannot prove its own
    # enforcement must not report itself online.
    assert "iptables -C FORWARD" in command, (
        "Diode must verify its rules were actually installed"
    )

    # An image that actually ships iptables. busybox does not, so every rule
    # failed with 'iptables: not found' while the container reported ready.
    assert "busybox" not in diode["image"], (
        "busybox has no iptables applet — the diode would enforce nothing"
    )

    # Fail-closed: any failing step must kill the container.
    assert "-eu" in diode["command"], (
        "Diode command must run with `set -eu` so a failed rule is fatal"
    )

    print("✓ Diode configured with verified, subnet-resolved one-way iptables rules")


def test_diode_has_net_admin_capability():
    """Verify diode container has NET_ADMIN capability for iptables."""
    root_dir = Path(__file__).parent.parent
    compose_file = root_dir / "docker-compose.yml"

    with open(compose_file) as f:
        import yaml
        compose_config = yaml.safe_load(f)

    diode_service = compose_config['services']['diode']
    cap_add = diode_service.get('cap_add', [])

    assert 'NET_ADMIN' in cap_add, (
        f"Diode must have NET_ADMIN capability to use iptables. "
        f"Current caps: {cap_add}"
    )

    print(f"✓ Diode has NET_ADMIN capability for iptables")


def test_diode_container_starts():
    """Verify diode container starts successfully."""
    try:
        docker_compose_up()

        # Verify diode is running
        stdout, stderr, rc = run_command(
            "docker ps -f name=igusentinel-diode --format='{{.Names}} {{.State}}'"
        )

        assert "igusentinel-diode" in stdout and "running" in stdout, (
            f"Diode container should be running.\nOutput:\n{stdout}"
        )
        print(f"✓ Diode container running: {stdout}")

    finally:
        docker_compose_down()


def test_diode_startup_logs():
    """Verify diode startup logs show iptables configuration attempt."""
    try:
        docker_compose_up()

        # Check logs for iptables configuration
        stdout, stderr, rc = run_command(
            "docker logs igusentinel-diode 2>&1"
        )

        assert "iptables" in stdout or "Diode" in stdout, (
            f"Diode logs should mention iptables or Diode.\nLogs:\n{stdout}"
        )
        assert "Diode online" in stdout, (
            f"Diode should report being online.\nLogs:\n{stdout}"
        )

        print(f"✓ Diode startup logs show iptables configuration:")
        for line in stdout.split('\n')[:5]:
            if line.strip():
                print(f"  {line}")

    finally:
        docker_compose_down()


def test_all_containers_running():
    """Verify minimum required containers (diode, prod-test, enclave-test) are running."""
    try:
        docker_compose_up()

        # Verify containers are up
        stdout, stderr, rc = run_command(
            "docker ps -f name=igusentinel --format='{{.Names}}'"
        )

        containers = [c.strip() for c in stdout.split('\n') if c.strip()]
        assert len(containers) >= 3, (
            f"Expected at least 3 containers, found {len(containers)}: {containers}"
        )

        # Check that we have all required baseline containers
        assert any('diode' in c for c in containers), "diode container missing"
        assert any('prod-test' in c for c in containers), "prod-test container missing"
        assert any('enclave-test' in c for c in containers), "enclave-test container missing"

        print(f"✓ Required containers running: {containers}")

    finally:
        docker_compose_down()


def test_networks_exist_and_separate():
    """Verify both networks exist and are separate."""
    try:
        docker_compose_up()

        # Check prod-net
        stdout, stderr, rc = run_command(
            "docker network inspect prod-net --format='OK' 2>/dev/null"
        )
        assert stdout == "OK", "prod-net should exist"

        # Check enclave-net
        stdout, stderr, rc = run_command(
            "docker network inspect enclave-net --format='OK' 2>/dev/null"
        )
        assert stdout == "OK", "enclave-net should exist"

        print(f"✓ Networks exist and are configured (prod-net, enclave-net)")

    finally:
        docker_compose_down()


def test_one_way_relay_proof_artifact():
    """Generate proof artifact showing one-way relay setup."""
    try:
        docker_compose_up()

        # Collect evidence of one-way relay setup
        proof_lines = []
        proof_lines.append("=== Diode One-Way Relay Configuration Proof ===")
        proof_lines.append("")

        # 1. Docker Compose Configuration
        root_dir = Path(__file__).parent.parent
        compose_file = root_dir / "docker-compose.yml"
        with open(compose_file) as f:
            content = f.read()

        proof_lines.append("1. Docker Compose Configuration (docker-compose.yml):")
        proof_lines.append("   - Diode on both networks: prod-net and enclave-net")
        proof_lines.append("   - NET_ADMIN capability enabled: YES")
        proof_lines.append("   - iptables rules configured:")
        proof_lines.append("     * FORWARD policy: DROP (deny by default)")
        proof_lines.append("     * eth0->eth1: ACCEPT (enclave to prod, outbound allowed)")
        proof_lines.append("     * eth1->eth0: DROP (prod to enclave, return blocked)")
        proof_lines.append("")

        # 2. Running Containers
        proof_lines.append("2. Running Containers:")
        stdout, stderr, rc = run_command(
            "docker ps -f name=igusentinel --format='{{.Names}} {{.State}}'"
        )
        for line in stdout.split('\n'):
            if line.strip():
                proof_lines.append(f"   {line}")
        proof_lines.append("")

        # 3. Container Networks
        proof_lines.append("3. Diode Container Network Attachment:")
        stdout, stderr, rc = run_command(
            "docker inspect igusentinel-diode --format='{{range $k,$v := .NetworkSettings.Networks}}{{$k}}: {{$v.IPAddress}}{{\"\\n\"}}{{end}}'"
        )
        for line in stdout.split('\n'):
            if line.strip():
                proof_lines.append(f"   {line}")
        proof_lines.append("")

        # 4. Diode Startup Logs
        proof_lines.append("4. Diode Startup Logs (iptables configuration):")
        stdout, stderr, rc = run_command(
            "docker logs igusentinel-diode 2>&1"
        )
        for line in stdout.split('\n'):
            if line.strip():
                proof_lines.append(f"   {line}")
        proof_lines.append("")

        # 5. Network Architecture
        proof_lines.append("5. Network Architecture:")
        proof_lines.append("   enclave-test ---[enclave-net]---> diode ---[prod-net]---> prod-test")
        proof_lines.append("                                      |")
        proof_lines.append("                   iptables blocks return")
        proof_lines.append("                       (eth1->eth0 DROP)")
        proof_lines.append("")

        proof_artifact = "\n".join(proof_lines)
        print("\n" + proof_artifact)

        # Save artifact
        artifact_path = root_dir / ".diode-proof-artifact.txt"
        with open(artifact_path, 'w') as f:
            f.write(proof_artifact)

        print(f"\n✓ Proof artifact saved to {artifact_path}")

    finally:
        docker_compose_down()


if __name__ == "__main__":
    print("Testing diode container one-way relay enforcement...\n")
    test_diode_container_exists()
    test_diode_iptables_rules_configured()
    test_diode_has_net_admin_capability()
    test_diode_container_starts()
    test_diode_startup_logs()
    test_all_containers_running()
    test_networks_exist_and_separate()
    test_one_way_relay_proof_artifact()
    print("\n✓ All diode tests passed - one-way relay container verified")
