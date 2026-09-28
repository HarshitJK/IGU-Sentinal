#!/usr/bin/env python3
"""Verify an already running demo stack. No host routes or firewall changes.

Add routes only inside the two disposable test containers, prove that a packet
crosses production -> enclave and that its reply hits the reverse DROP rule.
Also require the actual one-way flow feed to reach Sentinel's scoring pipeline.
"""
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import urllib.error


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(f"{args[0:3]} failed: {result.stderr}")
    return result


def container_ip(name, network):
    info = json.loads(run("docker", "inspect", name).stdout)[0]
    return info["NetworkSettings"]["Networks"][network]["IPAddress"]


def verify():
    prod = container_ip("igusentinel-prod-test", "prod-net")
    enclave = container_ip("igusentinel-enclave-test", "enclave-net")
    for container, subnet, gateway in (
        ("igusentinel-prod-test", "172.31.20.0/24", "172.31.10.254"),
        ("igusentinel-enclave-test", "172.31.10.0/24", "172.31.20.254"),
    ):
        run("docker", "exec", container, "ip", "route", "replace", subnet, "via", gateway)

    def counters():
        output = run("docker", "exec", "igusentinel-diode", "iptables", "-nvxL", "FORWARD").stdout
        values = {}
        for line in output.splitlines():
            columns = line.split()
            if len(columns) > 2 and columns[2] in ("ACCEPT", "DROP"):
                values[columns[2]] = int(columns[0])
        return values, output

    before, _ = counters()
    # An echo request must reach the enclave; its reply must be blocked. Unlike
    # "ping failed", increasing BOTH counters establishes the routed path.
    ping = run("docker", "exec", "igusentinel-prod-test", "ping", "-c", "2", "-W", "1", enclave, check=False)
    after, rules = counters()
    assert ping.returncode != 0, "round-trip communication unexpectedly succeeded"
    assert after["ACCEPT"] > before["ACCEPT"], "no forward packet reached the diode"
    assert after["DROP"] > before["DROP"], "no reverse packet was blocked by the diode"
    # Initiating traffic in the opposite direction must hit DROP as well.
    run("docker", "exec", "igusentinel-enclave-test", "ping", "-c", "1", "-W", "1", prod, check=False)
    final, rules = counters()
    assert final["DROP"] > after["DROP"], "enclave-originated traffic did not hit DROP"

    headers = {}
    if os.environ.get("IGU_API_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["IGU_API_TOKEN"]
    status = {}
    for _ in range(30):
        request = urllib.request.Request("http://127.0.0.1:8000/capture/status", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                status = json.load(response)
        except urllib.error.URLError:
            time.sleep(1)
            continue
        if status.get("flows_scored", 0) > 0 and status.get("alerts_emitted", 0) > 0:
            break
        time.sleep(1)
    assert status.get("interface") == "udp:9000", status
    assert status.get("flows_scored", 0) > 0 and status.get("alerts_emitted", 0) > 0, status
    proof = "PASS: forward delivery, reverse DROP, and live flow scoring\n" + rules + json.dumps(status, indent=2)
    Path(".diode-proof-artifact.txt").write_text(proof + "\n")
    print(proof)


if __name__ == "__main__":
    verify()
