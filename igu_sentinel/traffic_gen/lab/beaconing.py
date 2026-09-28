"""C2 beaconing lab generator (curl wrapper).

Generates a c2_beaconing capture by issuing periodic HTTPS GET requests to a
lab endpoint at a configurable interval following the existing lab module pattern.

The interval range mirrors detect/rules.py BEACON_INTERVAL_MIN_S=5 ..
BEACON_INTERVAL_MAX_S=300.  curl is used because it produces realistic TLS
ClientHellos that tshark can observe, enabling JA4 extraction.

Capture starts BEFORE the first request so the full session is recorded.
"""
from __future__ import annotations

import logging
from pathlib import Path

from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab._tools import ensure_tools
from igu_sentinel.traffic_gen.lab.capture import DEFAULT_IFACE, capture_lab_run

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

THREAT_CLASS = "c2_beaconing"


def run(
    target: str,
    duration: int,
    *,
    port: int = 443,
    protocol: str = "https",
    interval: float = 30.0,
    jitter: float = 1.0,
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Generate C2-style beaconing traffic to target and capture it.

    Runs for duration seconds, issuing one curl request every interval
    seconds (floor-capped to 0.1s).  interval should satisfy
    rules.py BEACON_INTERVAL_MIN_S=5 .. BEACON_INTERVAL_MAX_S=300 so the
    rule engine can detect it.

    Args:
        target:   Lab-only endpoint (loopback or RFC1918).
        duration: Total capture duration in seconds.
        port:     Destination port (default 443 for HTTPS).
        protocol: https (default) or http.
        interval: Mean beacon interval in seconds (5-300 recommended).
        jitter:   Max deviation applied to the sleep (sleep = interval - jitter).

    Returns:
        Path to the captured pcap.

    Raises:
        ValueError: if target is not a permitted lab endpoint.
        LabToolMissing: if curl or tshark are not installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)
    ensure_tools("curl", "tshark")

    url = f"{protocol}://{target}:{port}/"
    sleep_s = max(0.1, interval - abs(jitter))
    max_time = max(1, int(interval))
    deadline = int(duration)

    # POSIX sh loop: beacon until elapsed time reaches deadline.
    # sh -c avoids creating temp script files and handles bounded execution.
    loop = (
        "end=$(( $(date -u +%s) + DEADLINE ));"
        " while [ $(date -u +%s) -lt $end ]; do"
        "   curl -sSk --max-time MAXTIME -o /dev/null 'URL' 2>/dev/null;"
        "   sleep SLEEP;"
        " done"
        .replace("DEADLINE", str(deadline))
        .replace("MAXTIME", str(max_time))
        .replace("URL", url)
        .replace("SLEEP", str(sleep_s))
    )
    cmd = ["sh", "-c", loop]
    return capture_lab_run(
        threat_class=THREAT_CLASS,
        target=target,
        duration=duration,
        tool_cmd=cmd,
        tool_name="curl",
        iface=iface,
        lab_suffix=lab_suffix,
        out_root=out_root,
        _popen=_popen,
        _sleep=_sleep,
    )
