"""Benign background-traffic lab generator (iperf3 wrapper).

Default tool is ``iperf3`` in client mode against a lab ``iperf3 -s`` endpoint::

    iperf3 -c <target> -t <duration> [-u] [-p <port>] [-b <bitrate>]

``ostinato`` and ``trex`` are supported as optional richer generators when their
binaries are present; if not, we log a clear line and fall back to iperf3 rather
than failing. A benign class is essential training data — the model needs to
learn what *normal* looks like, not only attacks.
"""
from __future__ import annotations

import logging
from pathlib import Path

from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab._tools import tool_available
from igu_sentinel.traffic_gen.lab.capture import DEFAULT_IFACE, capture_lab_run

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

THREAT_CLASS = "benign"


def _build_iperf3_cmd(target: str, duration: int, port: int, protocol: str, bitrate: str | None) -> list[str]:
    cmd = ["iperf3", "-c", target, "-t", str(int(duration))]
    if protocol.lower() == "udp":
        cmd.append("-u")
        # iperf3 UDP defaults to a tiny 1 Mbit/s; let the caller push more.
        cmd += ["-b", bitrate or "10M"]
    elif bitrate:
        cmd += ["-b", bitrate]
    if port:
        cmd += ["-p", str(int(port))]
    return cmd


def run(
    target: str,
    duration: int,
    *,
    port: int = 5201,
    protocol: str = "tcp",
    bitrate: str | None = None,
    prefer: str = "iperf3",
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Generate benign traffic to ``target`` and capture it.

    ``prefer`` may request ``ostinato`` or ``trex``; if that binary is missing we
    log the reason and use iperf3 instead. Returns the captured pcap path.

    Raises:
        ValueError: if ``target`` is not a permitted lab endpoint.
        LabToolMissing: if neither the chosen generator nor iperf3 is installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)

    prefer = (prefer or "iperf3").lower()
    profile = _params.get("profile")  # optional path to an ostinato/trex profile
    cmd = None
    tool_name = None

    if prefer in ("ostinato", "trex"):
        if not tool_available(prefer):
            # Not installed: skip gracefully with a clear line, use iperf3.
            log.info("[lab] %s not installed; using iperf3 for benign traffic", prefer)
        elif not profile:
            # Installed, but ostinato/trex are profile-driven and a profile is
            # lab-specific — without one there is nothing to replay, so we log the
            # requirement and still produce real traffic via iperf3.
            log.info(
                "[lab] %s is installed but needs a 'profile' path to drive it; "
                "using iperf3 for this run", prefer,
            )
        else:
            cmd = [prefer, str(profile)]
            tool_name = prefer
            log.info("[lab] driving benign traffic with %s profile %s", prefer, profile)

    if cmd is None:
        cmd = _build_iperf3_cmd(target, duration, port, protocol, bitrate)
        tool_name = "iperf3"

    return capture_lab_run(
        threat_class=THREAT_CLASS,
        target=target,
        duration=duration,
        tool_cmd=cmd,
        tool_name=tool_name,
        iface=iface,
        lab_suffix=lab_suffix,
        out_root=out_root,
        _popen=_popen,
        _sleep=_sleep,
    )
