"""TCP SYN flood lab generator (hping3 wrapper).

Produces ``volumetric_ddos`` traffic by running::

    timeout <duration>s hping3 -S --flood -p <port> --rand-source <target>

against a lab endpoint, while tshark records the result. ``--flood`` sends as
fast as possible and never stops on its own, so the ``timeout`` wrapper is
mandatory — the run is bounded by ``duration`` and can never outlive it.

Requires root (raw sockets) in the environment that actually runs it; that is a
runtime concern of the lab compose network, not of this wiring.
"""
from __future__ import annotations

from pathlib import Path

from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab._tools import timeout_prefix, timeout_tool
from igu_sentinel.traffic_gen.lab.capture import DEFAULT_IFACE, capture_lab_run

THREAT_CLASS = "volumetric_ddos"


def run(
    target: str,
    duration: int,
    *,
    port: int = 80,
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Launch a bounded hping3 SYN flood against ``target`` and capture it.

    Returns:
        Path to the captured pcap.

    Raises:
        ValueError: if ``target`` is not a permitted lab endpoint.
        LabToolMissing: if hping3/tshark/timeout are not installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)

    cmd = timeout_prefix(duration) + [
        "hping3",
        "-S",            # SYN
        "--flood",       # as fast as possible, ignore replies
        "-p", str(int(port)),
        "--rand-source", # spoof a spread of source IPs
        target,
    ]
    return capture_lab_run(
        threat_class=THREAT_CLASS,
        target=target,
        duration=duration,
        tool_cmd=cmd,
        tool_name="hping3",
        iface=iface,
        extra_tools=(timeout_tool(),),
        lab_suffix=lab_suffix,
        out_root=out_root,
        _popen=_popen,
        _sleep=_sleep,
    )
