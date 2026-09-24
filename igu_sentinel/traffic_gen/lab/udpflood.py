"""UDP flood lab generator (hping3 wrapper).

Produces ``volumetric_ddos`` traffic by running::

    timeout <duration>s hping3 --udp --flood -p <port> --rand-source <target>

Bounded by ``duration`` via the ``timeout`` wrapper exactly as the SYN flood is —
``--flood`` never terminates on its own.
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
    port: int = 53,
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Launch a bounded hping3 UDP flood against ``target`` and capture it.

    Returns:
        Path to the captured pcap.

    Raises:
        ValueError: if ``target`` is not a permitted lab endpoint.
        LabToolMissing: if hping3/tshark/timeout are not installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)

    cmd = timeout_prefix(duration) + [
        "hping3",
        "--udp",
        "--flood",
        "-p", str(int(port)),
        "--rand-source",
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
