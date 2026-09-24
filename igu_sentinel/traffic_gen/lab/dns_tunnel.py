"""DNS tunnelling lab generator (dnscat2 / iodine client wrapper).

Drives a real DNS tunnelling client against a tunnelling server that must be
running **inside the lab network** (the ``target``). dnscat2 is preferred; iodine
is used if dnscat2 is absent. The client is wrapped in ``timeout`` so the tunnel
session is bounded by ``duration`` and cannot run on.

This wires the client only. Standing up the matching server (``dnscat2 --dns ...``
or ``iodined``) and delegating a tunnel domain to it is a lab-topology concern
handled in the compose network, not here — the guard still ensures the client can
only ever point at a lab endpoint.
"""
from __future__ import annotations

import logging
from pathlib import Path

from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab._tools import (
    LabToolMissing,
    first_available,
    install_hint,
    timeout_prefix,
    timeout_tool,
)
from igu_sentinel.traffic_gen.lab.capture import DEFAULT_IFACE, capture_lab_run

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

THREAT_CLASS = "dga_dns_tunneling"

_DNSCAT_NAMES = ("dnscat2", "dnscat")
_IODINE_NAMES = ("iodine",)


def _build_command(target: str, duration: int, port: int, domain: str) -> tuple[list[str], str]:
    """Choose an installed tunnelling client and build its bounded command."""
    dnscat = first_available(_DNSCAT_NAMES)
    if dnscat:
        cmd = timeout_prefix(duration) + [
            dnscat,
            "--dns", f"server={target},port={int(port)}",
            "--no-encryption",  # lab metadata generation; not securing anything
            domain,
        ]
        return cmd, dnscat

    iodine = first_available(_IODINE_NAMES)
    if iodine:
        # -f foreground so timeout can bound it; -r skip raw-tunnel probe.
        cmd = timeout_prefix(duration) + [iodine, "-f", "-r", target, domain]
        return cmd, iodine

    raise LabToolMissing(
        install_hint("dnscat2") + " or " + install_hint("iodine")
    )


def run(
    target: str,
    duration: int,
    *,
    port: int = 53,
    domain: str = "tunnel.sentinel-lab",
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Run a bounded DNS tunnelling client against the lab server and capture it.

    Returns the captured pcap path.

    Raises:
        ValueError: if ``target`` is not a permitted lab endpoint.
        LabToolMissing: if neither dnscat2 nor iodine (nor tshark) is installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)

    cmd, tool_name = _build_command(target, duration, port, domain)
    return capture_lab_run(
        threat_class=THREAT_CLASS,
        target=target,
        duration=duration,
        tool_cmd=cmd,
        tool_name=tool_name,
        iface=iface,
        extra_tools=(timeout_tool(),),
        lab_suffix=lab_suffix,
        out_root=out_root,
        _popen=_popen,
        _sleep=_sleep,
    )
