"""DGA / DNS tunneling traffic generator (dnscat2/iodine + DGA wrapper).

Two modes, selected by the ``mode`` variant key:

  * ``mock`` (default) — delegate to :mod:`mock`. CI-safe, no packets, unchanged.
  * ``lab`` — generate REAL DNS traffic against a lab endpoint (``target``):
      - dns_tunnel: a bounded dnscat2/iodine client session, or
      - dga:        from-scratch DGA domains queried at the lab DNS server,
    captured with tshark and turned into FlowRecords via the ingest path.
"""
from typing import List

from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock

_LAB_ATTACKS = {"dns_tunnel", "dga"}


def _generate_lab(threat_class, target, attack, rate, size, port, duration, params) -> List[FlowRecord]:
    from igu_sentinel.traffic_gen import lab
    from igu_sentinel.traffic_gen.lab import dns_tunnel, dga

    if not target:
        raise ValueError("lab mode requires a 'target' (a lab endpoint you own)")

    attack = (attack or "dga").lower()
    if attack not in _LAB_ATTACKS:
        raise ValueError(
            f"unknown DNS lab attack {attack!r}; expected one of {sorted(_LAB_ATTACKS)}"
        )

    run_fn = {"dns_tunnel": dns_tunnel.run, "dga": dga.run}[attack]

    lab_params = {k: v for k, v in params.items() if k not in ("source_mode",)}
    lab_params.setdefault("port", int(port))
    return lab.generate_lab_flows(run_fn, target=target, duration=int(duration), **lab_params)


def generate(
    threat_class: str = "dga_dns_tunneling",
    source_mode: str = "fixed",
    rate: int = 50,
    size: int = 80,
    port: int = 53,
    duration: int = 1,
    mode: str = "mock",
    target: str | None = None,
    attack: str | None = None,
    **params,
) -> List[FlowRecord]:
    """
    Generate DGA/DNS tunneling traffic.

    mock mode invokes the synthetic generator. lab mode invokes, per ``attack``:
    - dns_tunnel: a bounded dnscat2/iodine tunnelling client against the lab DNS
    - dga:        from-scratch DGA domain queries against the lab DNS

    Returns a list of FlowRecords (fabricated in mock mode; extracted from a real
    capture in lab mode).
    """
    if mode == "lab":
        return _generate_lab(threat_class, target, attack, rate, size, port, duration, params)

    # mock mode: unchanged from the original contract — no new kwargs passed on.
    return mock.generate(
        threat_class=threat_class,
        source_mode=source_mode,
        rate=rate,
        size=size,
        port=port,
        duration=duration,
    )
