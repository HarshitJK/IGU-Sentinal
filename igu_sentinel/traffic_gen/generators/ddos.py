"""DDoS/volumetric attack traffic generator (hping3/iperf3 wrapper).

Two modes, selected by the ``mode`` variant key:

  * ``mock`` (default) — delegate to :mod:`mock`, fabricating DDoS-shaped feature
    vectors. CI-safe, deterministic, generates no packets. Behaviour is unchanged
    from before lab mode existed.
  * ``lab`` — generate REAL traffic against a lab endpoint (``target``) using
    hping3 (SYN/UDP flood) or the from-scratch slowloris client, capture it with
    tshark, and build FlowRecords from the pcap via the ingest path. Requires a
    lab target and raises if one is missing or not private.
"""
from typing import List

from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock

# Lab attack name -> module. Imported lazily inside lab mode so that importing
# this generator (and the whole mock pipeline) never requires the lab subpackage.
_LAB_ATTACKS = {"syn_flood", "udp_flood", "slowloris"}


def _generate_lab(threat_class, target, attack, rate, size, port, duration, params) -> List[FlowRecord]:
    from igu_sentinel.traffic_gen import lab
    from igu_sentinel.traffic_gen.lab import synflood, udpflood, slowloris

    if not target:
        raise ValueError("lab mode requires a 'target' (a lab endpoint you own)")

    attack = (attack or "syn_flood").lower()
    if attack not in _LAB_ATTACKS:
        raise ValueError(
            f"unknown DDoS lab attack {attack!r}; expected one of {sorted(_LAB_ATTACKS)}"
        )

    run_fn = {
        "syn_flood": synflood.run,
        "udp_flood": udpflood.run,
        "slowloris": slowloris.run,
    }[attack]

    # Only forward params the lab modules understand; drop mock-only knobs.
    lab_params = {k: v for k, v in params.items() if k not in ("source_mode",)}
    lab_params.setdefault("port", int(port))
    return lab.generate_lab_flows(run_fn, target=target, duration=int(duration), **lab_params)


def generate(
    threat_class: str = "volumetric_ddos",
    source_mode: str = "rand",
    rate: int = 1000,
    size: int = 64,
    port: int = 80,
    duration: int = 1,
    mode: str = "mock",
    target: str | None = None,
    attack: str | None = None,
    **params,
) -> List[FlowRecord]:
    """
    Generate volumetric DDoS traffic.

    mock mode invokes the synthetic generator. lab mode invokes, per ``attack``:
    - syn_flood: hping3 -S --flood -p <port> --rand-source <target>
    - udp_flood: hping3 --udp --flood -p <port> --rand-source <target>
    - slowloris: the bounded from-scratch slow-headers client

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
