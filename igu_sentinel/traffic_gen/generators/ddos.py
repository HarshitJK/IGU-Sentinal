"""DDoS/volumetric attack traffic generator (hping3/iperf3 wrapper)."""
from typing import List
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock


def generate(
    threat_class: str = "volumetric_ddos",
    source_mode: str = "rand",
    rate: int = 1000,
    size: int = 64,
    port: int = 80,
    duration: int = 1,
) -> List[FlowRecord]:
    """
    Generate volumetric DDoS traffic via hping3/iperf3.

    In production, this would invoke:
    - hping3 --icmp -i u100 --rand-source target (ICMP flood)
    - iperf3 -u -b 10M -l 64 -t 60 target (UDP flood)

    For now, delegates to mock generator with DDoS characteristics.
    """
    return mock.generate(
        threat_class=threat_class,
        source_mode=source_mode,
        rate=rate,
        size=size,
        port=port,
        duration=duration,
    )
