"""Reconnaissance/scanning traffic generator (nmap/masscan wrapper)."""
from typing import List
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock


def generate(
    threat_class: str = "recon_scanning",
    source_mode: str = "rand",
    rate: int = 100,
    size: int = 64,
    port: int = 22,
    duration: int = 1,
) -> List[FlowRecord]:
    """
    Generate recon/scanning traffic via nmap/masscan/Ostinato/TRex.

    In production, this would invoke:
    - nmap -sS -p- --timing T5 target (SYN scan)
    - masscan -p1-65535 --rate 1000 target
    - TRex --stateless-profile example.yaml

    For now, delegates to mock generator with scanning characteristics.
    """
    return mock.generate(
        threat_class=threat_class,
        source_mode=source_mode,
        rate=rate,
        size=size,
        port=port,
        duration=duration,
    )
