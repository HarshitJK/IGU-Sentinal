"""Data exfiltration traffic generator."""
from typing import List
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock


def generate(
    threat_class: str = "data_exfiltration",
    source_mode: str = "fixed",
    rate: int = 5,
    size: int = 512,
    port: int = 443,
    duration: int = 1,
) -> List[FlowRecord]:
    """
    Generate data exfiltration traffic.

    For now, delegates to mock generator with exfiltration characteristics.
    """
    return mock.generate(
        threat_class=threat_class,
        source_mode=source_mode,
        rate=rate,
        size=size,
        port=port,
        duration=duration,
    )
