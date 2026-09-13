"""DGA / DNS tunneling traffic generator (dnscat2/iodine wrapper)."""
from typing import List
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock


def generate(
    threat_class: str = "dga_dns_tunneling",
    source_mode: str = "fixed",
    rate: int = 50,
    size: int = 80,
    port: int = 53,
    duration: int = 1,
) -> List[FlowRecord]:
    """
    Generate DGA/DNS tunneling traffic via dnscat2/iodine.

    For now, delegates to mock generator with DNS tunneling characteristics.
    """
    return mock.generate(
        threat_class=threat_class,
        source_mode=source_mode,
        rate=rate,
        size=size,
        port=port,
        duration=duration,
    )
