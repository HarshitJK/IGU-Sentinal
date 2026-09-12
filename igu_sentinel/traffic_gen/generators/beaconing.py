"""C2 beaconing traffic generator (Slowloris/dnscat2 wrapper)."""
from typing import List
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.generators import mock


def generate(
    threat_class: str = "c2_beaconing",
    source_mode: str = "fixed",
    rate: int = 10,
    size: int = 128,
    port: int = 443,
    duration: int = 1,
) -> List[FlowRecord]:
    """
    Generate C2 beaconing traffic via dnscat2/dns-exfil or HTTP.

    In production, this would invoke:
    - dnscat2 for DNS beaconing
    - dns-exfil for DNS exfiltration
    - curl/wget with persistent keep-alive for HTTP beaconing

    For now, delegates to mock generator with beaconing characteristics.
    """
    return mock.generate(
        threat_class=threat_class,
        source_mode=source_mode,
        rate=rate,
        size=size,
        port=port,
        duration=duration,
    )
