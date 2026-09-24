"""Real lab traffic generators.

Every module here generates *actual* packets against a lab endpoint the operator
controls and captures them to a pcap, which ingest then turns into FlowRecords —
in contrast to :mod:`igu_sentinel.traffic_gen.generators.mock`, which fabricates
feature vectors directly.

Safety model:
  * :func:`validate_lab_target` gates every generator to loopback / RFC1918 /
    lab-compose hostnames only; a public target raises ``ValueError``.
  * External tools are checked up front with clear install hints
    (:class:`LabToolMissing`) instead of raw ``FileNotFoundError``.
  * Traffic tools are bounded by ``duration`` (via ``timeout`` or an explicit
    loop deadline) and torn down on exit.

Each traffic module exposes ``run(target, duration, **params) -> Path`` returning
the captured pcap path.
"""
from igu_sentinel.traffic_gen.lab._guard import (
    DEFAULT_LAB_SUFFIXES,
    is_lab_target,
    validate_lab_target,
)
from igu_sentinel.traffic_gen.lab._tools import (
    LabToolMissing,
    ensure_tools,
    install_hint,
    tool_available,
)
from igu_sentinel.traffic_gen.lab.capture import (
    DEFAULT_IFACE,
    capture_lab_run,
    generate_lab_flows,
    pcap_to_flows,
)

__all__ = [
    "validate_lab_target",
    "is_lab_target",
    "DEFAULT_LAB_SUFFIXES",
    "LabToolMissing",
    "ensure_tools",
    "tool_available",
    "install_hint",
    "DEFAULT_IFACE",
    "capture_lab_run",
    "pcap_to_flows",
    "generate_lab_flows",
]
