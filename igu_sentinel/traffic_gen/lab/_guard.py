"""Target-safety guard for the lab traffic generators.

Every generator in :mod:`igu_sentinel.traffic_gen.lab` sends *real* packets. That
is the whole point of the lab harness — but it also makes it the one place in
this codebase that can, if misused, put attack traffic on a network the user
does not own. So the rule is absolute and enforced here, once, for every module
to reuse:

    Real traffic may only ever target a lab endpoint the operator controls.

Concretely a target is accepted only if it is

  * a loopback address (``127.0.0.1``, ``::1``),
  * an RFC1918 private IPv4 address (``10/8``, ``172.16/12``, ``192.168/16``),
  * an IPv6 unique-local address (``fc00::/7``), or
  * a hostname that ends in one of the recognised lab/compose suffixes
    (see :data:`DEFAULT_LAB_SUFFIXES`), e.g. a Docker-Compose service name.

Anything else — a public IP, a public hostname, an empty value — raises
:class:`ValueError`. There is deliberately no flag, env var, or override that
turns this off: a public target is never a legitimate input to this harness.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, Sequence

# Hostname suffixes we treat as "inside the lab / compose network". A hostname
# is accepted only when it ends with one of these. Compose resolves a service by
# its name inside the project network, so the default placeholder target used by
# the shipped lab config — ``sentinel-lab-target`` — matches ``-lab-target``.
# Operators can extend this per-run with the ``lab_suffix`` parameter rather than
# editing this file.
DEFAULT_LAB_SUFFIXES: tuple[str, ...] = (
    "-lab-target",
    "-lab",
    ".lab",
    ".sentinel-lab",
    ".internal",
    ".localhost",
)

# Exact hostnames that are always local.
_ALWAYS_LOCAL_HOSTS: frozenset[str] = frozenset({"localhost"})

# Explicit allowed IP ranges. Kept explicit rather than relying on
# ``ip.is_private`` so the policy is exactly RFC1918 + loopback + IPv6 ULA and
# does NOT silently accept, say, link-local (169.254/16) or CGNAT (100.64/10).
_ALLOWED_NETWORKS: tuple[ipaddress._BaseNetwork, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
    )
)


def _normalise_suffixes(lab_suffix: str | Iterable[str] | None) -> tuple[str, ...]:
    """Combine the default lab suffixes with any operator-supplied ones."""
    extra: Sequence[str]
    if lab_suffix is None:
        extra = ()
    elif isinstance(lab_suffix, str):
        extra = (lab_suffix,)
    else:
        extra = tuple(lab_suffix)
    return DEFAULT_LAB_SUFFIXES + tuple(s.lower() for s in extra if s)


def is_lab_target(target: str, lab_suffix: str | Iterable[str] | None = None) -> bool:
    """Return ``True`` if ``target`` is a permitted lab endpoint, else ``False``.

    Non-raising companion to :func:`validate_lab_target`; use it where a boolean
    is more convenient (tests, conditionals).
    """
    if not isinstance(target, str) or not target.strip():
        return False

    candidate = target.strip()

    # An IP literal must fall inside one of the explicitly allowed ranges.
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        ip = None
    if ip is not None:
        return any(ip in net for net in _ALLOWED_NETWORKS)

    # Otherwise it is a hostname: allow only recognised local/lab names.
    host = candidate.lower().rstrip(".")
    if host in _ALWAYS_LOCAL_HOSTS:
        return True
    return any(host.endswith(suffix) for suffix in _normalise_suffixes(lab_suffix))


def validate_lab_target(target: str, lab_suffix: str | Iterable[str] | None = None) -> str:
    """Return ``target`` unchanged if it is a permitted lab endpoint.

    Raises:
        ValueError: if ``target`` is empty, a public IP address, or a hostname
            that does not end in a recognised lab/compose suffix. The message
            names the offending value and states the policy, so an operator who
            pointed a generator at the wrong host learns why immediately.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError(
            "lab generators require an explicit lab target "
            "(a loopback/RFC1918 address or a compose-service hostname); "
            f"got {target!r}"
        )
    if not is_lab_target(target, lab_suffix=lab_suffix):
        raise ValueError(
            f"refusing to generate real traffic against {target!r}: lab "
            "generators may only target a loopback address, an RFC1918 private "
            "address (10/8, 172.16/12, 192.168/16), an IPv6 unique-local "
            "address (fc00::/7), or a hostname ending in a lab/compose suffix "
            f"{DEFAULT_LAB_SUFFIXES}. Point 'target' at a lab endpoint you own."
        )
    return target.strip()
