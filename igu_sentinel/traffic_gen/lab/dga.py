"""DGA (domain-generation-algorithm) query traffic for the lab.

Two published, open DGA families are implemented *from scratch* in Python here —
no third-party DGA code is downloaded or executed:

  * ``date_dga``    — a date-seeded pseudo-random concatenation DGA in the style
                      of Conficker/CryptoLocker: a simple LCG seeded from the day
                      emits a run of letters, and a TLD is appended. This is the
                      canonical "new set of random-looking domains every day"
                      pattern that DGA detection targets.
  * ``banjori_dga`` — the banjori mutation DGA: each domain is derived from the
                      previous one by adding, per position, an offset computed
                      from the first four bytes of the seed label. Produces long
                      pronounceable-looking .com domains.

The generated names are then queried against the **lab DNS endpoint only** over
UDP (a minimal DNS query is built by hand — no external resolver library and no
query to real DNS infrastructure). tshark records the resulting query packets,
and ingest turns them into ``dga_dns_tunneling`` FlowRecords.

Runnable as a module so the capture orchestrator can launch it as a subprocess::

    python -m igu_sentinel.traffic_gen.lab.dga --target <lab> --duration 10
"""
from __future__ import annotations

import argparse
import logging
import socket
import struct
import sys
import time
from datetime import date, datetime
from pathlib import Path
from typing import List

from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab.capture import DEFAULT_IFACE, capture_lab_run

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

THREAT_CLASS = "dga_dns_tunneling"

_TLDS = ("com", "net", "org", "info", "biz", "ru")


# ── DGA algorithms (implemented from scratch) ─────────────────────────────────
def date_dga(seed_date: date, count: int, tld: str = "com") -> List[str]:
    """Date-seeded LCG concatenation DGA (Conficker/CryptoLocker family style)."""
    # Seed from the date so the whole set rotates daily — the defining property.
    state = (seed_date.year * 10000 + seed_date.month * 100 + seed_date.day) & 0xFFFFFFFF
    domains: List[str] = []
    for _ in range(max(1, count)):
        length = 8 + (state % 9)  # 8..16 chars, as most DGA families produce
        chars = []
        for _ in range(length):
            # Numerical Recipes LCG constants.
            state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
            chars.append(chr(ord("a") + (state >> 16) % 26))
        domains.append("".join(chars) + "." + tld)
    return domains


def banjori_dga(seed_domain: str, count: int) -> List[str]:
    """Banjori mutation DGA: each domain mutates the previous one's label.

    Reimplemented from the published algorithm: offsets derived from the first
    four label bytes are added, with carry, across the label characters.
    """
    label, _, tld = seed_domain.partition(".")
    tld = tld or "com"
    label = "".join(c for c in label.lower() if c.isalpha()) or "earnestnessbiophysicalohax"
    # Work in 0..25 letter space; mutate the leading four positions each round
    # from offsets derived from the current label, then carry the change along
    # the rest of the label — the banjori "each domain derives from the previous"
    # property that yields long pronounceable-looking names.
    chars = [(ord(c) - ord("a")) % 26 for c in label]
    domains: List[str] = []
    for _ in range(max(1, count)):
        d0, d1, d2, d3 = chars[0], chars[1], chars[2], chars[3]
        chars[0] = (chars[0] + d1 + 1) % 26
        chars[1] = (chars[1] + d2 + d0) % 26
        chars[2] = (chars[2] + d3 + d1) % 26
        chars[3] = (chars[3] + d0 + d2) % 26
        for i in range(4, len(chars)):
            chars[i] = (chars[i] + chars[i - 4]) % 26
        domains.append("".join(chr(c + ord("a")) for c in chars) + "." + tld)
    return domains


def generate_domains(count: int, seed_date: date | None = None, algo: str = "all") -> List[str]:
    """Generate ``count`` DGA domains using the requested algorithm(s)."""
    seed_date = seed_date or date.today()
    algo = (algo or "all").lower()
    if algo == "date":
        return date_dga(seed_date, count)
    if algo == "banjori":
        return banjori_dga("earnestnessbiophysicalohax.com", count)
    # "all": interleave both families so the class is not a single algorithm.
    half = max(1, count // 2)
    combined = date_dga(seed_date, half) + banjori_dga("earnestnessbiophysicalohax.com", count - half)
    return combined[:count]


# ── DNS query emission (self-contained, lab-only) ─────────────────────────────
def _build_dns_query(domain: str, qid: int) -> bytes:
    """Build a minimal DNS A-record query packet by hand (no resolver library)."""
    header = struct.pack(">HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii", "ignore")
        for part in domain.split(".") if part
    ) + b"\x00"
    question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def send_dns_queries(target: str, port: int, domains: List[str], duration: int) -> int:
    """Send DNS queries for ``domains`` to the lab DNS ``target`` over UDP.

    Bounded by ``duration``: loops over the domain list, re-cycling if needed,
    until the window closes. Returns the number of queries sent. No responses are
    required — the lab DNS container may or may not answer; the query packets are
    what training needs.
    """
    validate_lab_target(target)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sent = 0
    deadline = time.monotonic() + max(1, duration)
    try:
        i = 0
        while time.monotonic() < deadline and domains:
            domain = domains[i % len(domains)]
            try:
                sock.sendto(_build_dns_query(domain, qid=i), (target, int(port)))
                sent += 1
            except OSError as exc:
                log.debug("[lab] dns send failed for %s: %s", domain, exc)
            i += 1
            time.sleep(0.02)  # ~50 qps; realistic DGA callback cadence
    finally:
        sock.close()
    return sent


def run(
    target: str,
    duration: int,
    *,
    port: int = 53,
    count: int = 200,
    algo: str = "all",
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Generate DGA DNS-query traffic against the lab DNS endpoint and capture it.

    Spawns this module as a subprocess (so the queries are real packets tshark
    records) and returns the captured pcap path.

    Raises:
        ValueError: if ``target`` is not a permitted lab endpoint.
        LabToolMissing: if tshark is not installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)

    cmd = [
        sys.executable, "-m", "igu_sentinel.traffic_gen.lab.dga",
        "--target", target,
        "--duration", str(int(duration)),
        "--port", str(int(port)),
        "--count", str(int(count)),
        "--algo", str(algo),
    ]
    return capture_lab_run(
        threat_class=THREAT_CLASS,
        target=target,
        duration=duration,
        tool_cmd=cmd,
        tool_name=None,  # runs under the current interpreter
        iface=iface,
        lab_suffix=lab_suffix,
        out_root=out_root,
        _popen=_popen,
        _sleep=_sleep,
    )


def _main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit lab DGA DNS queries.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--algo", default="all")
    args = parser.parse_args(argv)

    # Guard again inside the child: this entry point sends real packets.
    validate_lab_target(args.target)
    domains = generate_domains(args.count, datetime.now().date(), args.algo)
    sent = send_dns_queries(args.target, args.port, domains, args.duration)
    print(f"[lab-dga] sent {sent} DNS queries for {len(domains)} generated domains to {args.target}:{args.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
