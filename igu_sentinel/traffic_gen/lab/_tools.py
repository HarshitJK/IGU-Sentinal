"""External-tool detection for the lab generators.

The lab harness shells out to real tools (``tshark``, ``hping3``, ``iperf3``,
``dnscat2``/``iodine`` ...). None of them are Python dependencies, so on a fresh
machine they are simply absent. Letting that surface as a raw
``FileNotFoundError`` deep inside ``subprocess`` tells the operator nothing
actionable, so every lab run checks the tools it needs up front and fails — or
skips — with a message that names the missing binary and how to get it.
"""
from __future__ import annotations

import logging
import shutil
from typing import Iterable

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

# Human-readable install hints per tool. Kept generic (no single distro assumed)
# because the lab compose network may be Alpine, Debian, or a dev macOS host.
_INSTALL_HINTS: dict[str, str] = {
    "tshark": "install Wireshark/tshark (e.g. `apt install tshark` or `brew install wireshark`)",
    "hping3": "install hping3 (e.g. `apt install hping3`)",
    "iperf3": "install iperf3 (e.g. `apt install iperf3` or `brew install iperf3`)",
    "timeout": "install GNU coreutils (`timeout`; on macOS `brew install coreutils` gives `gtimeout`)",
    "dnscat2": "install dnscat2 (https://github.com/iagox86/dnscat2) — build the client/server yourself",
    "iodine": "install iodine (e.g. `apt install iodine`)",
    "dig": "install dnsutils/bind-tools (e.g. `apt install dnsutils`) for the `dig` DNS client",
    "ostinato": "install Ostinato (optional; https://ostinato.org)",
    "trex": "install Cisco TRex (optional; https://trex-tgn.cisco.com)",
}


class LabToolMissing(RuntimeError):
    """A required external tool is not on ``PATH``.

    A subclass of ``RuntimeError`` (not ``FileNotFoundError``) so callers can
    catch it precisely and so it never masquerades as a generic missing-file
    error from unrelated code.
    """


def which(tool: str) -> str | None:
    """Thin wrapper over :func:`shutil.which` (kept for a single mock seam)."""
    return shutil.which(tool)


def install_hint(tool: str) -> str:
    """Return a clear 'install X to run this generator' line for ``tool``."""
    hint = _INSTALL_HINTS.get(tool, f"install {tool}")
    return f"'{tool}' not found on PATH — {hint} to run this generator."


def tool_available(tool: str, *, log_if_missing: bool = True) -> bool:
    """Return whether ``tool`` is on ``PATH``, logging a hint if it is not.

    Used for *optional* tools (e.g. ostinato/trex) that should be skipped
    gracefully rather than treated as a hard error.
    """
    if which(tool) is not None:
        return True
    if log_if_missing:
        log.info(install_hint(tool))
    return False


def ensure_tools(*tools: str) -> None:
    """Verify every tool in ``tools`` is on ``PATH`` before a run starts.

    Raises:
        LabToolMissing: naming each missing binary and how to install it, so the
            operator never sees a bare ``FileNotFoundError`` from ``subprocess``.
    """
    missing = [t for t in tools if which(t) is None]
    if missing:
        lines = [install_hint(t) for t in missing]
        for line in lines:
            log.error(line)
        raise LabToolMissing(" ".join(lines))


def first_available(candidates: Iterable[str]) -> str | None:
    """Return the first tool in ``candidates`` present on ``PATH``, else ``None``."""
    for tool in candidates:
        if which(tool) is not None:
            return tool
    return None


def timeout_prefix(duration: int) -> list[str]:
    """Return a ``timeout <n>s`` argv prefix so an unbounded tool cannot run on.

    Tools like ``hping3 --flood`` never stop on their own, so every invocation is
    wrapped in coreutils ``timeout`` (or macOS ``gtimeout``). Returns the tool
    name that must be present so the caller can add it to its PATH check.
    """
    tool = first_available(("timeout", "gtimeout")) or "timeout"
    return [tool, f"{int(duration)}s"]


def timeout_tool() -> str:
    """Name of the timeout binary that :func:`timeout_prefix` will use."""
    return first_available(("timeout", "gtimeout")) or "timeout"
