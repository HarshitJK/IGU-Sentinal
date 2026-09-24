"""Capture orchestration shared by every lab generator.

The contract for a lab run is fixed and lives here so no generator reimplements
it:

  1. Validate the target (defence in depth — each module validates too).
  2. Verify the tools the run needs are installed.
  3. Start ``tshark -i <iface> -a duration:<n> -w <pcap>`` FIRST, so the capture
     is already recording before any traffic is generated.
  4. Launch the traffic tool as a child process, bounded so it cannot outlive
     the run.
  5. Wait for the capture window to close, then tear down every child process —
     on normal exit, timeout, or error alike.
  6. Hand the resulting ``.pcap`` back.

Turning that ``.pcap`` into ``FlowRecord`` objects is deliberately NOT done here
with fresh parsing: :func:`pcap_to_flows` delegates to
:func:`igu_sentinel.ingest.extract_flows_from_pcap`, the exact feature-extraction
path used for live ingest, so the lab and live pipelines can never drift apart.
"""
from __future__ import annotations

import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab._tools import ensure_tools

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

# Linux loopback: the default lab compose network is Linux, and loopback keeps a
# misconfigured run from ever leaving the host. Override per-run with ``iface``.
DEFAULT_IFACE = "lo"

# Where pcaps and per-run logs land. Under datasets/, which is .gitignored, so
# captured traffic is never committed.
_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LAB_RUNS = _REPO_ROOT / "datasets" / "lab_runs"

# Let tshark bind and start recording before traffic begins, and how long past
# the capture window we wait before force-killing.
_CAPTURE_WARMUP_S = 0.5
_WAIT_GRACE_S = 5.0
_TERM_GRACE_S = 3.0


def _run_dir(threat_class: str, out_root: Optional[Path]) -> Path:
    root = Path(out_root) if out_root is not None else DEFAULT_LAB_RUNS
    d = root / threat_class
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cleanup(proc, name: str) -> None:
    """Terminate a child process if it is still running; never raise."""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=_TERM_GRACE_S)
            except Exception:
                proc.kill()
    except Exception as exc:  # pragma: no cover - defensive teardown
        log.warning("failed to clean up %s process: %s", name, exc)


def capture_lab_run(
    *,
    threat_class: str,
    target: str,
    duration: int,
    tool_cmd: Sequence[str],
    tool_name: Optional[str] = None,
    iface: str = DEFAULT_IFACE,
    extra_tools: Sequence[str] = (),
    lab_suffix=None,
    out_root: Optional[Path] = None,
    _popen=None,
    _sleep=None,
) -> Path:
    """Run one capture-wrapped traffic burst and return the captured pcap path.

    Args:
        threat_class: Label for the run; also the output sub-directory.
        target: Lab endpoint (validated here and by the caller).
        duration: Capture/traffic window in seconds. tshark stops itself after
            this via ``-a duration:`` and the tool is expected to be bounded too.
        tool_cmd: Full argv of the traffic tool to launch.
        tool_name: Binary that must exist for ``tool_cmd`` (for the PATH check);
            ``None`` for Python-based generators run via the current interpreter,
            which is guaranteed present — then only tshark and ``extra_tools`` are
            checked.
        iface: Capture interface (default loopback).
        extra_tools: Any additional binaries ``tool_cmd`` depends on (e.g.
            ``timeout``) to check up front.
        out_root: Override the datasets/lab_runs root (used by tests).
        _popen / _sleep: Test seams; default to ``subprocess.Popen`` / ``time.sleep``.

    Returns:
        Path to the ``.pcap`` written by tshark.

    Raises:
        ValueError: if ``target`` is not a permitted lab endpoint.
        LabToolMissing: if tshark or a required tool is absent from PATH.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)
    required = ["tshark", *([tool_name] if tool_name else []), *extra_tools]
    ensure_tools(*required)

    popen = _popen if _popen is not None else subprocess.Popen
    sleep = _sleep if _sleep is not None else time.sleep

    ts = datetime.now().strftime("%Y%m%dT%H%M%S_%f")
    run_dir = _run_dir(threat_class, out_root)
    pcap_path = run_dir / f"{ts}.pcap"
    log_path = run_dir / f"{ts}.log"

    tshark_cmd = [
        "tshark",
        "-i", str(iface),
        "-a", f"duration:{int(duration)}",
        "-w", str(pcap_path),
    ]

    capture_proc = None
    tool_proc = None
    with open(log_path, "a") as logf:
        logf.write(f"# lab run {ts} threat_class={threat_class} target={target}\n")
        logf.write(f"# capture: {' '.join(tshark_cmd)}\n")
        logf.write(f"# tool:    {' '.join(str(a) for a in tool_cmd)}\n")
        logf.flush()
        try:
            log.info("[lab] starting capture -> %s (iface=%s, %ss)", pcap_path, iface, duration)
            capture_proc = popen(tshark_cmd, stdout=logf, stderr=logf)

            # Give tshark a moment to actually start recording before traffic.
            sleep(_CAPTURE_WARMUP_S)

            log.info("[lab] launching %s against %s", tool_name, target)
            tool_proc = popen(list(tool_cmd), stdout=logf, stderr=logf)

            # tshark exits on its own after ``duration``; wait for it, with grace.
            try:
                capture_proc.wait(timeout=int(duration) + _WAIT_GRACE_S)
            except subprocess.TimeoutExpired:
                log.warning("[lab] capture did not stop within grace; terminating")
        except Exception as exc:
            log.error("[lab] run failed: %s", exc)
            raise
        finally:
            # Bounded tools should already be done; tear everything down anyway
            # so nothing is left generating traffic after the window.
            _cleanup(tool_proc, tool_name)
            _cleanup(capture_proc, "tshark")

    return pcap_path


def pcap_to_flows(pcap_path: Path | str) -> List[FlowRecord]:
    """Extract FlowRecords from a captured pcap using the live-ingest path.

    This intentionally reuses :func:`igu_sentinel.ingest.extract_flows_from_pcap`
    rather than parsing packets here, so lab-generated flows are built by the
    same feature extraction that runs on real captured traffic.
    """
    from igu_sentinel.ingest import extract_flows_from_pcap

    return extract_flows_from_pcap(str(pcap_path))


def generate_lab_flows(
    run_fn,
    *,
    target: str,
    duration: int,
    **params,
) -> List[FlowRecord]:
    """Run a lab module's ``run()`` then turn its pcap into FlowRecords.

    ``run_fn`` is a lab module's ``run`` callable. Keeping this one-liner here
    lets every generator do capture-then-extract identically.
    """
    pcap_path = run_fn(target=target, duration=duration, **params)
    return pcap_to_flows(pcap_path)
