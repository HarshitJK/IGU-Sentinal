"""Flow ingest from tshark capture -> feature extraction.

Two capture sources, one shared flow-construction path:
  * extract_flows_from_pcap(path)        — batch read of a static .pcap file.
  * extract_flows_from_interface(iface)  — continuous live capture, batched into
                                           fixed windows (default 120ms).

Both feed the identical _build_flow_records() helper, so feature extraction is
never duplicated: the only difference is how packets arrive (a finished file vs.
a live tshark stream) and, for the live path, the fixed-window batching.
"""
import json
import queue
import subprocess
import threading
import time
import hashlib
import struct
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Tuple, Iterable, Iterator, Optional
from statistics import mean, stdev
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.ingest.ja4 import parse_tshark_fields_line


# Fixed 120ms capture window (locked in CLAUDE.md — deliberately NOT adaptive).
DEFAULT_WINDOW_MS = 120

# How long to wait after spawning live tshark before deciding it started cleanly.
# A bad interface name or missing capture permission makes tshark exit within
# this grace period, so we can surface a clear error instead of hanging.
_LIVE_STARTUP_GRACE_S = 0.6


class LiveCaptureError(RuntimeError):
    """Raised when live tshark capture cannot start (bad interface, no perms, ...).

    The API layer catches this and returns a clear error rather than letting the
    FastAPI process crash — important for demo reliability.
    """


def _extract_payload_entropy(packet_data: str) -> float:
    """Calculate Shannon entropy of packet payload."""
    import math

    if not packet_data:
        return 0.0

    # Convert hex string to bytes
    try:
        payload_bytes = bytes.fromhex(packet_data)
    except ValueError:
        return 0.0

    if len(payload_bytes) == 0:
        return 0.0

    # Calculate byte frequency
    frequency = defaultdict(int)
    for byte in payload_bytes:
        frequency[byte] += 1

    # Calculate Shannon entropy using log2
    entropy = 0.0
    payload_len = len(payload_bytes)
    for count in frequency.values():
        if count > 0:
            probability = count / payload_len
            entropy -= probability * math.log2(probability)

    return entropy


def _get_flow_key(packet: Dict[str, Any]) -> Tuple[str, int, str, int, str]:
    """Extract 5-tuple flow key from packet."""
    layers = packet.get("_source", {}).get("layers", {})

    ip_layer = layers.get("ip", {})
    src_ip = ip_layer.get("ip.src") or ip_layer.get("ip_src", "0.0.0.0")
    dst_ip = ip_layer.get("ip.dst") or ip_layer.get("ip_dst", "0.0.0.0")
    protocol = ip_layer.get("ip.proto") or ip_layer.get("ip_proto", "")

    src_port = 0
    dst_port = 0

    if "tcp" in layers:
        tcp_layer = layers["tcp"]
        src_port = int(tcp_layer.get("tcp.srcport") or tcp_layer.get("tcp_srcport", 0))
        dst_port = int(tcp_layer.get("tcp.dstport") or tcp_layer.get("tcp_dstport", 0))
        protocol = "TCP"
    elif "udp" in layers:
        udp_layer = layers["udp"]
        src_port = int(udp_layer.get("udp.srcport") or udp_layer.get("udp_srcport", 0))
        dst_port = int(udp_layer.get("udp.dstport") or udp_layer.get("udp_dstport", 0))
        protocol = "UDP"

    return (src_ip, src_port, dst_ip, dst_port, protocol)


def _get_packet_size(packet: Dict[str, Any]) -> int:
    """Extract packet size from tshark packet."""
    frame = packet.get("_source", {}).get("layers", {}).get("frame", {})
    frame_len = frame.get("frame.len") or frame.get("frame_len")
    if frame_len:
        try:
            return int(frame_len)
        except ValueError:
            pass
    return 0


def _get_ttl(packet: Dict[str, Any]) -> int:
    """Extract TTL from packet."""
    ip_layer = packet.get("_source", {}).get("layers", {}).get("ip", {})
    ttl = ip_layer.get("ip.ttl") or ip_layer.get("ip_ttl")
    if ttl:
        try:
            return int(ttl)
        except ValueError:
            pass
    return 64  # Default TTL


def _get_payload(packet: Dict[str, Any]) -> str:
    """Extract payload hex data from packet."""
    layers = packet.get("_source", {}).get("layers", {})

    # Try to get data layer or tcp payload
    if "data" in layers:
        return layers["data"].get("data.data") or layers["data"].get("data_data", "")
    if "tcp" in layers and "tcp.payload" in layers["tcp"]:
        return layers["tcp"]["tcp.payload"].replace(":", "")

    return ""


def _extract_ja4_map(pcap_path: str) -> Dict[Tuple[str, int, str, int, str], str]:
    """Extract JA4 fingerprints for TLS/QUIC Client Hello handshakes from pcap.

    Uses tshark with display filter to isolate Client Hellos without inspecting
    or decrypting any encrypted payload.
    """
    ja4_by_flow: Dict[Tuple[str, int, str, int, str], str] = {}
    cmd = [
        "tshark",
        "-r", str(pcap_path),
        "-Y", "tls.handshake.type == 1",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "tls.handshake.type",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.extension.type",
        "-e", "tls.handshake.extensions_alpn_str",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.extensions.supported_version",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if res.returncode == 0 and res.stdout.strip():
            for line in res.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("[") or line.startswith("{"):
                    continue
                parsed = parse_tshark_fields_line(line)
                if parsed:
                    flow_key, ja4_val = parsed
                    ja4_by_flow[flow_key] = ja4_val
    except Exception:
        pass
    return ja4_by_flow


def extract_flows_from_pcap(pcap_path: str) -> List[FlowRecord]:
    """
    Extract flows from a pcap file using tshark.

    Args:
        pcap_path: Path to pcap file

    Returns:
        List of FlowRecord objects
    """
    # Extract JA4 fingerprints for any TLS/QUIC handshakes
    ja4_map = _extract_ja4_map(pcap_path)

    # Run tshark to extract packets in JSON format
    try:
        result = subprocess.run(
            [
                "tshark",
                "-r", pcap_path,
                "-T", "json",
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"tshark timeout reading {pcap_path}")
    except FileNotFoundError:
        raise RuntimeError("tshark not found in PATH")

    if result.returncode != 0:
        raise RuntimeError(f"tshark failed: {result.stderr}")

    if not result.stdout.strip():
        return []

    # Parse JSON output
    try:
        packets = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse tshark JSON output: {e}")

    return _build_flow_records(packets, ja4_map)


def _build_flow_records(
    packets: List[Dict[str, Any]],
    ja4_map: Optional[Dict[Tuple[str, int, str, int, str], str]] = None,
) -> List[FlowRecord]:
    """Group tshark packet dicts into flows and build FlowRecords.

    This is the single, shared flow-construction path used by BOTH the static
    pcap ingest and the live-interface ingest. Each ``packet`` must have the
    tshark ``-T json`` shape (``packet["_source"]["layers"]``); the pcap path and
    the live path both produce exactly that shape, so neither reimplements
    feature extraction.

    Args:
        packets: List of tshark packet dicts (``-T json`` shape).
        ja4_map: Optional map of flow-key -> JA4 fingerprint for TLS/QUIC flows.
            Empty/None when no handshake metadata is available (typical for the
            live path, where JA4 is best-effort).

    Returns:
        List of FlowRecord objects, one per distinct 5-tuple flow.
    """
    if ja4_map is None:
        ja4_map = {}

    # Group packets by flow
    flows_data: Dict[Tuple, List] = defaultdict(list)
    packet_times: Dict[Tuple, List[float]] = defaultdict(list)

    for packet in packets:
        flow_key = _get_flow_key(packet)
        packet_size = _get_packet_size(packet)
        ttl = _get_ttl(packet)
        payload = _get_payload(packet)

        # Get packet timestamp
        frame = packet.get("_source", {}).get("layers", {}).get("frame", {})
        timestamp_str = frame.get("frame.time_epoch") or frame.get("frame_time_epoch") or frame.get("frame.time")
        timestamp = 0.0
        if timestamp_str:
            try:
                timestamp = float(timestamp_str)
            except (ValueError, TypeError):
                try:
                    clean_ts = str(timestamp_str).rstrip("Z")
                    if "." in clean_ts:
                        base, frac = clean_ts.split(".", 1)
                        clean_ts = f"{base}.{frac[:6]}"
                    timestamp = datetime.fromisoformat(clean_ts).timestamp()
                except Exception:
                    timestamp = 0.0

        flows_data[flow_key].append({
            "size": packet_size,
            "ttl": ttl,
            "payload": payload,
            "timestamp": timestamp
        })
        packet_times[flow_key].append(timestamp)

    # Create FlowRecord for each flow
    flow_records = []

    for flow_key, packets_info in flows_data.items():
        src_ip, src_port, dst_ip, dst_port, protocol = flow_key

        if not packets_info:
            continue

        # Calculate statistics
        packet_sizes = [p["size"] for p in packets_info if p["size"] > 0]
        ttls = [p["ttl"] for p in packets_info]
        timestamps = [p["timestamp"] for p in packets_info]

        if not packet_sizes or not timestamps:
            continue

        # Packet size statistics
        packet_size_stats = {
            "min": float(min(packet_sizes)),
            "max": float(max(packet_sizes)),
            "mean": float(mean(packet_sizes)) if len(packet_sizes) > 0 else 0.0,
            "std": float(stdev(packet_sizes)) if len(packet_sizes) > 1 else 0.0,
        }

        # Inter-arrival time statistics
        inter_arrivals = []
        for i in range(1, len(timestamps)):
            inter_arrival = timestamps[i] - timestamps[i - 1]
            if inter_arrival > 0:
                inter_arrivals.append(inter_arrival)

        if inter_arrivals:
            inter_arrival_stats = {
                "mean": float(mean(inter_arrivals)),
                "std": float(stdev(inter_arrivals)) if len(inter_arrivals) > 1 else 0.0,
            }
        else:
            inter_arrival_stats = {"mean": 0.0, "std": 0.0}

        # Entropy calculation
        all_payloads = "".join([p["payload"] for p in packets_info])
        entropy = _extract_payload_entropy(all_payloads)

        # Byte ratio (ratio of data bytes to total frame bytes)
        total_bytes = sum(packet_sizes)
        byte_ratio = 0.7  # Default for valid traffic
        if total_bytes > 0:
            byte_ratio = min(1.0, sum([len(p["payload"]) // 2 for p in packets_info]) / total_bytes)

        # TTL (use first packet's TTL as flow TTL)
        flow_ttl = ttls[0] if ttls else 64

        # Create flow_id based on flow tuple
        flow_id = hashlib.md5(
            f"{src_ip}:{src_port}:{dst_ip}:{dst_port}:{protocol}".encode()
        ).hexdigest()[:16]

        # Populated for TLS/QUIC flows if Client Hello occurred; None otherwise
        flow_ja4 = ja4_map.get(flow_key) or ja4_map.get((dst_ip, dst_port, src_ip, src_port, protocol))

        # Create FlowRecord
        flow_record = FlowRecord(
            flow_id=flow_id,
            timestamp=datetime.fromtimestamp(timestamps[0]) if timestamps[0] > 0 else datetime.now(),
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size_stats=packet_size_stats,
            inter_arrival_stats=inter_arrival_stats,
            entropy=entropy,
            byte_ratio=byte_ratio,
            ttl=int(flow_ttl),
            ja4=flow_ja4,
            beacon_interval_stats=None,
            dns_ngram_entropy=None,
            fanout_count=None,
        )

        flow_records.append(flow_record)

    return flow_records


# ── Live interface capture ────────────────────────────────────────────────────

def _iter_json_objects(line_iter: Iterable[str]) -> Iterator[Dict[str, Any]]:
    """Yield each complete top-level JSON object from tshark ``-T json`` output.

    tshark ``-T json`` emits a pretty-printed array; in live mode it streams the
    array incrementally and only closes ``]`` when capture ends. We therefore
    brace-count (string-aware) across the incoming lines and yield each packet
    object as soon as it is complete, without waiting for the array to close.
    """
    depth = 0
    in_str = False
    esc = False
    buf: List[str] = []
    for line in line_iter:
        for ch in line:
            if depth > 0:
                buf.append(ch)
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                if depth == 0:
                    buf = ["{"]
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0:
                        try:
                            yield json.loads("".join(buf))
                        except json.JSONDecodeError:
                            pass
                        buf = []


def _live_tshark_command(interface: str) -> List[str]:
    """Build the tshark command for line-buffered live JSON capture."""
    return ["tshark", "-i", interface, "-l", "-n", "-T", "json"]


def extract_flows_from_interface(
    interface: str,
    window_ms: int = DEFAULT_WINDOW_MS,
    stop_event: Optional[threading.Event] = None,
    _popen=None,
) -> Iterator[List[FlowRecord]]:
    """Continuously capture on a live interface, yielding FlowRecords per window.

    Spawns ``tshark -i <interface> -l -n -T json`` and batches the packets that
    arrive within each fixed ``window_ms`` window (default 120ms, per CLAUDE.md),
    flushing each window's packets through the shared _build_flow_records() path.
    Yields one ``List[FlowRecord]`` per window (an empty list for a window in
    which no packets arrived, so the caller sees a steady cadence and can detect
    that capture is live even before any traffic appears).

    Runs until ``stop_event`` is set, the tshark process ends, or the generator
    is closed. Reuses the exact feature-extraction logic of the pcap path — the
    only new behavior here is packet arrival (live stream) and windowing.

    Args:
        interface: Capture interface name (e.g. "en0", "lo0").
        window_ms: Fixed capture-window size in milliseconds.
        stop_event: Optional threading.Event; when set, capture stops promptly.
        _popen: Test seam — a callable replacing subprocess.Popen.

    Yields:
        List[FlowRecord] for each completed window.

    Raises:
        LiveCaptureError: If tshark is missing, or the interface does not exist
            or cannot be captured on (permission denied). Raised on first use.
    """
    if window_ms <= 0:
        raise ValueError("window_ms must be positive")

    spawn = _popen if _popen is not None else subprocess.Popen
    cmd = _live_tshark_command(interface)

    try:
        proc = spawn(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        raise LiveCaptureError("tshark not found in PATH")

    # ── Startup liveness check: a bad interface / missing permission makes
    # tshark exit almost immediately, so give it a brief grace then check. ──
    time.sleep(_LIVE_STARTUP_GRACE_S)
    if proc.poll() is not None and proc.returncode not in (0, None):
        err = ""
        try:
            if proc.stderr is not None:
                err = proc.stderr.read() or ""
        except Exception:
            pass
        raise LiveCaptureError(
            f"tshark could not capture on interface '{interface}': "
            f"{err.strip() or 'process exited (code %s)' % proc.returncode}"
        )

    # ── Reader thread: parse packet objects off tshark stdout into a queue. ──
    pkt_q: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
    _EOF = None  # sentinel

    def _reader() -> None:
        try:
            if proc.stdout is not None:
                for obj in _iter_json_objects(proc.stdout):
                    pkt_q.put(obj)
        except Exception:
            pass
        finally:
            pkt_q.put(_EOF)

    reader = threading.Thread(target=_reader, name="tshark-reader", daemon=True)
    reader.start()

    window_s = window_ms / 1000.0
    eof = False
    try:
        while not eof:
            if stop_event is not None and stop_event.is_set():
                break
            window_start = time.monotonic()
            packets: List[Dict[str, Any]] = []
            while True:
                remaining = window_s - (time.monotonic() - window_start)
                if remaining <= 0:
                    break
                try:
                    item = pkt_q.get(timeout=remaining)
                except queue.Empty:
                    break
                if item is _EOF:
                    eof = True
                    break
                packets.append(item)

            # JA4 is best-effort on the live path (no separate handshake pass);
            # the shared builder pulls it from ja4_map, empty here.
            yield _build_flow_records(packets, ja4_map={})
    finally:
        # Terminate tshark so the reader thread unblocks and no orphan remains.
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
