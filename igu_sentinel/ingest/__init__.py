"""Flow ingest from tshark capture -> feature extraction.

Two capture sources, one shared flow-construction path:
  * extract_flows_from_pcap(path)        — batch read of a static .pcap file.
  * extract_flows_from_interface(iface)  — continuous live capture, batched into
                                           fixed windows (default 120ms).

Both feed the identical _build_flow_records() helper, so feature extraction is
never duplicated: the only difference is how packets arrive (a finished file vs.
a live tshark stream) and, for the live path, the fixed-window batching.

Feature contract v2 additions extracted here:
  pkt_rate / byte_rate        — packets and bytes per second in window.
  syn_count / syn_fraction    — TCP SYN packets; distinguishes SYN floods.
  src_ip_entropy              — Shannon entropy of source IPs per window;
                                near 0 for single-source, high for spoofed.
  outbound_bytes / inbound_bytes — directional byte volumes; None when not
                                observable (uses PROTECTED_NETWORK_CIDRS).
  dns_query_len               — mean label length for DNS queries.
  dns_record_type             — most common DNS record type in window.
"""
import ipaddress
import json
import math
import os
import queue
import subprocess
import threading
import time
import hashlib
import struct
import tempfile
import socket
from collections import Counter, defaultdict, deque, OrderedDict
from datetime import datetime
from typing import List, Dict, Any, Tuple, Iterable, Iterator, Optional
from statistics import mean, stdev
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.ingest.ja4 import compute_ja4, parse_tshark_fields_line

# ── Protected-network CIDR configuration ─────────────────────────────────────
# Set via IGU_PROTECTED_CIDRS env var (comma-separated CIDR notation).
# Used to determine traffic direction for outbound_bytes / inbound_bytes.
# Example: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
# If not set (default), directional bytes are None (unknown).
_PROTECTED_CIDRS_RAW = os.environ.get("IGU_PROTECTED_CIDRS", "")
PROTECTED_NETWORKS = []
for _cidr in _PROTECTED_CIDRS_RAW.split(","):
    _cidr = _cidr.strip()
    if _cidr:
        try:
            PROTECTED_NETWORKS.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid IGU_PROTECTED_CIDRS entry: {_cidr!r}") from exc


# Fixed 120ms capture window (locked in CLAUDE.md — deliberately NOT adaptive).
DEFAULT_WINDOW_MS = 120


def extract_flows_from_udp(port=9000, bind="0.0.0.0", window_ms=DEFAULT_WINDOW_MS,
                           stop_event=None, counters=None):
    """Receive one JSON FlowRecord per datagram. No replies, probes or ACKs.

    Intended for a simulated diode carrying exported flow metadata. The kernel
    receive buffer and each scoring batch are bounded; UDP delivery is best effort.
    """
    stop_event = stop_event or threading.Event()
    counters = counters if counters is not None else {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        receiver.bind((bind, port))
        while not stop_event.is_set():
            deadline = time.monotonic() + window_ms / 1000
            batch = []
            while len(batch) < 512 and not stop_event.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                receiver.settimeout(remaining)
                try:
                    payload, _sender = receiver.recvfrom(65535)
                except socket.timeout:
                    break
                try:
                    batch.append(FlowRecord.model_validate_json(payload))
                except ValueError:
                    counters["invalid_datagrams"] = counters.get("invalid_datagrams", 0) + 1
            yield batch

# How long to wait after spawning live tshark before deciding it started cleanly.
# A bad interface name or missing capture permission makes tshark exit within
# this grace period, so we can surface a clear error instead of hanging.
_LIVE_STARTUP_GRACE_S = 0.6


# ── Cross-window flow state ───────────────────────────────────────────────────
# The 120ms capture window is fixed and deliberately not adaptive (CLAUDE.md).
# But three of the six mandated threat classes are DEFINED by behaviour over
# minutes, not milliseconds:
#   * c2_beaconing     - a callback every 30s is one packet per 250 windows
#   * recon_scanning   - a scanner pacing 14 targets per window never crosses
#                        the fan-out threshold, though it sweeps thousands/min
#   * data_exfiltration- a slow trickle looks like an idle session in any single
#                        window
# A stateless pipeline cannot see any of them. This table gives the DETECTORS
# memory without touching the capture window: the window stays fixed at 120ms,
# and these aggregates are layered on top.
#
# Memory is bounded on both axes - entries per key and total keys - with LRU
# eviction, so a flood cannot grow it without limit.

# How far back behavioural aggregates look.
FLOW_STATE_HORIZON_S = 300.0
# Arrival timestamps retained per flow (enough for a stable interval estimate).
_MAX_ARRIVALS_PER_FLOW = 64
# Hard cap on tracked flows / sources. A SYN flood with spoofed sources creates
# a new key per packet, so this bound is load-bearing, not decorative.
_MAX_TRACKED_FLOWS = 20000
_MAX_TRACKED_SOURCES = 5000

_state_lock = threading.Lock()
# flow_key -> deque of arrival timestamps
_flow_arrivals: "OrderedDict[Tuple, Any]" = OrderedDict()
# src_ip -> {(dst_ip, dst_port): last_seen_timestamp}
_source_targets: "OrderedDict[str, Dict[Tuple[str, int], float]]" = OrderedDict()


class FlowState:
    """Behavioural history owned by one capture/replay, never shared across inputs."""
    def __init__(self, arrivals=None, targets=None):
        self.arrivals = arrivals if arrivals is not None else OrderedDict()
        self.targets = targets if targets is not None else OrderedDict()
        self.fingerprints = OrderedDict()


_default_flow_state = FlowState(_flow_arrivals, _source_targets)


def reset_flow_state() -> None:
    """Clear all cross-window state (tests, and between capture sessions)."""
    with _state_lock:
        _flow_arrivals.clear()
        _source_targets.clear()
        _default_flow_state.fingerprints.clear()


def _record_arrival(flow_key: Tuple, ts: float, state=None) -> Optional[Dict[str, float]]:
    """Record a flow's arrival and return beacon interval stats once known.

    Returns None until enough callbacks have been seen to estimate an interval,
    so a flow is never described as beaconing on the strength of one packet.
    """
    state = state or _default_flow_state
    # Reconnects use new ephemeral source ports but belong to the same callback series.
    if len(flow_key) == 5:
        flow_key = (flow_key[0], flow_key[2], flow_key[3], flow_key[4])
    with _state_lock:
        arrivals = state.arrivals.get(flow_key)
        if arrivals is None:
            arrivals = deque(maxlen=_MAX_ARRIVALS_PER_FLOW)
            state.arrivals[flow_key] = arrivals
        else:
            state.arrivals.move_to_end(flow_key)
        if not arrivals or int(ts * 1000) // DEFAULT_WINDOW_MS != int(arrivals[-1] * 1000) // DEFAULT_WINDOW_MS:
            arrivals.append(ts)
        while len(state.arrivals) > _MAX_TRACKED_FLOWS:
            state.arrivals.popitem(last=False)   # evict least recently seen
        snapshot = list(arrivals)

    # Need at least 3 gaps (4 callbacks) before an interval means anything.
    if len(snapshot) < 4:
        return None
    cutoff = snapshot[-1] - 1200.0
    recent = [t for t in snapshot if t >= cutoff]
    if len(recent) < 4:
        return None
    gaps = [b - a for a, b in zip(recent, recent[1:]) if b > a]
    if len(gaps) < 3:
        return None
    return {
        "mean": float(mean(gaps)),
        "std": float(stdev(gaps)) if len(gaps) > 1 else 0.0,
    }


def _record_target(src_ip: str, dst_ip: str, dst_port: int, ts: float, state=None) -> int:
    """Record a contacted target and return the source's decayed fan-out.

    Fan-out was previously counted only within a single 120ms window, so an
    attacker probing 14 targets per window - a leisurely ~116/second - stayed
    under the threshold forever. Counting over a decaying horizon makes pacing
    stop working as an evasion.
    """
    state = state or _default_flow_state
    with _state_lock:
        targets = state.targets.get(src_ip)
        if targets is None:
            targets = {}
            state.targets[src_ip] = targets
        else:
            state.targets.move_to_end(src_ip)
        targets[(dst_ip, dst_port)] = ts
        # Bound per-source cardinality as well as the number of tracked sources.
        while len(targets) > 4096:
            del targets[next(iter(targets))]

        cutoff = ts - FLOW_STATE_HORIZON_S
        for key in [k for k, seen in targets.items() if seen < cutoff]:
            del targets[key]

        while len(state.targets) > _MAX_TRACKED_SOURCES:
            state.targets.popitem(last=False)
        return len(targets)


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



def _dns_ngram_entropy(names: List[str]) -> Optional[float]:
    """Character-bigram Shannon entropy over the DNS names queried in a flow.

    Algorithmically-generated domains (DGA) and data smuggled inside DNS labels
    produce near-random character sequences, so their bigram entropy is far
    higher than human-registered domains. Returns None when the flow carries no
    DNS query at all, so non-DNS traffic can never look like DNS tunnelling.
    """
    import math
    labels = []
    for n in names:
        for part in str(n).lower().split("."):
            if part:
                labels.append(part)
    joined = "".join(labels)
    if len(joined) < 3:
        return None
    bigrams: Dict[str, int] = defaultdict(int)
    total = 0
    for i in range(len(joined) - 1):
        bigrams[joined[i:i + 2]] += 1
        total += 1
    if not total:
        return None
    ent = 0.0
    for c in bigrams.values():
        pr = c / total
        ent -= pr * math.log2(pr)
    return float(ent)


def _get_dns_names(packet: Dict[str, Any]) -> List[str]:
    """Extract DNS query name(s) from a tshark packet, if any."""
    layers = packet.get("_source", {}).get("layers", {})
    dns = layers.get("dns")
    if not dns:
        return []
    raw = dns.get("dns.qry.name") or dns.get("dns_qry_name")
    if raw is None:
        # tshark may nest queries under a tree node
        for key, val in dns.items():
            if key.startswith("Queries") and isinstance(val, dict):
                for qk in val:
                    if isinstance(val[qk], dict):
                        raw = val[qk].get("dns.qry.name")
                        if raw:
                            break
            if raw:
                break
    if raw is None:
        return []
    return list(raw) if isinstance(raw, list) else [raw]


def _get_dns_record_type(packet: Dict[str, Any]) -> Optional[str]:
    """Extract the DNS query record type string (A, AAAA, TXT, MX, …).

    Returns None for non-DNS packets or when the type cannot be decoded.
    tshark exposes dns.qry.type as a decimal integer; we convert common values.
    """
    _DNS_TYPE_MAP = {
        "1": "A", "28": "AAAA", "5": "CNAME", "15": "MX",
        "16": "TXT", "2": "NS", "6": "SOA", "12": "PTR",
        "33": "SRV", "255": "ANY",
    }
    layers = packet.get("_source", {}).get("layers", {})
    dns = layers.get("dns")
    if not dns:
        return None
    def query_type(node):
        if isinstance(node, dict):
            if "dns.qry.type" in node:
                return node["dns.qry.type"]
            for value in node.values():
                found = query_type(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = query_type(value)
                if found is not None:
                    return found
        return None
    raw = query_type(dns)
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    return _DNS_TYPE_MAP.get(str(raw), str(raw)) if raw is not None else None


def _is_tcp_syn(packet: Dict[str, Any]) -> bool:
    """Return True if this packet is a TCP SYN (and not SYN-ACK)."""
    layers = packet.get("_source", {}).get("layers", {})
    tcp = layers.get("tcp")
    if not tcp:
        return False
    flags_raw = tcp.get("tcp.flags") or tcp.get("tcp_flags")
    if flags_raw is None:
        tree = tcp.get("tcp.flags_tree", tcp)
        return str(tree.get("tcp.flags.syn")) == "1" and str(tree.get("tcp.flags.ack", "0")) == "0"
    try:
        flags = int(str(flags_raw), 16) if str(flags_raw).startswith("0x") else int(flags_raw, 16)
    except (ValueError, TypeError):
        try:
            flags = int(flags_raw)
        except (ValueError, TypeError):
            return False
    # SYN=0x02, ACK=0x10; a SYN-ACK has both set — only pure SYN counts here.
    return bool(flags & 0x02) and not bool(flags & 0x10)


def _ip_in_protected(ip_str: str) -> bool:
    """Return True if ip_str falls within any configured PROTECTED_NETWORKS."""
    if not PROTECTED_NETWORKS:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PROTECTED_NETWORKS)
    except ValueError:
        return False


def _shannon_entropy_of_strings(items: List[str]) -> float:
    """Shannon entropy of a collection of strings (0 for empty or single unique)."""
    if not items:
        return 0.0
    counts = Counter(items)
    total = len(items)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


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
    """Compatibility collector; each record still uses live-style fixed windows.

    Streaming callers should consume iter_flows_from_pcap instead.
    """
    return [flow for window in iter_flows_from_pcap(pcap_path) for flow in window]


def iter_flows_from_pcap(pcap_path: str, counters=None) -> Iterator[List[FlowRecord]]:
    """Stream packet JSON from tshark; never load the whole capture into memory."""
    with tempfile.TemporaryFile(mode="w+") as errors:
        try:
            proc = subprocess.Popen(["tshark", "-r", str(pcap_path), "-n", "-T", "json", "--no-duplicate-keys"],
                                    stdout=subprocess.PIPE, stderr=errors, text=True)
        except FileNotFoundError as exc:
            raise RuntimeError("tshark not found in PATH") from exc
        try:
            yield from flow_windows_from_packets(_iter_json_objects(proc.stdout), counters=counters)
            if proc.wait(timeout=10) != 0:
                errors.seek(0)
                raise RuntimeError(f"tshark failed: {errors.read(4096)}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            if proc.stdout:
                proc.stdout.close()


def _packet_epoch(packet):
    frame = packet.get("_source", {}).get("layers", {}).get("frame", {})
    value = frame.get("frame.time_epoch") or frame.get("frame_time_epoch") or frame.get("frame.time") or 0
    try:
        return float(value)
    except (TypeError, ValueError):
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


class PacketWindow:
    """Shared capture-time windowing for both tshark live capture and replay."""
    def __init__(self, window_ms=DEFAULT_WINDOW_MS, counters=None):
        self.window_ms = window_ms
        self.bucket = None
        self.last_bucket = -1
        self.packets = []
        self.state = FlowState()
        self.counters = counters if counters is not None else {}

    def push(self, packet):
        bucket = int(_packet_epoch(packet) * 1000) // self.window_ms
        if bucket < self.last_bucket or (self.bucket is not None and bucket < self.bucket):
            self.counters["late_packets"] = self.counters.get("late_packets", 0) + 1
            return None
        ready = None
        if self.bucket is not None and bucket != self.bucket:
            ready = self.flush()
        self.bucket = bucket
        if len(self.packets) < 4096:
            self.packets.append(packet)
        else:
            self.counters["packets_dropped"] = self.counters.get("packets_dropped", 0) + 1
        return ready

    def flush(self):
        packets, self.packets = self.packets, []
        if self.bucket is not None:
            self.last_bucket = self.bucket
        self.bucket = None
        return _build_flow_records(packets, _ja4_from_packets(packets), state=self.state, window_ms=self.window_ms)


def flow_windows_from_packets(packets, window_ms=DEFAULT_WINDOW_MS, counters=None):
    window = PacketWindow(window_ms, counters=counters)
    for packet in packets:
        ready = window.push(packet)
        if ready is not None:
            yield ready
    if window.packets:
        yield window.flush()


def _build_flow_records(
    packets: List[Dict[str, Any]],
    ja4_map: Optional[Dict[Tuple[str, int, str, int, str], str]] = None,
    state=None,
    window_ms=DEFAULT_WINDOW_MS,
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
    state = state or _default_flow_state
    if ja4_map is None:
        ja4_map = {}

    # Group packets by flow
    flows_data: Dict[Tuple, List] = defaultdict(list)
    packet_times: Dict[Tuple, List[float]] = defaultdict(list)

    for packet in packets:
        flow_key = _get_flow_key(packet)
        src_ip_pkt = flow_key[0]
        packet_size = _get_packet_size(packet)
        ttl = _get_ttl(packet)
        payload = _get_payload(packet)

        # Use the same parser for capture-time windowing and record timestamps.
        timestamp = _packet_epoch(packet)

        flows_data[flow_key].append({
            "size": packet_size,
            "ttl": ttl,
            "payload": payload,
            "timestamp": timestamp,
            "dns_names": _get_dns_names(packet),
            # v2 additions per packet
            "is_syn": _is_tcp_syn(packet),
            "dns_record_type": _get_dns_record_type(packet),
            "src_ip": src_ip_pkt,
        })
        packet_times[flow_key].append(timestamp)

    # ── Fan-out: distinct targets contacted by each source within this window ──
    # This is the primary discriminator between reconnaissance/scanning and a
    # volumetric flood. A port scan is ONE source touching MANY distinct
    # (dst_ip, dst_port) targets, so its fan-out is high while its per-target
    # volume stays tiny. A flood concentrates enormous volume on ONE target, so
    # its fan-out stays ~1 no matter how fast the packets arrive. Rate-based
    # features alone cannot tell these apart — both are "many packets, fast".
    #
    # Computed per capture window over the flows in that window, because the
    # 5-tuple FlowRecord itself carries no source/destination IP (schema-fixed).
    targets_by_source: Dict[str, set] = defaultdict(set)
    for (f_src_ip, _f_sport, f_dst_ip, f_dst_port, _f_proto) in flows_data:
        targets_by_source[f_src_ip].add((f_dst_ip, f_dst_port))

    sources_by_target = defaultdict(list)
    syns_by_target = defaultdict(int)
    for (source, _, destination, port, proto), observations in flows_data.items():
        sources_by_target[(destination, port, proto)].extend([source] * len(observations))
        syns_by_target[(destination, port, proto)] += sum(p["is_syn"] for p in observations)

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

        # Byte ratio: payload bytes over total frame bytes.
        #
        # When no payload is extractable this used to default to 0.7 — a value
        # with no derivation that the model could not tell apart from a measured
        # one. That is common, not rare: encrypted traffic and protocols tshark
        # dissects (DNS, TLS records) frequently yield no raw payload, so a
        # meaningful fraction of real flows carried a fabricated mid-range value
        # feeding feature 7 and three rules.
        #
        # Measuring 0.0 is the truthful answer — "we observed no payload bytes"
        # — and byte_ratio_measured records whether the figure is an observation
        # or an absence, so absence is itself available as a signal.
        total_bytes = sum(packet_sizes)
        payload_bytes = sum(len(p["payload"]) // 2 for p in packets_info)
        byte_ratio = min(1.0, payload_bytes / total_bytes) if total_bytes > 0 else 0.0

        # TTL (use first packet's TTL as flow TTL)
        flow_ttl = ttls[0] if ttls else 64

        # Flow identity = 5-tuple AND the window it was first seen in.
        #
        # Keying on the 5-tuple alone meant a host reusing an ephemeral port
        # produced a DIFFERENT flow with an IDENTICAL id, so two alerts minutes
        # apart were indistinguishable and the hash-chained audit log could not
        # separate them. SHA-256 rather than MD5: the truncation to 64 bits
        # already makes collisions a practical concern over a long capture, and
        # there is no reason to start from a weaker digest.
        window_epoch = int((timestamps[0] if timestamps and timestamps[0] > 0 else time.time()) * 1000) // DEFAULT_WINDOW_MS
        flow_id = hashlib.sha256(
            f"{src_ip}:{src_port}:{dst_ip}:{dst_port}:{protocol}:{window_epoch}".encode()
        ).hexdigest()[:16]

        # Populated for TLS/QUIC flows if Client Hello occurred; None otherwise
        flow_ja4 = ja4_map.get(flow_key) or ja4_map.get((dst_ip, dst_port, src_ip, src_port, protocol))

        # ── Cross-window behavioural state ───────────────────────────────────
        # Uses the flow's first arrival in this window as its sample point, so a
        # burst inside one window counts once and the interval measured is the
        # callback period rather than the intra-burst packet spacing.
        first_ts = timestamps[0] if timestamps and timestamps[0] > 0 else time.time()
        beacon_stats = _record_arrival(flow_key, first_ts, state)
        fanout = _record_target(src_ip, dst_ip, dst_port, first_ts, state)
        if flow_ja4:
            state.fingerprints[flow_key] = (first_ts, flow_ja4)
            state.fingerprints.move_to_end(flow_key)
            while len(state.fingerprints) > _MAX_TRACKED_FLOWS:
                state.fingerprints.popitem(last=False)
        elif flow_key in state.fingerprints:
            seen, cached_ja4 = state.fingerprints[flow_key]
            if 0 <= first_ts - seen <= FLOW_STATE_HORIZON_S:
                flow_ja4 = cached_ja4
            else:
                del state.fingerprints[flow_key]

        # ── v2 feature extraction ─────────────────────────────────────────────
        n_packets = len(packets_info)

        # Denominator is the configured observation window, not burst spacing.
        span_s = window_ms / 1000.0
        pkt_rate = n_packets / span_s
        byte_rate = total_bytes / span_s

        # SYN statistics (TCP only).
        syn_count = sum(1 for p in packets_info if p.get("is_syn", False))
        syn_fraction = syn_count / n_packets if n_packets > 0 else 0.0

        # Aggregate sources targeting the same destination/service in this window.
        src_ip_entropy = _shannon_entropy_of_strings(
            sources_by_target[(dst_ip, dst_port, protocol)])

        # Directional byte volumes — only computable when PROTECTED_NETWORKS is set.
        # outbound = bytes leaving protected network; inbound = bytes entering.
        outbound_bytes_val: Optional[int] = None
        inbound_bytes_val: Optional[int] = None
        if PROTECTED_NETWORKS:
            src_protected = _ip_in_protected(src_ip)
            dst_protected = _ip_in_protected(dst_ip)
            if src_protected and not dst_protected:
                # Flow goes from inside to outside — it's outbound.
                outbound_bytes_val = total_bytes
                reverse = flows_data.get((dst_ip, dst_port, src_ip, src_port, protocol))
                inbound_bytes_val = sum(p["size"] for p in reverse) if reverse else None
            elif dst_protected and not src_protected:
                # Flow goes from outside to inside — it's inbound.
                inbound_bytes_val = total_bytes
                reverse = flows_data.get((dst_ip, dst_port, src_ip, src_port, protocol))
                outbound_bytes_val = sum(p["size"] for p in reverse) if reverse else None
            # else: both or neither protected — direction ambiguous, leave as None

        # DNS query features.
        dns_names_all = [n for p in packets_info for n in p.get("dns_names", [])]
        dns_query_len_val: Optional[float] = None
        if dns_names_all:
            label_lengths = [
                float(sum(len(label) for label in name.split("."))) / max(1, name.count(".") + 1)
                for name in dns_names_all
            ]
            dns_query_len_val = mean(label_lengths)

        dns_types = [p.get("dns_record_type") for p in packets_info if p.get("dns_record_type")]
        dns_record_type_val: Optional[str] = None
        if dns_types:
            dns_record_type_val = Counter(dns_types).most_common(1)[0][0]

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
            # Populated from cross-window state. This was hardcoded None, which
            # meant the c2_beaconing rule - gated on `if flow.beacon_interval_stats`
            # - could never fire on real captured traffic. One of the six
            # mandated classes had no working rule-layer detection on live data.
            beacon_interval_stats=beacon_stats,
            dns_ngram_entropy=_dns_ngram_entropy(
                [n for p in packets_info for n in p.get("dns_names", [])]
            ),
            # Distinct (dst_ip, dst_port) targets this SOURCE touched over the
            # cross-window horizon, not just this 120ms window. Window-local
            # counting let a scanner evade the threshold purely by pacing.
            fanout_count=max(fanout, len(targets_by_source.get(src_ip, ())) or 1),
            # ── v2 fields ─────────────────────────────────────────────────────
            target_pkt_rate=len(sources_by_target[(dst_ip, dst_port, protocol)]) / span_s,
            target_syn_fraction=syns_by_target[(dst_ip, dst_port, protocol)] / len(sources_by_target[(dst_ip, dst_port, protocol)]),
            pkt_rate=pkt_rate,
            byte_rate=byte_rate,
            syn_count=syn_count,
            syn_fraction=syn_fraction,
            src_ip_entropy=src_ip_entropy,
            outbound_bytes=outbound_bytes_val,
            inbound_bytes=inbound_bytes_val,
            dns_query_len=dns_query_len_val,
            dns_record_type=dns_record_type_val,
        )

        flow_records.append(flow_record)

    return flow_records


# ── Live interface capture ────────────────────────────────────────────────────

def _iter_json_objects(line_iter: Iterable[str], max_object_chars=2_000_000) -> Iterator[Dict[str, Any]]:
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
                if len(buf) > max_object_chars:
                    raise LiveCaptureError("tshark packet JSON exceeds configured size limit")
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
                        except json.JSONDecodeError as exc:
                            raise LiveCaptureError("Malformed tshark packet JSON") from exc
                        buf = []

    if depth:
        raise LiveCaptureError("tshark packet JSON truncated at EOF")


def _live_tshark_command(interface: str) -> List[str]:
    """Build the tshark command for line-buffered live JSON capture.

    ``-J tls`` asks tshark to include the TLS protocol tree in its JSON output,
    which is what makes live JA4 possible. Without it the live path produced no
    handshake metadata at all and every live flow had ``ja4=None`` - so the JA4
    rules, and model features 12-15, were dead on real traffic even though
    CLAUDE.md calls JA4 the mandated primary signal for encrypted_malware.

    This still decrypts nothing: only Client Hello metadata is read, which is
    sent in the clear before any session key exists.
    """
    return ["tshark", "-i", interface, "-l", "-n", "-J", "tls ip tcp udp frame dns", "-T", "json", "--no-duplicate-keys"]


def _ja4_from_packets(
    packets: List[Dict[str, Any]]
) -> Dict[Tuple[str, int, str, int, str], str]:
    """Build a flow-key -> JA4 map from Client Hellos in a live packet batch.

    The pcap path gets this from a second tshark pass (``_extract_ja4_map``),
    which is not possible on a live stream - there is no file to re-read. This
    reads the same handshake fields out of the packets already in hand.
    """
    out: Dict[Tuple[str, int, str, int, str], str] = {}
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        tls = layers.get("tls")
        if not tls:
            continue
        blob = json.dumps(tls)
        # Handshake type 1 == Client Hello. Anything else carries no JA4 input.
        if '"tls.handshake.type": "1"' not in blob and '"tls.handshake.type":"1"' not in blob:
            continue

        def collect(field: str) -> List[str]:
            """Pull every value for ``field`` out of the nested TLS tree."""
            found: List[str] = []

            def walk(node):
                if isinstance(node, dict):
                    for k, v in node.items():
                        if k == field:
                            found.extend(v if isinstance(v, list) else [v])
                        else:
                            walk(v)
                elif isinstance(node, list):
                    for item in node:
                        walk(item)

            walk(tls)
            return [f for f in found if f not in ("", None)]

        flow_key = _get_flow_key(packet)
        native_ja4 = collect("tls.handshake.ja4")
        if native_ja4:
            out[flow_key] = native_ja4[0]
            continue
        src_ip, src_port, dst_ip, dst_port, protocol = flow_key
        ciphers = collect("tls.handshake.ciphersuite")
        exts = collect("tls.handshake.extension.type")
        alpn = collect("tls.handshake.extensions_alpn_str")
        sni = collect("tls.handshake.extensions_server_name")
        versions = collect("tls.handshake.extensions.supported_version")
        raw_ver = collect("tls.handshake.version")

        try:
            out[flow_key] = compute_ja4(
                protocol=protocol,
                tls_version=raw_ver[0] if raw_ver else None,
                cipher_suites=ciphers,
                extension_types=exts,
                alpn=alpn[0] if alpn else None,
                sni=sni[0] if sni else None,
                supported_versions=versions,
                signature_algorithms=collect("tls.handshake.sig_hash_alg"),
            )
        except Exception:
            # JA4 is best effort: a malformed handshake must not stop the
            # window from being scored on every other signal.
            continue
    return out


def extract_flows_from_interface(
    interface: str,
    window_ms: int = DEFAULT_WINDOW_MS,
    stop_event: Optional[threading.Event] = None,
    _popen=None,
    counters=None,
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
    counters = counters if counters is not None else {}
    pkt_q = queue.Queue(maxsize=8192)
    reader_done = threading.Event()
    reader_errors = []
    stderr_tail = deque(maxlen=8)

    def drain_stderr():
        if proc.stderr is not None:
            while True:
                chunk = proc.stderr.read(1024)
                if not chunk:
                    break
                stderr_tail.append(chunk)

    errors_thread = threading.Thread(target=drain_stderr, name="tshark-stderr", daemon=True)
    errors_thread.start()

    def _reader():
        try:
            if proc.stdout is not None:
                for obj in _iter_json_objects(proc.stdout):
                    try:
                        pkt_q.put_nowait(obj)
                    except queue.Full:
                        counters["packets_dropped"] = counters.get("packets_dropped", 0) + 1
        except Exception as exc:
            reader_errors.append(exc)
        finally:
            reader_done.set()

    reader = threading.Thread(target=_reader, name="tshark-reader", daemon=True)
    reader.start()
    window = PacketWindow(window_ms, counters)
    try:
        while not (reader_done.is_set() and pkt_q.empty()):
            if stop_event is not None and stop_event.is_set():
                break
            try:
                item = pkt_q.get(timeout=window_ms / 1000)
            except queue.Empty:
                yield window.flush()  # bounded idle latency, even without the next packet
                continue
            ready = window.push(item)
            if ready is not None:
                yield ready
        if reader_errors:
            raise LiveCaptureError(str(reader_errors[0]))
        if proc.poll() not in (None, 0):
            raise LiveCaptureError("tshark exited: " + "".join(stderr_tail)[-4096:])
        if window.packets:
            yield window.flush()
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
                proc.wait(timeout=2)
            except Exception:
                pass
        reader.join(timeout=2)
        errors_thread.join(timeout=2)
        for handle in (proc.stdout, proc.stderr):
            close = getattr(handle, "close", None)
            if close is not None:
                close()
