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
from collections import defaultdict, deque, OrderedDict
from datetime import datetime
from typing import List, Dict, Any, Tuple, Iterable, Iterator, Optional
from statistics import mean, stdev
from igu_sentinel.schemas import FlowRecord
from igu_sentinel.ingest.ja4 import compute_ja4, parse_tshark_fields_line


# Fixed 120ms capture window (locked in CLAUDE.md — deliberately NOT adaptive).
DEFAULT_WINDOW_MS = 120

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


def reset_flow_state() -> None:
    """Clear all cross-window state (tests, and between capture sessions)."""
    with _state_lock:
        _flow_arrivals.clear()
        _source_targets.clear()


def _record_arrival(flow_key: Tuple, ts: float) -> Optional[Dict[str, float]]:
    """Record a flow's arrival and return beacon interval stats once known.

    Returns None until enough callbacks have been seen to estimate an interval,
    so a flow is never described as beaconing on the strength of one packet.
    """
    with _state_lock:
        arrivals = _flow_arrivals.get(flow_key)
        if arrivals is None:
            arrivals = deque(maxlen=_MAX_ARRIVALS_PER_FLOW)
            _flow_arrivals[flow_key] = arrivals
        else:
            _flow_arrivals.move_to_end(flow_key)
        arrivals.append(ts)
        while len(_flow_arrivals) > _MAX_TRACKED_FLOWS:
            _flow_arrivals.popitem(last=False)   # evict least recently seen
        snapshot = list(arrivals)

    # Need at least 3 gaps (4 callbacks) before an interval means anything.
    if len(snapshot) < 4:
        return None
    cutoff = snapshot[-1] - FLOW_STATE_HORIZON_S
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


def _record_target(src_ip: str, dst_ip: str, dst_port: int, ts: float) -> int:
    """Record a contacted target and return the source's decayed fan-out.

    Fan-out was previously counted only within a single 120ms window, so an
    attacker probing 14 targets per window - a leisurely ~116/second - stayed
    under the threshold forever. Counting over a decaying horizon makes pacing
    stop working as an evasion.
    """
    with _state_lock:
        targets = _source_targets.get(src_ip)
        if targets is None:
            targets = {}
            _source_targets[src_ip] = targets
        else:
            _source_targets.move_to_end(src_ip)
        targets[(dst_ip, dst_port)] = ts

        cutoff = ts - FLOW_STATE_HORIZON_S
        for key in [k for k, seen in targets.items() if seen < cutoff]:
            del targets[key]

        while len(_source_targets) > _MAX_TRACKED_SOURCES:
            _source_targets.popitem(last=False)
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
            "timestamp": timestamp,
            "dns_names": _get_dns_names(packet),
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
        window_epoch = int(timestamps[0]) if timestamps and timestamps[0] > 0 else int(time.time())
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
        beacon_stats = _record_arrival(flow_key, first_ts)
        fanout = _record_target(src_ip, dst_ip, dst_port, first_ts)

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
    """Build the tshark command for line-buffered live JSON capture.

    ``-J tls`` asks tshark to include the TLS protocol tree in its JSON output,
    which is what makes live JA4 possible. Without it the live path produced no
    handshake metadata at all and every live flow had ``ja4=None`` - so the JA4
    rules, and model features 12-15, were dead on real traffic even though
    CLAUDE.md calls JA4 the mandated primary signal for encrypted_malware.

    This still decrypts nothing: only Client Hello metadata is read, which is
    sent in the clear before any session key exists.
    """
    return ["tshark", "-i", interface, "-l", "-n", "-J", "tls ip tcp udp frame dns", "-T", "json"]


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

            # JA4 is extracted from the Client Hellos in this window, so the
            # live path now produces the same fingerprints the pcap path does.
            yield _build_flow_records(packets, ja4_map=_ja4_from_packets(packets))
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
