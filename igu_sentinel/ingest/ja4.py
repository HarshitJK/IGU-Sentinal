"""JA4 TLS/QUIC Client Hello fingerprint generator (FoxIO JA4 specification).

JA4 is a 36-character fingerprint formatted as:
    JA4_a_JA4_b_JA4_c

Where:
  JA4_a (10 chars):
    [0]     Protocol: 't' (TCP) or 'q' (QUIC/UDP)
    [1:3]   TLS Version: '13', '12', '11', '10', 's3', 's2', or '00'
            (highest non-GREASE version from supported_versions extension if present;
             otherwise from the Client Hello record/version field)
    [3]     SNI: 'd' (domain SNI present) or 'i' (no SNI or IP address)
    [4:6]   Number of cipher suites (2 digits zero-padded, excluding GREASE, max 99)
    [6:8]   Number of extensions (2 digits zero-padded, excluding GREASE, SNI, ALPN, max 99)
    [8:10]  First and last character of first ALPN string, or '00' if absent

  JA4_b (12 chars):
    First 12 chars of SHA-256 of sorted non-GREASE cipher suites (4-hex lowercase, comma-separated),
    or '000000000000' if none.

  JA4_c (12 chars):
    First 12 chars of SHA-256 of sorted non-GREASE, non-SNI, non-ALPN extensions
    (4-hex lowercase, comma-separated), or '000000000000' if none.

Reference: https://github.com/FoxIO-LLC/ja4
Zero Payload Decryption: Only Client Hello handshake metadata is inspected.
"""

import hashlib
import ipaddress
import re
from typing import List, Optional, Tuple, Union


# ── GREASE (RFC 8701) ────────────────────────────────────────────────────────
# Values matching 0x?a?a where the two nibbles are identical:
# 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
# 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
def is_grease(val: int) -> bool:
    """Return True if 16-bit value is a GREASE identifier (RFC 8701)."""
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) & 0xF0) == (val & 0xF0)


def _to_int(val: Union[int, str]) -> Optional[int]:
    """Parse integer from hex string (0x1301) or decimal string ('43') or int."""
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        try:
            return int(s, 16)
        except ValueError:
            return None


def _format_hex4(val: int) -> str:
    """Format 16-bit integer as 4-character lowercase hex string."""
    return f"{val & 0xFFFF:04x}"


# ── TLS version mapping ──────────────────────────────────────────────────────
_VERSION_MAP = {
    0x0304: "13",  # TLS 1.3
    0x0303: "12",  # TLS 1.2
    0x0302: "11",  # TLS 1.1
    0x0301: "10",  # TLS 1.0
    0x0300: "s3",  # SSL 3.0
    0x0002: "s2",  # SSL 2.0
}


def _resolve_tls_version(
    raw_version: Optional[Union[int, str]],
    supported_versions: Optional[List[Union[int, str]]] = None,
) -> str:
    """Resolve 2-character TLS version string per JA4 specification."""
    # 1. Check supported_versions extension (highest valid version wins)
    if supported_versions:
        parsed_vers = []
        for v in supported_versions:
            iv = _to_int(v)
            if iv is not None and not is_grease(iv):
                parsed_vers.append(iv)
        # Check from highest to lowest standard TLS version
        for v_code in (0x0304, 0x0303, 0x0302, 0x0301, 0x0300):
            if v_code in parsed_vers:
                return _VERSION_MAP[v_code]

    # 2. Fall back to record/handshake version
    if raw_version is not None:
        iv = _to_int(raw_version)
        if iv is not None and iv in _VERSION_MAP:
            return _VERSION_MAP[iv]
        s_ver = str(raw_version).lower()
        if "1.3" in s_ver:
            return "13"
        if "1.2" in s_ver:
            return "12"
        if "1.1" in s_ver:
            return "11"
        if "1.0" in s_ver:
            return "10"

    return "00"


# ── SNI helper ────────────────────────────────────────────────────────────────
def _resolve_sni(server_name: Optional[str]) -> str:
    """Return 'd' if server_name is a valid domain name, 'i' if IP or missing."""
    if not server_name:
        return "i"
    sni = str(server_name).strip()
    if not sni:
        return "i"
    # Check if SNI is an IP address
    try:
        ipaddress.ip_address(sni)
        return "i"  # IP address SNI
    except ValueError:
        pass
    # Basic check for domain-like string
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", sni) or "." in sni:
        return "d"
    return "d" if any(c.isalpha() for c in sni) else "i"


# ── ALPN helper ───────────────────────────────────────────────────────────────
def _resolve_alpn(alpn_str: Optional[str]) -> str:
    """Return 2-character ALPN representation: first and last char of first ALPN."""
    if not alpn_str:
        return "00"
    # Can be comma-separated list of protocols
    first = str(alpn_str).split(",")[0].strip()
    if not first:
        return "00"
    if len(first) == 1:
        return f"{first[0]}{first[0]}"
    return f"{first[0]}{first[-1]}"


# ── Core JA4 Calculation ─────────────────────────────────────────────────────
def compute_ja4(
    protocol: str = "TCP",
    tls_version: Optional[Union[int, str]] = None,
    cipher_suites: Optional[List[Union[int, str]]] = None,
    extension_types: Optional[List[Union[int, str]]] = None,
    alpn: Optional[str] = None,
    sni: Optional[str] = None,
    supported_versions: Optional[List[Union[int, str]]] = None,
) -> str:
    """Compute 36-character JA4 fingerprint for a TLS/QUIC Client Hello.

    Args:
        protocol: 'TCP' (yields 't') or 'UDP'/'QUIC' (yields 'q').
        tls_version: Raw version integer or hex string (e.g. 0x0303).
        cipher_suites: List of cipher suite integers or hex strings.
        extension_types: List of extension type integers or hex strings.
        alpn: ALPN string (e.g. 'h2', 'http/1.1').
        sni: Server Name Indication string (domain or IP).
        supported_versions: List of supported version integers/strings.

    Returns:
        36-character JA4 fingerprint: JA4_a_JA4_b_JA4_c
    """
    # ── JA4_a: 10 chars ──
    # [0] Protocol
    proto_char = "q" if str(protocol).upper() in ("UDP", "QUIC") else "t"

    # [1:3] TLS Version
    ver_str = _resolve_tls_version(tls_version, supported_versions)

    # [3] SNI indicator ('d' or 'i')
    sni_char = _resolve_sni(sni)

    # Filter non-GREASE ciphers
    valid_ciphers: List[int] = []
    if cipher_suites:
        for c in cipher_suites:
            ic = _to_int(c)
            if ic is not None and not is_grease(ic):
                valid_ciphers.append(ic)

    # Filter non-GREASE, non-SNI (0), non-ALPN (16) extensions
    valid_exts: List[int] = []
    if extension_types:
        for e in extension_types:
            ie = _to_int(e)
            if ie is not None and not is_grease(ie):
                # SNI = 0x0000 (0), ALPN = 0x0010 (16)
                if ie not in (0, 16):
                    valid_exts.append(ie)

    # [4:6] Cipher count (max 99)
    cipher_count_str = f"{min(len(valid_ciphers), 99):02d}"

    # [6:8] Extension count (max 99)
    ext_count_str = f"{min(len(valid_exts), 99):02d}"

    # [8:10] ALPN (2 chars)
    alpn_str = _resolve_alpn(alpn)

    ja4_a = f"{proto_char}{ver_str}{sni_char}{cipher_count_str}{ext_count_str}{alpn_str}"

    # ── JA4_b: 12 hex chars ──
    # Sorted list of 4-character hex cipher suites joined by comma
    if valid_ciphers:
        sorted_ciphers = sorted(_format_hex4(c) for c in valid_ciphers)
        ja4_b = hashlib.sha256(",".join(sorted_ciphers).encode()).hexdigest()[:12]
    else:
        ja4_b = "000000000000"

    # ── JA4_c: 12 hex chars ──
    # Sorted list of 4-character hex extensions joined by comma
    if valid_exts:
        sorted_exts = sorted(_format_hex4(e) for e in valid_exts)
        ja4_c = hashlib.sha256(",".join(sorted_exts).encode()).hexdigest()[:12]
    else:
        ja4_c = "000000000000"

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


# ── Parser for tshark -T fields lines ─────────────────────────────────────────
def parse_tshark_fields_line(line: str) -> Optional[Tuple[Tuple[str, int, str, int, str], str]]:
    """Parse one tab-delimited line from tshark extracting Client Hello.

    Expected field order:
      0: ip.src
      1: tcp.srcport
      2: udp.srcport
      3: ip.dst
      4: tcp.dstport
      5: udp.dstport
      6: tls.handshake.type
      7: tls.handshake.version
      8: tls.handshake.ciphersuite
      9: tls.handshake.extension.type
      10: tls.handshake.extensions_alpn_str
      11: tls.handshake.extensions_server_name
      12: tls.handshake.extensions.supported_version (optional)

    Returns:
        ((src_ip, src_port, dst_ip, dst_port, protocol), ja4_fingerprint) or None
    """
    parts = line.strip().split("\t")
    if len(parts) < 10:
        return None

    src_ip = parts[0].strip()
    tcp_src = parts[1].strip()
    udp_src = parts[2].strip()
    dst_ip = parts[3].strip()
    tcp_dst = parts[4].strip()
    udp_dst = parts[5].strip()
    hs_type = parts[6].strip()

    # Must be Client Hello (handshake type 1)
    # Note: tshark can return '1' or '0x01' or '1,1' for reassembled/multiple
    hs_types = [h.strip() for h in hs_type.split(",") if h.strip()]
    if not any(h in ("1", "0x01") for h in hs_types):
        return None

    if tcp_src:
        src_port = int(tcp_src.split(",")[0])
        dst_port = int(tcp_dst.split(",")[0]) if tcp_dst else 0
        protocol = "TCP"
    elif udp_src:
        src_port = int(udp_src.split(",")[0])
        dst_port = int(udp_dst.split(",")[0]) if udp_dst else 0
        protocol = "UDP"
    else:
        return None

    flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)

    raw_ver = parts[7].strip() if len(parts) > 7 else ""
    ciphers_raw = parts[8].strip().split(",") if len(parts) > 8 and parts[8].strip() else []
    exts_raw = parts[9].strip().split(",") if len(parts) > 9 and parts[9].strip() else []
    alpn_raw = parts[10].strip() if len(parts) > 10 else ""
    sni_raw = parts[11].strip() if len(parts) > 11 else ""
    sup_ver_raw = parts[12].strip().split(",") if len(parts) > 12 and parts[12].strip() else []

    ja4 = compute_ja4(
        protocol=protocol,
        tls_version=raw_ver,
        cipher_suites=ciphers_raw,
        extension_types=exts_raw,
        alpn=alpn_raw,
        sni=sni_raw,
        supported_versions=sup_ver_raw,
    )
    return flow_key, ja4
