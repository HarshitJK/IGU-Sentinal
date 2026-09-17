"""Alert schema output and SHA-256 hash-chained tamper-evident logging.

Chain construction (security-critical — read before changing)
------------------------------------------------------------
Each entry's hash commits to BOTH its own content AND its position in the
chain::

    hash_n = SHA256( canonical({seq: n, prev_hash: hash_{n-1}, ...content}) )

Including ``prev_hash`` and ``seq`` inside the hashed preimage is what makes
this an actual chain: editing entry *k* changes ``hash_k``, which invalidates
``hash_{k+1}`` (because ``hash_k`` is part of its preimage), and so on to the
head. An attacker must therefore rewrite every subsequent entry, and the head
hash — which an operator can pin externally via :func:`get_chain_head` — still
changes.

A previous implementation hashed only the alert content and stored
``prev_hash`` as an unauthenticated sibling field. That is NOT a chain: because
no hash covered ``prev_hash``, any entry could be rewritten and the downstream
``prev_hash`` pointers patched to match, and verification still passed. See
``tests/test_alert.py::test_alert_verify_detects_chain_rewrite`` for the
regression test that pins this down.

Optional keyed mode
-------------------
Plain SHA-256 is tamper-*evident* only against an attacker who cannot recompute
the chain. An attacker with write access to the log file can always recompute a
whole self-consistent chain. Set ``IGU_ALERT_HMAC_KEY`` to switch to
HMAC-SHA256, which an attacker cannot forge without the key.
"""
import hashlib
import hmac
import json
import os
import threading
from collections import deque
from typing import Deque, Optional

from igu_sentinel.schemas import Alert

# Genesis pointer for the first entry in a chain.
GENESIS_HASH = "0" * 64

# The alert log is an in-memory ring buffer. Unbounded growth was a memory
# exhaustion vector: a sustained capture emits alerts indefinitely and nothing
# ever reclaimed them. Override with IGU_ALERT_LOG_MAX.
_DEFAULT_MAX_ENTRIES = 100_000


def _max_entries() -> int:
    try:
        val = int(os.environ.get("IGU_ALERT_LOG_MAX", _DEFAULT_MAX_ENTRIES))
    except ValueError:
        return _DEFAULT_MAX_ENTRIES
    return val if val > 0 else _DEFAULT_MAX_ENTRIES


# The content fields that are covered by the hash, in fixed order.
_CONTENT_FIELDS = (
    "timestamp",
    "flow_id",
    "threat_class",
    "confidence_score",
    "evidence",
)

# ── chain state (guarded by _lock: the API scores flows across threads) ───────
_lock = threading.Lock()
_alert_log: Deque[str] = deque(maxlen=_max_entries())
_chain_head: str = GENESIS_HASH   # hash of the most recent entry
_next_seq: int = 0                # sequence number for the next entry


def _digest(payload: str) -> str:
    """SHA-256, or HMAC-SHA256 when IGU_ALERT_HMAC_KEY is configured."""
    key = os.environ.get("IGU_ALERT_HMAC_KEY")
    if key:
        return hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(payload.encode()).hexdigest()


def _compute_sha256(data: str) -> str:
    """Compute the chain digest of ``data`` (kept for backwards compatibility)."""
    return _digest(data)


def _preimage(seq: int, prev_hash: str, content: dict) -> str:
    """Build the canonical byte string that an entry's hash commits to.

    ``seq`` and ``prev_hash`` are inside the preimage on purpose — that is the
    whole point of the chain. ``separators`` pins the encoding so a round-trip
    through ``json.dumps``/``json.loads`` cannot change the digest.
    """
    return json.dumps(
        {"seq": seq, "prev_hash": prev_hash, **{k: content[k] for k in _CONTENT_FIELDS}},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _entry_hash(entry: dict) -> str:
    """Recompute the expected hash for a parsed log entry."""
    return _digest(_preimage(int(entry["seq"]), entry["prev_hash"], entry))


def log_alert(alert: Alert) -> str:
    """Append an alert to the hash chain.

    Each entry carries its sequence number, the previous entry's hash, and a
    hash computed over both of those plus the alert content — so any edit to an
    earlier entry invalidates every later one.

    Args:
        alert: Alert object to log.

    Returns:
        JSON string of the appended log entry.
    """
    global _chain_head, _next_seq

    content = {
        "timestamp": alert.timestamp.isoformat(),
        "flow_id": alert.flow_id,
        "threat_class": alert.threat_class,
        "confidence_score": alert.confidence_score,
        "evidence": alert.evidence,
    }

    with _lock:
        seq = _next_seq
        prev_hash = _chain_head
        entry_hash = _digest(_preimage(seq, prev_hash, content))

        log_entry = {
            "seq": seq,
            **content,
            "prev_hash": prev_hash,
            "hash": entry_hash,
        }
        log_entry_json = json.dumps(log_entry)

        _alert_log.append(log_entry_json)
        _chain_head = entry_hash
        _next_seq = seq + 1

        # Durable disk persistence (R15)
        log_path = os.environ.get("IGU_ALERT_LOG_PATH")
        if log_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(log_entry_json + "\n")
            except OSError:
                pass

    return log_entry_json


def verify_alert_chain(log_entries: list[str]) -> bool:
    """Verify hash-chain integrity over a contiguous run of entries.

    Checks, for every entry:
      1. ``hash`` equals the digest of ``(seq, prev_hash, content)`` — so an
         edit anywhere in the preimage is caught.
      2. ``prev_hash`` equals the previous entry's ``hash``.
      3. ``seq`` increments by exactly one (no silent insertion or deletion).
      4. The run starts at the genesis pointer when it starts at ``seq == 0``.
         A run starting later (the ring buffer dropped older entries) is
         verified internally from its own first ``prev_hash``.

    Args:
        log_entries: Log entries as JSON strings, oldest first.

    Returns:
        True if the chain is intact, False if tampering is detected.
    """
    if not log_entries:
        return True

    expected_prev: Optional[str] = None
    expected_seq: Optional[int] = None

    for entry_str in log_entries:
        try:
            entry = json.loads(entry_str)
        except json.JSONDecodeError:
            return False

        # Legacy entries (no seq) can no longer be verified under the current
        # construction — reject rather than silently accepting a weaker chain.
        if "seq" not in entry or "prev_hash" not in entry or "hash" not in entry:
            return False
        try:
            seq = int(entry["seq"])
        except (TypeError, ValueError):
            return False
        if any(f not in entry for f in _CONTENT_FIELDS):
            return False

        if expected_seq is None:
            # First entry of the run.
            if seq == 0 and entry["prev_hash"] != GENESIS_HASH:
                return False
            expected_prev = entry["prev_hash"]
        if expected_seq is not None and seq != expected_seq:
            return False
        if entry["prev_hash"] != expected_prev:
            return False

        # hash must match the digest over (seq, prev_hash, content)
        if not hmac.compare_digest(str(entry["hash"]), _entry_hash(entry)):
            return False

        expected_prev = entry["hash"]
        expected_seq = seq + 1

    return True


def get_alert_log() -> list[str]:
    """Return a snapshot of the retained alert log, oldest first."""
    with _lock:
        return list(_alert_log)


def get_chain_head() -> str:
    """Return the hash of the most recent entry.

    Pin this value somewhere the pipeline cannot write (an operator's notes, a
    write-once store, a signed message) to detect a wholesale rewrite of the
    log — which plain SHA-256 chaining alone cannot prevent.
    """
    with _lock:
        return _chain_head


def _clear_log() -> None:
    """Reset the chain (tests only)."""
    global _alert_log, _chain_head, _next_seq
    with _lock:
        _alert_log = deque(maxlen=_max_entries())
        _chain_head = GENESIS_HASH
        _next_seq = 0


def log_alert_to_file(alert: Alert, filepath: str) -> None:
    """Append an alert to the chain and mirror the entry to a file.

    Args:
        alert: Alert object to log.
        filepath: Path to the append-only log file.
    """
    log_entry = log_alert(alert)
    # If IGU_ALERT_LOG_PATH already wrote to this exact filepath, avoid duplicate write
    if os.environ.get("IGU_ALERT_LOG_PATH") != filepath:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")


def restore_chain_from_disk(filepath: Optional[str] = None) -> bool:
    """Restore _chain_head and _next_seq from an append-only log file on disk.

    Verifies the hash chain across existing entries to ensure state integrity
    before continuing the sequence.

    Args:
        filepath: Path to the log file. Defaults to IGU_ALERT_LOG_PATH.

    Returns:
        True if the chain was restored successfully (or file is empty/nonexistent),
        False if the on-disk chain is corrupt or failed integrity verification.
    """
    global _chain_head, _next_seq, _alert_log
    target_path = filepath or os.environ.get("IGU_ALERT_LOG_PATH")
    if not target_path or not os.path.exists(target_path):
        return True

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            return True

        if not verify_alert_chain(lines):
            return False

        last_entry = json.loads(lines[-1])
        with _lock:
            _chain_head = str(last_entry["hash"])
            _next_seq = int(last_entry["seq"]) + 1
            max_len = _max_entries()
            _alert_log = deque(lines[-max_len:], maxlen=max_len)
        return True
    except Exception:
        return False


# Auto-restore state on import if configured
if os.environ.get("IGU_ALERT_LOG_PATH"):
    restore_chain_from_disk()
