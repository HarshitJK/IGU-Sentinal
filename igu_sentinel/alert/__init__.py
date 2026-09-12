"""Alert schema output and SHA-256 hash-chained logging."""
import json
import hashlib
from datetime import datetime
from igu_sentinel.schemas import Alert


# Global alert log (hash-chained)
_alert_log: list[str] = []


def _compute_sha256(data: str) -> str:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data.encode()).hexdigest()


def _get_previous_hash() -> str:
    """Get the hash of the last log entry."""
    if not _alert_log:
        return "0" * 64  # Genesis block hash (all zeros)

    last_entry = json.loads(_alert_log[-1])
    return last_entry["hash"]


def log_alert(alert: Alert) -> str:
    """Log an alert with SHA-256 hash chaining.

    Each alert is logged as JSON with:
    - All alert fields
    - SHA-256 hash of the entry (content-based)
    - Reference to previous entry's hash (for chain verification)

    Args:
        alert: Alert object to log

    Returns:
        JSON string representing the log entry
    """
    # Create log entry (without hash first)
    entry = {
        "timestamp": alert.timestamp.isoformat(),
        "flow_id": alert.flow_id,
        "threat_class": alert.threat_class,
        "confidence_score": alert.confidence_score,
        "evidence": alert.evidence,
    }

    # Compute hash of this entry (content-based)
    entry_json = json.dumps(entry, sort_keys=True)
    entry_hash = _compute_sha256(entry_json)

    # Get previous hash for chain verification
    prev_hash = _get_previous_hash()

    # Create final log entry with metadata
    log_entry = {
        "timestamp": alert.timestamp.isoformat(),
        "flow_id": alert.flow_id,
        "threat_class": alert.threat_class,
        "confidence_score": alert.confidence_score,
        "evidence": alert.evidence,
        "hash": entry_hash,
        "prev_hash": prev_hash,
    }

    log_entry_json = json.dumps(log_entry)

    # Add to log
    _alert_log.append(log_entry_json)

    return log_entry_json


def verify_alert_chain(log_entries: list[str]) -> bool:
    """Verify hash-chain integrity of logged alerts.

    Checks that:
    1. Each entry's hash matches its content
    2. Each entry's prev_hash matches the previous entry's hash
    3. The first entry's prev_hash is the genesis hash (all zeros)

    Args:
        log_entries: List of logged alert entries (JSON strings)

    Returns:
        True if hash chain is intact, False if tampering detected
    """
    if not log_entries:
        # Empty log is valid
        return True

    expected_prev_hash = "0" * 64  # Genesis block hash

    for i, entry_str in enumerate(log_entries):
        try:
            entry = json.loads(entry_str)
        except json.JSONDecodeError:
            # Invalid JSON
            return False

        # Verify prev_hash matches
        if entry.get("prev_hash") != expected_prev_hash:
            return False

        # Verify content hash
        # Reconstruct the entry without hash/prev_hash to compute content hash
        content = {
            "timestamp": entry["timestamp"],
            "flow_id": entry["flow_id"],
            "threat_class": entry["threat_class"],
            "confidence_score": entry["confidence_score"],
            "evidence": entry["evidence"],
        }

        content_json = json.dumps(content, sort_keys=True)
        computed_hash = _compute_sha256(content_json)

        if entry.get("hash") != computed_hash:
            # Content hash mismatch means tampering
            return False

        # Update expected previous hash for next iteration
        expected_prev_hash = entry["hash"]

    return True


def get_alert_log() -> list[str]:
    """Get the current alert log.

    Returns:
        List of JSON strings representing logged alerts
    """
    return _alert_log.copy()


def _clear_log() -> None:
    """Clear the alert log (for testing only)."""
    global _alert_log
    _alert_log = []


def log_alert_to_file(alert: Alert, filepath: str) -> None:
    """Log an alert to a file (append mode).

    Args:
        alert: Alert object to log
        filepath: Path to log file
    """
    log_entry = log_alert(alert)
    with open(filepath, "a") as f:
        f.write(log_entry + "\n")
