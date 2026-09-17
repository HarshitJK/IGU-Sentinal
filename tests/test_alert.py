"""Test alert/ hash-chained logging and verification."""
import json
from datetime import datetime
from igu_sentinel.schemas import Alert
from igu_sentinel.alert import log_alert, verify_alert_chain, get_alert_log


def test_alert_log_single():
    """Alert logging should produce a valid log entry."""
    alert = Alert(
        timestamp=datetime.now(),
        flow_id="flow_001",
        threat_class="volumetric_ddos",
        confidence_score=0.85,
        evidence=["high_rate"],
    )

    log_entry = log_alert(alert)

    # Log entry should be parseable JSON
    parsed = json.loads(log_entry)
    assert parsed["flow_id"] == "flow_001"
    assert parsed["threat_class"] == "volumetric_ddos"
    assert "hash" in parsed or "hash_chain" in parsed
    print("✓ test_alert_log_single passed")


def test_alert_log_chain_integrity():
    """Hash chain should link consecutive alerts."""
    # Clear the log
    from igu_sentinel.alert import _clear_log
    _clear_log()

    alert1 = Alert(
        timestamp=datetime.now(),
        flow_id="flow_001",
        threat_class="volumetric_ddos",
        confidence_score=0.85,
        evidence=["high_rate"],
    )

    alert2 = Alert(
        timestamp=datetime.now(),
        flow_id="flow_002",
        threat_class="c2_beaconing",
        confidence_score=0.75,
        evidence=["beacon_interval"],
    )

    # Log both alerts
    log_entry1 = log_alert(alert1)
    log_entry2 = log_alert(alert2)

    parsed1 = json.loads(log_entry1)
    parsed2 = json.loads(log_entry2)

    # Second entry should reference first entry's hash
    assert "prev_hash" in parsed2
    assert parsed2["prev_hash"] == parsed1["hash"]
    print("✓ test_alert_log_chain_integrity passed")


def test_alert_verify_valid_chain():
    """Valid hash chain should pass verification."""
    # Clear the log
    from igu_sentinel.alert import _clear_log
    _clear_log()

    # Log a sequence of alerts
    alerts = [
        Alert(
            timestamp=datetime.now(),
            flow_id=f"flow_{i:03d}",
            threat_class="volumetric_ddos" if i % 2 == 0 else "c2_beaconing",
            confidence_score=0.75 + i * 0.01,
            evidence=[f"evidence_{i}"],
        )
        for i in range(5)
    ]

    log_entries = [log_alert(alert) for alert in alerts]

    # Get the log and verify
    log = get_alert_log()
    is_valid = verify_alert_chain(log)
    assert is_valid, "Valid chain should pass verification"
    print("✓ test_alert_verify_valid_chain passed")


def test_alert_verify_detects_tampering():
    """Tampering with log entries should be detected."""
    # Clear the log
    from igu_sentinel.alert import _clear_log
    _clear_log()

    # Log a sequence of alerts
    alerts = [
        Alert(
            timestamp=datetime.now(),
            flow_id=f"flow_{i:03d}",
            threat_class="volumetric_ddos",
            confidence_score=0.75,
            evidence=["evidence"],
        )
        for i in range(3)
    ]

    log_entries = [log_alert(alert) for alert in alerts]

    # Get the log
    log = get_alert_log()

    # Verify it's valid
    assert verify_alert_chain(log), "Original log should be valid"

    # Tamper with the second entry
    tampered_log = log.copy()
    parsed = json.loads(tampered_log[1])
    parsed["threat_class"] = "encrypted_malware"  # Change the threat class
    tampered_log[1] = json.dumps(parsed)

    # Verification should fail
    is_valid = verify_alert_chain(tampered_log)
    assert not is_valid, "Tampered chain should fail verification"
    print("✓ test_alert_verify_detects_tampering passed")


def test_alert_verify_detects_hash_tampering():
    """Tampering with hashes should be detected."""
    # Clear the log
    from igu_sentinel.alert import _clear_log
    _clear_log()

    # Log a sequence
    alerts = [
        Alert(
            timestamp=datetime.now(),
            flow_id=f"flow_{i:03d}",
            threat_class="volumetric_ddos",
            confidence_score=0.75,
            evidence=["evidence"],
        )
        for i in range(3)
    ]

    log_entries = [log_alert(alert) for alert in alerts]
    log = get_alert_log()

    # Tamper with the hash of the first entry
    tampered_log = log.copy()
    parsed = json.loads(tampered_log[0])
    parsed["hash"] = "0" * 64  # Set hash to all zeros
    tampered_log[0] = json.dumps(parsed)

    # Verification should fail because second entry won't match prev_hash
    is_valid = verify_alert_chain(tampered_log)
    assert not is_valid, "Hash tampering should be detected"
    print("✓ test_alert_verify_detects_hash_tampering passed")


def test_alert_empty_log_verification():
    """Empty log should be valid."""
    is_valid = verify_alert_chain([])
    assert is_valid, "Empty log should be valid"
    print("✓ test_alert_empty_log_verification passed")


def test_alert_verify_detects_chain_rewrite():
    """Rewriting an entry AND patching downstream prev_hash must still fail.

    Regression test for the original construction, where the entry hash covered
    only the alert content and `prev_hash` was an unauthenticated sibling field.
    An attacker could edit any entry, recompute its content hash, then patch the
    next entry's `prev_hash` to match — and verification passed. The chain now
    hashes (seq, prev_hash, content) together, so that patch no longer works.
    """
    import hashlib
    from igu_sentinel.alert import _clear_log, _compute_sha256

    _clear_log()
    for i in range(4):
        log_alert(
            Alert(
                timestamp=datetime.now(),
                flow_id=f"flow_{i:03d}",
                threat_class="c2_beaconing",
                confidence_score=0.9,
                evidence=[f"evidence_{i}"],
            )
        )

    log = get_alert_log()
    assert verify_alert_chain(log), "freshly written chain must verify"

    # Attacker edits entry 1 to hide a detection...
    forged = log.copy()
    entry = json.loads(forged[1])
    entry["threat_class"] = "recon_scanning"
    entry["confidence_score"] = 0.01
    entry["evidence"] = ["nothing_to_see_here"]

    # ...recomputes a content-only hash (the old, forgeable scheme)...
    content = {
        k: entry[k]
        for k in ("timestamp", "flow_id", "threat_class", "confidence_score", "evidence")
    }
    entry["hash"] = hashlib.sha256(
        json.dumps(content, sort_keys=True).encode()
    ).hexdigest()
    forged[1] = json.dumps(entry)

    # ...and patches the next entry's prev_hash to point at the forged hash.
    nxt = json.loads(forged[2])
    nxt["prev_hash"] = entry["hash"]
    forged[2] = json.dumps(nxt)

    assert not verify_alert_chain(forged), "chain rewrite must be detected"
    print("✓ test_alert_verify_detects_chain_rewrite passed")


def test_alert_verify_detects_entry_deletion():
    """Dropping an entry from the middle breaks the sequence and must fail."""
    from igu_sentinel.alert import _clear_log

    _clear_log()
    for i in range(4):
        log_alert(
            Alert(
                timestamp=datetime.now(),
                flow_id=f"flow_{i:03d}",
                threat_class="volumetric_ddos",
                confidence_score=0.8,
                evidence=["evidence"],
            )
        )

    log = get_alert_log()
    assert verify_alert_chain(log)

    truncated = [log[0], log[2], log[3]]  # entry 1 excised
    assert not verify_alert_chain(truncated), "deletion must be detected"
    print("✓ test_alert_verify_detects_entry_deletion passed")


def test_alert_chain_head_advances():
    """The chain head must commit to every appended entry."""
    from igu_sentinel.alert import _clear_log, get_chain_head, GENESIS_HASH

    _clear_log()
    assert get_chain_head() == GENESIS_HASH

    heads = []
    for i in range(3):
        log_alert(
            Alert(
                timestamp=datetime.now(),
                flow_id=f"flow_{i:03d}",
                threat_class="data_exfiltration",
                confidence_score=0.7,
                evidence=["evidence"],
            )
        )
        heads.append(get_chain_head())

    assert len(set(heads)) == 3, "each append must move the head"
    assert heads[-1] == json.loads(get_alert_log()[-1])["hash"]
    print("✓ test_alert_chain_head_advances passed")


def test_alert_persistence_and_recovery(tmp_path, monkeypatch):
    """R15: Chain state should persist to disk and recover across simulated restarts."""
    from igu_sentinel.alert import (
        _clear_log,
        get_chain_head,
        restore_chain_from_disk,
        verify_alert_chain,
    )

    log_file = tmp_path / "alerts.log"
    monkeypatch.setenv("IGU_ALERT_LOG_PATH", str(log_file))

    _clear_log()
    alert1 = Alert(
        timestamp=datetime.now(),
        flow_id="persist_001",
        threat_class="volumetric_ddos",
        confidence_score=0.9,
        evidence=["rate_exceeded"],
    )
    alert2 = Alert(
        timestamp=datetime.now(),
        flow_id="persist_002",
        threat_class="c2_beaconing",
        confidence_score=0.85,
        evidence=["beacon_interval"],
    )

    entry1 = log_alert(alert1)
    entry2 = log_alert(alert2)

    head_before = get_chain_head()

    # Verify written to disk
    assert log_file.exists()
    disk_lines = [line.strip() for line in log_file.read_text().splitlines() if line.strip()]
    assert len(disk_lines) == 2
    assert verify_alert_chain(disk_lines)

    # Simulate restart by clearing in-memory state
    _clear_log()
    assert get_chain_head() != head_before

    # Restore from disk
    restored = restore_chain_from_disk(str(log_file))
    assert restored is True
    assert get_chain_head() == head_before

    # Append new alert after restart; chain should seamlessly continue
    alert3 = Alert(
        timestamp=datetime.now(),
        flow_id="persist_003",
        threat_class="recon_scanning",
        confidence_score=0.78,
        evidence=["fanout_detected"],
    )
    entry3 = log_alert(alert3)

    disk_lines_after = [line.strip() for line in log_file.read_text().splitlines() if line.strip()]
    assert len(disk_lines_after) == 3
    assert verify_alert_chain(disk_lines_after)

    parsed3 = json.loads(entry3)
    assert parsed3["seq"] == 2
    assert parsed3["prev_hash"] == json.loads(entry2)["hash"]
    print("✓ test_alert_persistence_and_recovery passed")

