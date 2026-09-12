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
