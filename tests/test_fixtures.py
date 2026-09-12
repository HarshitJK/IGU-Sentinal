"""Test that fixture files load and parse correctly."""
import json
from pathlib import Path
from igu_sentinel.schemas import FlowRecord


FIXTURES_DIR = Path(__file__).parent / "fixtures"
THREAT_CLASSES = [
    "benign",
    "volumetric_ddos",
    "c2_beaconing",
    "dga_dns_tunneling",
    "encrypted_malware",
    "recon_scanning",
    "data_exfiltration",
]


def test_fixture_files_exist():
    """All fixture files should exist."""
    for threat_class in THREAT_CLASSES:
        fixture_file = FIXTURES_DIR / f"{threat_class}_sample.jsonl"
        assert (
            fixture_file.exists()
        ), f"Fixture file {fixture_file} does not exist"
        print(f"✓ Fixture file exists: {threat_class}_sample.jsonl")


def test_fixtures_parse_as_flow_records():
    """All fixture files should parse into valid FlowRecords."""
    for threat_class in THREAT_CLASSES:
        fixture_file = FIXTURES_DIR / f"{threat_class}_sample.jsonl"
        flows = []

        with open(fixture_file) as f:
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    flow = FlowRecord(**data)
                    flows.append(flow)

        assert len(flows) >= 5, (
            f"Fixture {threat_class} has {len(flows)} flows, "
            f"expected at least 5"
        )
        print(f"✓ {threat_class}: {len(flows)} flows parsed successfully")


def test_fixture_schema_compliance():
    """All fixture flows should have correct required fields."""
    required_fields = {
        "flow_id",
        "timestamp",
        "src_port",
        "dst_port",
        "protocol",
        "packet_size_stats",
        "inter_arrival_stats",
        "entropy",
        "byte_ratio",
        "ttl",
    }

    for threat_class in THREAT_CLASSES:
        fixture_file = FIXTURES_DIR / f"{threat_class}_sample.jsonl"

        with open(fixture_file) as f:
            for line_num, line in enumerate(f, 1):
                if line.strip():
                    data = json.loads(line)
                    missing_fields = required_fields - set(data.keys())
                    assert (
                        not missing_fields
                    ), f"Line {line_num} in {threat_class} missing fields: {missing_fields}"

        print(f"✓ {threat_class}: all flows have required fields")
