"""Tests for the REAL lab traffic generators (igu_sentinel/traffic_gen/lab/).

Two invariants matter most and are covered here:

  (a) The lab-target guard rejects any public IP/hostname for EVERY lab module,
      before a single packet or subprocess can be created.
  (b) No real ``hping3`` / ``iperf3`` / ``tshark`` / ``dnscat2`` process is ever
      spawned in CI: ``subprocess.Popen`` and ``shutil.which`` are mocked, so the
      whole capture-and-generate path runs without touching the network.

Everything here is CI-safe. The existing mock-mode tests in
``tests/test_traffic_gen.py`` are intentionally left untouched.
"""
from datetime import date, datetime
from pathlib import Path
from unittest import mock

import pytest
import yaml

from igu_sentinel.schemas import FlowRecord
from igu_sentinel.traffic_gen.lab import (
    benign,
    dga,
    dns_tunnel,
    slowloris,
    synflood,
    udpflood,
)
from igu_sentinel.traffic_gen.lab._guard import is_lab_target, validate_lab_target
from igu_sentinel.traffic_gen.lab._tools import LabToolMissing

# Every module exposing run(target, duration, **params) -> Path.
LAB_MODULES = [synflood, udpflood, slowloris, dga, dns_tunnel, benign]
LAB_MODULE_IDS = ["synflood", "udpflood", "slowloris", "dga", "dns_tunnel", "benign"]

PUBLIC_TARGETS = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "example.com",
    "google.com",
    "attacker.evil.net",
    "169.254.1.1",       # link-local — not a lab target
    "100.64.0.1",        # CGNAT — not RFC1918
    "2606:4700:4700::1111",  # public IPv6
    "",
]

LAB_TARGETS = [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.5.5",
    "192.168.1.10",
    "::1",
    "fc00::1",
    "localhost",
    "sentinel-lab-target",
    "db.sentinel-lab",
    "web-lab",
]


# ── Guard ─────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("target", LAB_TARGETS)
def test_guard_accepts_lab_targets(target):
    assert is_lab_target(target)
    assert validate_lab_target(target) == target


@pytest.mark.parametrize("target", PUBLIC_TARGETS)
def test_guard_rejects_public_targets(target):
    assert not is_lab_target(target)
    with pytest.raises(ValueError):
        validate_lab_target(target)


@pytest.mark.parametrize("module", LAB_MODULES, ids=LAB_MODULE_IDS)
@pytest.mark.parametrize("target", ["8.8.8.8", "example.com", ""])
def test_every_lab_module_rejects_public_target(module, target):
    """run() on every lab module must raise ValueError for a public/empty target,
    and must NOT spawn any subprocess in the process."""
    with mock.patch("subprocess.Popen") as popen, \
         mock.patch("subprocess.run") as srun:
        with pytest.raises(ValueError):
            module.run(target, 1)
        popen.assert_not_called()
        srun.assert_not_called()


# ── No real process is ever spawned ───────────────────────────────────────────
def _fake_proc():
    proc = mock.MagicMock()
    proc.poll.return_value = 0
    proc.wait.return_value = 0
    proc.returncode = 0
    return proc


@pytest.mark.parametrize("module", LAB_MODULES, ids=LAB_MODULE_IDS)
def test_lab_run_spawns_no_real_process(module, tmp_path):
    """A full lab run against a private target must use mocked subprocess only."""
    captured_cmds = []

    def fake_popen(cmd, **kwargs):
        captured_cmds.append(list(cmd))
        return _fake_proc()

    with mock.patch("subprocess.Popen", side_effect=fake_popen) as popen, \
         mock.patch("subprocess.run") as srun, \
         mock.patch("igu_sentinel.traffic_gen.lab._tools.shutil.which",
                    return_value="/usr/bin/fake"), \
         mock.patch("time.sleep", return_value=None):
        pcap = module.run("10.0.0.9", 2, out_root=tmp_path)

    assert isinstance(pcap, Path)
    # tshark capture + the traffic tool = at least two Popen calls, all mocked.
    assert popen.call_count >= 2
    srun.assert_not_called()
    # First spawned process is always the tshark capture, started before traffic.
    assert captured_cmds[0][0] == "tshark"
    assert "-w" in captured_cmds[0]


@pytest.mark.parametrize("module", LAB_MODULES, ids=LAB_MODULE_IDS)
def test_lab_run_missing_tool_gives_clear_message(module, tmp_path):
    """A missing external tool raises LabToolMissing (not a raw FileNotFoundError)
    with an actionable install hint, before any process is spawned."""
    with mock.patch("subprocess.Popen") as popen, \
         mock.patch("igu_sentinel.traffic_gen.lab._tools.shutil.which",
                    return_value=None):
        with pytest.raises(LabToolMissing) as excinfo:
            module.run("10.0.0.9", 2, out_root=tmp_path)
        assert "not found on PATH" in str(excinfo.value)
        popen.assert_not_called()


# ── DGA algorithms (from-scratch, pure) ───────────────────────────────────────
def test_dga_domains_are_deterministic_and_daily():
    d1 = dga.date_dga(date(2026, 1, 1), 5)
    d2 = dga.date_dga(date(2026, 1, 1), 5)
    d3 = dga.date_dga(date(2026, 1, 2), 5)
    assert d1 == d2                 # deterministic for a given day
    assert d1 != d3                 # rotates day to day
    assert all(dom.endswith(".com") for dom in d1)
    assert all(dom.split(".")[0].isalpha() for dom in d1)


def test_dga_generate_domains_mixes_families():
    domains = dga.generate_domains(20, date(2026, 3, 15), algo="all")
    assert len(domains) == 20
    assert len(set(domains)) == 20  # no duplicates


def test_dga_banjori_is_self_referential():
    b = dga.banjori_dga("earnestnessbiophysicalohax.com", 3)
    assert len(b) == 3
    assert all("." in dom for dom in b)


def test_dns_query_packet_is_wellformed():
    pkt = dga._build_dns_query("abc.sentinel-lab", qid=42)
    # DNS header is 12 bytes; QID in the first two, QDCOUNT=1 at bytes 4-5.
    assert len(pkt) > 12
    assert pkt[0:2] == (42).to_bytes(2, "big")
    assert pkt[4:6] == (1).to_bytes(2, "big")


def test_send_dns_queries_refuses_public_target():
    with pytest.raises(ValueError):
        dga.send_dns_queries("8.8.8.8", 53, ["x.com"], 1)


# ── Slowloris (from-scratch) guard ────────────────────────────────────────────
def test_slowloris_attack_refuses_public_target():
    with pytest.raises(ValueError):
        slowloris.slowloris_attack("8.8.8.8", 80, 1, max_sockets=1)


# ── Generator lab dispatch + runner integration ───────────────────────────────
def _fake_flow():
    return FlowRecord(
        flow_id="lab", timestamp=datetime.now(), src_port=1234, dst_port=80,
        protocol="TCP",
        packet_size_stats={"min": 40.0, "max": 1500.0, "mean": 100.0, "std": 10.0},
        inter_arrival_stats={"mean": 0.001, "std": 0.0001},
        entropy=3.0, byte_ratio=0.9, ttl=64, ja4=None,
        beacon_interval_stats=None, dns_ngram_entropy=None, fanout_count=1,
    )


def test_ddos_generator_lab_dispatch():
    from igu_sentinel.traffic_gen.generators import ddos

    with mock.patch("igu_sentinel.traffic_gen.lab.synflood.run",
                    return_value=Path("/tmp/x.pcap")) as run_fn, \
         mock.patch("igu_sentinel.traffic_gen.lab.capture.pcap_to_flows",
                    return_value=[_fake_flow()]):
        flows = ddos.generate(threat_class="volumetric_ddos", mode="lab",
                              target="10.0.0.5", attack="syn_flood", duration=3, port=80)
    assert len(flows) == 1
    assert run_fn.call_args.kwargs["target"] == "10.0.0.5"


def test_dns_generator_lab_dispatch():
    from igu_sentinel.traffic_gen.generators import dns_tunneling

    with mock.patch("igu_sentinel.traffic_gen.lab.dga.run",
                    return_value=Path("/tmp/d.pcap")) as run_fn, \
         mock.patch("igu_sentinel.traffic_gen.lab.capture.pcap_to_flows",
                    return_value=[_fake_flow()]):
        flows = dns_tunneling.generate(threat_class="dga_dns_tunneling", mode="lab",
                                       target="sentinel-lab-target", attack="dga", duration=2)
    assert len(flows) == 1
    assert run_fn.call_args.kwargs["target"] == "sentinel-lab-target"


def test_ddos_generator_lab_requires_target():
    from igu_sentinel.traffic_gen.generators import ddos

    with pytest.raises(ValueError):
        ddos.generate(mode="lab", attack="syn_flood", duration=1)


def test_ddos_generator_lab_rejects_unknown_attack():
    from igu_sentinel.traffic_gen.generators import ddos

    with pytest.raises(ValueError):
        ddos.generate(mode="lab", target="10.0.0.1", attack="not_a_real_attack", duration=1)


def test_runner_skips_lab_variants_by_default():
    """The mock/aggregate path must never fire lab variants (CI-safe)."""
    from igu_sentinel.traffic_gen.runner import run_traffic_gen

    cfg = Path("igu_sentinel/traffic_gen/config/lab_ddos.yaml")
    with mock.patch("subprocess.Popen") as popen:
        out = run_traffic_gen(str(cfg))            # allow_lab defaults to False
    assert out == []
    popen.assert_not_called()


def test_runner_runs_lab_when_allowed():
    """With allow_lab=True the lab config dispatches to the (mocked) lab modules."""
    from igu_sentinel.traffic_gen.runner import run_traffic_gen

    cfg = Path("igu_sentinel/traffic_gen/config/lab_ddos.yaml")
    with mock.patch("igu_sentinel.traffic_gen.lab.synflood.run", return_value=Path("/tmp/a.pcap")), \
         mock.patch("igu_sentinel.traffic_gen.lab.udpflood.run", return_value=Path("/tmp/b.pcap")), \
         mock.patch("igu_sentinel.traffic_gen.lab.slowloris.run", return_value=Path("/tmp/c.pcap")), \
         mock.patch("igu_sentinel.traffic_gen.lab.dns_tunnel.run", return_value=Path("/tmp/d.pcap")), \
         mock.patch("igu_sentinel.traffic_gen.lab.dga.run", return_value=Path("/tmp/e.pcap")), \
         mock.patch("igu_sentinel.traffic_gen.lab.capture.pcap_to_flows", return_value=[_fake_flow()]):
        out = run_traffic_gen(str(cfg), allow_lab=True)
    # Five lab variants in the shipped config, each yielding one (mocked) flow.
    assert len(out) == 5
    assert {item["threat_class"] for item in out} == {"volumetric_ddos", "dga_dns_tunneling"}


def test_runner_rejects_lab_mode_on_non_lab_tool():
    """mode: lab on a tool that cannot generate real traffic is a config error."""
    import tempfile
    from igu_sentinel.traffic_gen.runner import run_traffic_gen

    config = {"variants": [{
        "threat_class": "recon_scanning", "tool": "scanning", "mode": "lab",
        "target": "10.0.0.1", "duration": 1,
    }]}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config, f)
        path = f.name
    try:
        with pytest.raises(ValueError):
            run_traffic_gen(path, allow_lab=True)
    finally:
        Path(path).unlink()


# ── Shipped lab config sanity ─────────────────────────────────────────────────
def test_lab_config_targets_are_all_lab_endpoints():
    cfg = Path("igu_sentinel/traffic_gen/config/lab_ddos.yaml")
    with open(cfg) as f:
        data = yaml.safe_load(f)
    variants = data["variants"]
    assert variants, "lab_ddos.yaml should define variants"
    for v in variants:
        assert v["mode"] == "lab"
        assert is_lab_target(v["target"]), f"{v['target']} is not a lab endpoint"
