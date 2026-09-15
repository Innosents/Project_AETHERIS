"""
Unit Tests for PassiveStackClassifier & TCP SYN/ACK / DHCP Option 55 OS Inference.
Verifies:
- TCP SYN/ACK TTL and Window size classification
- DHCP Option 55 Parameter Request List classification
- Authoritative inference of EMBEDDED_LINUX_STB, WINDOWS_NT, TIZEN_OS, and ANDROID_WLAN_BRIDGE
- Targeted validation of 192.168.1.73 (WINDOWS_NT) and 192.168.1.67 (EMBEDDED_LINUX_STB)
- Persistence to spatial_ledger.db
"""

import pytest
import sqlite3
from graphpath.discovery.fingerprint import PassiveStackClassifier
from graphpath.cli.sweep import SubnetSweeper


@pytest.fixture
def classifier(tmp_path):
    db_file = tmp_path / "test_os_profiles.db"
    return PassiveStackClassifier(db_path=str(db_file))


def test_windows_nt_inference(classifier):
    """Verifies TCP SYN/ACK TTL=128 and Windows Option 55 yields WINDOWS_NT."""
    # 192.168.1.73 (Compal Workstation)
    res = classifier.classify_target("192.168.1.73")
    assert res["os_profile"] == "WINDOWS_NT"
    assert res["synack_ttl"] == 128
    assert res["window_size"] == 64240

    # Infer from raw inputs
    inf = PassiveStackClassifier.infer_os_profile(
        ttl=128,
        window_size=64240,
        option55="1,3,6,15,31,33,43,44,46,47,119,121,249,252"
    )
    assert inf["os_profile"] == "WINDOWS_NT"


def test_embedded_linux_stb_inference(classifier):
    """Verifies TCP SYN/ACK TTL=64 and STB Option 55 yields EMBEDDED_LINUX_STB."""
    # 192.168.1.67 (Media STB)
    res = classifier.classify_target("192.168.1.67")
    assert res["os_profile"] == "EMBEDDED_LINUX_STB"
    assert res["synack_ttl"] == 64
    assert res["window_size"] == 14600
    assert "1,3,6,12,15,28" in res["option55"]

    # Infer from raw inputs
    inf = PassiveStackClassifier.infer_os_profile(
        ttl=64,
        window_size=14600,
        option55="1,3,6,12,15,28,42,43,66,67,121"
    )
    assert inf["os_profile"] == "EMBEDDED_LINUX_STB"


def test_tizen_os_inference(classifier):
    """Verifies Samsung Smart TV signatures yield TIZEN_OS."""
    res = classifier.classify_target("192.168.1.65")
    assert res["os_profile"] == "TIZEN_OS"
    assert res["synack_ttl"] == 64

    inf = PassiveStackClassifier.infer_os_profile(
        ttl=64,
        window_size=29200,
        option55="1,3,6,15,28,33,43,119,121,252",
        extra_hints="samsung smart tv"
    )
    assert inf["os_profile"] == "TIZEN_OS"


def test_android_wlan_bridge_inference(classifier):
    """Verifies Wi-Fi extender/bridge signatures yield ANDROID_WLAN_BRIDGE."""
    res = classifier.classify_target("192.168.1.66")
    assert res["os_profile"] == "ANDROID_WLAN_BRIDGE"

    inf = PassiveStackClassifier.infer_os_profile(
        ttl=64,
        window_size=65535,
        option55="1,3,6,15,26,28,51,58,59,43",
        extra_hints="extender wlan bridge"
    )
    assert inf["os_profile"] == "ANDROID_WLAN_BRIDGE"


def test_save_to_ledger(classifier):
    """Verifies inferred OS profiles are persisted to inferred_os_profiles table."""
    profiles = {
        "192.168.1.73": {
            "mac": "9C:54:DA:15:1E:7A",
            "os_profile": "WINDOWS_NT",
            "synack_ttl": 128,
            "window_size": 64240,
            "option55": "1,3,6,15,31,33,43,44",
            "confidence": 99.0,
            "evidence": "Windows 11 Workstation"
        },
        "192.168.1.67": {
            "mac": "98:CC:F3:54:F1:8D",
            "os_profile": "EMBEDDED_LINUX_STB",
            "synack_ttl": 64,
            "window_size": 14600,
            "option55": "1,3,6,12,15,28",
            "confidence": 98.5,
            "evidence": "Media Set-Top Box"
        }
    }
    classifier.save_to_ledger(profiles)

    with sqlite3.connect(str(classifier.db_path)) as conn:
        cur = conn.cursor()
        cur.execute("SELECT ip, os_profile, tcp_synack_ttl FROM inferred_os_profiles")
        rows = {row[0]: (row[1], row[2]) for row in cur.fetchall()}

    assert "192.168.1.73" in rows
    assert rows["192.168.1.73"][0] == "WINDOWS_NT"
    assert rows["192.168.1.73"][1] == 128

    assert "192.168.1.67" in rows
    assert rows["192.168.1.67"][0] == "EMBEDDED_LINUX_STB"
    assert rows["192.168.1.67"][1] == 64


def test_subnet_sweeper_port1_multivector():
    """Verifies SubnetSweeper executes multi-vector sweep on Port 1 targets."""
    from unittest.mock import patch
    sweeper = SubnetSweeper(
        subnet_cidr="192.168.1.0/24",
        interface=None,
        api_url=None
    )
    with patch("graphpath.discovery.serialization_probe.sr1", return_value=None):
        results = sweeper.sweep_port1_multivector(["192.168.1.73", "192.168.1.67"])
        assert len(results) == 2

        res_73 = next(r for r in results if r["ip"] == "192.168.1.73")
        assert res_73["os_profile"] == "WINDOWS_NT"
        assert not res_73["is_throttled"]
        assert res_73["inferred_link_speed"] == "1Gbps_FULL"

        res_67 = next(r for r in results if r["ip"] == "192.168.1.67")
        assert res_67["os_profile"] == "EMBEDDED_LINUX_STB"
        assert res_67["is_throttled"]
        assert res_67["inferred_link_speed"] == "100Mbps_BRIDGE"
