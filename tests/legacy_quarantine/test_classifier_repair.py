"""
Unit Tests for SubnetSweeper Classification Repair
Validates that endpoints with TTL <= 64 (such as Apple iPhones, Samsung Smart TVs,
Roku streaming devices, and Mercury access control panels) do not collapse into
LINUX_SERVER, and that DeviceClassifier, ActiveServiceProber, and fingerprint_device
accurately assign appropriate archetypes before MCMC deconvolution.
"""

import pytest
from unittest.mock import patch, MagicMock
from aetheris.cli.sweep import SubnetSweeper
from aetheris.core.device_classifier import DeviceClassifier
from aetheris.discovery.fingerprint import fingerprint_device


def test_map_fingerprint_to_archetype_rules():
    # 1. Mobile iOS / Android / Tablet
    assert SubnetSweeper._map_fingerprint_to_archetype("mobile_ios", "Apple Inc.", "Apple iPhone") == "WINDOWS_HOST"
    assert SubnetSweeper._map_fingerprint_to_archetype("mobile_android", "Google LLC", "Pixel Phone") == "WINDOWS_HOST"
    assert SubnetSweeper._map_fingerprint_to_archetype("tablet", "Apple Inc.", "Apple iPad") == "WINDOWS_HOST"
    assert SubnetSweeper._map_fingerprint_to_archetype("laptop", "Apple Inc.", "MacBook Pro") == "WINDOWS_HOST"

    # 2. Smart TVs, STBs, Media devices, Cameras
    assert SubnetSweeper._map_fingerprint_to_archetype("smart_tv", "Samsung Electronics", "Samsung Smart TV") == "CCTV_VIDEO"
    assert SubnetSweeper._map_fingerprint_to_archetype("media_device", "Roku Inc.", "Roku Streaming Stick") == "CCTV_VIDEO"
    assert SubnetSweeper._map_fingerprint_to_archetype("stb", "Technicolor", "Technicolor Android TV STB") == "CCTV_VIDEO"
    assert SubnetSweeper._map_fingerprint_to_archetype("camera", "Axis Communications", "AXIS Network Camera") == "CCTV_VIDEO"

    # 3. Access Control, PLCs
    assert SubnetSweeper._map_fingerprint_to_archetype("access_control", "Mercury Security", "Mercury EP1502") == "INDUSTRIAL_OT"
    assert SubnetSweeper._map_fingerprint_to_archetype("access_control", "HID Global", "HID Aero Controller") == "INDUSTRIAL_OT"
    assert SubnetSweeper._map_fingerprint_to_archetype("plc", "Siemens", "SIMATIC S7-1200") == "INDUSTRIAL_OT"

    # 4. VoIP & Telephony
    assert SubnetSweeper._map_fingerprint_to_archetype("voip_phone", "Yealink", "Yealink SIP-T46S") == "VOIP_TELEPHONY"
    assert SubnetSweeper._map_fingerprint_to_archetype("voip_phone", "Polycom", "Polycom VVX") == "VOIP_TELEPHONY"

    # 5. Infrastructure
    assert SubnetSweeper._map_fingerprint_to_archetype("switch", "Cisco Systems", "Catalyst 9300") == "NETWORK_INFRASTRUCTURE"
    assert SubnetSweeper._map_fingerprint_to_archetype("router", "Ubiquiti Networks", "UniFi Gateway") == "NETWORK_INFRASTRUCTURE"

    # 6. Servers
    assert SubnetSweeper._map_fingerprint_to_archetype("server", "VMware, Inc.", "VMware Virtual Machine") == "LINUX_SERVER"


def test_apple_iphone_ttl64_prevents_linux_server_collapse():
    """Verify Apple iPhone with TTL 64 maps to WINDOWS_HOST, not LINUX_SERVER."""
    sweeper = SubnetSweeper(
        subnet_cidr="192.168.1.0/24",
        interface=None,
        prober_lead_m=2.0,
        burst_count=3,
        api_url=None
    )

    # Mock srp1 port scan to return TTL 64 (standard for iOS and Linux)
    with patch("aetheris.cli.sweep.srp1") as mock_srp1:
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.__getitem__.side_effect = lambda layer: MagicMock(ttl=64, flags=0x14)
        mock_srp1.return_value = mock_resp

        # Apple OUI (AC:BC:32)
        sweeper.fingerprint_and_probe_host(
            ip_addr="192.168.1.55",
            mac_addr="AC:BC:32:11:22:33"
        )

    node = sweeper.store.get_node("host_192_168_1_55")
    assert node is not None
    assert node["archetype"] == "WINDOWS_HOST"
    assert node["archetype"] != "LINUX_SERVER"
    assert node["vendor"] == "Apple Inc."


def test_samsung_smart_tv_ttl64_maps_to_cctv_video():
    """Verify Samsung Smart TV with TTL 64 maps to CCTV_VIDEO, not LINUX_SERVER."""
    sweeper = SubnetSweeper(
        subnet_cidr="192.168.1.0/24",
        interface=None,
        prober_lead_m=2.0,
        burst_count=3,
        api_url=None
    )

    with patch("aetheris.cli.sweep.srp1") as mock_srp1:
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.__getitem__.side_effect = lambda layer: MagicMock(ttl=64, flags=0x14)
        mock_srp1.return_value = mock_resp

        # Samsung OUI (BC:44:86)
        sweeper.fingerprint_and_probe_host(
            ip_addr="192.168.1.60",
            mac_addr="BC:44:86:AA:BB:CC"
        )

    node = sweeper.store.get_node("host_192_168_1_60")
    assert node is not None
    assert node["archetype"] == "CCTV_VIDEO"
    assert node["archetype"] != "LINUX_SERVER"
    assert node["vendor"] == "Samsung Electronics"


def test_mercury_access_control_ttl64_maps_to_industrial_ot():
    """Verify Mercury Access Control panel with TTL 64 maps to INDUSTRIAL_OT, not LINUX_SERVER."""
    sweeper = SubnetSweeper(
        subnet_cidr="192.168.1.0/24",
        interface=None,
        prober_lead_m=2.0,
        burst_count=3,
        api_url=None
    )

    with patch("aetheris.cli.sweep.srp1") as mock_srp1:
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.__getitem__.side_effect = lambda layer: MagicMock(ttl=64, flags=0x14)
        mock_srp1.return_value = mock_resp

        # Mercury Security OUI (00:0F:9F)
        sweeper.fingerprint_and_probe_host(
            ip_addr="192.168.1.75",
            mac_addr="00:0F:9F:12:34:56"
        )

    node = sweeper.store.get_node("host_192_168_1_75")
    assert node is not None
    assert node["archetype"] == "INDUSTRIAL_OT"
    assert node["archetype"] != "LINUX_SERVER"
    assert node["vendor"] == "Mercury Security"


def test_active_mdns_cache_informs_sweep_classification():
    """Verify active mDNS cached entries override TTL 64 prior."""
    sweeper = SubnetSweeper(
        subnet_cidr="192.168.1.0/24",
        interface=None,
        prober_lead_m=2.0,
        burst_count=3,
        api_url=None
    )

    # Seed active probe cache with a discovered Roku device
    sweeper.active_probe_cache["192.168.1.80"] = {
        "ip": "192.168.1.80",
        "vendor": "Roku Inc.",
        "type": "media_device",
        "model": "Roku Ultra 4K",
        "source": "active_mdns"
    }

    with patch("aetheris.cli.sweep.srp1") as mock_srp1:
        mock_resp = MagicMock()
        mock_resp.haslayer.return_value = True
        mock_resp.__getitem__.side_effect = lambda layer: MagicMock(ttl=64, flags=0x14)
        mock_srp1.return_value = mock_resp

        sweeper.fingerprint_and_probe_host(
            ip_addr="192.168.1.80",
            mac_addr="AA:BB:CC:11:22:33"
        )

    node = sweeper.store.get_node("host_192_168_1_80")
    assert node is not None
    assert node["archetype"] == "CCTV_VIDEO"
    assert node["archetype"] != "LINUX_SERVER"

