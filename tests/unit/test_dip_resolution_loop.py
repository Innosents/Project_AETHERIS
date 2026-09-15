"""
Unit Tests for DIP Identity Resolution Loop & Progressive Property Aggregation
Validates that DeviceIdentityProfileManager merges partial markers without overwriting,
computes composite confidence scores accurately based on evidence depth,
and integrates with passive DPI and active service probes.
"""

import tempfile
import pytest
from unittest.mock import MagicMock
from graphpath.core.dip_manager import DeviceIdentityProfileManager
from graphpath.discovery.discovery_engine import DiscoveryEngine


def test_dip_get_or_create_and_lookup():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    dip = DeviceIdentityProfileManager(storage_path=temp_path)
    dip.profiles = {}

    mac = "00:11:22:33:44:55"
    ip = "192.168.1.50"

    prof = dip.get_or_create(mac, ip)
    assert prof is not None
    assert prof["mac"] == mac
    assert prof["ip"] == ip
    assert prof["confidence"] == 0.30

    # Retrieve existing
    looked_up = dip.lookup(mac)
    assert looked_up is not None
    assert looked_up["mac"] == mac


def test_dip_progressive_confidence_scaling():
    """
    Validates confidence levels:
    - MAC OUI only: 50%
    - OUI + OS TTL match: 70%
    - OUI + Open Port / Service: 85%
    - OUI + mDNS/DHCP Hostname or Model String: 98%
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    dip = DeviceIdentityProfileManager(storage_path=temp_path)
    dip.profiles = {}

    mac = "AC:BC:32:00:11:22"
    ip = "192.168.1.100"

    # Step 1: MAC OUI only -> 50%
    p1 = dip.ingest_observation(
        mac=mac,
        ip=ip,
        vendor="Apple Inc.",
        evidence_source="mac_oui"
    )
    assert p1["vendor"] == "Apple Inc."
    assert p1["confidence"] == 0.50

    # Step 2: OUI + OS TTL match -> 70%
    p2 = dip.ingest_observation(
        mac=mac,
        ip=ip,
        os_family="linux",
        evidence_source="probe_ttl"
    )
    assert p2["vendor"] == "Apple Inc."
    assert p2["os_family"] == "linux"
    assert p2["confidence"] == 0.70

    # Step 3: OUI + Open Port / Service -> 85%
    p3 = dip.ingest_observation(
        mac=mac,
        ip=ip,
        evidence_source="open_port_443"
    )
    assert p3["confidence"] == 0.85

    # Step 4: OUI + mDNS/DHCP Hostname or Model String -> 98%
    p4 = dip.ingest_observation(
        mac=mac,
        ip=ip,
        model="Apple iPhone 14",
        hostname="iPhone-John",
        evidence_source="active_mdns"
    )
    assert p4["hostname"] == "iPhone-John"
    assert p4["model"] == "Apple iPhone 14"
    assert p4["confidence"] == 0.98


def test_dip_partial_marker_merging_no_overwrite():
    """Partial markers (e.g. only hostname or only model) must merge without blanking vendor."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    dip = DeviceIdentityProfileManager(storage_path=temp_path)
    dip.profiles = {}

    mac = "00:0C:29:12:34:56"
    ip = "192.168.1.20"

    # Observation 1: OUI provides vendor
    dip.ingest_observation(mac=mac, ip=ip, vendor="VMware, Inc.", dev_type="server")
    prof = dip.lookup(mac)
    assert prof["vendor"] == "VMware, Inc."
    assert prof["dev_type"] == "server"

    # Observation 2: DHCP hostname only
    dip.ingest_observation(mac=mac, ip=ip, hostname="prod-db-01", evidence_source="dhcp")
    prof2 = dip.lookup(mac)
    assert prof2["vendor"] == "VMware, Inc."
    assert prof2["hostname"] == "prod-db-01"
    assert prof2["dev_type"] == "server"

    # Observation 3: Banner model only
    dip.ingest_observation(mac=mac, ip=ip, model="ESXi Virtual Host", evidence_source="http_banner")
    prof3 = dip.lookup(mac)
    assert prof3["vendor"] == "VMware, Inc."
    assert prof3["hostname"] == "prod-db-01"
    assert prof3["model"] == "ESXi Virtual Host"


def test_discovery_engine_passive_dpi_and_switch_learning():
    """Tests passive L2/L3 packet ingestion feeds DIP manager."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    engine = DiscoveryEngine(enable_tap=False)
    engine.dip_manager = DeviceIdentityProfileManager(storage_path=temp_path)
    engine.dip_manager.profiles = {}

    # Simulate CDP switch frame discovery
    switch_data = {
        "switch_id": "core-sw-01",
        "protocol": "CDP",
        "raw_mac": "00:00:0C:99:88:77",
        "management_ip": "10.0.0.1",
        "system_name": "cisco-core-9300",
        "port_id": "GigabitEthernet1/0/1"
    }
    engine._handle_switch_discovered(switch_data)

    sw_prof = engine.dip_manager.lookup("00:00:0C:99:88:77")
    assert sw_prof is not None
    assert sw_prof["vendor"] == "Cisco Systems"
    assert sw_prof["hostname"] == "cisco-core-9300"
    assert sw_prof["dev_type"] == "switch"

