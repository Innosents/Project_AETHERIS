"""
Unit Tests for Phase 22 L2 SNMP CAM Parser & SnmpFdbAdapter
Validates:
- Stateless parse_cam_table_oids relational mapping and OID sanitization
- Asynchronous context manager and deterministic dispatcher cleanup
- SNMPv3 authentication configuration and extraction
- SNMPv2c fallback traversal over community collections
- SwitchportTelemetryPort Pydantic validation and Memurai event bus delivery
"""

import asyncio
from typing import Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from aetheris.core.ports.l2_switchport import SwitchportTelemetryPort
from aetheris.core.parsers.snmp_cam_parser import parse_cam_table_oids
from aetheris.infrastructure.adapters.snmp_fdb_adapter import SnmpFdbAdapter


# =========================================================================
# 1. Stateless SNMP CAM Parser Tests
# =========================================================================

def test_parse_cam_table_oids_nominal():
    """Verifies relational assembly of MAC OIDs, Bridge Port mappings, and ifNames."""
    # OID suffix: 00:11:22:33:44:55 -> bridge port 2
    # OID suffix: AA:BB:CC:DD:EE:FF -> bridge port 5
    raw_cam_table = {
        "1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85": 2,
        "1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255": 5,
    }
    raw_bridge_map = {
        "1.3.6.1.2.1.17.1.4.1.2.2": 101,  # bridge port 2 -> ifIndex 101
        "1.3.6.1.2.1.17.1.4.1.2.5": 102,  # bridge port 5 -> ifIndex 102
    }
    raw_ifname_map = {
        "1.3.6.1.2.1.31.1.1.1.1.101": "GigabitEthernet1/0/1",
        "1.3.6.1.2.1.31.1.1.1.1.102": "GigabitEthernet1/0/2",
    }

    result = parse_cam_table_oids(raw_cam_table, raw_bridge_map, raw_ifname_map)
    assert result == {
        "00:11:22:33:44:55": "GigabitEthernet1/0/1",
        "aa:bb:cc:dd:ee:ff": "GigabitEthernet1/0/2",
    }


def test_parse_cam_table_oids_short_oid_and_unknown_ifindex():
    """Verifies malformed OIDs (< 6 parts) are discarded and missing ifNames fallback safely."""
    raw_cam_table = {
        "1.2.3": 1,  # short OID (< 6 parts)
        "1.3.6.1.2.1.17.4.3.1.2.10.20.30.40.50.60": 9,  # bridge port 9 has no ifName
    }
    raw_bridge_map = {
        "1.3.6.1.2.1.17.1.4.1.2.9": 999,
    }
    raw_ifname_map = {}

    result = parse_cam_table_oids(raw_cam_table, raw_bridge_map, raw_ifname_map)
    assert "0a:14:1e:28:32:3c" in result
    assert result["0a:14:1e:28:32:3c"] == "Unknown-IfIndex-999"
    assert len(result) == 1


# =========================================================================
# 2. SnmpFdbAdapter Lifecycle & Extraction Tests
# =========================================================================

@pytest.mark.asyncio
async def test_snmp_fdb_adapter_context_manager():
    """Validates asynchronous context manager entry and close() execution."""
    async with SnmpFdbAdapter(community="public", target_ip="192.168.1.1") as adapter:
        assert adapter.community == "public"
        assert adapter.target_ip == "192.168.1.1"
        assert adapter.engine is not None
        assert adapter.auth_data is None


@pytest.mark.asyncio
async def test_snmp_fdb_adapter_v3_credentials():
    """Validates SNMPv3 USM user configuration."""
    adapter = SnmpFdbAdapter(
        target_ip="10.0.0.1",
        v3_user="secadmin",
        v3_auth="AuthPass123!",
        v3_priv="PrivPass123!",
    )
    try:
        assert adapter.auth_data is not None
        assert adapter.auth_data.userName == "secadmin"
    finally:
        adapter.close()


@pytest.mark.asyncio
async def test_snmp_fdb_adapter_v3_extraction():
    """Validates SNMPv3 successful extraction bypassing v2c fallback."""
    adapter = SnmpFdbAdapter(
        target_ip="192.168.1.1",
        v3_user="admin",
        v3_auth="auth_pass",
        v3_priv="priv_pass",
    )
    mock_cam = {"00:11:22:33:44:55": "GigabitEthernet1/0/1"}

    with patch.object(adapter, "_extract_with_auth", new=AsyncMock(return_value=mock_cam)) as mock_extract:
        matrix = await adapter.extract_cam_matrix("192.168.1.1")
        assert matrix == mock_cam
        assert mock_extract.call_count == 1
        assert mock_extract.call_args[0][1] == adapter.auth_data
    adapter.close()


@pytest.mark.asyncio
async def test_snmp_fdb_adapter_v2c_fallback():
    """Validates fallback to SNMPv2c communities when SNMPv3 yields no results."""
    adapter = SnmpFdbAdapter(
        target_ip="192.168.1.1",
        v3_user="admin",
        v3_auth="auth_pass",
        v3_priv="priv_pass",
        telemetry_context={"snmp_communities": ["private", "public"]},
    )
    mock_v2_cam = {"aa:bb:cc:dd:ee:ff": "GigabitEthernet1/0/24"}

    async def side_effect(ip, auth):
        # Fail on v3 and first community, succeed on second community
        if getattr(auth, "userName", None) == "admin":
            return {}
        if getattr(auth, "communityName", None) == "private":
            return {}
        return mock_v2_cam

    with patch.object(adapter, "_extract_with_auth", new=AsyncMock(side_effect=side_effect)):
        matrix = await adapter.extract_cam_matrix("192.168.1.1")
        assert matrix == mock_v2_cam
    adapter.close()


@pytest.mark.asyncio
async def test_snmp_fdb_adapter_crawl_switch_and_bus_push():
    """Validates crawl_switch validates SwitchportTelemetryPort and pushes to Memurai queue."""
    mock_bus = AsyncMock()
    mock_bus.push_telemetry = AsyncMock(return_value=1)

    adapter = SnmpFdbAdapter(
        target_ip="172.16.1.254",
        community="public",
        event_bus=mock_bus,
    )

    fake_matrix = {
        "00:11:22:33:44:01": "GigabitEthernet1/0/1",
        "00:11:22:33:44:02": "Trunk_Uplink",
        "00:11:22:33:44:03": "Trunk_Uplink",
        "00:11:22:33:44:04": "Trunk_Uplink",
        "00:11:22:33:44:05": "Trunk_Uplink",  # density 4 -> is_trunk = True
    }

    with patch.object(adapter, "extract_cam_matrix", new=AsyncMock(return_value=fake_matrix)):
        records = await adapter.crawl_switch("172.16.1.254")

    assert len(records) == 5
    assert mock_bus.push_telemetry.call_count == 5

    # Check non-trunk access port
    access_record = next(r for r in records if r.mac_address == "00:11:22:33:44:01")
    assert access_record.port_name == "GigabitEthernet1/0/1"
    assert access_record.mac_density == 1
    assert access_record.is_trunk is False

    # Check trunk port
    trunk_record = next(r for r in records if r.mac_address == "00:11:22:33:44:05")
    assert trunk_record.mac_density == 4
    assert trunk_record.is_trunk is True

    # Check queue name pushed
    assert mock_bus.push_telemetry.call_args[0][0] == "aetheris:telemetry:switch_fdb"
    adapter.close()
