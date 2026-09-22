"""
Unit Tests for Enterprise Bridge Forwarding Database (CAM Table) Crawler
Validates:
- Decimal OID suffix to MAC & VLAN parsing (dot1d & dot1q)
- Link-layer multicast, broadcast, and virtual router MAC filtering (HSRP, VRRP, NLB)
- Thread-isolated async PySNMP MIB walks with bridge-port to ifIndex translation
- Port density analytics and trunk classification (>= 4 MACs or trunk alias)
- Fast-bailout and fallback to ARP cache on unresponsive switches
- SQLite switchport_mappings ledger persistence
- JSON serialization symmetry (zero bare bytes)
"""

import json
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from aetheris.core.crawlers.bridge_fdb import (
    BridgeFdbCrawler,
    BridgeFDBCrawler,
    crawl_switch_fdb,
    oid_suffix_to_mac_and_vlan,
    is_virtual_or_multicast_mac,
    save_to_ledger,
    DOT1D_TP_FDB_PORT,
    DOT1Q_TP_FDB_PORT,
    DOT1D_BASE_PORT_IFINDEX,
    IF_NAME,
    IF_DESCR,
    IF_ALIAS,
    SYS_DESCR,
)
from aetheris.core.probers.sanitization import sanitize_prober_payload


# =========================================================================
# 1. Decimal OID Suffix to MAC & VLAN Parsing Tests
# =========================================================================

def test_oid_suffix_to_mac_and_vlan():
    """Verifies decimal OID suffix decoding for both dot1d (6-octet) and dot1q (7-octet)."""
    # 6 decimal octets (Bridge MIB)
    oid_dot1d = f"{DOT1D_TP_FDB_PORT}.0.17.34.51.68.85"
    mac, vlan = oid_suffix_to_mac_and_vlan(oid_dot1d, DOT1D_TP_FDB_PORT)
    assert mac == "00:11:22:33:44:55"
    assert vlan == 1

    # 7 decimal octets (Q-Bridge MIB: VLAN 20 + MAC)
    oid_dot1q = f"{DOT1Q_TP_FDB_PORT}.20.16.120.91.61.8.128"
    mac, vlan = oid_suffix_to_mac_and_vlan(oid_dot1q, DOT1Q_TP_FDB_PORT)
    assert mac == "10:78:5B:3D:08:80"
    assert vlan == 20

    # Extended decimal prefix (>7 octets)
    oid_ext = f"{DOT1Q_TP_FDB_PORT}.1.100.0.17.34.51.68.85"
    mac, vlan = oid_suffix_to_mac_and_vlan(oid_ext, DOT1Q_TP_FDB_PORT)
    assert mac == "00:11:22:33:44:55"
    assert vlan == 100

    # Non-matching base OID
    mac, vlan = oid_suffix_to_mac_and_vlan("1.3.6.1.4.1.9.9.99.1.1", DOT1D_TP_FDB_PORT)
    assert mac is None
    assert vlan is None

    # Empty suffix
    mac, vlan = oid_suffix_to_mac_and_vlan(DOT1D_TP_FDB_PORT, DOT1D_TP_FDB_PORT)
    assert mac is None
    assert vlan is None


# =========================================================================
# 2. Virtual MAC & Multicast Suppression Tests
# =========================================================================

def test_virtual_and_multicast_mac_filtering():
    """Verifies link-layer multicast, broadcast, and virtual router MAC filtering."""
    # Broadcast & Null
    assert is_virtual_or_multicast_mac("FF:FF:FF:FF:FF:FF") is True
    assert is_virtual_or_multicast_mac("00:00:00:00:00:00") is True

    # IPv4 / IPv6 Multicast
    assert is_virtual_or_multicast_mac("01:00:5E:00:00:01") is True
    assert is_virtual_or_multicast_mac("33:33:00:00:00:02") is True

    # Spanning Tree / LLDP
    assert is_virtual_or_multicast_mac("01:80:C2:00:00:00") is True

    # Cisco HSRP v1 & v2
    assert is_virtual_or_multicast_mac("00:00:0C:07:AC:01") is True
    assert is_virtual_or_multicast_mac("00:00:0C:9F:F0:01") is True

    # VRRP IPv4 & IPv6
    assert is_virtual_or_multicast_mac("00:00:5E:00:01:01") is True
    assert is_virtual_or_multicast_mac("00:00:5E:00:02:01") is True

    # Microsoft NLB
    assert is_virtual_or_multicast_mac("02:BF:01:02:03:04") is True
    assert is_virtual_or_multicast_mac("03:BF:01:02:03:04") is True

    # Cisco GLBP
    assert is_virtual_or_multicast_mac("00:07:B4:00:01:01") is True

    # Valid physical host MACs
    assert is_virtual_or_multicast_mac("00:11:22:33:44:55") is False
    assert is_virtual_or_multicast_mac("10:78:5B:3D:08:80") is False
    assert is_virtual_or_multicast_mac("BC:7E:8B:0D:82:CA") is False


# =========================================================================
# 3. SNMP MIB Walk & Interface Translation Mock Tests
# =========================================================================

class MockVarBind:
    def __init__(self, oid, val):
        self.oid = oid
        self.val = val

    def __getitem__(self, idx):
        if idx == 0:
            return self.oid
        elif idx == 1:
            return self.val
        raise IndexError

    def prettyPrint(self):
        return str(self.val)


async def mock_async_get_cmd(engine, auth, target, context, vb):
    """Simulates successful sysDescr liveness probe."""
    return (None, 0, 0, [MockVarBind(SYS_DESCR, "Cisco IOS Software, C2960X Software")])


def _extract_oid(vb):
    try:
        return str(vb[0])
    except Exception:
        pass
    try:
        args = getattr(vb, "_ObjectType__args", None)
        if args:
            oid_id = args[0]
            oid_args = getattr(oid_id, "_ObjectIdentity__args", None)
            if oid_args:
                return str(oid_args[0])
    except Exception:
        pass
    return str(vb)


async def mock_async_walk_cmd(engine, auth, target, context, vb):
    """Simulates walk of dot1dBasePortIfIndex, ifName, ifAlias, and FDB tables."""
    base_oid = _extract_oid(vb)

    if base_oid == DOT1D_BASE_PORT_IFINDEX:
        # Bridge Port 1 -> ifIndex 10101
        # Bridge Port 2 -> ifIndex 10102
        # Bridge Port 3 -> ifIndex 10103
        yield (None, 0, 0, [MockVarBind(f"{DOT1D_BASE_PORT_IFINDEX}.1", 10101)])
        yield (None, 0, 0, [MockVarBind(f"{DOT1D_BASE_PORT_IFINDEX}.2", 10102)])
        yield (None, 0, 0, [MockVarBind(f"{DOT1D_BASE_PORT_IFINDEX}.3", 10103)])

    elif base_oid == IF_NAME:
        yield (None, 0, 0, [MockVarBind(f"{IF_NAME}.10101", "Gi1/0/1")])
        yield (None, 0, 0, [MockVarBind(f"{IF_NAME}.10102", "Gi1/0/2")])
        yield (None, 0, 0, [MockVarBind(f"{IF_NAME}.10103", "Gi1/0/3")])

    elif base_oid == IF_DESCR:
        yield (None, 0, 0, [MockVarBind(f"{IF_DESCR}.10101", "GigabitEthernet1/0/1")])
        yield (None, 0, 0, [MockVarBind(f"{IF_DESCR}.10102", "GigabitEthernet1/0/2")])
        yield (None, 0, 0, [MockVarBind(f"{IF_DESCR}.10103", "GigabitEthernet1/0/3")])

    elif base_oid == IF_ALIAS:
        yield (None, 0, 0, [MockVarBind(f"{IF_ALIAS}.10101", "Accounting-PC Drop")])
        yield (None, 0, 0, [MockVarBind(f"{IF_ALIAS}.10102", "Network-Printer Drop")])
        yield (None, 0, 0, [MockVarBind(f"{IF_ALIAS}.10103", "Uplink to Distribution")])

    elif base_oid == DOT1Q_TP_FDB_PORT:
        # MAC 00:11:22:33:44:55 on VLAN 10 -> Bridge Port 1
        yield (None, 0, 0, [MockVarBind(f"{DOT1Q_TP_FDB_PORT}.10.0.17.34.51.68.85", 1)])
        # MAC 00:11:22:33:44:56 on VLAN 10 -> Bridge Port 2
        yield (None, 0, 0, [MockVarBind(f"{DOT1Q_TP_FDB_PORT}.10.0.17.34.51.68.86", 2)])

    elif base_oid == DOT1D_TP_FDB_PORT:
        # MAC 00:11:22:33:44:57 on VLAN 1 -> Bridge Port 3
        yield (None, 0, 0, [MockVarBind(f"{DOT1D_TP_FDB_PORT}.0.17.34.51.68.87", 3)])


def test_fdb_crawl_snmp_mock_success():
    """Verifies complete SNMP walk, ifIndex resolution, interface naming, and alias attachment."""
    crawler = BridgeFdbCrawler(community="public", timeout=1.0)

    with patch("pysnmp.hlapi.v3arch.asyncio.get_cmd", side_effect=mock_async_get_cmd), \
         patch("pysnmp.hlapi.v3arch.asyncio.walk_cmd", side_effect=mock_async_walk_cmd):

        mappings = crawler.crawl_snmp("10.0.0.1")

        assert "00:11:22:33:44:55" in mappings
        assert "00:11:22:33:44:56" in mappings
        assert "00:11:22:33:44:57" in mappings

        # Port 1: Gi1/0/1, Accounting-PC Drop, VLAN 10
        m1 = mappings["00:11:22:33:44:55"]
        assert m1["port_name"] == "Gi1/0/1"
        assert m1["if_index"] == 10101
        assert m1["if_alias"] == "Accounting-PC Drop"
        assert m1["vlan_id"] == 10
        assert m1["is_trunk"] is False
        assert m1["mac_density"] == 1

        # Port 2: Gi1/0/2, Network-Printer Drop, VLAN 10
        m2 = mappings["00:11:22:33:44:56"]
        assert m2["port_name"] == "Gi1/0/2"
        assert m2["if_index"] == 10102
        assert m2["if_alias"] == "Network-Printer Drop"
        assert m2["vlan_id"] == 10
        assert m2["is_trunk"] is False

        # Port 3: Gi1/0/3, Uplink to Distribution, VLAN 1
        m3 = mappings["00:11:22:33:44:57"]
        assert m3["port_name"] == "Gi1/0/3"
        assert m3["if_index"] == 10103
        assert m3["if_alias"] == "Uplink to Distribution"
        assert m3["vlan_id"] == 1
        # Uplink keyword in alias should flag is_trunk = True
        assert m3["is_trunk"] is True


# =========================================================================
# 4. Port Density Analytics & Trunk Classification Tests
# =========================================================================

async def mock_async_trunk_walk(engine, auth, target, context, vb):
    base_oid = _extract_oid(vb)
    if base_oid == DOT1D_BASE_PORT_IFINDEX:
        yield (None, 0, 0, [MockVarBind(f"{DOT1D_BASE_PORT_IFINDEX}.1", 10101)])
    elif base_oid == IF_NAME:
        yield (None, 0, 0, [MockVarBind(f"{IF_NAME}.10101", "Gi1/0/1")])
    elif base_oid == IF_ALIAS:
        yield (None, 0, 0, [MockVarBind(f"{IF_ALIAS}.10101", "Standard Access Drop")])
    elif base_oid == DOT1D_TP_FDB_PORT:
        # 4 unique MACs learned on Port 1 -> triggers trunk classification
        for i in range(1, 5):
            yield (None, 0, 0, [MockVarBind(f"{DOT1D_TP_FDB_PORT}.0.17.34.51.68.{i:02d}", 1)])


def test_fdb_trunk_classification():
    """Verifies switchports with >= 4 MACs are classified as is_trunk = True."""
    crawler = BridgeFdbCrawler(community="public", timeout=1.0)

    with patch("pysnmp.hlapi.v3arch.asyncio.get_cmd", side_effect=mock_async_get_cmd), \
         patch("pysnmp.hlapi.v3arch.asyncio.walk_cmd", side_effect=mock_async_trunk_walk):

        mappings = crawler.crawl_snmp("10.0.0.2")

        assert len(mappings) >= 4
        sample_mac = "00:11:22:33:44:01"
        assert sample_mac in mappings
        entry = mappings[sample_mac]
        assert entry["mac_density"] == 4
        assert entry["is_trunk"] is True


# =========================================================================
# 5. Unresponsive Target & Fallback Handling Tests
# =========================================================================

def test_fdb_unresponsive_target_fallback():
    """Verifies fast bailout on unreachable switches and clean fallback to ARP cache."""
    crawler = BridgeFdbCrawler(community="invalid_comm", timeout=0.1)

    mock_arp = "  192.168.1.50          02-11-22-33-44-55     dynamic\n"
    with patch("subprocess.check_output", return_value=mock_arp):
        mappings = crawler.crawl("192.168.1.1")
        assert "02:11:22:33:44:55" in mappings
        entry = mappings["02:11:22:33:44:55"]
        assert entry["source"] == "L2-BridgeCache"


# =========================================================================
# 6. JSON Serialization Symmetry & Payload Sanitization
# =========================================================================

def test_fdb_json_serializability_and_symmetry():
    """Verifies that all FDB crawler entries round-trip symmetrically through json.dumps()."""
    sample_entry = {
        "mac": "00:11:22:33:44:55",
        "port_name": "Gi1/0/1\x00\x1f",
        "port": "Gi1/0/1",
        "switchport": "Gi1/0/1",
        "if_index": 10101,
        "if_alias": "Accounting Drop\x00",
        "vlan_id": 10,
        "is_trunk": False,
        "mac_density": 1,
        "medium": "Ethernet",
        "source": "SNMP-BridgeFDB",
        "raw_response": b"\x01\x02\x03\x04"
    }
    sanitized = sanitize_prober_payload(sample_entry)
    assert sanitized["port_name"] == "Gi1/0/1"
    assert sanitized["if_alias"] == "Accounting Drop"
    assert sanitized["raw_response"] == "01020304"

    dumped = json.dumps(sanitized)
    assert isinstance(dumped, str)
    assert json.loads(dumped) == sanitized


# =========================================================================
# 7. SQLite Switchport Mappings Ledger Persistence Tests
# =========================================================================

def test_fdb_sqlite_ledger_persistence():
    """Verifies switchport mappings persist cleanly to switchport_mappings table in SQLite."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db = tf.name

    mappings = {
        "00:11:22:33:44:55": {
            "mac": "00:11:22:33:44:55",
            "port_name": "Gi1/0/1",
            "if_index": 10101,
            "if_alias": "Desk Drop 1",
            "vlan_id": 10,
            "is_trunk": False,
            "mac_density": 1,
            "source": "SNMP-BridgeFDB"
        },
        "00:11:22:33:44:56": {
            "mac": "00:11:22:33:44:56",
            "port_name": "Gi1/0/2",
            "if_index": 10102,
            "if_alias": "Trunk Link",
            "vlan_id": 20,
            "is_trunk": True,
            "mac_density": 4,
            "source": "SNMP-BridgeFDB"
        }
    }

    saved = save_to_ledger(mappings, switch_ip="10.0.0.1", switch_name="Core-Switch-01", db_path=temp_db)
    assert saved == 2

    with sqlite3.connect(temp_db) as conn:
        cur = conn.cursor()
        rows = cur.execute("""
            SELECT switch_ip, switch_name, mac_address, port_name, if_index, if_alias, vlan_id, is_trunk, mac_density, source
            FROM switchport_mappings ORDER BY mac_address
        """).fetchall()

    assert len(rows) == 2

    # Row 1
    assert rows[0][0] == "10.0.0.1"
    assert rows[0][1] == "Core-Switch-01"
    assert rows[0][2] == "00:11:22:33:44:55"
    assert rows[0][3] == "Gi1/0/1"
    assert rows[0][4] == 10101
    assert rows[0][5] == "Desk Drop 1"
    assert rows[0][6] == 10
    assert rows[0][7] == 0
    assert rows[0][8] == 1

    # Row 2
    assert rows[1][0] == "10.0.0.1"
    assert rows[1][2] == "00:11:22:33:44:56"
    assert rows[1][3] == "Gi1/0/2"
    assert rows[1][4] == 10102
    assert rows[1][5] == "Trunk Link"
    assert rows[1][6] == 20
    assert rows[1][7] == 1
    assert rows[1][8] == 4


# =========================================================================
# 8. Standalone crawl_switch_fdb Function Test
# =========================================================================

def test_standalone_crawl_switch_fdb():
    """Verifies standalone functional wrapper crawl_switch_fdb."""
    mock_arp = "  192.168.1.100         02-AA-BB-CC-DD-EE     dynamic\n"
    with patch("subprocess.check_output", return_value=mock_arp):
        res = crawl_switch_fdb("192.168.1.1", timeout=0.1)
        assert isinstance(res, dict)
        assert "02:AA:BB:CC:DD:EE" in res
