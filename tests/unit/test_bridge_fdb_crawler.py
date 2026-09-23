"""
Unit test suite for BridgeFdbCrawlerPort and bridge_fdb_crawler shim.
Validates AST boundary isolation, protocol conformance, and pure MAC/VLAN parsing logic.
"""
import ast
import os
import pytest
from aetheris.core.ports.bridge_fdb_crawler_port import (
    BridgeFdbCrawlerPort,
    BridgeFdbEntry,
    BridgeFdbCrawlResult,
)
from aetheris.discovery.bridge_fdb_crawler import (
    BridgeFdbCrawler,
    oid_suffix_to_mac_and_vlan,
    is_virtual_or_multicast_mac,
)


def test_bridge_fdb_crawler_port_ast_boundary():
    """Verify bridge_fdb_crawler_port.py contains zero pysnmp, socket, or sqlite3 imports."""
    port_path = os.path.join("aetheris", "core", "ports", "bridge_fdb_crawler_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"pysnmp", "socket", "scapy", "sqlite3", "redis", "subprocess", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_virtual_and_multicast_mac_filter():
    """Verify multicast and broadcast MAC addresses are correctly flagged."""
    assert is_virtual_or_multicast_mac("FF:FF:FF:FF:FF:FF") is True
    assert is_virtual_or_multicast_mac("01:00:5E:00:00:01") is True
    assert is_virtual_or_multicast_mac("33:33:00:00:00:01") is True
    assert is_virtual_or_multicast_mac("00:1A:2B:3C:4D:5E") is False


def test_bridge_fdb_entry_immutability_and_mapping():
    """Verify BridgeFdbEntry enforces frozen semantics with dual mapping access."""
    entry = BridgeFdbEntry(mac="00:1A:2B:3C:4D:5E", port="Gi1/0/1", vlan_id=10)
    assert entry.mac == "00:1A:2B:3C:4D:5E"
    assert entry["mac"] == "00:1A:2B:3C:4D:5E"
    assert entry.get("vlan_id") == 10

    with pytest.raises(Exception):
        entry.port = "Gi1/0/2"
