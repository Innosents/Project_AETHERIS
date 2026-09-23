"""
Unit test suite for IspGuiScraperPort, GatewaySwitchportStoragePort, and IspGuiScraper.
Validates AST boundary isolation, table parsing heuristics, ledger persistence, and schema immutability.
"""
import ast
import os
import sqlite3
import pytest
from aetheris.core.ports.isp_gui_scraper_port import (
    IspGuiScraperPort,
    GatewaySwitchportStoragePort,
    GatewaySwitchportRecord,
    IspScraperSummary,
)
from aetheris.discovery.isp_gui_scraper import (
    IspGuiScraper,
    GatewaySwitchportLedger,
    parse_device_table_text,
    sync_to_ledger,
)


def test_isp_gui_scraper_port_ast_boundary():
    """Verify isp_gui_scraper_port.py contains zero sqlite3, requests, bs4, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "isp_gui_scraper_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"sqlite3", "requests", "bs4", "socket", "scapy", "subprocess", "redis", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_isp_gui_scraper_protocol_conformance():
    """Verify IspGuiScraper and GatewaySwitchportLedger conform to their respective protocols."""
    scraper = IspGuiScraper()
    assert isinstance(scraper, IspGuiScraperPort)

    ledger = GatewaySwitchportLedger()
    assert isinstance(ledger, GatewaySwitchportStoragePort)


def test_parse_device_table_text_ethernet_and_wlan():
    """Verify extraction of Ethernet switchports and WLAN interfaces from raw gateway text."""
    raw_dump = """
    DHCP Client ThinkPad-T14
    192.168.1.70 1C:CE:51:93:BA:90
    Ethernet Port 1 1000 Mbps Full
    
    DHCP Client Samsung-SmartTV
    192.168.1.65 BC:7E:8B:0D:82:CA
    Wireless Frequency: 5G
    """
    records = parse_device_table_text(raw_dump)
    assert len(records) == 2

    # Ethernet Device
    eth_dev = records[0]
    assert isinstance(eth_dev, GatewaySwitchportRecord)
    assert eth_dev.mac_address == "1c:ce:51:93:ba:90"
    assert eth_dev["mac_address"] == "1c:ce:51:93:ba:90"
    assert eth_dev.connection_type == "Ethernet"
    assert eth_dev.port_id == "Port 1"
    assert eth_dev.link_speed_mbps == 1000
    assert eth_dev.duplex == "Full"
    assert eth_dev["ip_address"] == "192.168.1.70"

    # Wireless Device
    wlan_dev = records[1]
    assert isinstance(wlan_dev, GatewaySwitchportRecord)
    assert wlan_dev.mac_address == "bc:7e:8b:0d:82:ca"
    assert wlan_dev.connection_type == "Wireless"
    assert wlan_dev.frequency == "5G"


def test_models_immutability_and_summary():
    """Verify record immutability and summary aggregation."""
    rec = GatewaySwitchportRecord(
        mac_address="00:11:22:33:44:55",
        hostname="AccessPoint-01",
        connection_type="Ethernet",
        port_id="Port 4"
    )
    assert rec.port_id == "Port 4"
    assert rec["hostname"] == "AccessPoint-01"
    assert "mac_address" in rec

    with pytest.raises(Exception):
        rec.port_id = "Port 1"

    sample_text = """
    192.168.1.10 00:11:22:33:44:55 Ethernet Port 2 1000 Mbps Full
    192.168.1.20 00:AA:BB:CC:DD:EE Wireless Frequency: 2.4G
    """
    summary = IspGuiScraper.summarize(sample_text)
    assert isinstance(summary, IspScraperSummary)
    assert summary.total_records == 2
    assert summary.ethernet_count == 1
    assert summary.wireless_count == 1


def test_sync_to_ledger_sqlite_persistence(tmp_path):
    """Verify persisting switchport records to relational SQLite ledger."""
    db_file = tmp_path / "test_spatial_ledger.db"
    records = [
        GatewaySwitchportRecord(
            mac_address="11:22:33:44:55:66",
            hostname="Core-Gateway",
            ip_address="192.168.1.1",
            connection_type="Ethernet",
            port_id="Port 1",
            link_speed_mbps=1000,
            duplex="Full"
        )
    ]

    sync_to_ledger(records, db_path=db_file)
    assert db_file.exists()

    with sqlite3.connect(str(db_file)) as conn:
        cur = conn.cursor()
        cur.execute("SELECT mac_address, hostname, port_id, link_speed_mbps FROM gateway_switchports")
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "11:22:33:44:55:66"
        assert row[1] == "Core-Gateway"
        assert row[2] == "Port 1"
        assert row[3] == 1000

