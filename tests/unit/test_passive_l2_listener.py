"""
Unit test suite for PassiveL2ListenerPort and PassiveL2TopologyListener adapter.
Validates AST boundary isolation, protocol conformance, packet dissection, and schema dual-access.
"""
import ast
import os
from unittest.mock import MagicMock
import pytest
from aetheris.core.ports.passive_l2_listener_port import (
    PassiveL2ListenerPort,
    L2SwitchTelemetryRecord,
    L2ListenerSummary,
)
from aetheris.discovery.passive_l2_listener import PassiveL2TopologyListener


def test_passive_l2_listener_port_ast_boundary():
    """Verify passive_l2_listener_port.py contains zero scapy, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "passive_l2_listener_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"scapy", "socket", "subprocess", "sqlite3", "redis", "urllib", "requests"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_passive_l2_listener_conformance():
    """Verify PassiveL2TopologyListener satisfies PassiveL2ListenerPort protocol."""
    listener = PassiveL2TopologyListener()
    assert isinstance(listener, PassiveL2ListenerPort)


def test_l2_switch_telemetry_model_immutability():
    """Verify L2SwitchTelemetryRecord schema validation and dual mapping lookups."""
    rec = L2SwitchTelemetryRecord(
        protocol="LLDP",
        switch_id="SW-MDF-CORE-01",
        system_name="SW-MDF-CORE-01",
        port_id="GigabitEthernet1/0/24",
        management_ip="192.168.1.2",
        raw_mac="00:11:22:33:44:55"
    )
    assert rec.switch_id == "SW-MDF-CORE-01"
    assert rec["switch_id"] == "SW-MDF-CORE-01"
    assert rec["protocol"] == "LLDP"
    assert rec.management_ip == "192.168.1.2"
    with pytest.raises(Exception):
        rec.switch_id = "SW-02"


def test_parse_lldp_frame_mocked():
    """Verify LLDPDU traversal and parsing logic with mocked Scapy structures."""
    listener = PassiveL2TopologyListener()
    mock_frame = MagicMock()
    mock_frame.haslayer.return_value = False

    chassis_layer = MagicMock()
    chassis_layer.id = b"00:11:22:33:44:00"

    sysname_layer = MagicMock()
    sysname_layer.system_name = b"Dist-Switch-01"

    port_layer = MagicMock()
    port_layer.id = b"TenGigabitEthernet1/1/1"

    mgmt_layer = MagicMock()
    mgmt_layer.management_address = bytes([10, 10, 7, 2])

    chassis_layer.payload = sysname_layer
    sysname_layer.payload = port_layer
    port_layer.payload = mgmt_layer
    mgmt_layer.payload = None

    from scapy.contrib.lldp import LLDPDUChassisID, LLDPDUSystemName, LLDPDUPortID, LLDPDUManagementAddress
    chassis_layer.__class__ = LLDPDUChassisID
    sysname_layer.__class__ = LLDPDUSystemName
    port_layer.__class__ = LLDPDUPortID
    mgmt_layer.__class__ = LLDPDUManagementAddress

    res = listener.parse_lldp_frame(chassis_layer)
    assert res is not None
    assert isinstance(res, (L2SwitchTelemetryRecord, dict))
    assert res["system_name"] == "Dist-Switch-01"
    assert res["port_id"] == "TenGigabitEthernet1/1/1"
    assert res["management_ip"] == "10.10.7.2"
