"""
Unit test suite for HwotSimulatorPort and hwot adapter.
Validates AST boundary isolation, protocol conformance, mock simulation flows, and schema dual-access.
"""
import ast
import os
import pytest
from aetheris.core.ports.hwot_port import (
    HwotSimulatorPort,
    HwotServerStatus,
    HwotTerminationResult,
)
from aetheris.mcp.hwot import (
    HwotSimulatorEngine,
    hwot_spawn_cip_plc,
    hwot_spawn_s7_plc,
    hwot_kill_all,
    ACTIVE_SERVERS,
)


def test_hwot_port_ast_boundary():
    """Verify hwot_port.py contains zero socket, struct, mcp, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "hwot_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "struct", "mcp", "fastapi", "uvicorn", "scapy", "subprocess", "sqlite3"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_hwot_protocol_conformance():
    """Verify HwotSimulatorEngine conforms to HwotSimulatorPort protocol."""
    engine = HwotSimulatorEngine()
    assert isinstance(engine, HwotSimulatorPort)


def test_hwot_server_status_immutability():
    """Verify HwotServerStatus schema validation, immutability, and dual mapping."""
    status = HwotServerStatus(
        status="RUNNING",
        protocol="CIP",
        port=44818,
        emulated_device="Allen-Bradley 1769-L33ER"
    )
    assert status.status == "RUNNING"
    assert status["status"] == "RUNNING"
    assert status["protocol"] == "CIP"
    assert status.port == 44818
    with pytest.raises(Exception):
        status.port = 8080


def test_hwot_lifecycle_execution():
    """Verify spawning and terminating ephemeral loopback servers."""
    try:
        res_cip = hwot_spawn_cip_plc(port=54818)
        assert res_cip["status"] in ("RUNNING", "ALREADY_RUNNING")
        assert res_cip["port"] == 54818

        res_s7 = hwot_spawn_s7_plc(port=20102)
        assert res_s7["status"] in ("RUNNING", "ALREADY_RUNNING")
        assert res_s7["port"] == 20102
    finally:
        kill_res = hwot_kill_all()
        assert isinstance(kill_res["terminated_ports"], list)
        assert 54818 in kill_res["terminated_ports"] or len(ACTIVE_SERVERS) == 0
