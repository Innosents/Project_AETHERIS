"""
Unit test suite for IndustrialDiscoveryPort and IndustrialDiscoveryEngine.
Validates AST boundary isolation, protocol conformance, OT handshakes, and schema immutability.
"""
import ast
import os
import pytest
from unittest.mock import patch, MagicMock
from aetheris.core.ports.industrial_discovery_port import (
    IndustrialDiscoveryPort,
    IndustrialProbeResult,
)
from aetheris.discovery.industrial_discovery import IndustrialDiscoveryEngine


def test_industrial_discovery_port_ast_boundary():
    """Verify industrial_discovery_port.py contains zero raw sockets, struct, or transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "industrial_discovery_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"socket", "struct", "select", "scapy", "subprocess", "sqlite3", "redis", "requests", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_industrial_discovery_engine_conformance():
    """Verify IndustrialDiscoveryEngine implements IndustrialDiscoveryPort."""
    engine = IndustrialDiscoveryEngine()
    assert isinstance(engine, IndustrialDiscoveryPort)


def test_probe_siemens_s7_mocked():
    """Verify Siemens S7Comm COTP + SZL 0x0011 handshake dissection."""
    engine = IndustrialDiscoveryEngine(timeout=0.5)

    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock

        # Responses: 1. COTP CC (Connection Confirm), 2. Setup ack, 3. SZL 0x0011 module text
        mock_sock.recv.side_effect = [
            b"\x03\x00\x00\x16\x11\xD0\x00\x01\x00\x00\x00\xC0\x01\x0A\xC1\x02\x01\x00\xC2\x02\x01\x02",
            b"\x03\x00\x00\x19\x02\xF0\x80\x32\x03\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\xF0\x00\x00\x01\x00\x01",
            b"\x03\x00\x00\x30\x02\xF0\x80\x32\x07\x00\x00\x00\x02\x00\x08\x00\x18\x00\x01\x12\x08CPU 1214C SIMATIC S7-1200 6ES7 214-1AG40-0XB0"
        ]

        res = engine.probe_siemens_s7("192.168.1.102", port=102)
        assert isinstance(res, IndustrialProbeResult)
        assert res.vendor == "Siemens"
        assert res.type == "plc"
        assert "1214C" in res.model or "S7-1200" in res.model
        assert res["vendor"] == "Siemens"
        assert "szl_raw" in res


def test_probe_ethernet_ip_cip_mocked():
    """Verify Rockwell Automation EtherNet/IP CIP ListIdentity probe."""
    engine = IndustrialDiscoveryEngine(timeout=0.5)

    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock

        # CIP ListIdentity Response with Micro850 PLC
        mock_sock.recv.return_value = b"\x63\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x0C\x00Micro850 2080-LC50-24QBB Rockwell Automation"

        res = engine.probe_ethernet_ip_cip("192.168.1.200", port=44818)
        assert isinstance(res, IndustrialProbeResult)
        assert res.vendor == "Rockwell Automation"
        assert res.type == "plc"
        assert "Micro850" in res.model
        assert res.get("protocol") == "EtherNet/IP CIP (Port 44818)"


def test_mercury_and_video_probes_mocked():
    """Verify Mercury MSP, RTSP/ONVIF, and Avigilon ACC probes return typed frozen records."""
    engine = IndustrialDiscoveryEngine(timeout=0.5)

    # 1. Mercury MSP
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"\x02\x01\x10ACK MP1502 OK\x03"

        msp_res = engine.probe_mercury_access("192.168.1.50", port=3001)
        assert isinstance(msp_res, IndustrialProbeResult)
        assert msp_res.vendor == "Mercury Security"
        assert msp_res["type"] == "access_control"

    # 2. RTSP / Axis Camera
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: AXIS M3046-V RTSP Server\r\n\r\n"

        rtsp_res = engine.probe_rtsp_onvif("192.168.1.60", port=554)
        assert isinstance(rtsp_res, IndustrialProbeResult)
        assert rtsp_res.vendor == "Axis Communications"
        assert rtsp_res.type == "camera"

    # 3. Avigilon ACC
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"AVIGILON_ACC_PONG\r\n"

        acc_res = engine.probe_avigilon_acc("192.168.1.70", port=38880)
        assert isinstance(acc_res, IndustrialProbeResult)
        assert acc_res.vendor == "Avigilon"
        assert acc_res.type == "nvr"

    # Immutability assertion
    with pytest.raises(Exception):
        msp_res.vendor = "Other"
