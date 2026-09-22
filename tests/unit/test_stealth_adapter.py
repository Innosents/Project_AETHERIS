"""
Unit Tests for Phase 24 L3 Stealth Telemetry Port, Parser, and StealthAdapter
Validates:
- StealthTelemetryPort schema invariants and validation
- Stateless packet crafting (WS-Discovery probe, LLMNR query)
- Stateless response parsing (NetBIOS, WS-Discovery, LLMNR)
- Asynchronous multi-variance probing via StealthAdapter and asyncio.gather
- Memurai bus push to 'aetheris:telemetry:stealth_identity'
"""

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from aetheris.core.ports.l3_stealth_inbound import StealthTelemetryPort
from aetheris.core.parsers.stealth_parser import (
    NETBIOS_NBSTAT_QUERY,
    build_wsd_probe,
    build_llmnr_query,
    parse_netbios_response,
    parse_wsd_response,
    parse_llmnr_response,
)
from aetheris.infrastructure.adapters.stealth_adapter import StealthAdapter


# =========================================================================
# 1. Telemetry Port Tests
# =========================================================================

def test_stealth_telemetry_port_validation():
    """Validates default values and non-negative constraints on StealthTelemetryPort."""
    port = StealthTelemetryPort(
        ip="192.168.1.50",
        hostname="DESKTOP-TEST",
        kernel_turnaround_us=125.5,
        latency_ms=0.125,
    )
    assert port.ip == "192.168.1.50"
    assert port.hostname == "DESKTOP-TEST"
    assert port.vendor == "generic"
    assert port.type == "workstation"
    assert port.is_active is True
    assert port.kernel_turnaround_us == 125.5

    with pytest.raises(ValueError):
        StealthTelemetryPort(ip="192.168.1.50", kernel_turnaround_us=-1.0, latency_ms=0.0)

    with pytest.raises(ValueError):
        StealthTelemetryPort(ip="192.168.1.50", kernel_turnaround_us=10.0, latency_ms=-0.5)


# =========================================================================
# 2. Stateless Packet Crafting & Parsing Tests
# =========================================================================

def test_stealth_parser_packet_crafting():
    """Validates WS-Discovery and LLMNR query generation."""
    assert len(NETBIOS_NBSTAT_QUERY) == 50

    wsd_bytes, msg_id = build_wsd_probe()
    assert b"soap:Envelope" in wsd_bytes
    assert b"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe" in wsd_bytes
    assert msg_id.encode("utf-8") in wsd_bytes

    llmnr_bytes = build_llmnr_query("192.168.1.100")
    assert b"in-addr" in llmnr_bytes
    assert b"arpa" in llmnr_bytes
    assert len(llmnr_bytes) > 20


def test_parse_netbios_response():
    """Validates parsing of synthetic NetBIOS NBSTAT node status frame."""
    # 56 bytes header
    header = b"\x80\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"  # 12 bytes
    header += b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"      # 34 bytes
    header += b"\x00\x21\x00\x01\x00\x00\x00\x00\x00\x00"      # 10 bytes = 56 bytes
    num_names = b"\x02"

    # Name 1: "WORKSTATION-01 " (0x00, Unique workstation)
    n1 = b"WORKSTATION-01 \x00\x04\x00"  # 15 bytes name + 1 byte suffix + 2 bytes flags
    # Name 2: "WORKGROUP      " (0x00, Group)
    n2 = b"WORKGROUP      \x00\x84\x00"  # 15 bytes name + 1 byte suffix + 2 bytes flags (0x8000 = group)
    mac = b"\x00\x11\x22\x33\x44\x55"

    raw_data = header + num_names + n1 + n2 + mac

    parsed = parse_netbios_response(raw_data)
    assert parsed["hostname"] == "WORKSTATION-01"
    assert parsed["computer_name"] == "WORKSTATION-01"
    assert parsed["workgroup"] == "WORKGROUP"
    assert parsed["mac"] == "00:11:22:33:44:55"
    assert parsed["type"] == "workstation"
    assert parsed["vendor"] == "Microsoft Corporation"


def test_parse_wsd_response():
    """Validates parsing of synthetic WS-Discovery ProbeMatches SOAP XML response."""
    xml_data = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        "<soap:Body>"
        "<wsd:ProbeMatches>"
        "<wsd:ProbeMatch>"
        "<wsa:EndpointReference>urn:uuid:12345678-1234-1234-1234-123456789abc</wsa:EndpointReference>"
        "<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>"
        "<wsd:Manufacturer>Axis Communications</wsd:Manufacturer>"
        "<wsd:ModelName>AXIS M3045-V</wsd:ModelName>"
        "<wsd:FriendlyName>Axis Lobby Camera</wsd:FriendlyName>"
        "</wsd:ProbeMatch>"
        "</wsd:ProbeMatches>"
        "</soap:Body>"
        "</soap:Envelope>"
    ).encode("utf-8")

    parsed = parse_wsd_response(xml_data)
    assert parsed["vendor"] == "Axis Communications"
    assert parsed["model"] == "IP Surveillance Camera"
    assert parsed["friendly_name"] == "Axis Lobby Camera"
    assert parsed["endpoint_uuid"] == "12345678-1234-1234-1234-123456789abc"
    assert parsed["type"] == "camera"


def test_parse_llmnr_response():
    """Validates parsing of synthetic LLMNR DNS response answer section."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 1, 0, 0)
    qname = b"\x011\x011\x011\x011\x07in-addr\x04arpa\x00"
    question = qname + struct.pack(">HH", 12, 1)

    rdata = b"\x08DESKTOP1\x05local\x00"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata

    parsed = parse_llmnr_response(header + question + answer)
    assert parsed["hostname"] == "DESKTOP1"


# =========================================================================
# 3. StealthAdapter Ingestion & Event Bus Tests
# =========================================================================

@pytest.mark.asyncio
async def test_stealth_adapter_probe_endpoint_success():
    """Validates concurrent probe execution and aggregation into StealthTelemetryPort."""
    adapter = StealthAdapter(timeout=0.2)

    fake_nb_data = (
        b"\x80\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x01"
        b"LAPTOP-CORP-01 \x00\x04\x00"
        b"\x00\xAA\xBB\xCC\xDD\xEE"
    )

    def mock_transceive(ip, port, payload, timeout):
        if port == 137:
            return fake_nb_data, 180.0
        return b"", 0.0

    with patch.object(adapter, "_udp_transceive", side_effect=mock_transceive):
        telemetry = await adapter.probe_endpoint("192.168.1.10")

    assert telemetry is not None
    assert telemetry.ip == "192.168.1.10"
    assert telemetry.hostname == "LAPTOP-CORP-01"
    assert telemetry.type == "laptop"
    assert telemetry.mac == "00:AA:BB:CC:DD:EE"
    assert telemetry.kernel_turnaround_us == 180.0
    assert "netbios" in telemetry.probes


@pytest.mark.asyncio
async def test_stealth_adapter_process_target_publishes_to_bus():
    """Validates that process_target pushes validated telemetry to Memurai bus."""
    mock_bus = AsyncMock()
    mock_bus.push_telemetry = AsyncMock(return_value=1)

    adapter = StealthAdapter(event_bus=mock_bus, timeout=0.2)

    mock_port = StealthTelemetryPort(
        ip="10.0.0.99",
        hostname="SEC-PRINTER",
        vendor="HP",
        type="printer",
        kernel_turnaround_us=250.0,
        latency_ms=0.25,
    )

    with patch.object(adapter, "probe_endpoint", new=AsyncMock(return_value=mock_port)):
        res = await adapter.process_target("10.0.0.99")

    assert res == mock_port
    assert mock_bus.push_telemetry.call_count == 1
    call_args = mock_bus.push_telemetry.call_args[0]
    assert call_args[0] == "aetheris:telemetry:stealth_identity"
    assert call_args[1]["ip"] == "10.0.0.99"
    assert call_args[1]["type"] == "printer"


@pytest.mark.asyncio
async def test_stealth_adapter_unresponsive_target():
    """Validates that unresponsive endpoints return None."""
    adapter = StealthAdapter(timeout=0.1)

    with patch.object(adapter, "_udp_transceive", return_value=(b"", 0.0)):
        res = await adapter.probe_endpoint("192.0.2.1")
        assert res is None
