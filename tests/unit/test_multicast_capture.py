"""
Unit tests validating Phase 12 Hexagonal Architecture Refactoring:
- MulticastTelemetryPort inbound schema validation
- MulticastCaptureAdapter wire packet parsing and Memurai telemetry dispatch
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from scapy.all import Ether, IP, UDP, DNS, DNSRR, Raw

from aetheris.core.ports.l2_multicast_inbound import MulticastTelemetryPort
from aetheris.infrastructure.adapters.multicast_capture import MulticastCaptureAdapter


def test_multicast_telemetry_port_contract():
    """Validates structural constraints and sanitization on MulticastTelemetryPort."""
    # 1. Valid mDNS payload
    port_mdns = MulticastTelemetryPort(
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.100",
        protocol="mdns",
        discovered_services=["_airplay._tcp.local.", "AppleTV._airplay._tcp.local."],
        hostname="AppleTV.local",
    )
    assert port_mdns.mac_address == "00:11:22:33:44:55"
    assert port_mdns.protocol == "MDNS"
    assert len(port_mdns.discovered_services) == 2
    assert port_mdns.hostname == "AppleTV.local"
    assert port_mdns.server_header is None

    # 2. Valid SSDP payload with hyphens in MAC
    port_ssdp = MulticastTelemetryPort(
        mac_address="AA-BB-CC-DD-EE-FF",
        ip_address="192.168.1.101",
        protocol="ssdp",
        discovered_services=["urn:schemas-upnp-org:device:ZonePlayer:1"],
        server_header="Linux/4.14 UPnP/1.0 Sonos/56.0-68190",
    )
    assert port_ssdp.mac_address == "aa-bb-cc-dd-ee-ff"
    assert port_ssdp.protocol == "SSDP"
    assert port_ssdp.server_header == "Linux/4.14 UPnP/1.0 Sonos/56.0-68190"

    # 3. Invalid MAC format
    with pytest.raises(ValueError, match="Malformed MAC address format"):
        MulticastTelemetryPort(
            mac_address="invalid-mac-str",
            ip_address="192.168.1.102",
            protocol="MDNS",
        )

    # 4. Invalid protocol
    with pytest.raises(ValueError, match="Protocol must be mDNS or SSDP"):
        MulticastTelemetryPort(
            mac_address="00:11:22:33:44:55",
            ip_address="192.168.1.103",
            protocol="DNS",
        )


@pytest.mark.asyncio
async def test_multicast_capture_adapter_ingestion():
    """Validates frame parsing and non-blocking telemetry push to Memurai queue."""
    mock_bus = MagicMock()
    mock_bus.push_telemetry = AsyncMock()

    loop = asyncio.get_running_loop()
    adapter = MulticastCaptureAdapter(interface="eth0", event_bus=mock_bus, loop=loop)

    # 1. Simulate mDNS DNS Answer Packet
    mdns_pkt = (
        Ether(src="00:11:22:33:44:55")
        / IP(src="192.168.1.50")
        / UDP(sport=5353, dport=5353)
        / DNS(an=DNSRR(type=12, rrname=b"_airplay._tcp.local.", rdata=b"AppleTV._airplay._tcp.local."))
    )
    adapter._packet_callback(mdns_pkt)

    # 2. Simulate SSDP HTTP Notify Packet
    ssdp_raw = (
        b"NOTIFY * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"SERVER: Linux/4.14 UPnP/1.0 Sonos/56.0-68190\r\n"
        b"NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\n"
        b"USN: uuid:RINCON_00112233445501400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n"
    )
    ssdp_pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff")
        / IP(src="192.168.1.60")
        / UDP(sport=1900, dport=1900)
        / Raw(load=ssdp_raw)
    )
    adapter._packet_callback(ssdp_pkt)

    # Yield to let scheduled coroutines complete
    await asyncio.sleep(0.05)

    assert mock_bus.push_telemetry.call_count == 2
    calls = mock_bus.push_telemetry.call_args_list

    # Assert mDNS queue payload
    q1, payload1 = calls[0][0]
    assert q1 == "aetheris:telemetry:multicast_intel"
    assert payload1["mac_address"] == "00:11:22:33:44:55"
    assert payload1["ip_address"] == "192.168.1.50"
    assert payload1["protocol"] == "MDNS"
    assert "_airplay._tcp.local." in payload1["discovered_services"]
    assert "AppleTV._airplay._tcp.local." in payload1["discovered_services"]

    # Assert SSDP queue payload
    q2, payload2 = calls[1][0]
    assert q2 == "aetheris:telemetry:multicast_intel"
    assert payload2["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert payload2["ip_address"] == "192.168.1.60"
    assert payload2["protocol"] == "SSDP"
    assert payload2["server_header"] == "Linux/4.14 UPnP/1.0 Sonos/56.0-68190"
    assert any("urn:schemas-upnp-org:device:ZonePlayer:1" in s for s in payload2["discovered_services"])


def test_multicast_capture_adapter_lifecycle():
    """Validates start, stop, and context manager lifecycle hooks."""
    mock_bus = MagicMock()
    adapter = MulticastCaptureAdapter(interface="eth0", event_bus=mock_bus)

    assert adapter.sniffer is None
    # Context manager invocation
    with adapter as a:
        assert a.sniffer is not None
    assert adapter.sniffer is None

