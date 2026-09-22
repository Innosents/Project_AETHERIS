"""
Unit Tests for Phase 23 L2 SPAN Port Definition, Parser, and SpanTapAdapter
Validates:
- SpanCaptureTelemetryPort schema validation and defaults
- Stateless ERSPAN II/III decapsulation and multicast constant tables
- Promiscuous packet capture demultiplexing across STP, Chassis, and Multicast delegates
- Zero-lock subscriber dispatch and graceful unregistering
- Asynchronous context manager and telemetry snapshot generation
"""

import asyncio
from unittest.mock import MagicMock, patch
import pytest

from scapy.all import Ether, IP, UDP
from scapy.contrib.cdp import CDPv2_HDR
from scapy.contrib.lldp import LLDPDU
from scapy.contrib.erspan import ERSPAN_II, ERSPAN_III
from scapy.layers.l2 import GRE, STP

from aetheris.core.ports.l2_span_inbound import SpanCaptureTelemetryPort
from aetheris.core.parsers.span_parser import (
    decapsulate_erspan,
    MAC_STP,
    MAC_LLDP,
    MAC_CDP,
    MULTICAST_UDP_PORTS,
)
from aetheris.infrastructure.adapters.span_tap_adapter import SpanTapAdapter, SpanCaptureEngine


# =========================================================================
# 1. Telemetry Port Tests
# =========================================================================

def test_span_capture_telemetry_port_defaults():
    """Validates default values and field constraints of SpanCaptureTelemetryPort."""
    port = SpanCaptureTelemetryPort(interface="eth0")
    assert port.interface == "eth0"
    assert port.status == "STOPPED"
    assert port.total_frames == 0
    assert port.chassis_frames == 0
    assert port.stp_frames == 0
    assert port.multicast_frames == 0
    assert port.unhandled_frames == 0


def test_span_capture_telemetry_port_validation():
    """Validates non-negative constraints on frame counts."""
    port = SpanCaptureTelemetryPort(
        interface="tap0",
        status="RUNNING",
        total_frames=100,
        chassis_frames=20,
        stp_frames=15,
        multicast_frames=60,
        unhandled_frames=5,
    )
    assert port.total_frames == 100
    with pytest.raises(ValueError):
        SpanCaptureTelemetryPort(interface="tap0", total_frames=-1)


# =========================================================================
# 2. Stateless Protocol Parser Tests
# =========================================================================

def test_span_parser_constants():
    """Validates well-known L2 multicast MACs and UDP discovery ports."""
    assert MAC_STP == "01:80:c2:00:00:00"
    assert MAC_LLDP == "01:80:c2:00:00:0e"
    assert MAC_CDP == "01:00:0c:cc:cc:cc"
    assert {67, 68, 137, 138, 1900, 3702, 5353, 5355}.issubset(MULTICAST_UDP_PORTS)


def test_decapsulate_erspan_variants():
    """Validates ERSPAN II, ERSPAN III, and plain GRE inner Ethernet payload extraction."""
    inner_eth = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")

    # Plain non-encapsulated packet -> returns None
    assert decapsulate_erspan(inner_eth) is None

    # GRE encapsulated packet
    gre_pkt = IP() / GRE() / inner_eth
    assert decapsulate_erspan(gre_pkt) == inner_eth

    # ERSPAN II encapsulated packet
    erspan2_pkt = IP() / GRE() / ERSPAN_II() / inner_eth
    assert decapsulate_erspan(erspan2_pkt) == inner_eth

    # ERSPAN III encapsulated packet
    erspan3_pkt = IP() / GRE() / ERSPAN_III() / inner_eth
    assert decapsulate_erspan(erspan3_pkt) == inner_eth


# =========================================================================
# 3. SpanTapAdapter Demultiplexing & Ingestion Tests
# =========================================================================

def test_span_tap_adapter_delegate_registration():
    """Validates delegate registration, execution, and unregistration."""
    adapter = SpanTapAdapter(interface="eth0")
    received = []

    callback = lambda pkt: received.append(pkt)
    adapter.register_delegate("raw", callback)
    assert callback in adapter._subscribers["raw"]

    pkt = Ether()
    adapter._packet_callback(pkt)
    assert len(received) == 1

    assert adapter.unregister_delegate("raw", callback) is True
    assert adapter.unregister_delegate("raw", callback) is False

    adapter._packet_callback(pkt)
    assert len(received) == 1  # Not called after unregistering


def test_span_tap_adapter_protocol_demux():
    """Validates frame classification across STP, Chassis, Multicast, and Unhandled."""
    adapter = SpanTapAdapter(interface="eth1")

    stp_received = []
    chassis_received = []
    multicast_received = []

    adapter.register_delegate("stp_intelligence", lambda pkt: stp_received.append(pkt))
    adapter.register_delegate("chassis_intelligence", lambda pkt: chassis_received.append(pkt))
    adapter.register_delegate("multicast_identity", lambda pkt: multicast_received.append(pkt))

    # 1. STP Frame
    stp_pkt = Ether(dst=MAC_STP) / STP()
    adapter._packet_callback(stp_pkt)
    assert len(stp_received) == 1

    # 2. LLDP Frame
    lldp_pkt = Ether(dst=MAC_LLDP) / LLDPDU()
    adapter._packet_callback(lldp_pkt)
    assert len(chassis_received) == 1

    # 3. CDP Frame
    cdp_pkt = Ether(dst=MAC_CDP) / CDPv2_HDR()
    adapter._packet_callback(cdp_pkt)
    assert len(chassis_received) == 2

    # 4. Multicast UDP (mDNS)
    mdns_pkt = Ether() / IP() / UDP(sport=5353, dport=5353)
    adapter._packet_callback(mdns_pkt)
    assert len(multicast_received) == 1

    # 5. Unhandled Frame (plain TCP)
    tcp_pkt = Ether() / IP()
    adapter._packet_callback(tcp_pkt)

    # Check stats
    telemetry = adapter.get_telemetry()
    assert telemetry.interface == "eth1"
    assert telemetry.status == "STOPPED"
    assert telemetry.total_frames == 5
    assert telemetry.stp_frames == 1
    assert telemetry.chassis_frames == 2
    assert telemetry.multicast_frames == 1
    assert telemetry.unhandled_frames == 1


def test_span_tap_adapter_erspan_demux():
    """Validates inner frame dispatching when frame is encapsulated in ERSPAN III."""
    adapter = SpanTapAdapter(interface="eth0")
    stp_received = []
    adapter.register_delegate("stp_intelligence", lambda pkt: stp_received.append(pkt))

    inner_stp = Ether(dst=MAC_STP) / STP()
    outer_erspan = IP() / GRE() / ERSPAN_III() / inner_stp

    adapter._packet_callback(outer_erspan)
    assert len(stp_received) == 1
    assert adapter.stats["stp_frames"] == 1


@pytest.mark.asyncio
async def test_span_tap_adapter_async_lifecycle():
    """Validates start, stop, and async context manager with sniffer mock."""
    with patch("aetheris.infrastructure.adapters.span_tap_adapter.AsyncSniffer") as mock_sniffer:
        mock_instance = MagicMock()
        mock_sniffer.return_value = mock_instance

        async with SpanTapAdapter(interface="eth0") as adapter:
            assert adapter._is_running is True
            mock_instance.start.assert_called_once()
            telemetry = adapter.get_telemetry()
            assert telemetry.status == "RUNNING"

        mock_instance.stop.assert_called_once()
        assert adapter._is_running is False
        assert adapter.get_telemetry().status == "STOPPED"

