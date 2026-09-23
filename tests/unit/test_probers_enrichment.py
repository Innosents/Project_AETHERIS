"""
Unit tests validating Phase 1, Phase 2, and Phase 3 prober remediation:
- SpanCaptureEngine multiplexing and delegation
- Sanitization of NaN, Inf, and dataclasses
- BaseAetherisProbe async context manager lifecycle
- ActiveTTLInterrogator ICMP packet building and checksum
- SpanningTreeTelemetryProbe 802.1t VLAN ID extraction
"""

import dataclasses
import math
import pytest
from scapy.layers.l2 import Ether, STP
from scapy.all import IP, UDP

from aetheris.core.probers.span_engine import SpanCaptureEngine
from aetheris.core.probers.base_probe import BaseAetherisProbe
from aetheris.core.probers.sanitization import sanitize_prober_payload
from aetheris.core.probers.l2_physical.stp_intelligence import SpanningTreeTelemetryProbe
from aetheris.core.probers.l3_network.ttl_interrogator import (
    _icmp_checksum,
    _build_icmp_echo,
    ActiveTTLInterrogator,
)
from aetheris.core.probers.snmp_cam_extractor import ActiveCAMExtractor


@dataclasses.dataclass
class MockDeviceTelemetry:
    device_id: str
    temperature_c: float
    firmware_rev: str


class MockConcreteProbe(BaseAetherisProbe):
    def __init__(self, target_ip="127.0.0.1", telemetry_context=None):
        super().__init__(target_ip, telemetry_context or {})
        self.rolled_back = False

    async def execute(self):
        return {"status": "OK"}

    async def rollback(self):
        self.rolled_back = True
        return True


def test_sanitization_nan_inf_and_dataclass():
    """Validates coercion of NaN and Inf floats to None, and recursive dataclass serialization."""
    payload = {
        "nan_val": float("nan"),
        "inf_val": float("inf"),
        "neg_inf_val": float("-inf"),
        "normal_val": 42.5,
        "nested": MockDeviceTelemetry(device_id="PLC-01", temperature_c=float("nan"), firmware_rev="v2.1"),
    }
    sanitized = sanitize_prober_payload(payload)
    assert sanitized["nan_val"] is None
    assert sanitized["inf_val"] is None
    assert sanitized["neg_inf_val"] is None
    assert sanitized["normal_val"] == 42.5
    assert sanitized["nested"]["device_id"] == "PLC-01"
    assert sanitized["nested"]["temperature_c"] is None
    assert sanitized["nested"]["firmware_rev"] == "v2.1"


@pytest.mark.asyncio
async def test_base_probe_async_context_manager():
    """Validates that BaseAetherisProbe.__aexit__ automatically calls rollback()."""
    probe = MockConcreteProbe()
    assert probe.rolled_back is False
    async with probe as p:
        res = await p.execute()
        assert res["status"] == "OK"
    assert probe.rolled_back is True


def test_span_capture_engine_registry_and_dispatch():
    """Validates SpanCaptureEngine subscription registry and delegate routing."""
    engine = SpanCaptureEngine(interface="eth0")

    stp_frames = []
    chassis_frames = []
    multicast_frames = []

    engine.register_delegate("stp_intelligence", lambda pkt: stp_frames.append(pkt))
    engine.register_delegate("chassis_intelligence", lambda pkt: chassis_frames.append(pkt))
    engine.register_delegate("multicast_identity", lambda pkt: multicast_frames.append(pkt))

    # Construct mock frames
    # 1. STP Frame
    stp_pkt = Ether(dst="01:80:c2:00:00:00") / STP()
    engine._unified_packet_loop(stp_pkt)
    assert len(stp_frames) == 1
    assert len(chassis_frames) == 0

    # 2. LLDP Frame
    lldp_pkt = Ether(dst="01:80:c2:00:00:0e")
    engine._unified_packet_loop(lldp_pkt)
    assert len(chassis_frames) == 1

    # 3. Multicast NetBIOS Frame
    netbios_pkt = Ether() / IP(dst="255.255.255.255") / UDP(sport=137, dport=137)
    engine._unified_packet_loop(netbios_pkt)
    assert len(multicast_frames) == 1

    assert engine.stats["stp_frames"] == 1
    assert engine.stats["chassis_frames"] == 1
    assert engine.stats["multicast_frames"] == 1
    assert engine.stats["total_frames"] == 3


def test_stp_vlan_id_extraction():
    """Validates 802.1t / PVST+ VLAN ID extraction from bridge priority."""
    probe = SpanningTreeTelemetryProbe()

    # Priority 32768 + VLAN 100 = 32868 (0x8064)
    # Low 12 bits: 0x064 = 100
    pkt = Ether(src="00:11:22:33:44:55", dst="01:80:c2:00:00:00") / STP(
        rootid=0x8064,
        bridgeid=0x8064001122334455,
        pathcost=10,
    )
    # Explicitly set bridgeprio on the layer
    pkt[STP].bridgeprio = 0x8064

    probe._stp_callback(pkt)
    result = probe.results.get("00:11:22:33:44:55")
    assert result is not None
    assert result["bridge_priority"] == 0x8064
    assert result["vlan_id"] == 100


def test_ttl_interrogator_checksum_and_packet():
    """Validates ICMP checksum calculation and Echo packet building."""
    seq = 42
    pid = 12345
    packet = _build_icmp_echo(pid, seq)
    assert len(packet) == 8 + 32  # 8 bytes ICMP header + 32 bytes payload
    assert packet[0] == 8  # Echo Request
    assert packet[1] == 0  # Code 0

    # Verify checksum validation
    chksum = _icmp_checksum(packet)
    assert chksum == 0  # RFC 1071 valid checksum evaluates to 0 over packet


@pytest.mark.asyncio
async def test_snmp_cam_extractor_context_manager():
    """Validates ActiveCAMExtractor async context manager and close() method."""
    async with ActiveCAMExtractor("127.0.0.1", telemetry_context={"snmp_communities": ["public"]}) as ext:
        assert ext.target_ip == "127.0.0.1"
        assert hasattr(ext, "close")


def test_multicast_identity_probe_parsing():
    """Validates mDNS service pointers and SSDP Server/User-Agent extraction."""
    import re
    from unittest.mock import MagicMock
    from scapy.all import Ether, IP, UDP, DNS, DNSRR, Raw
    from aetheris.core.probers.l3_network.multicast_identity import MulticastIdentityProbe

    probe = MulticastIdentityProbe()
    # 1. mDNS test frame
    mdns_pkt = (
        Ether(src="00:11:22:33:44:55")
        / IP()
        / UDP(sport=5353, dport=5353)
        / DNS(an=DNSRR(type=12, rrname=b"_airplay._tcp.local.", rdata=b"AppleTV._airplay._tcp.local."))
    )
    probe._multicast_callback(mdns_pkt)

    # 2. SSDP test frame
    ssdp_pkt = (
        Ether(src="00:11:22:33:44:55")
        / IP()
        / UDP(sport=1900, dport=1900)
        / Raw(load=b"HTTP/1.1 200 OK\r\nSERVER: Linux/4.14 UPnP/1.0 Sonos/56.0-68190\r\n\r\n")
    )
    probe._multicast_callback(ssdp_pkt)

    matrix = probe.identity_matrix
    assert "00:11:22:33:44:55" in matrix
    assert "_airplay._tcp.local." in matrix["00:11:22:33:44:55"]["mdns_services"]
    assert "AppleTV._airplay._tcp.local." in matrix["00:11:22:33:44:55"]["mdns_services"]
    assert "Linux/4.14 UPnP/1.0 Sonos/56.0-68190" in matrix["00:11:22:33:44:55"]["ssdp_headers"]


@pytest.mark.asyncio
async def test_fused_spatial_orchestrator():
    """Validates _execute_l2_multiplexer and execute_fused_spatial_sweep."""
    import json
    from unittest.mock import patch, MagicMock
    from aetheris.core.orchestrator import _execute_l2_multiplexer, execute_fused_spatial_sweep

    with patch("aetheris.core.probers.span_engine.AsyncSniffer") as mock_sniffer, \
         patch("aetheris.core.probers.l3_network.ttl_interrogator.ActiveTTLInterrogator.execute") as mock_ttl:
        mock_sniffer.return_value = MagicMock()
        mock_ttl.return_value = {"ttl_matrix": {"10.0.0.1": 1}}

        # Multiplexer test
        l2_res = await _execute_l2_multiplexer("eth0", 0.01)
        assert "chassis_intelligence" in l2_res
        assert "spanning_tree_intelligence" in l2_res
        assert "multicast_identity" in l2_res
        assert json.loads(json.dumps(l2_res)) is not None

        # Sweep test
        sweep = await execute_fused_spatial_sweep("10.0.0.0/30", "eth0", duration=0.01)
        assert sweep["orchestration_state"] == "SPATIAL_FUSION_COMPLETE"
        assert sweep["target_subnet"] == "10.0.0.0/30"
        assert sweep["l3_hop_intelligence"] == {"10.0.0.1": 1}
        assert set(sweep.keys()) == {
            "orchestration_state",
            "target_subnet",
            "chassis_intelligence",
            "spanning_tree_intelligence",
            "multicast_identity",
            "l3_hop_intelligence",
            "topological_memory",
        }
        assert json.loads(json.dumps(sweep)) == sweep



