"""
Unit tests validating Phase 13 Hexagonal Architecture Refactoring:
- TcpSkewTelemetryPort inbound contract constraints and serialization
- TcpSkewCaptureAdapter sliding-window saturation, top-5% buffer bloat filtering, and NAT boundary detection
- TCPClockSkewProbe compatibility facade resolution
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from scapy.all import Ether, IP, TCP

from aetheris.core.ports.l3_tcp_skew_inbound import TcpSkewTelemetryPort
from aetheris.infrastructure.adapters.tcp_skew_adapter import TcpSkewCaptureAdapter


def test_tcp_skew_telemetry_port_contract():
    """Validates schema defaults, constraints, and serialization of TcpSkewTelemetryPort."""
    port = TcpSkewTelemetryPort(
        target_ip="192.168.1.50",
        active_ephemeral_flows=3,
        clock_spread_ticks=1500000,
        detected_kernel_frequencies_hz=[100.0, 250.0],
        hidden_nat_detected=True,
    )
    assert port.target_ip == "192.168.1.50"
    assert port.active_ephemeral_flows == 3
    assert port.clock_spread_ticks == 1500000
    assert port.detected_kernel_frequencies_hz == [100.0, 250.0]
    assert port.hidden_nat_detected is True

    # Test defaults
    port_default = TcpSkewTelemetryPort(target_ip="10.0.0.1")
    assert port_default.active_ephemeral_flows == 0
    assert port_default.clock_spread_ticks == 0
    assert port_default.detected_kernel_frequencies_hz == []
    assert port_default.hidden_nat_detected is False


@pytest.mark.asyncio
async def test_tcp_skew_capture_adapter_saturation_and_dispatch():
    """Validates sliding-window saturation, buffer bloat outlier trimming, and telemetry dispatch."""
    mock_bus = MagicMock()
    mock_bus.push_telemetry = AsyncMock()

    loop = asyncio.get_running_loop()
    # Use window of 10 samples for deterministic test triggering
    adapter = TcpSkewCaptureAdapter(
        interface="eth0",
        event_bus=mock_bus,
        capture_window_samples=10,
        loop=loop,
    )

    src_ip = "192.168.1.100"
    # Inject 10 packets for sport 40001 (TSval incrementing at 1000 Hz: 10 ticks per 10ms)
    base_ts = 100000
    for i in range(10):
        # Introduce a single massive outlier (simulating SPAN buffer bloat)
        ts_increment = 5000 if i == 9 else i * 10
        pkt = (
            IP(src=src_ip, dst="192.168.1.1")
            / TCP(
                sport=40001,
                dport=80,
                options=[("Timestamp", (base_ts + ts_increment, 0))],
            )
        )
        adapter._process_packet(pkt)

    await asyncio.sleep(0.05)

    # Assert telemetry dispatch to aetheris:telemetry:tcp_skew_intel
    assert mock_bus.push_telemetry.call_count == 1
    queue, payload = mock_bus.push_telemetry.call_args[0]
    assert queue == "aetheris:telemetry:tcp_skew_intel"
    assert payload["target_ip"] == src_ip
    assert payload["active_ephemeral_flows"] == 1
    assert len(payload["detected_kernel_frequencies_hz"]) == 1

    # Verify evaluated flow was evicted to prevent memory leaks
    assert 40001 not in adapter.flow_matrix[src_ip]


def test_tcp_skew_adapter_lifecycle():
    """Validates start, stop, and context manager lifecycle hooks."""
    mock_bus = MagicMock()
    adapter = TcpSkewCaptureAdapter(interface="eth0", event_bus=mock_bus)

    assert adapter.sniffer is None
    with adapter as a:
        assert a.sniffer is not None
    assert adapter.sniffer is None


def test_tcp_clock_skew_probe_compatibility_facade():
    """Validates that TCPClockSkewProbe import and compatibility facade resolve cleanly."""
    from aetheris.core.probers.l3_network.tcp_skew_probe import TCPClockSkewProbe as Probe1
    from aetheris.core.probers.tcp_clock_skew_probe import TCPClockSkewProbe as Probe2

    probe1 = Probe1(target_ip="192.168.1.50")
    probe2 = Probe2(target_ip="192.168.1.50")
    assert probe1.probe_id == "L3-TCP-SKEW-NAT-001"
    assert probe2.probe_id == "L3-TCP-SKEW-NAT-001"

    # Test callback on probe
    pkt = (
        IP(src="192.168.1.50", dst="192.168.1.1")
        / TCP(
            sport=50001,
            dport=443,
            options=[("Timestamp", (1234567, 0))],
        )
    )
    probe1._frame_callback(pkt)
    assert 50001 in probe1.flow_matrix
    assert len(probe1.flow_matrix[50001]) == 1
    assert probe1.flow_matrix[50001][0][1] == 1234567

