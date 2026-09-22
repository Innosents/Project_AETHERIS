"""
Unit Tests for Phase 25 L3 TCP Zero-Window Port, Parser, and Adapter
Validates:
- TcpZeroWindowTelemetryPort schema validation and defaults
- Stateless zero-window inspection and flags filtering
- Mathematical exhaustion matrix thresholding (nominal vs transient vs locked)
- Asynchronous monitoring via TcpZeroWindowAdapter and Memurai event bus delivery
- Backward compatibility facade TCPZeroWindowProbe
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from scapy.all import Ether, IP, TCP

from aetheris.core.ports.l3_window_inbound import TcpZeroWindowTelemetryPort
from aetheris.core.parsers.tcp_window_parser import (
    inspect_tcp_zero_window,
    evaluate_exhaustion_matrix,
)
from aetheris.infrastructure.adapters.tcp_zero_window_adapter import TcpZeroWindowAdapter
from aetheris.core.probers.zero_window_probe import TCPZeroWindowProbe


# =========================================================================
# 1. Telemetry Port Tests
# =========================================================================

def test_tcp_zero_window_port_validation():
    """Validates default values and field invariants of TcpZeroWindowTelemetryPort."""
    port = TcpZeroWindowTelemetryPort(
        target_ip="192.168.1.10",
        status="LOCKED",
        exhaustion_matrix={"192.168.1.10:80->192.168.1.100:54321": {"count": 5}},
    )
    assert port.probe_id == "L3-TCP-ZEROWINDOW-001"
    assert port.target_ip == "192.168.1.10"
    assert port.status == "LOCKED"
    assert port.capture_duration_sec == 45.0
    assert port.event_vector == "OS_TCP_BUFFER_COLLAPSE"
    assert "192.168.1.10:80->192.168.1.100:54321" in port.exhaustion_matrix

    with pytest.raises(ValueError):
        TcpZeroWindowTelemetryPort(target_ip="10.0.0.1", status="LOCKED", capture_duration_sec=-1.0)


# =========================================================================
# 2. Stateless Parser Tests
# =========================================================================

def test_inspect_tcp_zero_window():
    """Validates TCP zero-window detection and SYN/RST transient exclusion."""
    # 1. Nominal ACK frame with non-zero window
    nominal_pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=50000, flags="A", window=64240)
    assert inspect_tcp_zero_window(nominal_pkt) is None

    # 2. Absolute zero-window established ACK frame
    zero_win_pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=50000, flags="A", window=0)
    res = inspect_tcp_zero_window(zero_win_pkt)
    assert res is not None
    flow_key, ts = res
    assert flow_key == "10.0.0.1:80->10.0.0.2:50000"
    assert ts > 0

    # 3. SYN frame with window=0 (transient, must be excluded)
    syn_pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=50000, flags="S", window=0)
    assert inspect_tcp_zero_window(syn_pkt) is None

    # 4. RST frame with window=0 (connection reset, must be excluded)
    rst_pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=50000, flags="RA", window=0)
    assert inspect_tcp_zero_window(rst_pkt) is None


def test_evaluate_exhaustion_matrix():
    """Validates mathematical thresholding of buffer exhaustion states."""
    # 1. Empty matrix -> Nominal
    status, sustained = evaluate_exhaustion_matrix({})
    assert status == "NOMINAL_BUFFER_STATE"
    assert sustained == {}

    # 2. Transient micro-stalls (count <= 3)
    micro_stall_matrix = {
        "10.0.0.1:80->10.0.0.2:50000": {"count": 2, "timestamps": [1.0, 1.1]}
    }
    status, sustained = evaluate_exhaustion_matrix(micro_stall_matrix, threshold=3)
    assert status == "TRANSIENT_MICRO_STALLS_DETECTED"
    assert sustained == {}

    # 3. Sustained exhaustion collapse (> 3)
    sustained_matrix = {
        "10.0.0.1:80->10.0.0.2:50000": {"count": 6, "timestamps": [1.0, 1.1, 1.2, 1.3, 1.4, 1.5]},
        "10.0.0.1:443->10.0.0.3:50001": {"count": 1, "timestamps": [2.0]},
    }
    status, sustained = evaluate_exhaustion_matrix(sustained_matrix, threshold=3)
    assert status == "LOCKED"
    assert len(sustained) == 1
    assert "10.0.0.1:80->10.0.0.2:50000" in sustained


# =========================================================================
# 3. Infrastructure Adapter Tests
# =========================================================================

@pytest.mark.asyncio
async def test_tcp_zero_window_adapter_monitoring_sustained():
    """Validates monitoring loop pushes sustained collapse alerts to Memurai bus."""
    mock_bus = AsyncMock()
    mock_bus.push_telemetry = AsyncMock(return_value=1)

    adapter = TcpZeroWindowAdapter(event_bus=mock_bus, timeout=0.01)

    # Inject 4 zero-window packets on the same flow
    pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=443, dport=49152, flags="A", window=0)
    for _ in range(4):
        adapter._on_packet(pkt)

    with patch("aetheris.infrastructure.adapters.tcp_zero_window_adapter.AsyncSniffer") as mock_sniffer:
        mock_inst = MagicMock()
        mock_sniffer.return_value = mock_inst

        telemetry = await adapter.monitor_target("192.168.1.100", duration=0.01)

    assert telemetry.status == "LOCKED"
    assert "192.168.1.100:443->192.168.1.1:49152" in telemetry.exhaustion_matrix
    assert mock_bus.push_telemetry.call_count == 1
    queue, payload = mock_bus.push_telemetry.call_args[0]
    assert queue == "aetheris:telemetry:os_buffer_collapse"
    assert payload["target_ip"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_tcp_zero_window_adapter_nominal_does_not_publish():
    """Validates nominal buffer status does not generate bus telemetry alerts."""
    mock_bus = AsyncMock()
    adapter = TcpZeroWindowAdapter(event_bus=mock_bus, timeout=0.01)

    with patch("aetheris.infrastructure.adapters.tcp_zero_window_adapter.AsyncSniffer"):
        telemetry = await adapter.monitor_target("10.0.0.5", duration=0.01)

    assert telemetry.status == "NOMINAL_BUFFER_STATE"
    assert mock_bus.push_telemetry.call_count == 0


# =========================================================================
# 4. Backward Compatibility Facade Tests
# =========================================================================

@pytest.mark.asyncio
async def test_tcp_zero_window_probe_compat_facade():
    """Validates legacy TCPZeroWindowProbe context manager and execution API."""
    probe = TCPZeroWindowProbe(target_ip="192.168.1.50", telemetry_context={"capture_duration_sec": 0.01})
    assert probe.target_ip == "192.168.1.50"
    assert probe.probe_id == "L3-TCP-ZEROWINDOW-001"

    # Inject frame via legacy _frame_callback
    pkt = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=80, dport=40000, flags="A", window=0)
    for _ in range(5):
        probe._frame_callback(pkt)

    with patch("aetheris.infrastructure.adapters.tcp_zero_window_adapter.AsyncSniffer"):
        async with probe:
            res = await probe.execute()

    assert res["status"] == "LOCKED"
    assert "exhaustion_matrix" in res
    assert res["event_vector"] == "OS_TCP_BUFFER_COLLAPSE"

    # Verify rollback clears structures
    await probe.rollback()
    assert len(probe.collapse_matrix) == 0

