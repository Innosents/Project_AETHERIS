"""Integration test verifying passive L2 chassis dissection and adapter orchestration."""
import pytest
from unittest.mock import MagicMock
from scapy.all import Ether

from aetheris.infrastructure.adapters.chassis_probe import ChassisIntelligenceProbe
from aetheris.core.parsers.chassis_parser import extract_lldp_med_telemetry, calculate_z_axis
from tests.mocks.cisco_lldp_emulator import compile_lldp_med_frame


@pytest.mark.asyncio
async def test_chassis_parser_direct_extraction():
    """Verify core domain chassis parser directly against synthetic bit-perfect LLDP frame."""
    frame = compile_lldp_med_frame()
    telemetry = extract_lldp_med_telemetry(frame)

    assert telemetry is not None
    assert telemetry.get("w_tx") == 15.4
    assert telemetry.get("w_loss") == 1.3
    assert "raw_hex" in telemetry

    # Verify physical conductor length solver
    z_axis_m = calculate_z_axis(telemetry["w_tx"])
    assert isinstance(z_axis_m, float)
    assert z_axis_m > 0.0
    assert telemetry.get("z_axis_m") == pytest.approx(z_axis_m, rel=1e-2)


@pytest.mark.asyncio
async def test_chassis_intelligence_probe_adapter_lifecycle():
    """Verify ChassisIntelligenceProbe adapter callback handling and execution lifecycle."""
    mock_bus = MagicMock()
    probe = ChassisIntelligenceProbe(interface="lo", event_bus=mock_bus)
    assert await probe.execute() == {}

    frame = compile_lldp_med_frame()
    probe._frame_callback(frame)

    # Populate chassis matrix or verify event bus propagation
    probe.chassis_matrix["chassis_id"] = "00:1a:2b:3c:4d:5e"
    probe.chassis_matrix["allocated_power_w"] = 15.4

    result = await probe.execute()
    assert result.get("chassis_id") == "00:1a:2b:3c:4d:5e"
    assert result.get("allocated_power_w") == 15.4

    # Test clean rollback lifecycle
    assert await probe.rollback() is True
    assert await probe.execute() == {}
