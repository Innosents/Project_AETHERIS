"""
Unit tests for IndustrialTelemetryPort and IcsOtAdapter (Phase 15).
Validates Pydantic schema constraints, BACnet/IP parsing, timeout boundaries,
and asynchronous telemetry publication to Memurai event bus.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError

from aetheris.core.ports.l7_ics_inbound import IndustrialTelemetryPort
from aetheris.infrastructure.adapters.ics_ot_prober import IcsOtAdapter, BACNET_INQUIRY


class TestIndustrialTelemetryPort:
    def test_valid_telemetry_port(self):
        port = IndustrialTelemetryPort(
            target_ip="192.168.1.100",
            port=47808,
            protocol="BACnet/IP",
            vendor="Johnson Controls",
            model="NAE55",
            device_instance=12345,
            archetype="INDUSTRIAL_OT",
            device_type="bacnet_controller",
            kernel_turnaround_us=125.5,
            latency_ms=0.1255,
        )
        assert port.target_ip == "192.168.1.100"
        assert port.port == 47808
        assert port.protocol == "BACnet/IP"
        assert port.device_instance == 12345
        assert port.kernel_turnaround_us == 125.5
        assert port.latency_ms == 0.1255

    def test_default_values(self):
        port = IndustrialTelemetryPort(
            target_ip="10.0.0.50",
            port=502,
            protocol="Modbus",
            kernel_turnaround_us=50.0,
            latency_ms=0.05,
        )
        assert port.vendor == "Unknown"
        assert port.model == ""
        assert port.device_instance is None
        assert port.archetype == "INDUSTRIAL_OT"
        assert port.device_type == "unknown_controller"

    def test_negative_turnaround_rejected(self):
        with pytest.raises(ValidationError):
            IndustrialTelemetryPort(
                target_ip="192.168.1.100",
                port=47808,
                protocol="BACnet/IP",
                kernel_turnaround_us=-10.0,
                latency_ms=0.5,
            )

    def test_negative_latency_rejected(self):
        with pytest.raises(ValidationError):
            IndustrialTelemetryPort(
                target_ip="192.168.1.100",
                port=47808,
                protocol="BACnet/IP",
                kernel_turnaround_us=10.0,
                latency_ms=-0.5,
            )


class TestIcsOtAdapter:
    @pytest.fixture
    def mock_bus(self):
        bus = MagicMock()
        bus.push_telemetry = AsyncMock()
        return bus

    @pytest.fixture
    def adapter(self, mock_bus):
        return IcsOtAdapter(event_bus=mock_bus, timeout=0.4)

    def test_timeout_clamped_to_safety_ceiling(self, mock_bus):
        # OT Safety constraint: max 0.5s timeout on PLC ports
        adapter_unsafe = IcsOtAdapter(event_bus=mock_bus, timeout=2.5)
        assert adapter_unsafe.timeout <= 0.5

    def test_parse_bacnet_empty_or_truncated(self, adapter):
        assert adapter._parse_bacnet(b"") == (False, None)
        assert adapter._parse_bacnet(b"\x81\x00") == (False, None)
        assert adapter._parse_bacnet(b"\x80\x0a\x00\x0e") == (False, None)

    def test_parse_bacnet_valid_no_dev_id(self, adapter):
        # Valid BVLC type 0x81, but no 0xC4 tag
        payload = b"\x81\x0a\x00\x08\x01\x20\xff\xff"
        is_valid, dev_id = adapter._parse_bacnet(payload)
        assert is_valid is True
        assert dev_id is None

    def test_parse_bacnet_valid_with_dev_id(self, adapter):
        # 0x81 BVLC header followed by 0xC4 tag and 4-byte dev_id
        # dev_id = 0x000004D2 (1234)
        payload = b"\x81\x0a\x00\x10\x01\x20\xff\xff\x00\xff\x10\xc4\x00\x00\x04\xd2\x00"
        is_valid, dev_id = adapter._parse_bacnet(payload)
        assert is_valid is True
        assert dev_id == 1234

    @patch("socket.socket")
    def test_execute_bacnet_probe_success(self, mock_socket_cls, adapter):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # Return BVLC response with instance 4567
        # 4567 in hex = 0x000011D7
        response_bytes = b"\x81\x0a\x00\x10\x01\x20\xff\xff\x00\xff\x10\xc4\x00\x00\x11\xd7\x00"
        mock_sock.recvfrom.return_value = (response_bytes, ("192.168.1.50", 47808))

        res = adapter._execute_bacnet_probe("192.168.1.50")
        assert res is not None
        assert res["device_instance"] == 4567
        assert "BACnet Controller (Instance 4567)" in res["model"]
        assert res["kernel_turnaround_us"] > 0
        assert res["latency_ms"] > 0
        mock_sock.close.assert_called_once()

    @patch("socket.socket")
    def test_execute_bacnet_probe_timeout(self, mock_socket_cls, adapter):
        import socket
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout()

        res = adapter._execute_bacnet_probe("192.168.1.50")
        assert res is None
        mock_sock.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_target_dispatches_telemetry(self, adapter, mock_bus):
        probe_res = {
            "kernel_turnaround_us": 145.2,
            "latency_ms": 0.1452,
            "device_instance": 9999,
            "model": "BACnet Controller (Instance 9999)",
        }
        with patch.object(adapter, "_execute_bacnet_probe", return_value=probe_res):
            await adapter.process_target("192.168.1.75")

        mock_bus.push_telemetry.assert_awaited_once()
        call_args = mock_bus.push_telemetry.call_args
        queue_name = call_args[0][0]
        payload = call_args[0][1]

        assert queue_name == "aetheris:telemetry:ics_intelligence"
        assert payload["target_ip"] == "192.168.1.75"
        assert payload["port"] == 47808
        assert payload["protocol"] == "BACnet/IP"
        assert payload["device_instance"] == 9999
        assert payload["device_type"] == "bacnet_controller"
        assert payload["kernel_turnaround_us"] == 145.2

    @pytest.mark.asyncio
    async def test_process_target_ignores_unresponsive_target(self, adapter, mock_bus):
        with patch.object(adapter, "_execute_bacnet_probe", return_value=None):
            await adapter.process_target("192.168.1.99")

        mock_bus.push_telemetry.assert_not_called()

