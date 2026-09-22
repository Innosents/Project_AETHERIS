"""
Unit tests for ModbusAdapter (Phase 18).
Validates Modbus TCP telemetry extraction, IndustrialTelemetryPort schema compliance,
timeout clamping, and asynchronous publication to Memurai event bus.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from aetheris.infrastructure.adapters.modbus_adapter import ModbusAdapter, MODBUS_READ_DEVICE_ID
from aetheris.core.parsers.industrial_parser import parse_modbus_mei_response


class TestModbusParserMEI:
    def test_parse_modbus_mei_response_valid(self):
        # Construct synthetic MBAP (7 bytes) + FC 0x2B + MEI 0x0E + Read Dev ID 0x01 +
        # Conformity 0x01 + MoreFollows 0x00 + NextObj 0x00 + NumObj 3
        mbap = b"\x00\x01\x00\x00\x00\x1f\x01"
        mei_header = b"\x2b\x0e\x01\x01\x00\x00\x03"
        # Obj 0: Vendor "Schneider Electric"
        obj0 = b"\x00\x12Schneider Electric"
        # Obj 1: Model "Modicon M340"
        obj1 = b"\x01\x0cModicon M340"
        # Obj 2: Firmware "v3.20"
        obj2 = b"\x02\x05v3.20"

        frame = mbap + mei_header + obj0 + obj1 + obj2
        parsed = parse_modbus_mei_response(frame)

        assert parsed["vendor"] == "Schneider Electric"
        assert parsed["model"] == "Modicon M340"
        assert parsed["firmware"] == "v3.20"

    def test_parse_modbus_mei_response_fallback(self):
        # MEI response (FC 0x2B) without structured objects, triggering regex fallback
        frame = b"\x00\x01\x00\x00\x00\x18\x01\x2b\x0e\x01\x00\x00\x00Schneider Electric PLC"
        parsed = parse_modbus_mei_response(frame)
        assert parsed["vendor"] == "Schneider Electric"


class TestModbusAdapter:
    @pytest.fixture
    def mock_bus(self):
        bus = MagicMock()
        bus.push_telemetry = AsyncMock()
        return bus

    @pytest.fixture
    def adapter(self, mock_bus):
        return ModbusAdapter(event_bus=mock_bus, timeout=0.4)

    def test_adapter_initialization(self, mock_bus):
        adapter = ModbusAdapter(event_bus=mock_bus, timeout=2.0)
        assert adapter.timeout <= 0.5
        assert adapter.consume_queue == "aetheris:telemetry:l3_active"
        assert adapter.publish_queue == "aetheris:telemetry:ics_intelligence"

    @pytest.mark.asyncio
    async def test_process_target_success_dispatches_telemetry(self, adapter, mock_bus):
        mock_data = {
            "vendor": "Schneider Electric",
            "model": "BMXP342020",
            "firmware": "v2.80",
            "kernel_turnaround_us": 142.5,
            "latency_ms": 0.1425,
        }

        with patch.object(adapter, "_probe_socket", return_value=mock_data):
            await adapter.process_target("192.168.1.88", port=502)

        mock_bus.push_telemetry.assert_awaited_once()
        queue, payload = mock_bus.push_telemetry.call_args[0]
        assert queue == "aetheris:telemetry:ics_intelligence"
        assert payload["target_ip"] == "192.168.1.88"
        assert payload["port"] == 502
        assert payload["protocol"] == "Modbus TCP (Port 502)"
        assert payload["vendor"] == "Schneider Electric"
        assert payload["model"] == "BMXP342020"
        assert payload["archetype"] == "INDUSTRIAL_OT"
        assert payload["device_type"] == "modbus_plc"
        assert payload["kernel_turnaround_us"] == 142.5
        assert payload["latency_ms"] == 0.1425

    @pytest.mark.asyncio
    async def test_process_target_unresponsive_suppressed(self, adapter, mock_bus):
        with patch.object(adapter, "_probe_socket", return_value={}):
            await adapter.process_target("192.168.1.99", port=502)

        mock_bus.push_telemetry.assert_not_called()

    def test_probe_socket_refusal_handled(self, adapter):
        # Non-listening port should return {} without exception
        res = adapter._probe_socket("127.0.0.1", port=19502)
        assert res == {}

    @pytest.mark.asyncio
    async def test_process_bacnet_target_dispatches_telemetry(self, adapter, mock_bus):
        mock_bacnet_data = {
            "vendor": "Johnson Controls",
            "model": "BACnet Controller (Instance 1234)",
            "device_instance": 1234,
            "kernel_turnaround_us": 250.0,
            "latency_ms": 0.25,
        }

        with patch.object(adapter, "_probe_bacnet_socket", return_value=mock_bacnet_data):
            res = await adapter.process_bacnet_target("10.0.0.55", port=47808)

        assert res is not None
        assert res.protocol == "BACnet/IP (UDP 47808)"
        assert res.device_type == "bacnet_controller"
        assert res.archetype == "INDUSTRIAL_OT"
        assert res.vendor == "Johnson Controls"
        assert res.device_instance == 1234

        mock_bus.push_telemetry.assert_awaited_once()
        queue, payload = mock_bus.push_telemetry.call_args[0]
        assert queue == "aetheris:telemetry:ics_intelligence"
        assert payload["target_ip"] == "10.0.0.55"
        assert payload["port"] == 47808
        assert payload["device_instance"] == 1234

    @pytest.mark.asyncio
    async def test_process_bacnet_target_unresponsive_suppressed(self, adapter, mock_bus):
        with patch.object(adapter, "_probe_bacnet_socket", return_value={}):
            res = await adapter.process_bacnet_target("10.0.0.99", port=47808)

        assert res is None
        mock_bus.push_telemetry.assert_not_called()

    def test_probe_bacnet_socket_refusal_handled(self, adapter):
        res = adapter._probe_bacnet_socket("127.0.0.1", port=49999)
        assert res == {}

