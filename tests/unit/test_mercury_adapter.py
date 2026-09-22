"""
Unit tests for MercuryMspTelemetryPort and MercuryMspAdapter (Phase 17).
Validates RS-485 sub-node topology contracts, stateless frame parsing,
and asynchronous telemetry publication to Memurai event bus.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError

from aetheris.core.ports.l7_mercury_inbound import MercuryMspTelemetryPort
from aetheris.core.parsers.mercury_parser import parse_msp_frame, ACK_PAYLOAD, MSPParser
from aetheris.infrastructure.adapters.mercury_adapter import MercuryMspAdapter


class TestMercuryMspTelemetryPort:
    def test_valid_telemetry_port(self):
        port = MercuryMspTelemetryPort(
            target_ip="192.168.1.150",
            target_port=3001,
            readers=4,
            rex=2,
            strikes=4,
            dps=4,
            controller_model="Mercury LP1502",
            archetype="PHYSICAL_SECURITY",
        )
        assert port.target_ip == "192.168.1.150"
        assert port.target_port == 3001
        assert port.readers == 4
        assert port.rex == 2
        assert port.strikes == 4
        assert port.dps == 4
        assert port.controller_model == "Mercury LP1502"
        assert port.archetype == "PHYSICAL_SECURITY"

    def test_default_values(self):
        port = MercuryMspTelemetryPort(target_ip="10.0.0.1")
        assert port.target_port == 3001
        assert port.readers == 0
        assert port.rex == 0
        assert port.strikes == 0
        assert port.dps == 0
        assert port.controller_model == "Mercury MP1502/EP1502"
        assert port.archetype == "PHYSICAL_SECURITY"

    def test_negative_subnodes_rejected(self):
        with pytest.raises(ValidationError):
            MercuryMspTelemetryPort(target_ip="192.168.1.150", readers=-1)
        with pytest.raises(ValidationError):
            MercuryMspTelemetryPort(target_ip="192.168.1.150", rex=-1)
        with pytest.raises(ValidationError):
            MercuryMspTelemetryPort(target_ip="192.168.1.150", strikes=-1)
        with pytest.raises(ValidationError):
            MercuryMspTelemetryPort(target_ip="192.168.1.150", dps=-1)

    def test_extra_fields_ignored(self):
        port = MercuryMspTelemetryPort(
            target_ip="192.168.1.150",
            aux_relays=8,
            firmware="v2.1",
        )
        assert port.target_ip == "192.168.1.150"
        assert not hasattr(port, "aux_relays")


class TestMercuryParser:
    def test_parse_msp_frame_standard(self):
        raw = b"\x02R2_X2_S2_D2\x03\r\n"
        topo = parse_msp_frame(raw)
        assert topo == {"readers": 2, "rex": 2, "strikes": 2, "dps": 2}

    def test_parse_msp_frame_arbitrary_topology(self):
        raw = b"\x02R8_X4_S8_D8\x03"
        topo = parse_msp_frame(raw)
        assert topo == {"readers": 8, "rex": 4, "strikes": 8, "dps": 8}

    def test_parse_msp_frame_partial_tokens(self):
        raw = b"\x02R4_S4\x03"
        topo = parse_msp_frame(raw)
        assert topo == {"readers": 4, "rex": 0, "strikes": 4, "dps": 0}

    def test_parse_msp_frame_malformed_tokens(self):
        raw = b"\x02Rfoo_X_S_Dbar\x03"
        topo = parse_msp_frame(raw)
        assert topo == {"readers": 0, "rex": 0, "strikes": 0, "dps": 0}

    def test_parse_msp_frame_invalid_utf8(self):
        raw = b"\x02\xff\xfe\xfd\x03"
        topo = parse_msp_frame(raw)
        assert topo == {"readers": 0, "rex": 0, "strikes": 0, "dps": 0}

    def test_ack_payload_constant(self):
        assert ACK_PAYLOAD == b"\x02\x01\x04\x03"


class TestMercuryMspAdapter:
    @pytest.fixture
    def mock_bus(self):
        bus = MagicMock()
        bus.push_telemetry = AsyncMock()
        return bus

    @pytest.fixture
    def adapter(self, mock_bus):
        return MercuryMspAdapter(event_bus=mock_bus, timeout=0.4)

    def test_adapter_initialization(self, adapter):
        assert adapter.timeout <= 0.5
        assert adapter.consume_queue == "aetheris:telemetry:l3_active"
        assert adapter.publish_queue == "aetheris:telemetry:physical_security"

    @pytest.mark.asyncio
    async def test_process_target_live_exchange(self, adapter, mock_bus):
        from tests.mocks.mercury_mp1502_emulator import MercuryMP1502Emulator
        emulator = MercuryMP1502Emulator(readers=4, rex=2, strikes=4, dps=4)

        server = await asyncio.start_server(emulator.handle_client, "127.0.0.1", 13001)
        await asyncio.sleep(0.1)
        try:
            await adapter.process_target("127.0.0.1", port=13001)

            # Assert telemetry was dispatched to Memurai bus
            mock_bus.push_telemetry.assert_awaited_once()
            queue, payload = mock_bus.push_telemetry.call_args[0]
            assert queue == "aetheris:telemetry:physical_security"
            assert payload["target_ip"] == "127.0.0.1"
            assert payload["target_port"] == 13001
            assert payload["readers"] == 4
            assert payload["rex"] == 2
            assert payload["strikes"] == 4
            assert payload["dps"] == 4
            assert payload["controller_model"] == "Mercury MP1502/EP1502"
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_process_target_connection_refused(self, adapter, mock_bus):
        # Must gracefully return without exception
        await adapter.process_target("127.0.0.1", port=19999)
        mock_bus.push_telemetry.assert_not_called()
