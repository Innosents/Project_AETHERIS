"""
Unit tests for MercuryPanelTelemetryPort and MercuryPanelAdapter (Phase 19).
Validates access control panel telemetry contracts, stateless binary response parsing,
and asynchronous telemetry publication to the Memurai event bus.
"""

import asyncio
import json
import socket
import threading
import pytest
from unittest.mock import AsyncMock, MagicMock
from pydantic import ValidationError

from aetheris.core.ports.l7_mercury_inbound import MercuryPanelTelemetryPort
from aetheris.core.parsers.mercury_parser import (
    parse_mercury_response,
    MERCURY_STATUS_INQUIRY,
    KNOWN_MERCURY_MODELS,
    probe_mercury_panel,
)
from aetheris.infrastructure.adapters.mercury_adapter import (
    MercuryPanelAdapter,
    MercuryMspAdapter,
)


class TestMercuryPanelTelemetryPort:
    def test_valid_telemetry_port(self):
        port = MercuryPanelTelemetryPort(
            target_ip="192.168.1.200",
            port=3001,
            model="Mercury LP1502 Access Controller",
            firmware="1.24",
            kernel_turnaround_us=450.5,
            latency_ms=0.4505,
        )
        assert port.target_ip == "192.168.1.200"
        assert port.port == 3001
        assert port.protocol == "Mercury Security Protocol (Port 3001)"
        assert port.vendor == "Mercury Security"
        assert port.model == "Mercury LP1502 Access Controller"
        assert port.firmware == "1.24"
        assert port.archetype == "PHYSICAL_SECURITY"
        assert port.is_security_controller is True
        assert port.kernel_turnaround_us == 450.5
        assert port.latency_ms == 0.4505

    def test_default_values(self):
        port = MercuryPanelTelemetryPort(
            target_ip="10.0.0.50",
            model="Mercury EP2500 Controller",
            kernel_turnaround_us=120.0,
            latency_ms=0.12,
        )
        assert port.port == 3001
        assert port.protocol == "Mercury Security Protocol (Port 3001)"
        assert port.vendor == "Mercury Security"
        assert port.firmware == "N/A"
        assert port.archetype == "PHYSICAL_SECURITY"
        assert port.is_security_controller is True

    def test_negative_values_rejected(self):
        with pytest.raises(ValidationError):
            MercuryPanelTelemetryPort(
                target_ip="192.168.1.200",
                model="Mercury LP1502 Access Controller",
                kernel_turnaround_us=-1.0,
                latency_ms=0.1,
            )
        with pytest.raises(ValidationError):
            MercuryPanelTelemetryPort(
                target_ip="192.168.1.200",
                model="Mercury LP1502 Access Controller",
                kernel_turnaround_us=100.0,
                latency_ms=-0.5,
            )

    def test_extra_fields_ignored(self):
        port = MercuryPanelTelemetryPort(
            target_ip="192.168.1.200",
            model="Mercury LP1502",
            kernel_turnaround_us=150.0,
            latency_ms=0.15,
            unrecognized_telemetry="discard_me",
        )
        assert port.target_ip == "192.168.1.200"
        assert not hasattr(port, "unrecognized_telemetry")


class TestMercuryParserPanel:
    def test_parse_text_signature(self):
        raw = b"\x00\x10\x00\x02\x00\x00\x01\x18\x00\x00Mercury LP1502 Controller FW: 1.24"
        parsed = parse_mercury_response(raw)
        assert "LP1502" in parsed["model"]
        assert parsed["firmware"] == "1.24"

    def test_parse_binary_fallback(self):
        # Model 0x08 -> LP4502, major 2, minor 5 -> 2.5
        raw = bytes([0x00, 0x10, 0x00, 0x08, 0x00, 0x00, 0x02, 0x05, 0x00, 0x00])
        parsed = parse_mercury_response(raw)
        assert parsed["model"] == "Mercury LP4502 High-Density Controller"
        assert parsed["firmware"] == "2.5"

    def test_parse_empty_or_malformed(self):
        parsed = parse_mercury_response(b"")
        assert parsed["model"] == "Mercury Security Access Controller"
        assert parsed["firmware"] == "N/A"

    def test_status_inquiry_constant(self):
        assert MERCURY_STATUS_INQUIRY == b"\x00\x10\x00\x01\x00\x00\x00\x00\xff\xff"
        assert len(MERCURY_STATUS_INQUIRY) == 10

    def test_known_models_coverage(self):
        assert 0x01 in KNOWN_MERCURY_MODELS
        assert 0x02 in KNOWN_MERCURY_MODELS
        assert 0x08 in KNOWN_MERCURY_MODELS
        assert 0x80 in KNOWN_MERCURY_MODELS


class TestMercuryPanelAdapter:
    @pytest.fixture
    def mock_bus(self):
        bus = MagicMock()
        bus.push_telemetry = AsyncMock()
        return bus

    @pytest.fixture
    def adapter(self, mock_bus):
        return MercuryPanelAdapter(event_bus=mock_bus, timeout=0.4)

    def test_adapter_initialization(self, adapter):
        assert adapter.timeout <= 0.5
        assert adapter.consume_queue == "aetheris:telemetry:l3_active"
        assert adapter.publish_queue == "aetheris:telemetry:physical_security"

    @pytest.mark.asyncio
    async def test_process_target_live_exchange(self, adapter, mock_bus):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        received = b""

        def handle_client():
            nonlocal received
            try:
                client, _ = server_sock.accept()
                received = client.recv(1024)
                client.sendall(b"\x00\x10\x00\x02\x00\x00\x01\x18\x00\x00Mercury LP1502 Controller FW: 1.24")
                client.close()
            except Exception:
                pass
            finally:
                server_sock.close()

        th = threading.Thread(target=handle_client)
        th.daemon = True
        th.start()

        await adapter.process_target("127.0.0.1", port=port)

        assert received == MERCURY_STATUS_INQUIRY
        mock_bus.push_telemetry.assert_awaited_once()
        queue, payload = mock_bus.push_telemetry.call_args[0]
        assert queue == "aetheris:telemetry:physical_security"
        assert payload["target_ip"] == "127.0.0.1"
        assert payload["port"] == port
        assert "LP1502" in payload["model"]
        assert payload["firmware"] == "1.24"
        assert payload["archetype"] == "PHYSICAL_SECURITY"
        assert payload["is_security_controller"] is True
        assert payload["kernel_turnaround_us"] > 0
        assert payload["latency_ms"] > 0

    @pytest.mark.asyncio
    async def test_process_target_connection_refused(self, adapter, mock_bus):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()

        await adapter.process_target("127.0.0.1", port=closed_port)
        mock_bus.push_telemetry.assert_not_called()

    @pytest.mark.asyncio
    async def test_msp_adapter_extension(self, mock_bus):
        msp_adapter = MercuryMspAdapter(event_bus=mock_bus, timeout=0.4)
        assert hasattr(msp_adapter, "process_panel_target")

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        def handle_client():
            try:
                client, _ = server_sock.accept()
                _ = client.recv(1024)
                client.sendall(b"\x00\x10\x00\x04\x00\x00\x02\x01\x00\x00Mercury LP2500 Distributed Controller FW: 2.1")
                client.close()
            except Exception:
                pass
            finally:
                server_sock.close()

        th = threading.Thread(target=handle_client)
        th.daemon = True
        th.start()

        await msp_adapter.process_panel_target("127.0.0.1", port=port)

        mock_bus.push_telemetry.assert_awaited_once()
        queue, payload = mock_bus.push_telemetry.call_args[0]
        assert queue == "aetheris:telemetry:physical_security"
        assert payload["target_ip"] == "127.0.0.1"
        assert "LP2500" in payload["model"]

