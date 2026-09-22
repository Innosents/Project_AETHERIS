"""
Unit tests for OnvifTelemetryPort and OnvifAdapter (Phase 20).
Validates ONVIF camera telemetry contracts, stateless XML response parsing,
and asynchronous telemetry publication to the Memurai event bus.
"""

import asyncio
import http.server
import socket
import threading
import pytest
from unittest.mock import AsyncMock, MagicMock
from pydantic import ValidationError

from aetheris.core.ports.l7_onvif_inbound import OnvifTelemetryPort
from aetheris.core.parsers.onvif_parser import (
    parse_onvif_device_information_xml,
    ONVIF_SOAP_GET_DEVICE_INFORMATION,
    probe_onvif_camera,
)
from aetheris.infrastructure.adapters.onvif_adapter import OnvifAdapter


SAMPLE_ONVIF_RESPONSE_XML = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Body>
        <tds:GetDeviceInformationResponse>
            <tds:Manufacturer>Axis Communications</tds:Manufacturer>
            <tds:Model>AXIS P1365-E Mk II</tds:Model>
            <tds:FirmwareVersion>9.80.3.5</tds:FirmwareVersion>
            <tds:SerialNumber>ACCC8E123456</tds:SerialNumber>
            <tds:HardwareId>654-A</tds:HardwareId>
        </tds:GetDeviceInformationResponse>
    </soap:Body>
</soap:Envelope>"""


class TestOnvifTelemetryPort:
    def test_valid_telemetry_port(self):
        port = OnvifTelemetryPort(
            target_ip="192.168.1.120",
            port=80,
            protocol="ONVIF Device Service",
            vendor="Axis Communications",
            model="AXIS P1365-E Mk II",
            firmware="9.80.3.5",
            serial_number="ACCC8E123456",
            hardware_id="654-A",
            archetype="CCTV_VIDEO",
            type="camera",
            is_onvif=True,
            kernel_turnaround_us=1250.0,
            latency_ms=1.25,
        )
        assert port.target_ip == "192.168.1.120"
        assert port.port == 80
        assert port.vendor == "Axis Communications"
        assert port.model == "AXIS P1365-E Mk II"
        assert port.firmware == "9.80.3.5"
        assert port.serial_number == "ACCC8E123456"
        assert port.hardware_id == "654-A"
        assert port.archetype == "CCTV_VIDEO"
        assert port.type == "camera"
        assert port.is_onvif is True
        assert port.kernel_turnaround_us == 1250.0
        assert port.latency_ms == 1.25

    def test_default_values(self):
        port = OnvifTelemetryPort(
            target_ip="10.0.0.15",
            kernel_turnaround_us=200.0,
            latency_ms=0.2,
        )
        assert port.port == 80
        assert port.protocol == "ONVIF Device Service"
        assert port.vendor == "Generic ONVIF"
        assert port.model == "IP Surveillance Camera"
        assert port.firmware == ""
        assert port.serial_number == ""
        assert port.hardware_id == ""
        assert port.archetype == "CCTV_VIDEO"
        assert port.type == "camera"
        assert port.is_onvif is True

    def test_negative_latency_rejected(self):
        with pytest.raises(ValidationError):
            OnvifTelemetryPort(
                target_ip="10.0.0.15",
                kernel_turnaround_us=-1.0,
                latency_ms=0.1,
            )
        with pytest.raises(ValidationError):
            OnvifTelemetryPort(
                target_ip="10.0.0.15",
                kernel_turnaround_us=100.0,
                latency_ms=-0.5,
            )

    def test_extra_fields_ignored(self):
        port = OnvifTelemetryPort(
            target_ip="10.0.0.15",
            kernel_turnaround_us=200.0,
            latency_ms=0.2,
            stream_uri="rtsp://10.0.0.15/live",
        )
        assert port.target_ip == "10.0.0.15"
        assert not hasattr(port, "stream_uri")


class TestOnvifParser:
    def test_parse_standard_xml(self):
        info = parse_onvif_device_information_xml(SAMPLE_ONVIF_RESPONSE_XML)
        assert info["manufacturer"] == "Axis Communications"
        assert info["model"] == "AXIS P1365-E Mk II"
        assert info["firmware"] == "9.80.3.5"
        assert info["serial"] == "ACCC8E123456"
        assert info["hardware_id"] == "654-A"

    def test_parse_regex_fallback(self):
        malformed = "<SOAP-ENV:Envelope><Manufacturer>Hikvision</Manufacturer><Model>DS-2CD2042WD-I</Model><FirmwareVersion>V5.4.5</FirmwareVersion><SerialNumber>DS-2CD-1234</SerialNumber>"
        info = parse_onvif_device_information_xml(malformed)
        assert info["manufacturer"] == "Hikvision"
        assert info["model"] == "DS-2CD2042WD-I"
        assert info["firmware"] == "V5.4.5"
        assert info["serial"] == "DS-2CD-1234"

    def test_parse_empty_or_whitespace(self):
        info = parse_onvif_device_information_xml("   ")
        assert info == {
            "manufacturer": "",
            "model": "",
            "firmware": "",
            "serial": "",
            "hardware_id": "",
        }

    def test_soap_envelope_constant(self):
        assert "GetDeviceInformation" in ONVIF_SOAP_GET_DEVICE_INFORMATION
        assert "soap:Envelope" in ONVIF_SOAP_GET_DEVICE_INFORMATION


class TestOnvifAdapter:
    @pytest.fixture
    def mock_bus(self):
        bus = MagicMock()
        bus.push_telemetry = AsyncMock()
        return bus

    @pytest.fixture
    def adapter(self, mock_bus):
        return OnvifAdapter(event_bus=mock_bus, timeout=0.4)

    def test_adapter_initialization(self, adapter):
        assert adapter.timeout <= 0.5
        assert adapter.consume_queue == "aetheris:telemetry:l3_active"
        assert adapter.publish_queue == "aetheris:telemetry:camera_intelligence"

    @pytest.mark.asyncio
    async def test_process_target_live_exchange(self, adapter, mock_bus):
        class ONVIFHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == "/onvif/device_service":
                    content = SAMPLE_ONVIF_RESPONSE_XML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/soap+xml; charset=utf-8")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), ONVIFHandler)
        port = server.server_address[1]
        th = threading.Thread(target=server.handle_request)
        th.daemon = True
        th.start()

        try:
            await adapter.process_target("127.0.0.1", port=port)

            mock_bus.push_telemetry.assert_awaited_once()
            queue, payload = mock_bus.push_telemetry.call_args[0]
            assert queue == "aetheris:telemetry:camera_intelligence"
            assert payload["target_ip"] == "127.0.0.1"
            assert payload["port"] == port
            assert payload["vendor"] == "Axis Communications"
            assert payload["model"] == "AXIS P1365-E Mk II"
            assert payload["firmware"] == "9.80.3.5"
            assert payload["serial_number"] == "ACCC8E123456"
            assert payload["hardware_id"] == "654-A"
            assert payload["archetype"] == "CCTV_VIDEO"
            assert payload["type"] == "camera"
            assert payload["is_onvif"] is True
            assert payload["kernel_turnaround_us"] > 0
            assert payload["latency_ms"] > 0
        finally:
            server.server_close()

    @pytest.mark.asyncio
    async def test_process_target_non_onvif(self, adapter, mock_bus):
        class NonONVIFHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                content = b"<html><body>Web Server</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), NonONVIFHandler)
        port = server.server_address[1]
        th = threading.Thread(target=server.handle_request)
        th.daemon = True
        th.start()

        try:
            await adapter.process_target("127.0.0.1", port=port)
            mock_bus.push_telemetry.assert_not_called()
        finally:
            server.server_close()

    @pytest.mark.asyncio
    async def test_process_target_connection_refused(self, adapter, mock_bus):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()

        await adapter.process_target("127.0.0.1", port=closed_port)
        mock_bus.push_telemetry.assert_not_called()

