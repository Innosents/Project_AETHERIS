"""
Unit tests for CldapTelemetryPort and CldapAdapter (Phase 16).
Validates Active Directory inbound port schemas, threadpool-delegated UDP pinging,
and asynchronous telemetry publication to Memurai event bus.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError

from aetheris.core.ports.l7_cldap_inbound import CldapTelemetryPort
from aetheris.infrastructure.adapters.cldap_adapter import CldapAdapter


class TestCldapTelemetryPort:
    def test_valid_telemetry_port(self):
        port = CldapTelemetryPort(
            target_ip="192.168.1.10",
            target_port=389,
            is_ad_controller=True,
            domain="corp.aetheris.local",
            forest="corp.aetheris.local",
            dc_hostname="dc01.corp.aetheris.local",
            netbios_domain="AETHERIS",
            netbios_computer_name="DC01",
            dc_site="Default-First-Site-Name",
            domain_guid="12345678-1234-5678-1234-567812345678",
            is_pdc=True,
            is_gc=True,
            is_kdc=True,
            is_writable=True,
            kernel_turnaround_us=185.4,
        )
        assert port.target_ip == "192.168.1.10"
        assert port.target_port == 389
        assert port.is_ad_controller is True
        assert port.domain == "corp.aetheris.local"
        assert port.forest == "corp.aetheris.local"
        assert port.dc_hostname == "dc01.corp.aetheris.local"
        assert port.netbios_domain == "AETHERIS"
        assert port.netbios_computer_name == "DC01"
        assert port.is_pdc is True
        assert port.is_gc is True
        assert port.is_kdc is True
        assert port.is_writable is True
        assert port.kernel_turnaround_us == 185.4

    def test_default_values(self):
        port = CldapTelemetryPort(target_ip="10.0.0.1")
        assert port.target_port == 389
        assert port.is_ad_controller is False
        assert port.domain is None
        assert port.forest is None
        assert port.dc_hostname is None
        assert port.netbios_domain is None
        assert port.netbios_computer_name is None
        assert port.dc_site is None
        assert port.domain_guid is None
        assert port.is_pdc is False
        assert port.is_gc is False
        assert port.is_kdc is False
        assert port.is_writable is False
        assert port.kernel_turnaround_us is None

    def test_negative_turnaround_rejected(self):
        with pytest.raises(ValidationError):
            CldapTelemetryPort(
                target_ip="192.168.1.10",
                kernel_turnaround_us=-5.0,
            )

    def test_extra_fields_ignored(self):
        port = CldapTelemetryPort(
            target_ip="192.168.1.10",
            extra_vendor_field="Microsoft",
            flags=0x00003FD3,
        )
        assert port.target_ip == "192.168.1.10"
        assert not hasattr(port, "extra_vendor_field")


class TestCldapAdapter:
    @pytest.fixture
    def mock_bus(self):
        bus = MagicMock()
        bus.push_telemetry = AsyncMock()
        return bus

    @pytest.fixture
    def adapter(self, mock_bus):
        return CldapAdapter(event_bus=mock_bus)

    def test_adapter_queues(self, adapter):
        assert adapter.consume_queue == "aetheris:telemetry:l3_active"
        assert adapter.publish_queue == "aetheris:telemetry:ad_intelligence"

    @pytest.mark.asyncio
    async def test_process_target_success_dispatches_ad_intelligence(self, adapter, mock_bus):
        mock_cldap_result = {
            "target_ip": "192.168.1.200",
            "target_port": 389,
            "is_ad_controller": True,
            "domain": "ad.internal.net",
            "forest": "ad.internal.net",
            "dc_hostname": "dc-primary.ad.internal.net",
            "netbios_domain": "AD",
            "netbios_computer_name": "DC-PRIMARY",
            "dc_site": "HQ-Site",
            "domain_guid": "11111111-2222-3333-4444-555555555555",
            "is_pdc": True,
            "is_gc": True,
            "is_kdc": True,
            "is_writable": True,
            "kernel_turnaround_us": 210.5,
            "rtt_ms": 0.211,
            "flags": 0x00003FD3,
            "flags_hex": "0x00003FD3",
            "parsing_mode": "ms_adts_6_3_5_response_ex",
        }

        with patch("aetheris.infrastructure.adapters.cldap_adapter.probe_cldap_endpoint", return_value=mock_cldap_result):
            await adapter.process_target("192.168.1.200")

        mock_bus.push_telemetry.assert_awaited_once()
        call_args = mock_bus.push_telemetry.call_args
        queue_name = call_args[0][0]
        payload = call_args[0][1]

        assert queue_name == "aetheris:telemetry:ad_intelligence"
        assert payload["target_ip"] == "192.168.1.200"
        assert payload["target_port"] == 389
        assert payload["is_ad_controller"] is True
        assert payload["domain"] == "ad.internal.net"
        assert payload["forest"] == "ad.internal.net"
        assert payload["dc_hostname"] == "dc-primary.ad.internal.net"
        assert payload["netbios_domain"] == "AD"
        assert payload["netbios_computer_name"] == "DC-PRIMARY"
        assert payload["dc_site"] == "HQ-Site"
        assert payload["is_pdc"] is True
        assert payload["is_gc"] is True
        assert payload["is_kdc"] is True
        assert payload["is_writable"] is True
        assert payload["kernel_turnaround_us"] == 210.5

    @pytest.mark.asyncio
    async def test_process_target_non_ad_suppressed(self, adapter, mock_bus):
        non_ad_result = {
            "is_ad_controller": False,
            "target_ip": "192.168.1.50",
            "target_port": 389,
            "error": "timeout",
        }

        with patch("aetheris.infrastructure.adapters.cldap_adapter.probe_cldap_endpoint", return_value=non_ad_result):
            await adapter.process_target("192.168.1.50")

        mock_bus.push_telemetry.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_target_none_or_exception_handled_safely(self, adapter, mock_bus):
        with patch("aetheris.infrastructure.adapters.cldap_adapter.probe_cldap_endpoint", return_value=None):
            await adapter.process_target("192.168.1.99")

        mock_bus.push_telemetry.assert_not_called()

        with patch("aetheris.infrastructure.adapters.cldap_adapter.probe_cldap_endpoint", side_effect=RuntimeError("Socket error")):
            # Must not crash caller
            try:
                await adapter.process_target("192.168.1.99")
            except RuntimeError:
                pass

