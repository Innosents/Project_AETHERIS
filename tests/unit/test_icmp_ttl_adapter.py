"""
Unit tests validating Phase 14 Hexagonal Architecture Refactoring:
- TtlTelemetryPort inbound schema validation and hop_count bounds
- IcmpTtlAdapter baseline determination, raw socket execution mock, and Memurai push
- ActiveTTLInterrogator compatibility facade and RFC 1071 checksum helpers
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from aetheris.core.ports.l3_ttl_inbound import TtlTelemetryPort
from aetheris.infrastructure.adapters.icmp_ttl_adapter import (
    IcmpTtlAdapter,
    _icmp_checksum,
    _build_icmp_echo,
)


def test_ttl_telemetry_port_contract():
    """Validates structural constraints and hop_count lower bound on TtlTelemetryPort."""
    # 1. Valid instance
    port = TtlTelemetryPort(
        target_ip="192.168.1.1",
        baseline_ttl=64,
        hop_count=2,
    )
    assert port.target_ip == "192.168.1.1"
    assert port.baseline_ttl == 64
    assert port.hop_count == 2

    # 2. Negative hop_count should raise ValidationError
    with pytest.raises(ValueError):
        TtlTelemetryPort(
            target_ip="192.168.1.1",
            baseline_ttl=64,
            hop_count=-1,
        )


def test_icmp_ttl_adapter_baseline_determination():
    """Validates baseline TTL categorization for standard OS archetypes."""
    mock_bus = MagicMock()
    adapter = IcmpTtlAdapter(event_bus=mock_bus)

    assert adapter._determine_baseline(50) == 64   # Linux/BSD/macOS
    assert adapter._determine_baseline(64) == 64
    assert adapter._determine_baseline(100) == 128  # Windows
    assert adapter._determine_baseline(128) == 128
    assert adapter._determine_baseline(200) == 255  # Network switch/router
    assert adapter._determine_baseline(255) == 255


def test_icmp_checksum_and_echo_packet():
    """Validates ICMP Type 8 Echo Request packet building and RFC 1071 checksum."""
    pid = 54321
    seq = 7
    packet = _build_icmp_echo(pid, seq)
    assert len(packet) == 8 + 32  # 8 bytes header + 32 bytes AETHERIS payload
    assert packet[0] == 8  # Type 8 Echo Request
    assert packet[1] == 0  # Code 0

    # RFC 1071 verification: checksum of valid packet evaluates to 0
    assert _icmp_checksum(packet) == 0


@pytest.mark.asyncio
async def test_icmp_ttl_adapter_process_targets():
    """Validates asynchronous target processing and telemetry publishing."""
    mock_bus = MagicMock()
    mock_bus.push_telemetry = AsyncMock()

    adapter = IcmpTtlAdapter(event_bus=mock_bus)

    # Mock raw sweep returning returning_ttl values
    mock_sweep = {
        "192.168.1.10": 62,   # baseline 64 -> hop_count 2
        "192.168.1.20": 125,  # baseline 128 -> hop_count 3
        "192.168.1.30": 250,  # baseline 255 -> hop_count 5
    }

    with patch.object(adapter, "_execute_raw_sweep", return_value=mock_sweep):
        derived = await adapter.process_targets(["192.168.1.10", "192.168.1.20", "192.168.1.30"])

    assert derived["192.168.1.10"] == 2
    assert derived["192.168.1.20"] == 3
    assert derived["192.168.1.30"] == 5

    assert mock_bus.push_telemetry.call_count == 3
    calls = mock_bus.push_telemetry.call_args_list

    q, payload = calls[0][0]
    assert q == "aetheris:telemetry:l3_ttl_intel"
    assert payload["target_ip"] == "192.168.1.10"
    assert payload["baseline_ttl"] == 64
    assert payload["hop_count"] == 2


def test_ttl_interrogator_compatibility_facade():
    """Validates compatibility imports and facade execution."""
    from aetheris.core.probers.l3_network.ttl_interrogator import (
        ActiveTTLInterrogator,
        _icmp_checksum as compat_chksum,
        _build_icmp_echo as compat_build,
    )
    from aetheris.core.probers.active_ttl_interrogator import (
        ActiveTTLInterrogator as CoreInterrogator,
    )

    interrogator = ActiveTTLInterrogator(target_ips=["192.168.1.1"])
    assert interrogator.target_ips == ["192.168.1.1"]
    assert interrogator.timeout <= 0.5
    assert hasattr(interrogator, "execute")

    core_interrogator = CoreInterrogator(target_ips=["192.168.1.1"])
    assert core_interrogator.target_ips == ["192.168.1.1"]

    pkt = compat_build(100, 1)
    assert compat_chksum(pkt) == 0

