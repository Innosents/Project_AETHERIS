"""Thin compatibility facade for legacy AETHERIS prober imports."""

from aetheris.core.ports.legacy_probe_port import (
    AetherisProbeRegistry,
    BaseAetherisProbe,
)
from aetheris.infrastructure.adapters.compat.probers_bridge import (
    ActiveCAMExtractor,
    ActiveTTLInterrogator,
    MulticastIdentityProbe,
    SpanningTreeTelemetryProbe,
    TCPClockSkewProbe,
    TCPZeroWindowProbe,
    _build_icmp_echo,
    _icmp_checksum,
    install_prober_compatibility_bridges,
)

install_prober_compatibility_bridges()

__all__ = [
    "ActiveCAMExtractor",
    "ActiveTTLInterrogator",
    "AetherisProbeRegistry",
    "BaseAetherisProbe",
    "MulticastIdentityProbe",
    "SpanningTreeTelemetryProbe",
    "TCPClockSkewProbe",
    "TCPZeroWindowProbe",
    "_build_icmp_echo",
    "_icmp_checksum",
    "install_prober_compatibility_bridges",
]
