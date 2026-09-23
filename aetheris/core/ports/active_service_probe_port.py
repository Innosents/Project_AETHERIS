"""
Project AETHERIS - Active Service Probe Hexagonal Port Contract (Phase 56).

Defines frozen, mapping-compatible Pydantic v2 models and the
``@runtime_checkable`` Protocol boundary for active mDNS, SSDP, NetBIOS,
WS-Discovery, LLMNR, and Intel AMT probing.

Separation rationale
--------------------
* ``_FrozenMappingModel`` — immutable Pydantic base with read-only dict
  surface so legacy callers using ``result.get("ip")`` / ``result["vendor"]``
  keep working without modification.  ``__setitem__`` raises ``TypeError``
  to make immutability explicit rather than silently allowing mutation.
* ``DiscoveredServiceEndpoint`` — canonical return type for all six
  single-result probe methods.
* ``StealthProbeSummary`` — return type for the concurrent stealth sweep.
* ``ActiveServiceProbePort`` — structural Protocol; implementations gain
  compliance via ``isinstance(obj, ActiveServiceProbePort)`` at runtime.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Frozen mapping-compatible base
# ---------------------------------------------------------------------------

class _FrozenMappingModel(BaseModel):
    """Pydantic v2 base model that is immutable yet dict-readable.

    * ``frozen=True``    — all fields are read-only after instantiation.
    * ``extra="allow"``  — extra keyword arguments are silently accepted and
                           stored so callers can pass ad-hoc keys without
                           validation errors during the transition period.
    * Dict surface       — ``__getitem__``, ``get``, ``__contains__``,
                           ``keys``, ``items``, ``values`` delegate to
                           ``model_dump()`` so the object is transparently
                           usable wherever a plain dict is expected.
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    # ------------------------------------------------------------------
    # Mapping read surface
    # ------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        if key in self.__class__.model_fields:
            return getattr(self, key)
        extra = self.__pydantic_extra__ or {}
        if key in extra:
            return extra[key]
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:  # type: ignore[override]
        raise TypeError(
            f"{self.__class__.__name__} is frozen; "
            f"cannot set key {key!r} after construction."
        )

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str) and key in self.__class__.model_fields:
            return getattr(self, key) is not None
        extra = self.__pydantic_extra__ or {}
        return key in extra

    def keys(self):  # type: ignore[override]
        return self.model_dump().keys()

    def items(self):  # type: ignore[override]
        return self.model_dump().items()

    def values(self):  # type: ignore[override]
        return self.model_dump().values()


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

class DiscoveredServiceEndpoint(_FrozenMappingModel):
    """Normalised, immutable record produced by a single active probe.

    All six unicast/multicast probe methods — ``probe_mdns``,
    ``probe_ssdp``, ``probe_netbios``, ``probe_ws_discovery``,
    ``probe_llmnr``, and ``probe_intel_amt`` — return instances of
    this model (or ``None``).

    Fields intentionally mirror the dict keys previously returned so
    that existing dict-access call sites require zero changes.
    """

    ip: str = Field(default="", description="Source IPv4 address of the responding device")
    hostname: str = Field(default="", description="Resolved NetBIOS / mDNS / LLMNR hostname")
    vendor: str = Field(default="generic", description="Hardware or software vendor name")
    type: str = Field(default="unknown", description="Device archetype slug (e.g. smart_tv, router)")
    model: str = Field(default="Network Endpoint", description="Device hardware or software model string")
    source: str = Field(default="", description="Telemetry provenance tag (e.g. active_mdns, netbios_137)")

    # Optional fields populated by specific probes only
    os_version: Optional[str] = Field(
        default=None,
        description="OS or firmware descriptor; populated by Intel AMT probe",
    )
    friendly_name: Optional[str] = Field(
        default=None,
        description="UPnP / WSD friendly name string; populated by WS-Discovery probe",
    )
    serial_number: Optional[str] = Field(
        default=None,
        description="Hardware serial number; populated by Roku ECP probe",
    )
    discovery_method: Optional[str] = Field(
        default=None,
        description="Protocol sub-method used to identify the device (e.g. roku_ecp_rest)",
    )
    raw_mdns: Optional[str] = Field(
        default=None,
        description="First 120 characters of the raw mDNS response payload (latin-1 decoded)",
    )
    server_header: Optional[str] = Field(
        default=None,
        description="Value of the HTTP Server: header from an SSDP 200 OK response",
    )


class StealthProbeSummary(_FrozenMappingModel):
    """Aggregated result of the concurrent multi-protocol stealth sweep.

    ``probe_stealth_endpoint`` fans out NetBIOS, WS-Discovery, LLMNR, and
    Intel AMT sub-probes concurrently; this model consolidates their outputs
    into a single immutable record.

    ``stealth_probes`` stores each sub-probe's serialised dict (keyed by
    source tag) so the payload remains JSON-serialisable without further
    transformation.
    """

    ip: str = Field(..., description="Target host IPv4 address")
    hostname: Optional[str] = Field(default=None, description="Resolved hostname (first winning probe)")
    vendor: Optional[str] = Field(default=None, description="Resolved vendor (first winning probe)")
    type: Optional[str] = Field(default=None, description="Device archetype (first winning probe)")
    model: Optional[str] = Field(default=None, description="Device model (first winning probe)")
    os_version: Optional[str] = Field(default=None, description="OS descriptor (first winning probe)")
    banners: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw banner map reserved for future L7 banner injection",
    )
    stealth_probes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Per-source serialised probe results keyed by source tag",
    )


# ---------------------------------------------------------------------------
# Port Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class ActiveServiceProbePort(Protocol):
    """Structural Protocol declaring the public active-probe API surface.

    Implementations satisfy this protocol by structural subtyping; no
    explicit ABC inheritance is required.  Use::

        assert isinstance(prober, ActiveServiceProbePort)

    to verify compliance at runtime.
    """

    def probe_mdns(self) -> List[DiscoveredServiceEndpoint]:
        """Broadcasts mDNS PTR queries and returns all decoded endpoints."""
        ...

    def probe_ssdp(self) -> List[DiscoveredServiceEndpoint]:
        """Sends UPnP M-SEARCH and returns all decoded SSDP endpoints."""
        ...

    def probe_netbios(self, target_ip: str) -> Optional[DiscoveredServiceEndpoint]:
        """Unicasts NetBIOS Node Status to UDP 137 and returns endpoint or None."""
        ...

    def probe_ws_discovery(self, target_ip: str) -> Optional[DiscoveredServiceEndpoint]:
        """Unicasts WS-Discovery SOAP Probe to UDP 3702 and returns endpoint or None."""
        ...

    def probe_llmnr(self, target_ip: str) -> Optional[DiscoveredServiceEndpoint]:
        """Unicasts LLMNR reverse PTR query to UDP 5355 and returns endpoint or None."""
        ...

    def probe_intel_amt(self, target_ip: str) -> Optional[DiscoveredServiceEndpoint]:
        """Probes Intel AMT HTTP interface on TCP 16992/16993; returns endpoint or None."""
        ...

    def probe_stealth_endpoint(self, target_ip: str) -> StealthProbeSummary:
        """Concurrent multi-protocol stealth sweep; returns aggregated summary."""
        ...

