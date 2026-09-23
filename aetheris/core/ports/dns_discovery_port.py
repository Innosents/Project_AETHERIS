"""
Project AETHERIS - DNS Discovery & Domain Enumeration Port
Hexagonal Protocol defining reverse PTR resolution, SRV harvesting,
and BGP latency overlay detection to unmask SD-WAN/Cloud VPN adjacencies.
Strict zero-I/O boundary: Contains zero socket, dnspython, or transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Set
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(dict):
    """Dual-mode structure supporting attribute lookups, dict access, CPython json.dumps, and frozen immutability."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        is_frozen = getattr(self.__class__, "_frozen", False) or getattr(self.__class__, "frozen", False)
        if hasattr(self.__class__, "model_config"):
            cfg = getattr(self.__class__, "model_config")
            if isinstance(cfg, dict) and cfg.get("frozen"):
                is_frozen = True
            elif getattr(cfg, "frozen", False):
                is_frozen = True
        if hasattr(self.__class__, "Config"):
            cfg_cls = getattr(self.__class__, "Config")
            if getattr(cfg_cls, "frozen", False):
                is_frozen = True
        object.__setattr__(self, "_is_frozen", is_frozen)

    def __getattribute__(self, item: str) -> Any:
        try:
            return self[item]
        except (KeyError, TypeError):
            pass
        return super().__getattribute__(item)

    def __setattr__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        self[item] = value

    def __setitem__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__setitem__(item, value)

    def __delattr__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        try:
            del self[item]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item}'")

    def __delitem__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__delitem__(item)

    def get(self, item: str, default: Any = None) -> Any:
        return super().get(item, default)

    def model_dump(self) -> Dict[str, Any]:
        return dict(self)

    def dict(self) -> Dict[str, Any]:
        return dict(self)


class GeoPoint(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    latitude: float = Field(default=0.0)
    longitude: float = Field(default=0.0)
    city: str = Field(default="")
    country: str = Field(default="")
    asn: Optional[str] = Field(default=None)
    isp: Optional[str] = Field(default=None)


class DnsSrvRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    service: str = Field(...)
    target: str = Field(...)
    port: int = Field(..., ge=1, le=65535)
    priority: int = Field(default=0)
    weight: int = Field(default=0)


class OverlayPathEvaluation(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    ptr_hostname: str = Field(default="")
    sensor_geo: GeoPoint = Field(default_factory=GeoPoint)
    target_geo: GeoPoint = Field(default_factory=GeoPoint)
    geodesic_distance_km: float = Field(default=0.0)
    rtt_min_ms: float = Field(default=0.0)
    empirical_rtt_ms: float = Field(default=0.0)
    rtt_delta_ms: float = Field(default=0.0)
    flags: List[str] = Field(default_factory=list)
    is_overlay: bool = Field(default=False)
    cloud_provider: str = Field(default="")


@runtime_checkable
class DnsDiscoveryPort(Protocol):
    """Hexagonal Protocol defining DNS discovery and overlay path evaluation."""

    def sweep_ptr_records(self, ips: List[str]) -> Dict[str, str]:
        """Performs reverse DNS PTR lookups for a list of IP addresses."""
        ...

    def discover_srv_records(self, domain: str) -> List[DnsSrvRecord]:
        """Discovers SRV records for domain controllers and VoIP services."""
        ...

    def evaluate_overlay_path(
        self,
        ip: str,
        ptr_hostname: str = "",
        empirical_rtt_ms: float = 0.0,
        sensor_geo: Optional[Dict[str, Any]] = None,
        target_geo: Optional[Dict[str, Any]] = None
    ) -> OverlayPathEvaluation:
        """Evaluates virtualized network adjacencies and unmasks SD-WAN/VPN overlays."""
        ...

