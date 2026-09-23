"""
Project AETHERIS - Unified Geolocation, LLDP-MED & Spatial Path Reasoner Port
Hexagonal Protocol defining macro WAN GPS resolution, great-circle Haversine geodesics,
speed-of-light optical fiber delay models, ANSI/TIA-1057 LLDP-MED civic location dissection,
and multi-hop physical connection path reasoning.
Strict zero-I/O boundary: Contains zero urllib, requests, socket, scapy, or transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Union, Tuple
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


class PublicGeoMetadata(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    public_ip: str = Field(default="10.10.7.1")
    country: str = Field(default="United States")
    country_code: str = Field(default="US")
    region: str = Field(default="")
    city: str = Field(default="Local Site")
    postal_code: str = Field(default="")
    latitude: float = Field(default=37.7749)
    longitude: float = Field(default=-122.4194)
    timezone: str = Field(default="UTC")
    isp: str = Field(default="Enterprise ISP Uplink")
    asn: str = Field(default="AS-Corporate")
    source: str = Field(default="environment_profile_fallback")
    gateway: Optional[str] = Field(default=None)


class NormalizedCivicAddress(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    building: str = Field(default="")
    floor: str = Field(default="")
    floor_raw: str = Field(default="")
    room: str = Field(default="")
    rack: str = Field(default="")
    country: str = Field(default="")
    zone_type: str = Field(default="STANDARD")
    is_restricted: bool = Field(default=False)
    is_public: bool = Field(default=False)


class PhysicalVectorResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    spatial_path: str = Field(...)
    src_civic: Union[NormalizedCivicAddress, Dict[str, Any]] = Field(...)
    dst_civic: Union[NormalizedCivicAddress, Dict[str, Any]] = Field(...)
    same_building: bool = Field(...)
    same_floor: bool = Field(...)
    same_room: bool = Field(...)
    latency_us: float = Field(default=0.0)
    byte_count: int = Field(default=0)
    flags: List[str] = Field(default_factory=list)


class SpatialPathSummary(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    macro_location: Union[PublicGeoMetadata, Dict[str, Any]] = Field(default_factory=dict)
    civic_location: Dict[str, Any] = Field(default_factory=dict)
    coordinates: Optional[Dict[str, Any]] = Field(default=None)
    spatial_path_trail: List[str] = Field(default_factory=list)
    accuracy_estimate_meters: Optional[float] = Field(default=None)
    is_virtual_overlay: bool = Field(default=False)
    overlay_flags: List[str] = Field(default_factory=list)


@runtime_checkable
class GeolocationEnginePort(Protocol):
    """Hexagonal boundary for public WAN GeoIP and speed-of-light delay models."""

    @classmethod
    def calculate_haversine_distance_km(cls, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Computes great-circle distance between two geographic coordinates in kilometers."""
        ...

    @classmethod
    def calculate_rtt_min_ms(cls, distance_km: float, inflation_scalar: float = 1.5) -> float:
        """Calculates minimum expected RTT in ms across fiber optics."""
        ...

    @classmethod
    def resolve_ip(cls, ip: str, force_refresh: bool = False) -> PublicGeoMetadata:
        """Resolves public IP metadata with caching."""
        ...

    @classmethod
    def resolve(cls, force_refresh: bool = False) -> PublicGeoMetadata:
        """Queries public GeoIP metadata."""
        ...


@runtime_checkable
class CivicLocationPort(Protocol):
    """Hexagonal boundary for ANSI/TIA-1057 LLDP-MED civic location dissection and spatial vector analysis."""

    @classmethod
    def decode_location_tlv(cls, payload: bytes) -> Dict[str, Any]:
        """Decodes LLDP-MED Location Identification TLV payload."""
        ...

    @classmethod
    def classify_zone(cls, room_or_zone: str) -> str:
        """Classifies room/zone into RESTRICTED, PUBLIC, or STANDARD."""
        ...

    @classmethod
    def normalize_civic_address(cls, raw_civic: Dict[str, Any]) -> NormalizedCivicAddress:
        """Normalizes civic address attributes into a clean, typed civic vector record."""
        ...

    @classmethod
    def compute_physical_vector(
        cls,
        src_civic: Dict[str, Any],
        dst_civic: Dict[str, Any],
        latency_us: float = 0.0,
        byte_count: int = 0
    ) -> PhysicalVectorResult:
        """Computes the physical spatial vector and evaluates tromboning/perimeter violations."""
        ...


@runtime_checkable
class SpatialPathReasonerPort(Protocol):
    """Hexagonal boundary for multi-hop spatial path deduction."""

    @staticmethod
    def compute_spatial_path(
        node_id: str,
        node_meta: Dict[str, Any],
        all_nodes: Dict[str, Dict[str, Any]],
        edges: List[Tuple[str, str, Dict[str, Any]]],
        macro_geo: Dict[str, Any]
    ) -> SpatialPathSummary:
        """Deduces physical and overlay connection trail."""
        ...
