"""
Project AETHERIS - Device Identity Profile (DIP) Port Contracts.
Defines immutable/mapping-compatible Pydantic models and Protocol boundaries
for identity profile caching, progressive learning, and decoupled storage persistence.
"""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Pydantic model with complete dictionary mapping read/write surface."""

    model_config = ConfigDict(extra="allow")

    def __getitem__(self, key: str) -> Any:
        if key in self.__class__.model_fields:
            return getattr(self, key)
        extra = self.__pydantic_extra__ or {}
        if key in extra:
            return extra[key]
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            setattr(self, key, value)
        else:
            extra = dict(self.__pydantic_extra__ or {})
            extra[key] = value
            object.__setattr__(self, "__pydantic_extra__", extra)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self:
            return self[key]
        return default

    def __contains__(self, key: str) -> bool:
        if key in self.__class__.model_fields:
            return getattr(self, key) is not None
        extra = self.__pydantic_extra__ or {}
        return key in extra

    def keys(self):
        return self.model_dump().keys()

    def items(self):
        return self.model_dump().items()

    def values(self):
        return self.model_dump().values()


class DeviceIdentityProfile(_MappingCompatibleModel):
    """Validated device identity profile with progressive learning metadata."""

    mac: str = Field(default="", description="Canonical colon-delimited MAC address")
    ip: str = Field(default="", description="Last known primary IPv4 or IPv6 address")
    vendor: str = Field(default="Unknown", description="Resolved hardware vendor")
    model: str = Field(default="Generic Endpoint", description="Device hardware model or brand")
    hostname: str = Field(default="", description="Resolved DNS/mDNS/NetBIOS hostname")
    dev_type: str = Field(default="unknown", description="Primary device category archetype")
    type: str = Field(default="unknown", description="Normalized device type alias")
    os_family: str = Field(default="unknown", description="Inferred OS family")
    observations: int = Field(default=0, ge=0, description="Total empirical observation count")
    times_observed: int = Field(default=0, ge=0, description="Alias for observations count")
    first_seen: float = Field(default=0.0, description="Initial observation epoch timestamp")
    last_seen: float = Field(default=0.0, description="Most recent observation epoch timestamp")
    confidence: float = Field(default=0.30, ge=0.0, le=1.0, description="Evidence confidence score")
    is_locked: bool = Field(default=False, description="Manual administrative override flag")
    environment_cidr: str = Field(default="default_lan", description="Associated network environment CIDR")
    source_proofs: List[str] = Field(default_factory=list, description="Historical telemetry proof sources")
    deep_signature: Dict[str, Any] = Field(default_factory=dict, description="L7 banner and deep prober fingerprint")
    profile_id: Optional[str] = Field(default=None, description="Unique profile identifier token")
    uplink_ip: Optional[str] = Field(default=None, description="Upstream gateway or switch IP")
    verified_fingerprint: bool = Field(default=False, description="Whether deep signature is verified")


class ProfileMatchResult(_MappingCompatibleModel):
    """Result of cross-referencing observation features against cached profiles."""

    matched: bool = Field(..., description="True if a profile match was established")
    profile: Optional[DeviceIdentityProfile] = Field(default=None, description="Matching identity profile")
    match_method: Optional[str] = Field(default=None, description="Method of match: mac, hostname, ip, or signature")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence of the match")


class ProfileLearningPayload(_MappingCompatibleModel):
    """Payload for incremental device learning from passive or active sweeps."""

    mac: str = Field(..., description="Target device MAC address")
    ip: str = Field(default="", description="Target device IP address")
    hostname: str = Field(default="", description="Observed network hostname")
    classified: Dict[str, Any] = Field(default_factory=dict, description="Classifier output attributes")
    env_cidr: str = Field(default="", description="Network environment CIDR")
    source_proof: str = Field(default="active_sweep", description="Evidence source tag")


@runtime_checkable
class DipStoragePort(Protocol):
    """Outbound port decoupling profile disk serialization and atomic file locking."""

    def load_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Loads serialized profile map from persistent storage."""
        ...

    def save_profiles(self, profiles: Dict[str, Dict[str, Any]]) -> bool:
        """Atomically persists profile map to persistent storage."""
        ...

    def get_storage_target(self) -> str:
        """Returns string representation of target storage destination."""
        ...


@runtime_checkable
class DeviceIdentityProfilePort(Protocol):
    """Inbound port contract for identity caching, learning, and cross-referencing."""

    def lookup(self, mac: str) -> Optional[DeviceIdentityProfile]:
        """Looks up cached profile by clean MAC address."""
        ...

    def lookup_by_mac(self, mac: str) -> Optional[DeviceIdentityProfile]:
        """Alias for lookup."""
        ...

    def lookup_by_ip(self, ip: str) -> Optional[DeviceIdentityProfile]:
        """Looks up highest confidence profile for a given IP."""
        ...

    def get_or_create(self, mac: str, ip: str = "") -> DeviceIdentityProfile:
        """Retrieves existing profile or initializes a newly discovered profile."""
        ...

    def ingest_observation(
        self,
        mac: str,
        ip: str = "",
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        hostname: Optional[str] = None,
        dev_type: Optional[str] = None,
        os_family: Optional[str] = None,
        evidence_source: str = "probe",
        **kwargs
    ) -> DeviceIdentityProfile:
        """Ingests telemetry observation and updates progressive confidence."""
        ...

    def lookup_dip(
        self,
        ip: str,
        mac: str = "",
        hostname: str = "",
        env_cidr: str = ""
    ) -> Optional[DeviceIdentityProfile]:
        """Multi-vector lookup across MAC, hostname, and environment-scoped IP."""
        ...

    def learn_device(
        self,
        ip: str,
        mac: str,
        hostname: str,
        classified: Dict[str, Any],
        env_cidr: str = "",
        source_proof: str = "active_sweep"
    ) -> Optional[DeviceIdentityProfile]:
        """Learns and registers newly classified device attributes."""
        ...

    def lock_profile(
        self,
        profile_id: str,
        custom_type: str,
        custom_vendor: str,
        custom_model: str,
        uplink_ip: Optional[str] = None
    ) -> bool:
        """Locks profile attributes against automated sweep overrides."""
        ...

    def get_all_profiles(self, env_cidr: Optional[str] = None) -> List[DeviceIdentityProfile]:
        """Retrieves all cached profiles optionally filtered by CIDR."""
        ...

    def lookup_by_fingerprint(
        self,
        mac: str = "",
        oui: str = "",
        deep_signature: Optional[Dict[str, Any]] = None
    ) -> Optional[DeviceIdentityProfile]:
        """Matches device by MAC, deep banner signatures, or OUI prefix."""
        ...

    def record_deep_signature(
        self,
        ip: str,
        mac: str,
        deep_fingerprint: Dict[str, Any],
        archetype: str,
        env_cidr: str = ""
    ) -> DeviceIdentityProfile:
        """Associates deep prober protocol fingerprint with device profile."""
        ...
