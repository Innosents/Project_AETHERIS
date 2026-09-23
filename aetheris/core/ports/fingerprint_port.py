"""
Project AETHERIS - Device Fingerprint & Passive Stack Classifier Port
Hexagonal Protocol defining multi-vector heuristic device classification,
TCP SYN/ACK fingerprinting, and DHCP Option 55 OS stack inference.
Strict zero-I/O boundary: Contains zero sqlite3, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Union
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


class DeviceFingerprintRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    mac: str = Field(default="00:00:00:00:00:00")
    vendor: str = Field(default="Unknown Vendor")
    type: str = Field(default="unknown")
    model: str = Field(default="Generic Device")
    open_ports: List[int] = Field(default_factory=list)
    banners: Dict[str, Any] = Field(default_factory=dict)
    services: List[str] = Field(default_factory=list)
    discovery_method: str = Field(default="heuristic_dna_fingerprint")
    hw_vendor: Optional[str] = Field(default=None)


class InferredOsProfileRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    mac: str = Field(default="00:00:00:00:00:00")
    os_profile: str = Field(...)
    confidence: float = Field(default=95.0, ge=0.0, le=100.0)
    synack_ttl: int = Field(default=64)
    window_size: int = Field(default=14600)
    option55: str = Field(default="")
    evidence: str = Field(default="")


@runtime_checkable
class DeviceFingerprintPort(Protocol):
    """Hexagonal Protocol defining multi-attribute heuristic hardware classification."""

    def fingerprint(
        self,
        ip: str,
        mac: str,
        open_ports: List[int],
        banners: Dict[str, Any],
        services: List[str]
    ) -> DeviceFingerprintRecord:
        """Fuses port patterns, banner strings, and MAC allocations into a discrete device record."""
        ...


@runtime_checkable
class PassiveStackStoragePort(Protocol):
    """Hexagonal persistence boundary for inferred OS profiles."""

    def save_profiles(self, profiles: Dict[str, InferredOsProfileRecord]) -> None:
        """Persists profile records to the ledger."""
        ...

