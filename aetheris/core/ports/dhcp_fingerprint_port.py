"""
Project AETHERIS - DHCP Fingerprint Port Interface
Hexagonal Protocol defining passive BOOTP/DHCP parameter request list decoding.
Strict zero-I/O boundary: Contains zero scapy, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List
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


class DhcpClassification(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    vendor: str = Field(default="Unknown Vendor")
    type: str = Field(default="unknown")
    model: str = Field(default="Generic DHCP Client")


class DhcpFingerprintResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    mac: str = Field(...)
    fingerprint_hash: str = Field(...)
    vendor_class_id: str = Field(default="")
    classification: DhcpClassification = Field(default_factory=DhcpClassification)
    discovery_method: str = Field(default="passive_dhcp_fingerprint")


@runtime_checkable
class DhcpFingerprintPort(Protocol):
    """Hexagonal Protocol defining passive DHCP Option 55/60 fingerprint classification."""

    @classmethod
    def classify_fingerprint(cls, fingerprint_hash: str, vendor_class_id: str = "") -> DhcpClassification:
        """Pure classification helper matching Option 55 sequence or Option 60 vendor class."""
        ...

    def parse_dhcp_options(self, packet: Any) -> Optional[DhcpFingerprintResult]:
        """Dissects live packet structure into normalized DhcpFingerprintResult."""
        ...

