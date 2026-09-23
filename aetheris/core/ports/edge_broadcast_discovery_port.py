"""
Project AETHERIS - Edge Node Broadcast & Multicast Discovery Port
Hexagonal Protocol defining targeted Layer 2/3 broadcast and multicast probes
(SIP PnP, WS-Discovery/ONVIF, SSDP, Ubiquiti, MikroTik, BACnet, EtherNet/IP).
Strict zero-I/O boundary: Contains zero socket, select, or network transport imports.
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


class DiscoveredEdgeNode(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(..., description="IPv4 address of responding edge endpoint")
    type: str = Field(default="generic")
    vendor: str = Field(default="generic")
    model: str = Field(default="Network Endpoint")
    protocol: str = Field(..., description="Discovery vector protocol (e.g. SIP PnP, ONVIF, BACnet)")
    hostname: Optional[str] = Field(default=None)
    banner: Optional[str] = Field(default=None)
    open_ports: List[int] = Field(default_factory=list)


@runtime_checkable
class EdgeBroadcastDiscoveryPort(Protocol):
    """Hexagonal Protocol defining targeted subnet broadcast and multicast sweeps."""

    def broadcast_targeted_cluster_probe(
        self,
        device_type: str = "generic",
        vendor: str = "generic",
        target_subnet: str = "10.10.4.0/24"
    ) -> List[DiscoveredEdgeNode]:
        """Dispatches cluster-specific broadcast probes and returns discovered nodes."""
        ...

