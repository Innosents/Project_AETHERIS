"""
Project AETHERIS - Bridge Forwarding Database (FDB / CAM) Crawler Port
Hexagonal Protocol defining Bridge-MIB / Q-BRIDGE-MIB switchport harvesting.
Strict zero-I/O boundary: Contains zero pysnmp, socket, or sqlite3 imports.
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


class BridgeFdbEntry(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    mac: str = Field(..., description="Normalized MAC address (XX:XX:XX:XX:XX:XX)")
    port: str = Field(..., description="Switch port identifier or index")
    vlan_id: Optional[int] = Field(default=None)
    status: Optional[str] = Field(default="learned")


class BridgeFdbCrawlResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    switch_ip: str = Field(...)
    entries: List[BridgeFdbEntry] = Field(default_factory=list)
    success: bool = Field(default=True)
    error_message: Optional[str] = Field(default=None)


@runtime_checkable
class BridgeFdbCrawlerPort(Protocol):
    """Hexagonal Protocol defining switch FDB / CAM table harvesting."""

    def crawl_switch(self, switch_ip: str, community: str = "public") -> BridgeFdbCrawlResult:
        """Harvests Bridge-MIB forwarding database entries from target switch."""
        ...

    @staticmethod
    def oid_suffix_to_mac_and_vlan(oid_suffix: str) -> Dict[str, Any]:
        """Pure helper resolving OID suffix into MAC address and VLAN ID."""
        ...

    @staticmethod
    def is_virtual_or_multicast_mac(mac: str) -> bool:
        """Pure filter rejecting virtual, multicast, or broadcast MACs."""
        ...
