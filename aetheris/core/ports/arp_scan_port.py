"""
Project AETHERIS - ARP Scanner Port Interface
Hexagonal Protocol defining Link-Layer ARP discovery and OS neighbor cache extraction.
Strict zero-I/O boundary: Contains zero scapy, socket, or subprocess imports.
"""
from typing import Protocol, runtime_checkable, List, Dict, Any, Optional
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


class ArpDeviceRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(..., description="IPv4 address discovered")
    mac: str = Field(..., description="Normalized EUI-48 MAC address (XX:XX:XX:XX:XX:XX)")
    source: str = Field(default="arp_scan", description="Discovery origin (e.g. scapy_raw_arp, os_arp_table)")


@runtime_checkable
class ArpScanPort(Protocol):
    """Hexagonal Protocol defining Layer 2 ARP broadcast interrogation."""

    def scan(self, network_cidr: str) -> List[ArpDeviceRecord]:
        """Executes link-layer ARP sweep and returns mapped devices."""
        ...

    @staticmethod
    def parse_arp_table_output(raw_output: str, target_cidr: Optional[str] = None) -> List[ArpDeviceRecord]:
        """Pure parsing helper converting OS 'arp -a' output to structured records."""
        ...
