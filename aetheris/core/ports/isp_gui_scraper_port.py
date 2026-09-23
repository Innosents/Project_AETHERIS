"""
Project AETHERIS - ISP Edge Gateway GUI / Table Scraper Port
Hexagonal Protocol defining edge gateway ASCII/HTML device table parsing,
perimeter Layer-2 switchport mapping, and relational ledger persistence.
Strict zero-I/O boundary: Contains zero sqlite3, requests, bs4, or socket imports.
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


class GatewaySwitchportRecord(_MappingCompatibleModel):
    """Immutable record representing a gateway switchport or wireless interface binding."""
    model_config = ConfigDict(frozen=True)
    mac_address: str = Field(...)
    hostname: str = Field(default="")
    ip_address: Optional[str] = Field(default=None)
    interface_name: Optional[str] = Field(default=None)
    port_id: str = Field(default="Ethernet")
    link_speed_mbps: Optional[int] = Field(default=1000)
    duplex: Optional[str] = Field(default="Full")
    frequency: Optional[str] = Field(default=None)
    connection_type: str = Field(default="Ethernet")


class IspScraperSummary(_MappingCompatibleModel):
    """Immutable aggregation summary of parsed gateway switchport entries."""
    model_config = ConfigDict(frozen=True)
    total_records: int = Field(default=0)
    ethernet_count: int = Field(default=0)
    wireless_count: int = Field(default=0)
    records: List[GatewaySwitchportRecord] = Field(default_factory=list)


@runtime_checkable
class IspGuiScraperPort(Protocol):
    """Hexagonal Protocol defining edge gateway ASCII table parsing."""

    @staticmethod
    def parse_text(raw_text: str) -> List[GatewaySwitchportRecord]:
        """Parses edge gateway ASCII/HTML table dumps into structured records."""
        ...


@runtime_checkable
class GatewaySwitchportStoragePort(Protocol):
    """Hexagonal Protocol defining relational persistence for gateway switchports."""

    def sync_records(self, devices: List[Union[GatewaySwitchportRecord, Dict[str, Any]]]) -> None:
        """Persists switchport records into the perimeter ledger."""
        ...

