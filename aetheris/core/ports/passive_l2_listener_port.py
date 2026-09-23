"""
Project AETHERIS - Passive L2 Topology Listener Port Interface
Hexagonal Protocol defining passive Layer 2 CDP & LLDP frame parsing and switch telemetry extraction.
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


class L2SwitchTelemetryRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True, extra="allow")
    protocol: str = Field(..., description="LLDP or CDP")
    switch_id: str = Field(...)
    chassis_id: Optional[str] = Field(default=None)
    system_name: Optional[str] = Field(default=None)
    port_id: Optional[str] = Field(default=None)
    management_ip: Optional[str] = Field(default=None)
    native_vlan: Optional[int] = Field(default=None)
    raw_mac: Optional[str] = Field(default=None)


class L2ListenerSummary(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    discovered_count: int = Field(default=0)
    switches: Dict[str, L2SwitchTelemetryRecord] = Field(default_factory=dict)
    protocols_observed: List[str] = Field(default_factory=list)


@runtime_checkable
class PassiveL2ListenerPort(Protocol):
    """Hexagonal Protocol defining passive Layer 2 switch topology discovery."""

    def process_packet(self, packet: Any) -> Optional[L2SwitchTelemetryRecord]:
        """Dissects an incoming Ethernet frame into structured switch telemetry."""
        ...

    def parse_lldp_frame(self, frame: Any) -> Optional[L2SwitchTelemetryRecord]:
        """Extracts topology, chassis, and management metadata from an 802.1AB LLDPDU frame."""
        ...

    def parse_cdp_frame(self, frame: Any) -> Optional[L2SwitchTelemetryRecord]:
        """Extracts topology, device, and SVI metadata from a Cisco Discovery Protocol frame."""
        ...
