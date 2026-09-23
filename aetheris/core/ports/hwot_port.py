"""
Project AETHERIS - Hardware OT (HWOT) Loopback Simulator Port Interface
Hexagonal Protocol defining ephemeral mock loopback responders for industrial protocols
(EtherNet/IP CIP, Siemens S7Comm ISO-on-TCP).
Strict zero-I/O boundary: Contains zero socket, struct, mcp, or network transport imports.
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


class HwotServerStatus(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    status: str = Field(...)
    protocol: Optional[str] = Field(default=None)
    port: int = Field(...)
    emulated_device: Optional[str] = Field(default=None)


class HwotTerminationResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    terminated_ports: List[int] = Field(default_factory=list)


@runtime_checkable
class HwotSimulatorPort(Protocol):
    """Hexagonal Protocol defining ephemeral OT device simulation contracts."""

    def spawn_cip_plc(self, port: int = 44818) -> HwotServerStatus:
        """Launches an ephemeral EtherNet/IP CIP PLC mock responder."""
        ...

    def spawn_s7_plc(self, port: int = 10102) -> HwotServerStatus:
        """Launches an ephemeral Siemens S7Comm ISO-on-TCP mock responder."""
        ...

    def kill_all(self) -> HwotTerminationResult:
        """Terminates all running mock loopback responders."""
        ...

