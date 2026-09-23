"""
Project AETHERIS - ICMP Reachability Sweep Port
Hexagonal Protocol defining concurrent network-layer ICMP echo operations,
host availability detection, and sweep aggregation.
Strict zero-I/O boundary: Contains zero subprocess, socket, scapy, or sqlite3 imports.
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


class IcmpHostResult(_MappingCompatibleModel):
    """Immutable result schema for an individual ICMP echo request."""
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    is_reachable: bool = Field(...)
    rtt_ms: Optional[float] = Field(default=None)
    ttl: Optional[int] = Field(default=None)
    status: str = Field(default="UNKNOWN")
    error: Optional[str] = Field(default=None)


class IcmpSweepSummary(_MappingCompatibleModel):
    """Immutable aggregation schema for concurrent ICMP sweeps."""
    model_config = ConfigDict(frozen=True)
    total_hosts: int = Field(default=0)
    reachable_hosts: List[str] = Field(default_factory=list)
    unreachable_hosts: List[str] = Field(default_factory=list)
    elapsed_sec: float = Field(default=0.0)


@runtime_checkable
class IcmpScanPort(Protocol):
    """Hexagonal Protocol defining ICMP echo reachability probing and bulk subnet sweeps."""

    def ping_host(self, ip: str, timeout_ms: int = 300) -> IcmpHostResult:
        """Executes an ICMP echo check against target IP."""
        ...

    def sweep(self, hosts: List[str], max_workers: int = 60) -> List[str]:
        """Executes concurrent ICMP reachability sweep returning active IP strings."""
        ...
