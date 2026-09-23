"""
Project AETHERIS - Concurrent TCP Port Scanner Port Interface
Hexagonal Protocol defining concurrent transport-layer port sweeps and status reporting.
Strict zero-I/O boundary: Contains zero socket, scapy, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Tuple
from pydantic import BaseModel, ConfigDict, Field

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 502, 554,
    631, 993, 995, 1433, 1521, 3306, 3389, 5060, 5432, 5985, 5986, 8080, 8443, 37777, 44818
]


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


class PortProbeResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    port: int = Field(...)
    is_open: bool = Field(...)
    latency_ms: Optional[float] = Field(default=None)

    def __iter__(self):
        """Allows legacy unpacking: port, is_open = scan_single_port(...)"""
        return iter((self.port, self.is_open))


class PortScanSummary(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    open_ports: List[int] = Field(default_factory=list)
    scanned_count: int = Field(default=0)
    status: str = Field(default="completed")

    def __iter__(self):
        """Allows legacy unpacking: open_ports, status = scan_ports_with_status(...)"""
        return iter((self.open_ports, self.status))


@runtime_checkable
class PortScanPort(Protocol):
    """Hexagonal Protocol defining concurrent TCP port sweeps."""

    def scan_single_port(self, ip: str, port: int, timeout: float = 0.4) -> PortProbeResult:
        """Tests if an individual TCP port is open."""
        ...

    def scan_ports(
        self,
        ip: str,
        ports: Optional[List[int]] = None,
        timeout: float = 0.4,
        max_workers: int = 50
    ) -> PortScanSummary:
        """Scans a list of target ports concurrently and returns open ports and status."""
        ...
