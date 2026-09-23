"""
Project AETHERIS - Serialization Prober Port Interface
Hexagonal Protocol defining active dual-payload ICMP transmission slope measurements,
Fast Ethernet bridge identification, and line-rate deconvolution.
Strict zero-I/O boundary: Contains zero scapy, socket, sqlite3, or network transport imports.
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


class SerializationSlopeRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True, extra="allow")
    ip: str = Field(...)
    switchport: str = Field(default="Port 1")
    rtt_64_us: float = Field(...)
    rtt_1400_us: float = Field(...)
    delta_t_serialization_us: float = Field(...)
    is_throttled: bool = Field(...)
    inferred_link_speed: str = Field(...)
    status: str = Field(...)
    samples_64: List[float] = Field(default_factory=list)
    samples_1400: List[float] = Field(default_factory=list)


class SerializationSweepSummary(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    total_scanned: int = Field(default=0)
    throttled_count: int = Field(default=0)
    line_rate_count: int = Field(default=0)
    records: List[SerializationSlopeRecord] = Field(default_factory=list)


@runtime_checkable
class SerializationProbePort(Protocol):
    """Hexagonal Protocol defining active ICMP transmission slope deconvolution."""

    def probe_host(
        self,
        ip: str,
        count: Optional[int] = None,
        timeout: Optional[float] = None
    ) -> SerializationSlopeRecord:
        """Sends dual-payload ICMP bursts to compute transmission slope Delta t."""
        ...

    def sweep_port1_targets(self, targets: Optional[List[str]] = None) -> List[SerializationSlopeRecord]:
        """Runs serialization slope sweep across endpoints."""
        ...


@runtime_checkable
class SerializationStoragePort(Protocol):
    """Hexagonal persistence boundary for serialization telemetry records."""

    def save_to_ledger(self, results: List[SerializationSlopeRecord]) -> None:
        """Persists serialization deconvolution records into the spatial ledger."""
        ...
