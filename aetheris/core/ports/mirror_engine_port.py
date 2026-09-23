"""
Project AETHERIS - Port Mirroring (SPAN/RSPAN/ERSPAN) & Frame Ingestion Port
Hexagonal Protocol defining promiscuous packet capture, multi-VLAN tag extraction,
ERSPAN GRE decapsulation, L2/L3/L4 demuxing, DPI stream hand-off, and lock-free stats aggregation.
Strict zero-I/O boundary: Contains zero socket, scapy, subprocess, or sqlite3 imports.
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


class DissectedFlowRecord(_MappingCompatibleModel):
    """Immutable record capturing dissected L2/L3/L4 headers, VLANs, and DPI payloads."""
    model_config = ConfigDict(frozen=True, extra="allow")
    src_mac: str = Field(default="")
    dst_mac: str = Field(default="")
    vlan_id: Optional[int] = Field(default=None)
    ethertype: int = Field(default=0)
    src_ip: Optional[str] = Field(default=None)
    dst_ip: Optional[str] = Field(default=None)
    proto: Optional[str] = Field(default=None)
    src_port: Optional[int] = Field(default=None)
    dst_port: Optional[int] = Field(default=None)
    opcode: Optional[str] = Field(default=None)
    telemetry: Dict[str, Any] = Field(default_factory=dict)


class MirrorCaptureSummary(_MappingCompatibleModel):
    """Immutable summary capturing mirrored SPAN ingestion statistics."""
    model_config = ConfigDict(frozen=True)
    packets_captured: int = Field(default=0)
    bytes_captured: int = Field(default=0)
    vlans_discovered: List[int] = Field(default_factory=list)
    protocols_detected: Dict[str, int] = Field(default_factory=dict)
    active_hosts_count: int = Field(default=0)
    ptp_hardware_timestamping: Dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class MirrorEnginePort(Protocol):
    """Hexagonal Protocol defining mirrored packet ingestion, VLAN dissection, and flow decoding."""

    def process_raw_frame(self, frame: bytes) -> DissectedFlowRecord:
        """Decodes raw wire frame into structured DissectedFlowRecord."""
        ...

    def get_summary_stats(self) -> MirrorCaptureSummary:
        """Returns snapshot of current mirrored traffic statistics."""
        ...

    def start_capture(self, interface: Optional[str] = None) -> None:
        """Starts live promiscuous/SPAN ingestion."""
        ...

    def stop_capture(self) -> None:
        """Stops live capture loop."""
        ...
