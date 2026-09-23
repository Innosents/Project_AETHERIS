"""
Project AETHERIS - Deep Industrial Protocol Discovery Port
Hexagonal Protocol defining non-disruptive, authentic OT / ICS active probes
across Siemens S7Comm, Rockwell EtherNet/IP CIP, Mercury Security MSP,
Modbus/TCP, RTSP/ONVIF, and Avigilon ACC.
Strict zero-I/O boundary: Contains zero socket, struct, select, or transport imports.
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


class IndustrialProbeResult(_MappingCompatibleModel):
    """Immutable result schema for industrial protocol discovery probes."""
    model_config = ConfigDict(frozen=True, extra="allow")
    vendor: str = Field(...)
    type: str = Field(...)
    model: str = Field(...)
    protocol: str = Field(...)
    status: Optional[str] = Field(default=None)
    szl_raw: Optional[str] = Field(default=None)
    cip_identity: Optional[str] = Field(default=None)
    raw_msp: Optional[str] = Field(default=None)
    rtsp_server_header: Optional[str] = Field(default=None)
    throughput_tracking: Optional[str] = Field(default=None)


@runtime_checkable
class IndustrialDiscoveryPort(Protocol):
    """Hexagonal Protocol defining deep industrial OT/ICS protocol discovery operations."""

    def probe_siemens_s7(self, ip: str, port: int = 102) -> Optional[IndustrialProbeResult]:
        """Performs RFC 1006 COTP + S7Comm SZL 0x0011 module identification."""
        ...

    def probe_ethernet_ip_cip(self, ip: str, port: int = 44818) -> Optional[IndustrialProbeResult]:
        """Performs EtherNet/IP CIP ListIdentity command (0x0063)."""
        ...

    def probe_mercury_access(self, ip: str, port: int = 3001) -> Optional[IndustrialProbeResult]:
        """Sends MSP framing POLL probe to identify Mercury access controllers."""
        ...

    def probe_modbus_tcp(self, ip: str, port: int = 502) -> Optional[IndustrialProbeResult]:
        """Performs Modbus MEI 14 / FC03 holding register discovery."""
        ...

    def probe_rtsp_onvif(self, ip: str, port: int = 554) -> Optional[IndustrialProbeResult]:
        """Performs RTSP OPTIONS and ONVIF video endpoint identification."""
        ...

    def probe_avigilon_acc(self, ip: str, port: int = 38880) -> Optional[IndustrialProbeResult]:
        """Queries Avigilon ACC cluster control port for NVR discovery."""
        ...
