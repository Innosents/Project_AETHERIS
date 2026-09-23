"""
Project AETHERIS - Deep Protocol Prober Port
Hexagonal Protocol defining targeted protocol handshakes and identity extraction.
Strict zero-I/O boundary: Contains zero socket, ssl, or network transport imports.
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


class TlsCertInfo(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    port: int = Field(default=443)
    common_name: str = Field(default="")
    organization: str = Field(default="")


class OnvifDeviceInfo(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    vendor: str = Field(default="Axis Communications")
    model: str = Field(default="Network Camera")
    firmware: str = Field(default="")
    type: str = Field(default="camera")


class DeepProbeEndpointResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(...)
    vendor: Optional[str] = Field(default=None)
    model: Optional[str] = Field(default=None)
    os_version: Optional[str] = Field(default=None)
    type: Optional[str] = Field(default=None)
    banner: Optional[str] = Field(default=None)
    details: Dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class DeepProberPort(Protocol):
    """Hexagonal Protocol defining deep application-layer protocol handshakes."""

    def probe_port(self, ip: str, port: int, timeout: float = 0.6) -> Optional[DeepProbeEndpointResult]:
        """Probes an open port using the appropriate protocol handshake."""
        ...

    @staticmethod
    def parse_onvif_soap_response(xml_text: str) -> Optional[OnvifDeviceInfo]:
        """Pure XML parser extracting manufacturer, model, and firmware from ONVIF SOAP response."""
        ...

    @staticmethod
    def parse_http_identity(http_response: str) -> Dict[str, str]:
        """Pure parser extracting Server header and HTML title from HTTP response."""
        ...

