"""
Project AETHERIS - Banner Grab Port Interface
Hexagonal Protocol defining Layer 4-7 service banner extraction and cryptographic certificate auditing.
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


class ParsedBannerTokens(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    server: Optional[str] = Field(default=None)
    title: Optional[str] = Field(default=None)
    cookie: Optional[str] = Field(default=None)
    tls_subject: Optional[str] = Field(default=None)
    raw_snippet: Optional[str] = Field(default=None)


class BannerGrabResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    ip: str = Field(...)
    port: int = Field(..., ge=1, le=65535)
    banner: str = Field(...)
    protocol_hint: Optional[str] = Field(default=None)
    tokens: Optional[ParsedBannerTokens] = Field(default=None)


@runtime_checkable
class BannerGrabPort(Protocol):
    """Hexagonal Protocol defining application-layer identity vector extraction."""

    def grab(self, ip: str, port: int, timeout: float = 1.0) -> Optional[BannerGrabResult]:
        """Extracts structured banner and certificate tokens from target port."""
        ...

    @staticmethod
    def parse_http_descriptors(raw_text: str) -> ParsedBannerTokens:
        """Pure parsing helper extracting title, server, and cookie tokens from raw text."""
        ...
