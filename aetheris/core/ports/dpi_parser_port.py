"""
Project AETHERIS - Deep Packet Inspection (DPI) Parser Port Interface
Hexagonal Protocol defining wire-speed application protocol decoding and OT framing dissection.
Strict zero-I/O boundary: Contains zero scapy, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Pydantic model supporting modern attribute access and legacy dictionary lookups."""
    def __getitem__(self, item: str) -> Any:
        try:
            return getattr(self, item)
        except AttributeError:
            if hasattr(self, "raw_metadata") and isinstance(self.raw_metadata, dict) and item in self.raw_metadata:
                return self.raw_metadata[item]
            if hasattr(self, "options") and isinstance(self.options, dict) and item in self.options:
                return self.options[item]
            raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        try:
            val = getattr(self, item)
            if val is not None:
                return val
        except AttributeError:
            pass
        if hasattr(self, "raw_metadata") and isinstance(self.raw_metadata, dict) and item in self.raw_metadata:
            return self.raw_metadata[item]
        if hasattr(self, "options") and isinstance(self.options, dict) and item in self.options:
            return self.options[item]
        return default

    def __contains__(self, item: str) -> bool:
        if hasattr(self, item) and getattr(self, item) is not None:
            return True
        if hasattr(self, "raw_metadata") and isinstance(self.raw_metadata, dict) and item in self.raw_metadata:
            return True
        if hasattr(self, "options") and isinstance(self.options, dict) and item in self.options:
            return True
        return False


class DpiPeripheralSubsystem(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True, extra="allow")
    id: str = Field(...)
    name: str = Field(...)
    type: str = Field(...)
    protocol: str = Field(...)
    port: str = Field(...)
    status: str = Field(default="Online / Supervised")
    edge_type: Optional[str] = Field(default=None)


class DpiDecodedPayload(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True, extra="allow")
    protocol: str = Field(...)
    vendor: Optional[str] = Field(default=None)
    model: Optional[str] = Field(default=None)
    type: Optional[str] = Field(default=None)
    hostname: Optional[str] = Field(default=None)
    mac: Optional[str] = Field(default=None)
    ip: Optional[str] = Field(default=None)
    firmware: Optional[str] = Field(default=None)
    options: Dict[str, Any] = Field(default_factory=dict)
    peripherals: List[DpiPeripheralSubsystem] = Field(default_factory=list)
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.protocol and self.protocol != "UNKNOWN") or bool(self.raw_metadata)


@runtime_checkable
class DpiParserPort(Protocol):
    """Hexagonal Protocol defining deep packet inspection payload decoding."""

    @staticmethod
    def parse_payload(payload: bytes, src_port: int, dst_port: int, proto: str) -> DpiDecodedPayload:
        """Inspects raw payload bytes and extracts structured protocol telemetry."""
        ...
