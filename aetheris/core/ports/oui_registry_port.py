"""Transport-free contracts for OUI data access and registry lookup."""

from typing import Any, Dict, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic payload retaining legacy dictionary access."""

    model_config = ConfigDict(frozen=True, extra="allow")

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __contains__(self, key: str) -> bool:
        if key in self.__class__.model_fields:
            return getattr(self, key) is not None
        return key in (self.__pydantic_extra__ or {})

    def keys(self):
        return self.model_dump().keys()

    def items(self):
        return self.model_dump().items()

    def values(self):
        return self.model_dump().values()

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared OUI fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class OuiVendorRecord(_MappingCompatibleModel):
    """Validated vendor mapping record."""

    mac_prefix: str = Field(..., min_length=1)
    vendor_name: str = Field(..., min_length=1)
    normalized_prefix: str = Field(..., min_length=1)


class OuiLookupResult(_MappingCompatibleModel):
    """Validated lookup outcome for a MAC address or OUI prefix."""

    matched: bool
    vendor: Optional[str] = None
    prefix: Optional[str] = None


class DeviceArchetypeProfile(_MappingCompatibleModel):
    """Validated vendor-to-device archetype profile."""

    archetype: str = Field(..., min_length=1)
    type: str = Field(..., min_length=1)


@runtime_checkable
class OuiDataSourcePort(Protocol):
    """Outbound source for loading raw OUI vendor records."""

    def load_oui_records(self) -> Dict[str, str]:
        ...


@runtime_checkable
class OuiRegistryPort(Protocol):
    """Inbound lookup contract for normalized OUI data."""

    def lookup(self, mac_or_prefix: str) -> Optional[str]:
        ...

    def is_known_vendor(self, mac: str) -> bool:
        ...

    def normalize_prefix(self, raw: str) -> str:
        ...

    def infer_archetype(self, vendor: str) -> Dict[str, str]:
        ...
