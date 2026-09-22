"""Typed core contracts for device DNA and OUI classification."""

from typing import Any, Dict, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic model with the legacy dictionary read surface."""

    model_config = ConfigDict(frozen=True, extra="allow")

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __contains__(self, key: str) -> bool:
        if key in self.__class__.model_fields:
            return getattr(self, key) is not None
        extra = self.__pydantic_extra__ or {}
        return key in extra

    def keys(self):
        return self.model_dump().keys()

    def items(self):
        return self.model_dump().items()

    def __setitem__(self, key: str, value: Any) -> None:
        """Preserve legacy enrichment writes without replacing declared fields."""
        if key in self.__class__.model_fields:
            raise TypeError("Declared device classification fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class DeviceDna(_MappingCompatibleModel):
    """Validated device identity evidence and optional enrichment fields."""

    mac: Optional[str] = None
    ip: Optional[str] = None
    vendor: Optional[str] = None
    type: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    os_family: Optional[str] = None


class OuiClassificationResult(_MappingCompatibleModel):
    """Validated OUI-derived vendor classification."""

    vendor: str = Field(..., min_length=1)
    type: str = Field(default="unknown", min_length=1)
    model: str = Field(..., min_length=1)
    os: Optional[str] = None
    archetype: Optional[str] = None


class DeviceClassificationResult(DeviceDna):
    """Validated, enriched device DNA returned by the classifier."""


@runtime_checkable
class DeviceClassifierPort(Protocol):
    """Port for deterministic device classification and NVP resolution."""

    @classmethod
    def classify_oui(cls, mac: str) -> Optional[OuiClassificationResult]:
        ...

    @classmethod
    def resolve_nvp(
        cls,
        mac: Optional[str] = None,
        vendor: Optional[str] = None,
        device_type: Optional[str] = None,
        default_nvp: float = 0.69,
    ) -> float:
        ...

    def classify(self, device_dna: DeviceDna) -> DeviceClassificationResult:
        ...
