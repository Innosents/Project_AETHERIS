"""Transport-free contracts for runtime path resolution."""

from pathlib import Path
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
            raise TypeError("Declared path fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class WorkspacePaths(_MappingCompatibleModel):
    """Validated workspace path metadata."""

    base_dir: str
    data_dir: str
    is_frozen: bool


class ResourcePathResult(_MappingCompatibleModel):
    """Validated resource resolution metadata."""

    relative_path: str
    resolved_path: str
    exists: bool


@runtime_checkable
class PathResolverPort(Protocol):
    """Port for runtime and workspace path resolution."""

    def is_frozen(self) -> bool:
        ...

    def detect_and_mount_live_workspace(self) -> Optional[Path]:
        ...

    def get_base_dir(self) -> Path:
        ...

    def get_resource_path(self, relative_path: str) -> Path:
        ...

    def get_data_dir(self) -> Path:
        ...
