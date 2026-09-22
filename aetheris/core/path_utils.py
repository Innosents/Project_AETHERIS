"""Backward-compatible facade for runtime path resolution."""

from pathlib import Path
from typing import Optional

from aetheris.core.ports.path_resolver_port import PathResolverPort
from aetheris.infrastructure.adapters.system.filesystem_path_adapter import (
    FilesystemPathAdapter,
)


_path_resolver: PathResolverPort = FilesystemPathAdapter()


def is_frozen() -> bool:
    """Returns True if the application is running in a frozen bundle."""
    return _path_resolver.is_frozen()


def detect_and_mount_live_workspace() -> Optional[Path]:
    """Finds and mounts a live source workspace when available."""
    return _path_resolver.detect_and_mount_live_workspace()


def get_base_dir() -> Path:
    """Returns the application root directory."""
    return _path_resolver.get_base_dir()


def get_resource_path(relative_path: str) -> Path:
    """Resolves a bundled or source-workspace resource path."""
    return _path_resolver.get_resource_path(relative_path)


def get_data_dir() -> Path:
    """Returns the writable data directory."""
    return _path_resolver.get_data_dir()


__all__ = [
    "detect_and_mount_live_workspace",
    "get_base_dir",
    "get_data_dir",
    "get_resource_path",
    "is_frozen",
]
