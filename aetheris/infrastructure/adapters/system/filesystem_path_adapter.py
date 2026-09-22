"""Concrete runtime and filesystem path resolution adapter."""

import os
import sys
from pathlib import Path
from typing import Optional

from aetheris.core.ports.path_resolver_port import PathResolverPort


class FilesystemPathAdapter(PathResolverPort):
    """Resolves source-workspace and frozen-bundle paths."""

    def is_frozen(self) -> bool:
        return bool(getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"))

    def detect_and_mount_live_workspace(self) -> Optional[Path]:
        candidates = [
            Path.cwd() / "aetheris",
            Path.cwd(),
            Path(sys.executable).resolve().parent / "aetheris",
            Path(sys.executable).resolve().parent,
            Path(__file__).resolve().parent.parent.parent.parent.parent
            if not self.is_frozen()
            else None,
            Path(__file__).resolve().parent.parent.parent.parent
            if not self.is_frozen()
            else None,
        ]
        for candidate in candidates:
            if candidate and candidate.exists():
                if (candidate / "core").is_dir() and (candidate / "discovery").is_dir():
                    resolved = candidate.resolve()
                    resolved_str = str(resolved)
                    if resolved_str not in sys.path:
                        sys.path.insert(0, resolved_str)
                    return resolved
                if (candidate / "aetheris").is_dir():
                    resolved = candidate.resolve()
                    resolved_str = str(resolved)
                    if resolved_str not in sys.path:
                        sys.path.insert(0, resolved_str)
                    return resolved
        return None

    def get_base_dir(self) -> Path:
        if self.is_frozen():
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent.parent.parent.parent.parent

    def get_resource_path(self, relative_path: str) -> Path:
        live_workspace = self.detect_and_mount_live_workspace()
        if live_workspace:
            live_asset = live_workspace / relative_path
            if live_asset.exists():
                return live_asset
            nested_asset = live_workspace / "aetheris" / relative_path
            if nested_asset.exists():
                return nested_asset

        if self.is_frozen():
            bundle_path = Path(sys._MEIPASS) / relative_path
            if bundle_path.exists():
                return bundle_path
            executable_path = Path(sys.executable).resolve().parent / relative_path
            if executable_path.exists():
                return executable_path
            return bundle_path

        direct_path = self.get_base_dir() / relative_path
        if direct_path.exists():
            return direct_path
        package_path = self.get_base_dir() / "aetheris" / relative_path
        if package_path.exists():
            return package_path
        return direct_path

    def get_data_dir(self) -> Path:
        live_workspace = self.detect_and_mount_live_workspace()
        if live_workspace:
            return live_workspace
        return self.get_base_dir()


__all__ = ["FilesystemPathAdapter"]
