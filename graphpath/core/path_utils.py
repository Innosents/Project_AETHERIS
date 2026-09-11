"""
GraphPath / Project AETHERIS Path & Environment Resolution Utilities
Provides unified base directory and static resource resolution across
both standard Python execution and frozen PyInstaller (.exe) standalone packages.
Supports Dynamic Hybrid Mounting: dynamically imports live source code
from the local workspace when present, avoiding the need to recompile the binary on every edit.
"""

import os
import sys
from pathlib import Path
from typing import Optional

def is_frozen() -> bool:
    """Returns True if the application is running in a PyInstaller or frozen binary bundle."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")

def detect_and_mount_live_workspace() -> Optional[Path]:
    """
    Detects if GraphPath source files exist in the current working directory,
    parent directory, or executable directory, and mounts them at index 0 of sys.path.
    """
    candidates = [
        Path.cwd() / "graphpath",
        Path.cwd(),
        Path(sys.executable).resolve().parent / "graphpath",
        Path(sys.executable).resolve().parent,
        Path(__file__).resolve().parent.parent.parent if not is_frozen() else None,
        Path(__file__).resolve().parent.parent if not is_frozen() else None
    ]
    for cand in candidates:
        if cand and cand.exists():
            if (cand / "core").is_dir() and (cand / "discovery").is_dir():
                resolved = cand.resolve()
                resolved_str = str(resolved)
                if resolved_str not in sys.path:
                    sys.path.insert(0, resolved_str)
                return resolved
            if (cand / "graphpath").is_dir():
                resolved = cand.resolve()
                resolved_str = str(resolved)
                if resolved_str not in sys.path:
                    sys.path.insert(0, resolved_str)
                return resolved
    return None

def get_base_dir() -> Path:
    """
    Returns the root directory of the application.
    - If running as a frozen executable: returns the directory containing the .exe (or the temp bundle).
    - If running from source: returns the project root.
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    else:
        return Path(__file__).resolve().parent.parent.parent

def get_resource_path(relative_path: str) -> Path:
    """
    Resolves bundled static assets, profiles, templates, and schemas.
    - First checks the live workspace directory if available.
    - In frozen mode: checks sys._MEIPASS (internal bundle), then falls back to exe folder.
    - In source mode: checks relative to get_base_dir().
    """
    live_ws = detect_and_mount_live_workspace()
    if live_ws:
        live_asset = live_ws / relative_path
        if live_asset.exists():
            return live_asset
        # Also check inside graphpath subdirectory if applicable
        if (live_ws / "graphpath" / relative_path).exists():
            return live_ws / "graphpath" / relative_path

    if is_frozen():
        bundle_path = Path(sys._MEIPASS) / relative_path
        if bundle_path.exists():
            return bundle_path
        exe_path = Path(sys.executable).resolve().parent / relative_path
        if exe_path.exists():
            return exe_path
        return bundle_path
    else:
        direct_path = get_base_dir() / relative_path
        if direct_path.exists():
            return direct_path
        pkg_path = get_base_dir() / "graphpath" / relative_path
        if pkg_path.exists():
            return pkg_path
        return direct_path

def get_data_dir() -> Path:
    """
    Returns a writable directory for logs, snapshots, and persistent caches.
    In frozen mode, defaults to the directory where the .exe resides or APPDATA.
    """
    live_ws = detect_and_mount_live_workspace()
    if live_ws:
        return live_ws
    return get_base_dir()
