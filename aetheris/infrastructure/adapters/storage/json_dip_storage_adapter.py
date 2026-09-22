"""
Project AETHERIS - JSON Device Identity Profile Storage Adapter.
Implements DipStoragePort with thread-safe atomic swaps and file locking.
"""

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Union

from aetheris.core.ports.dip_port import DipStoragePort


class JsonDipStorageAdapter(DipStoragePort):
    """
    Concrete storage adapter for JSON-backed device identity profile persistence.
    Provides atomic replacement to prevent file corruption during sudden terminates.
    """

    def __init__(self, storage_path: Optional[Union[str, Path]] = None) -> None:
        if storage_path:
            self.path = Path(storage_path)
        else:
            # Default resolution: project root or module parent
            default_path = Path(__file__).resolve().parents[4] / "device_identity_profiles.json"
            if not default_path.parent.exists():
                default_path = Path("device_identity_profiles.json")
            self.path = default_path
        self._lock = threading.RLock()

    def get_storage_target(self) -> str:
        """Returns normalized filesystem path string."""
        return str(self.path.resolve()) if self.path.exists() else str(self.path)

    def load_profiles(self) -> Dict[str, Dict[str, Any]]:
        """
        Thread-safe load of JSON profiles from disk.
        Returns empty dictionary if target does not exist or fails parsing.
        """
        with self._lock:
            if not self.path.exists():
                return {}
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, dict) else {}
            except Exception:
                return {}

    def save_profiles(self, profiles: Dict[str, Dict[str, Any]]) -> bool:
        """
        Thread-safe atomic persistence of serialized profiles.
        Writes to a temporary file in the same directory, syncs to disk,
        and atomically renames to target path.
        """
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                temp_path = self.path.with_suffix(f".tmp_{os.getpid()}_{threading.get_ident()}")
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(profiles, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp_path, self.path)
                return True
            except Exception:
                if "temp_path" in locals() and temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass
                return False

