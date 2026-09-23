"""
Project AETHERIS - Topology State Manager Port Interface
Hexagonal Protocol defining memory-bounded dual-ledger topology tracking,
LRU eviction, delta mutation extraction, and TTL lifecycle management.
Strict zero-I/O boundary: Contains zero websockets, socket, or network transport imports.
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


class DeltaPayloadRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    adds: List[Dict[str, Any]] = Field(default_factory=list)
    removes: List[str] = Field(default_factory=list)


class StateManagerMetrics(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    static_node_count: int = Field(default=0)
    ephemeral_node_count: int = Field(default=0)
    max_ephemeral: int = Field(default=50000)
    ttl_seconds: float = Field(default=300.0)


@runtime_checkable
class TopologyStateManagerPort(Protocol):
    """Hexagonal Protocol defining memory-bounded topology state tracking."""
    __test__ = False

    def upsert_ephemeral_telemetry(self, node_id: str, payload: Dict[str, Any]) -> None:
        """Executes O(1) injection and LRU eviction, updating the delta mutator."""
        ...

    def extract_and_flush_deltas(self) -> str:
        """Atomically extracts the delta and resets the ledger. Yields Cytoscape-ready JSON."""
        ...

    def get_metrics(self) -> StateManagerMetrics:
        """Returns current dual-ledger metrics and capacity boundaries."""
        ...
