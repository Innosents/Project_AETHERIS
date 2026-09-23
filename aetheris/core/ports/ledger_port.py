"""
Project AETHERIS - Spatial Topology Ledger Port Interface
Hexagonal Protocol defining asynchronous topology node/edge persistence,
temporal eviction, and graph store hydration.
Strict zero-I/O boundary: Contains zero redis, fakeredis, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Tuple
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


class NodeTelemetryPayload(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    node_id: str = Field(...)
    parent_switch_id: Optional[str] = Field(default=None)
    edge_type: str = Field(default="ETHERNET")
    distance_m: float = Field(default=0.0)
    confidence_pct: float = Field(default=0.0)
    tau_ns: Optional[float] = Field(default=None)
    node_props: Dict[str, Any] = Field(default_factory=dict)


class EvictionSummary(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    evicted_nodes: int = Field(default=0)
    evicted_edges: int = Field(default=0)


class HydratedNode(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    node_id: str = Field(...)
    props: Dict[str, Any] = Field(default_factory=dict)


class HydratedEdge(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    source_id: str = Field(...)
    target_id: str = Field(...)
    props: Dict[str, Any] = Field(default_factory=dict)


class HydrationStoreResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    nodes: List[HydratedNode] = Field(default_factory=list)
    edges: List[HydratedEdge] = Field(default_factory=list)

    def __iter__(self):
        """Supports legacy tuple unpacking: nodes, edges = await ledger.hydrate_store()"""
        return iter(([n.model_dump() for n in self.nodes], [e.model_dump() for e in self.edges]))


@runtime_checkable
class LedgerPort(Protocol):
    """Hexagonal Protocol defining graph and telemetry persistence contracts."""
    __test__ = False

    async def init_db(self) -> None:
        """Initializes backend structures and verifies client connectivity."""
        ...

    async def start_worker(self) -> None:
        """Starts asynchronous background write-behind worker."""
        ...

    async def shutdown(self) -> None:
        """Flushes queue and safely halts background worker."""
        ...

    async def hydrate_store(self) -> HydrationStoreResult:
        """Hydrates active nodes and edges for spatial visualization."""
        ...

    def evict_expired(self, max_age_seconds: float = 3600.0) -> EvictionSummary:
        """Evicts expired temporal entries based on maximum age threshold."""
        ...
