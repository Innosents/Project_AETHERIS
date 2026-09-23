"""
Project AETHERIS - Topology Graph Store Port Interface
Hexagonal Protocol defining directed topology graph persistence,
spatial distance edge estimation, and Cytoscape WebGL element projection.
Strict zero-I/O boundary: Contains zero networkx, socket, subprocess, or network transport imports.
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


class GraphNodeRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    node_id: str = Field(...)
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdgeRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    source: str = Field(...)
    target: str = Field(...)
    edge_type: str = Field(default="ETHERNET_LINK")
    distance_m: Optional[float] = Field(default=None)
    variance_m2: Optional[float] = Field(default=None)
    confidence_pct: float = Field(default=0.0)
    is_anchor: bool = Field(default=False)
    extra_attrs: Dict[str, Any] = Field(default_factory=dict)


class CytoscapeElement(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    data: Dict[str, Any] = Field(default_factory=dict)
    classes: str = Field(default="")


class GraphStoreExport(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    nodes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    edges: List[Dict[str, Any]] = Field(default_factory=list)
    cytoscape_elements: List[Dict[str, Any]] = Field(default_factory=list)


@runtime_checkable
class GraphStorePort(Protocol):
    """Hexagonal Protocol defining directed topology graph state manipulation."""
    __test__ = False

    def upsert_node(self, node_id: str, properties: Optional[Dict[str, Any]] = None) -> None:
        """Upserts a topological node (switch, endpoint, gateway, peripheral)."""
        ...

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str = "ETHERNET_LINK",
        distance_m: Optional[float] = None,
        variance_m2: Optional[float] = None,
        confidence_pct: float = 0.0,
        is_anchor: bool = False,
        **extra_attrs
    ) -> None:
        """Upserts a directed physical link with spatial uncertainty metrics."""
        ...

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves raw node properties if the node exists."""
        ...

    def get_edge(self, source: str, target: str) -> Optional[Dict[str, Any]]:
        """Retrieves link properties between two nodes if the edge exists."""
        ...

    def get_all_nodes(self) -> Dict[str, Dict[str, Any]]:
        """Returns a copy of all nodes and their property mappings."""
        ...

    def get_all_edges(self) -> List[Dict[str, Any]]:
        """Returns all edges formatted as an adjacency list."""
        ...

    def get_neighbors(self, node_id: str) -> List[str]:
        """Returns immediate outbound adjacent neighbors for a given node."""
        ...

    def get_cytoscape_elements(self) -> List[Dict[str, Any]]:
        """Serializes the topology graph for Cytoscape WebGL rendering."""
        ...

    def to_json(self) -> str:
        """Exports graph state to serialized JSON string."""
        ...

    def from_json(self, json_str: str) -> None:
        """Restores graph state from serialized JSON string."""
        ...
