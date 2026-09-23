"""
Project AETHERIS - Spatial Pipeline Orchestrator Port Interface
Hexagonal Protocol defining multi-layer telemetry fusion orchestration,
asynchronous hardware sweep coordination, and topological projection hand-off.
Strict zero-I/O boundary: Contains zero networkx, socket, scapy, subprocess, or sqlite3 imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Union
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


class FusionTelemetryInput(_MappingCompatibleModel):
    """Input parameters and telemetry matrices for spatial fusion execution."""
    model_config = ConfigDict(frozen=True, extra="allow")
    target_subnet: str = Field(default="192.168.1.0/24")
    duration: float = Field(default=65.0)
    l2_matrix: Dict[str, Any] = Field(default_factory=dict)
    l3_matrix: Dict[str, Any] = Field(default_factory=dict)
    cam_mapping: Dict[str, Any] = Field(default_factory=dict)


class SpatialFusionResult(_MappingCompatibleModel):
    """Output schema capturing completed multi-layer spatial topology fusion."""
    model_config = ConfigDict(frozen=True, extra="allow")
    orchestration_state: str = Field(default="SPATIAL_FUSION_COMPLETE")
    edge_port_mapping: Dict[str, Any] = Field(default_factory=dict)
    cytoscape_graph: Dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class SpatialOrchestratorPort(Protocol):
    """Hexagonal Protocol defining spatial fusion pipeline orchestration."""
    __test__ = False

    async def execute_aetheris_fusion(
        self, target_subnet: str, duration: float = 65.0
    ) -> SpatialFusionResult:
        """Executes asynchronous hardware telemetry capture and projects spatial topology."""
        ...
