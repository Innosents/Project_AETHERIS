"""
Project AETHERIS - Spatial Bayesian Fusion Engine Port Interface
Hexagonal Protocol defining Bayesian archetype evidence fusion, calibrated
kernel turnaround offsets, and multi-layer topology projection.
Strict zero-I/O boundary: Contains zero sqlite3, socket, subprocess, or network transport imports.
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


class ArchetypeInferenceResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    archetype: str = Field(...)
    confidence: float = Field(...)
    posterior: Dict[str, float] = Field(default_factory=dict)
    raw_tau_ns_samples: List[float] = Field(default_factory=list)
    min_tau_ns: float = Field(default=0.0)
    calibrated_kernel_turnaround_us: float = Field(default=1000.0)


class PortProfileRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    port_id: str = Field(default="Unknown")
    link_speed_mbps: int = Field(default=1000)
    connection_type: str = Field(default="Ethernet")
    t_hop_ns: float = Field(default=18.5)
    is_wireless: bool = Field(default=False)


class HopParametersRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    tier: str = Field(...)
    hop_delay_ns: float = Field(...)
    effective_rate_mbps: int = Field(...)
    sigma_jitter_ns: float = Field(...)


@runtime_checkable
class BayesianFusionPort(Protocol):
    """Hexagonal Protocol defining Bayesian likelihood calculation and latency compensation."""
    __test__ = False

    @classmethod
    def fuse_evidence(cls, observed_keys: List[str]) -> Dict[str, float]:
        """Calculates normalized posterior probabilities across archetypes."""
        ...

    @classmethod
    def infer_archetype_from_flight_times(
        cls,
        observed_keys: List[str],
        tau_ns_samples: List[float]
    ) -> ArchetypeInferenceResult:
        """Infers device archetype based on observed tokens and nanosecond flight times."""
        ...


@runtime_checkable
class SpatialSolverPort(Protocol):
    """Hexagonal Protocol defining graph projection from ingested discovery matrices."""
    __test__ = False

    def ingest_telemetry(
        self,
        chassis_matrix: Optional[Dict[str, Any]] = None,
        stp_matrix: Optional[Dict[str, Any]] = None,
        ttl_matrix: Optional[Dict[str, Any]] = None,
        multicast_matrix: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Ingests raw multi-signal telemetry matrices."""
        ...

    def project_topology(self, fused_matrix: Optional[Dict[str, Any]] = None) -> Any:
        """Projects ingested matrices into a directed topology graph."""
        ...
