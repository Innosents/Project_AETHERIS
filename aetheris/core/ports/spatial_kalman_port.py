"""
Project AETHERIS - Spatial Kalman Dynamic Estimator Port Interface
Hexagonal Protocol defining recursive physical distance state estimation,
inter-switch trunk transit delay deconvolution, and anchor hyperparameter calibration.
Strict zero-I/O boundary: Contains zero socket, subprocess, or network transport imports.
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


class AnchorRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    distance: float = Field(...)
    variance: float = Field(default=0.25)
    is_anchor: bool = Field(default=True)
    confidence_pct: float = Field(...)


class TrunkLinkRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    length_m: float = Field(...)
    media_type: str = Field(...)
    nvp: float = Field(...)
    one_way_flight_us: float = Field(...)
    asic_latency_us: float = Field(...)
    variance_m2: float = Field(...)


class PathTransitOverhead(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    flight_rtt_us: float = Field(...)
    asic_rtt_us: float = Field(...)
    total_overhead_rtt_us: float = Field(...)
    path_variance: float = Field(...)


class LinkStateEstimate(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    distance: float = Field(...)
    variance: float = Field(...)
    is_anchor: bool = Field(default=False)
    confidence_pct: float = Field(...)


@runtime_checkable
class SpatialKalmanPort(Protocol):
    """Hexagonal Protocol defining recursive spatial distance state filtering."""

    def register_anchor(self, link_id: str, true_distance_m: float, measurement_variance: float = 0.25) -> AnchorRecord:
        """Registers a known ground-truth anchor node distance."""
        ...

    def register_trunk_link(
        self,
        trunk_id: str,
        length_m: float,
        media_type: str = "COPPER_CAT6A",
        asic_latency_us: Optional[float] = None,
        variance_m2: float = 0.10
    ) -> TrunkLinkRecord:
        """Registers an inter-switch backbone trunk link."""
        ...

    def compute_path_transit_overhead(self, path_trunk_ids: List[str]) -> PathTransitOverhead:
        """Calculates round-trip propagation and ASIC transit latency over an ordered path."""
        ...

    def calibrate_hyperparameters_from_anchor(
        self,
        link_id: str,
        observed_rtt_us: float,
        target_stack_latency_us: float,
        prober_distance_m: float = 2.0,
        measurement_jitter_us: float = 0.02,
        path_trunk_ids: Optional[List[str]] = None
    ) -> None:
        """Calibrates building medium propagation velocity from anchor observation."""
        ...

    def update_link_rtt(
        self,
        link_id: str,
        observed_rtt_us: float,
        target_stack_latency_us: float,
        measurement_jitter_us: float = 0.05,
        prober_distance_m: float = 2.0,
        path_trunk_ids: Optional[List[str]] = None
    ) -> LinkStateEstimate:
        """Updates Bayesian distance posterior for an edge or trunk link."""
        ...

