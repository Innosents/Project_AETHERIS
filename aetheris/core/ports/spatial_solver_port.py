"""Transport-free contracts and immutable models for Weighted Least-Squares spatial solving."""

from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(BaseModel):
    """Frozen Pydantic payload retaining legacy dictionary access."""

    model_config = ConfigDict(frozen=True, extra="allow")

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __contains__(self, key: str) -> bool:
        if key in self.__class__.model_fields:
            return getattr(self, key) is not None
        return key in (self.__pydantic_extra__ or {})

    def keys(self):
        return self.model_dump().keys()

    def items(self):
        return self.model_dump().items()

    def values(self):
        return self.model_dump().values()

    def __len__(self) -> int:
        return len(self.model_dump())

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self.__class__.model_fields:
            raise TypeError("Declared spatial solver fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class SpatialSolverResultModel(_MappingCompatibleModel):
    """Encapsulates multi-anchor WLS calibration parameters."""

    calibrated_nvp: float
    calibrated_switch_latency_s: float
    calibrated_switch_latency_us: float = 0.0
    slowness_x2: float
    residuals: List[float] = Field(default_factory=list)
    anchor_count: int = 0
    wls_confidence: float = 0.0
    is_clamped: bool = False
    rmse_ns: float = 0.0
    fallback_nominal: bool = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if args:
            field_names = [
                "calibrated_nvp",
                "calibrated_switch_latency_s",
                "slowness_x2",
                "residuals",
                "anchor_count",
                "wls_confidence",
                "is_clamped",
                "rmse_ns",
                "fallback_nominal",
            ]
            for name, val in zip(field_names, args):
                kwargs[name] = val
        if "calibrated_switch_latency_us" not in kwargs and "calibrated_switch_latency_s" in kwargs:
            kwargs["calibrated_switch_latency_us"] = round(float(kwargs["calibrated_switch_latency_s"]) * 1e6, 4)
        super().__init__(**kwargs)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "calibrated_nvp": round(float(self.calibrated_nvp), 6),
            "calibrated_switch_latency_s": float(self.calibrated_switch_latency_s),
            "calibrated_switch_latency_us": round(float(self.calibrated_switch_latency_s) * 1e6, 4),
            "slowness_x2": float(self.slowness_x2),
            "residuals": [round(float(r), 4) for r in self.residuals],
            "anchor_count": int(self.anchor_count),
            "wls_confidence": round(float(self.wls_confidence), 2),
            "is_clamped": bool(self.is_clamped),
            "rmse_ns": round(float(self.rmse_ns), 4),
            "fallback_nominal": bool(self.fallback_nominal),
        }


class SpatialDistanceEstimateModel(_MappingCompatibleModel):
    """Encapsulates dynamically calibrated cable run distance estimate."""

    distance_m: float
    variance_m2: float
    confidence_pct: float
    net_flight_time_ns: float
    is_virtual_overlay: bool = False
    virtual_overlay_type: Optional[str] = None
    overlay_flags: List[str] = Field(default_factory=list)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if args:
            field_names = [
                "distance_m",
                "variance_m2",
                "confidence_pct",
                "net_flight_time_ns",
                "is_virtual_overlay",
                "virtual_overlay_type",
                "overlay_flags",
            ]
            for name, val in zip(field_names, args):
                kwargs[name] = val
        super().__init__(**kwargs)

    def __iter__(self):
        yield self.distance_m
        yield self.variance_m2
        yield self.confidence_pct
        yield self.net_flight_time_ns

    def to_dict(self) -> Dict[str, Any]:
        return {
            "distance_m": round(float(self.distance_m), 2),
            "variance_m2": round(float(self.variance_m2), 4),
            "confidence_pct": round(float(self.confidence_pct), 1),
            "net_flight_time_ns": round(float(self.net_flight_time_ns), 2),
            "is_virtual_overlay": self.is_virtual_overlay,
            "virtual_overlay_type": self.virtual_overlay_type,
            "overlay_flags": list(self.overlay_flags or []),
        }


@runtime_checkable
class SpatialSolverPort(Protocol):
    """Port for multi-anchor WLS calibration and spatial distance estimation."""

    def calibrate_multi_anchor(
        self,
        anchor_profiles: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        ...

    def calibrate_baseline(
        self,
        anchor_profiles: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        ...

    def estimate_distance(
        self,
        rtt_samples: Union[List[float], float],
        t_kernel: float,
        jitter_ns: Optional[float] = None,
        overlay_flags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "SpatialSolverResultModel",
    "SpatialDistanceEstimateModel",
    "SpatialSolverPort",
]

