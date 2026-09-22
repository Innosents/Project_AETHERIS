"""Transport-free contracts for low-voltage DC drop analysis and spatial fusion."""

from typing import Any, Optional, Protocol, runtime_checkable

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
            raise TypeError("Declared DC-drop fields are immutable")
        extra = dict(self.__pydantic_extra__ or {})
        extra[key] = value
        object.__setattr__(self, "__pydantic_extra__", extra)


class PeripheralElectricalEnvelopeModel(_MappingCompatibleModel):
    """Validated peripheral electrical envelope."""

    quiescent_current_a: float = Field(..., ge=0.0)
    peak_inrush_current_a: float = Field(..., ge=0.0)
    inductive_kickback_variance: bool = False


class ConductorDistanceResult(_MappingCompatibleModel):
    """Validated per-conductor distance computation output."""

    distance_m: float
    distance_ft: float
    sigma_distance_m: float
    sigma_distance_ft: float
    voltage_drop_v: float
    current_amps: float
    wire_gauge_awg: int
    temperature_c: float
    r_per_meter_ohms: float
    loop_resistance_ohms: float
    out_of_spec: bool
    status: str = Field(..., min_length=1)


class BaudDivergenceResult(_MappingCompatibleModel):
    """Validated baud-rate divergence assessment output."""

    status: str = Field(..., min_length=1)
    anomaly_detected: bool
    distance_dc_m: float
    expected_baud_distance_m: float
    divergence_ratio: float
    threshold_ratio: float


class DualPhysicalConstraintResult(_MappingCompatibleModel):
    """Validated RF/DC dual-constraint fusion output."""

    status: str = Field(..., min_length=1)
    anomaly_detected: bool
    distance_rf_m: float
    distance_dc_m: float
    distance_fused_m: float
    delta_distance_m: float
    tolerance_m: float
    agreement_score: float
    fault_classification: str = Field(..., min_length=1)


@runtime_checkable
class DcDropResolverPort(Protocol):
    """Port for low-voltage DC spatial drop and dual-constraint resolution."""

    def calculate_conductor_distance(
        self,
        v_source: float,
        v_terminal: float,
        current_amps: float,
        awg: int = 22,
        temp_c: float = 25.0,
        sigma_v: float = 0.05,
        sigma_i_ratio: float = 0.05,
    ) -> ConductorDistanceResult:
        ...

    def resolve_peripheral_telemetry(
        self,
        controller_id: str,
        peripheral: dict,
        v_source: float = 12.0,
        upstream_tdr_m: float = 0.0,
        temp_c: float = 25.0,
        d_tcp_flight_m: Optional[float] = None,
        expected_baud_distance_m: Optional[float] = None,
        raise_on_divergence: bool = True,
    ) -> dict:
        ...

    def evaluate_dual_physical_constraints(
        self,
        distance_rf_m: float,
        distance_dc_m: float,
        tolerance_m: float = 4.0,
    ) -> DualPhysicalConstraintResult:
        ...

    def get_conductor_resistance_per_meter(
        self,
        awg: int,
        temp_c: float = 25.0,
    ) -> float:
        ...

    def calculate_dynamic_spatial_drop(
        self,
        v_source: float,
        v_sampled: float,
        envelope: PeripheralElectricalEnvelopeModel,
        r_20: float,
        t_ambient: float = 20.0,
    ) -> tuple[float, float, str]:
        ...

    def evaluate_baud_rate_divergence(
        self,
        distance_dc_m: float,
        expected_baud_distance_m: float,
        threshold_ratio: float = 0.35,
        raise_on_divergence: bool = True,
        peripheral_id: Optional[str] = None,
    ) -> BaudDivergenceResult:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "PeripheralElectricalEnvelopeModel",
    "ConductorDistanceResult",
    "BaudDivergenceResult",
    "DualPhysicalConstraintResult",
    "DcDropResolverPort",
]
