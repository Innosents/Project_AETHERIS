import re
from pydantic import BaseModel, Field, field_validator

class BayesianTelemetryPort(BaseModel):
    """
    Strict inbound data contract for network state mutations.
    Acts as the primary Hexagonal Inbound Port isolating the domain core.
    """
    hardware_id: str = Field(
        ..., 
        description="IEEE 802 MAC address representation of the edge node."
    )
    splice_probability: float = Field(
        ..., 
        ge=0.0, 
        le=1.0, 
        description="Calculated Dirichlet anchor probability."
    )
    spatial_jitter_ms: float = Field(
        ..., 
        ge=0.0, 
        description="Observed Layer 2/3 latency variance in milliseconds."
    )

    @field_validator("hardware_id")
    @classmethod
    def validate_mac_address(cls, v: str) -> str:
        if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", v):
            raise ValueError(f"Invalid hardware_id format: {v}")
        return v.upper()


from typing import Optional
from aetheris.core.ports.l2_chassis_inbound import ChassisTelemetryPort


class ChassisIntelligencePort(ChassisTelemetryPort):
    """Hexagonal inbound port adapter bridging chassis telemetry to orchestrator."""
    hardware_id: Optional[str] = None

    def model_post_init(self, __context) -> None:
        if not self.hardware_id and self.mac_address:
            self.hardware_id = self.mac_address
