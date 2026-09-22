from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re

class DpiTelemetryPort(BaseModel):
    protocol: str = Field(..., description="Identified protocol (e.g., UBNT, MNDP, BACNET_IP, STP_BPDU)")
    mac_address: str = Field(..., description="Discovered endpoint MAC")
    vendor: str = Field(default="Unknown")
    device_type: str = Field(default="unknown")
    model: str = Field(default="")
    firmware: Optional[str] = None
    hostname: Optional[str] = None
    archetype: str = Field(..., description="Bayesian prior archetype classification")
    kernel_turnaround_us: Optional[float] = Field(None, ge=0.0)
    kernel_prior_std_us: Optional[float] = Field(None, ge=0.0)

    @field_validator('mac_address')
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not v or not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            return "00:00:00:00:00:00"
        return v.upper()

