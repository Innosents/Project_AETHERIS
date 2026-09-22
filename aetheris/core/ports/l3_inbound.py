from pydantic import BaseModel, Field, field_validator
import re

class Layer3TelemetryPort(BaseModel):
    ip_address: str = Field(..., description="IPv4 address of the discovered node")
    hardware_id: str = Field(..., description="Resolved MAC address")
    rtt_ms: float = Field(..., ge=0.0, description="Round Trip Time in milliseconds")
    open_ports: list[int] = Field(default_factory=list, description="List of responsive TCP/UDP ports")

    @field_validator('hardware_id')
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            raise ValueError(f'Invalid MAC: {v}')
        return v.upper()

