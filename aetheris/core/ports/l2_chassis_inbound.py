from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re

class ChassisTelemetryPort(BaseModel):
    mac_address: str = Field(..., description="Source MAC of the emitting switch/router")
    protocol: str = Field(..., description="Discovery protocol: 'CDP' or 'LLDP'")
    hostname: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    port_id: Optional[str] = None
    chassis_mac: Optional[str] = None

    @field_validator('mac_address', 'chassis_mac')
    @classmethod
    def validate_mac(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            return "00:00:00:00:00:00"
        return v.upper()

