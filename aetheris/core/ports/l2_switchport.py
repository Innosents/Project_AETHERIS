from pydantic import BaseModel, Field, field_validator
import re
from typing import Optional

class SwitchportTelemetryPort(BaseModel):
    switch_ip: str = Field(..., description="Management IP of the switch")
    mac_address: str = Field(..., description="Discovered endpoint MAC address")
    port_name: str = Field(..., description="Physical interface name or alias")
    vlan_id: int = Field(default=1, ge=1, le=4095)
    is_trunk: bool = Field(..., description="True if MAC density >= 4 or labeled uplink")
    mac_density: int = Field(default=1, ge=1)

    @field_validator('mac_address')
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            raise ValueError(f'Invalid MAC: {v}')
        return v.upper()

