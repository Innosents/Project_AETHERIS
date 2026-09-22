from pydantic import BaseModel, Field, field_validator
import re
from typing import List, Optional

class DhcpTelemetryPort(BaseModel):
    mac_address: str = Field(..., description="Client Hardware Address")
    ip_address: str = Field(default="0.0.0.0")
    os_profile: str = Field(..., description="Inferred OS archetype from PRL taxonomy")
    confidence: float = Field(..., ge=0.0, le=100.0)
    prl_hash: str = Field(..., description="Comma-separated Option 55 sequence")
    hostname: Optional[str] = None
    evidence: str = Field(...)

    @field_validator('mac_address')
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', v):
            raise ValueError(f'Invalid MAC: {v}')
        return v.upper()

