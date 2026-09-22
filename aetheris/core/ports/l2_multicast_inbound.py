from pydantic import BaseModel, Field, field_validator
import re
from typing import List, Optional

class MulticastTelemetryPort(BaseModel):
    mac_address: str = Field(..., description="Source MAC address")
    ip_address: str = Field(..., description="Source IPv4/IPv6 address")
    protocol: str = Field(..., description="mDNS or SSDP")
    discovered_services: List[str] = Field(default_factory=list, description="Service identifiers or SSDP USN/ST headers")
    server_header: Optional[str] = Field(None, description="Server banner extracted from SSDP")
    hostname: Optional[str] = Field(None, description="Resolved local hostname via mDNS")

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", v):
            raise ValueError("Malformed MAC address format")
        return v.lower()

    @field_validator("protocol")
    @classmethod
    def validate_proto(cls, v: str) -> str:
        if v.upper() not in ["MDNS", "SSDP"]:
            raise ValueError("Protocol must be mDNS or SSDP")
        return v.upper()

