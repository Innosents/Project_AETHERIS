"""
Project AETHERIS - Inbound L3 Stealth Telemetry Port Definition
Defines the Pydantic v2 contract for non-intrusive multi-variance stealth host interrogation
(NetBIOS, WS-Discovery, LLMNR) with kernel turnaround latency measurements.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class StealthTelemetryPort(BaseModel):
    ip: str = Field(..., description="Target host IP address")
    hostname: Optional[str] = Field(default="")
    computer_name: Optional[str] = Field(default="")
    workgroup: Optional[str] = Field(default="")
    mac: Optional[str] = Field(default="")
    vendor: str = Field(default="generic")
    type: str = Field(default="workstation")
    model: str = Field(default="Network Endpoint")
    friendly_name: Optional[str] = Field(default="")
    endpoint_uuid: Optional[str] = Field(default="")
    wsd_types: Optional[str] = Field(default="")
    is_active: bool = Field(default=True)
    kernel_turnaround_us: float = Field(..., ge=0.0)
    latency_ms: float = Field(..., ge=0.0)
    probes: Dict[str, Any] = Field(default_factory=dict)

