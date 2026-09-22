"""
Project AETHERIS - Inbound L3 TCP Window Telemetry Port Definition
Defines the Pydantic v2 contract for TCP zero-window receive buffer exhaustion telemetry.
"""

from typing import Dict, Any
from pydantic import BaseModel, Field


class TcpZeroWindowTelemetryPort(BaseModel):
    probe_id: str = Field(default="L3-TCP-ZEROWINDOW-001")
    target_ip: str = Field(...)
    status: str = Field(...)
    capture_duration_sec: float = Field(default=45.0, ge=0.0)
    exhaustion_matrix: Dict[str, Any] = Field(default_factory=dict)
    event_vector: str = Field(default="OS_TCP_BUFFER_COLLAPSE")

