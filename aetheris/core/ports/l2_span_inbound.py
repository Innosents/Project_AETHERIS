"""
Project AETHERIS - Inbound L2 SPAN Port Definition
Defines the Pydantic v2 telemetry contract for promiscuous SPAN/TAP frame ingestion.
"""

from pydantic import BaseModel, Field


class SpanCaptureTelemetryPort(BaseModel):
    interface: str = Field(..., description="Capture network interface")
    status: str = Field(default="STOPPED")
    total_frames: int = Field(default=0, ge=0)
    chassis_frames: int = Field(default=0, ge=0)
    stp_frames: int = Field(default=0, ge=0)
    multicast_frames: int = Field(default=0, ge=0)
    unhandled_frames: int = Field(default=0, ge=0)

