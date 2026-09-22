from pydantic import BaseModel, Field

class TtlTelemetryPort(BaseModel):
    target_ip: str = Field(..., description="Target endpoint IP address")
    baseline_ttl: int = Field(..., description="Inferred original OS TTL (e.g., 64, 128, 255)")
    hop_count: int = Field(..., ge=0, description="Calculated topological depth")

