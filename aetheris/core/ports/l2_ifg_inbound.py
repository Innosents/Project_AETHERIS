from pydantic import BaseModel, Field

class IfgTelemetryPort(BaseModel):
    target_ip: str = Field(..., description="Monitored downstream endpoint IP")
    avg_inter_frame_gap_ns: float = Field(..., ge=0.0)
    jitter_variance_ns: float = Field(..., ge=0.0)
    sample_size: int = Field(..., ge=1)
    inferred_downstream_hops: int = Field(default=1, ge=1)

