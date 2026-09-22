from pydantic import BaseModel, Field, ConfigDict
from typing import Optional


class CldapTelemetryPort(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target_ip: str = Field(..., description="Target DC IP address")
    target_port: int = Field(default=389)
    is_ad_controller: bool = Field(default=False)
    domain: Optional[str] = None
    forest: Optional[str] = None
    dc_hostname: Optional[str] = None
    netbios_domain: Optional[str] = None
    netbios_computer_name: Optional[str] = None
    dc_site: Optional[str] = None
    domain_guid: Optional[str] = None
    is_pdc: bool = Field(default=False)
    is_gc: bool = Field(default=False)
    is_kdc: bool = Field(default=False)
    is_writable: bool = Field(default=False)
    kernel_turnaround_us: Optional[float] = Field(None, ge=0.0)

