"""Transport-free contracts for passive security auditing and posture assessment."""

from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(dict):
    """Mapping-compatible, attribute-accessible, and JSON-serializable model."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        if name in self:
            return self[name]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def model_dump(self) -> Dict[str, Any]:
        return dict(self)


class AuditFindingRecord(_MappingCompatibleModel):
    """Validated finding payload supporting both finding_type and code."""

    def __init__(
        self,
        finding_type: str,
        severity: str,
        title: str,
        description: str,
        remediation: Optional[str] = None,
        code: Optional[str] = None,
        **kwargs,
    ):
        c = code or finding_type
        super().__init__(
            finding_type=finding_type,
            code=c,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            **kwargs,
        )


class VendorPostureRecord(_MappingCompatibleModel):
    """Validated vendor hardening posture record."""

    def __init__(
        self,
        vendor_name: str,
        category: str,
        common_defaults: str,
        risk_summary: str,
        hardening_steps: List[str],
        profile_key: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(
            vendor_name=vendor_name,
            category=category,
            common_defaults=common_defaults,
            risk_summary=risk_summary,
            hardening_steps=hardening_steps,
            profile_key=profile_key,
            **kwargs,
        )

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            profile_key = self.get("profile_key", "")
            vendor_name = self.get("vendor_name", "")
            return other.lower() in (profile_key.lower(), vendor_name.lower())
        return super().__eq__(other)


class DeviceAuditReport(_MappingCompatibleModel):
    """Validated top-level audit advisory report containing all 7 canonical keys."""

    def __init__(
        self,
        risk_level: str,
        risk_score: float,
        findings_count: int,
        findings: List[Union[AuditFindingRecord, Dict[str, Any]]],
        hardening_checklist: List[str],
        vendor_posture: Optional[Union[VendorPostureRecord, Dict[str, Any], str]] = None,
        assessed: bool = True,
        **kwargs,
    ):
        super().__init__(
            risk_level=risk_level,
            risk_score=risk_score,
            findings_count=findings_count,
            findings=findings,
            hardening_checklist=hardening_checklist,
            vendor_posture=vendor_posture,
            assessed=assessed,
            **kwargs,
        )


@runtime_checkable
class SecurityAuditorPort(Protocol):
    """Port contract for passive device posture auditing."""

    def audit_device(self, device_data: Dict[str, Any]) -> DeviceAuditReport:
        ...


__all__ = [
    "_MappingCompatibleModel",
    "AuditFindingRecord",
    "VendorPostureRecord",
    "DeviceAuditReport",
    "SecurityAuditorPort",
]
