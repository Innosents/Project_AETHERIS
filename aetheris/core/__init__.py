"""
Project AETHERIS - Core Orchestration & Security Subsystem.
"""

import aetheris.core.compat_probers

from aetheris.core.device_classifier import DeviceClassifier
from aetheris.core.security_auditor import SecurityAuditor
from aetheris.core.traffic_matrix import TrafficMatrixTracker, TrafficRoleClassifier
from aetheris.core.dip_manager import DeviceIdentityProfileManager
from aetheris.core.adaptive_orchestrator import AdaptiveDiscoveryOrchestrator, EvidenceVector
from aetheris.core.oui_registry import OuiRegistry
from aetheris.core.spatial_solver import (
    SpatialSolver,
    SpatialSolverResult,
    SpatialDistanceEstimate,
)
from aetheris.core.spatial_dc_drop import (
    DcConductorSolver,
    calculate_conductor_distance,
    resolve_peripheral_telemetry,
    evaluate_dual_physical_constraints,
    PeripheralElectricalEnvelope,
    High_Resistance_Anomaly,
    calculate_dynamic_spatial_drop,
    evaluate_baud_rate_divergence,
)

__all__ = [
    "DeviceClassifier",
    "OuiRegistry",
    "ScopeAuthorizationGuard",
    "SecurityAuditor",
    "TrafficMatrixTracker",
    "TrafficRoleClassifier",
    "DeviceIdentityProfileManager",
    "AdaptiveDiscoveryOrchestrator",
    "EvidenceVector",
    "SpatialSolver",
    "SpatialSolverResult",
    "SpatialDistanceEstimate",
    "DcConductorSolver",
    "calculate_conductor_distance",
    "resolve_peripheral_telemetry",
    "evaluate_dual_physical_constraints",
    "PeripheralElectricalEnvelope",
    "High_Resistance_Anomaly",
    "calculate_dynamic_spatial_drop",
    "evaluate_baud_rate_divergence",
]
