"""
Project AETHERIS - Core Orchestration & Security Subsystem.
"""

from graphpath.core.device_classifier import DeviceClassifier
from graphpath.core.scope_guard import ScopeAuthorizationGuard, get_scope_guard, configure_scope_guard
from graphpath.core.security_auditor import SecurityAuditor
from graphpath.core.traffic_matrix import TrafficMatrixTracker, TrafficRoleClassifier
from graphpath.core.dip_manager import DeviceIdentityProfileManager
from graphpath.core.adaptive_orchestrator import AdaptiveDiscoveryOrchestrator, EvidenceVector
from graphpath.core.oui_registry import OuiRegistry
from graphpath.core.spatial_solver import (
    SpatialSolver,
    SpatialSolverResult,
    SpatialDistanceEstimate,
)
from graphpath.core.spatial_dc_drop import (
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
    "get_scope_guard",
    "configure_scope_guard",
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