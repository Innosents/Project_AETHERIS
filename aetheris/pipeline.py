"""
Project AETHERIS - Spatial Pipeline Orchestrator Shim
Exposes SpatialOrchestrator and SpatialOrchestratorPort at root package level.
"""
from aetheris.orchestrator.pipeline import (
    SpatialOrchestrator,
    SpatialOrchestratorPort,
    FusionTelemetryInput,
    SpatialFusionResult,
    _MappingCompatibleModel,
)

__all__ = [
    "SpatialOrchestrator",
    "SpatialOrchestratorPort",
    "FusionTelemetryInput",
    "SpatialFusionResult",
    "_MappingCompatibleModel",
]

