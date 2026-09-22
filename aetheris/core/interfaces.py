"""Backward-compatible facade for modern core port contracts."""

from aetheris.core.ports.core_interfaces_port import (
    CamTableMapping,
    ConvergenceRecord,
    FlightTimeTelemetry,
    GroundTruthRecord,
    HardwareAuditResult,
    HardwareAuditorPort,
    L2PassivePort,
    L2TelemetryMatrix,
    L3ActivePort,
    L3HopTelemetry,
    SnmpAdapterPort,
    SpatialLedgerPort,
    TelemetryLedgerPort,
    _MappingCompatibleModel,
)

# Legacy names remain aliases so existing adapter inheritance and imports work.
L2PassiveAdapterInterface = L2PassivePort
L3ActiveAdapterInterface = L3ActivePort
SNMPAdapterInterface = SnmpAdapterPort
TelemetryLedgerInterface = TelemetryLedgerPort
SpatialLedgerInterface = SpatialLedgerPort
HardwareAuditorInterface = HardwareAuditorPort

__all__ = [
    "CamTableMapping",
    "ConvergenceRecord",
    "FlightTimeTelemetry",
    "GroundTruthRecord",
    "HardwareAuditResult",
    "HardwareAuditorInterface",
    "HardwareAuditorPort",
    "L2PassiveAdapterInterface",
    "L2PassivePort",
    "L2TelemetryMatrix",
    "L3ActiveAdapterInterface",
    "L3ActivePort",
    "L3HopTelemetry",
    "SNMPAdapterInterface",
    "SnmpAdapterPort",
    "SpatialLedgerInterface",
    "SpatialLedgerPort",
    "TelemetryLedgerInterface",
    "TelemetryLedgerPort",
    "_MappingCompatibleModel",
]
