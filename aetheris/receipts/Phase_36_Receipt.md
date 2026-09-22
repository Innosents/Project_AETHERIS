# Phase 36 Engineering Receipt: Hexagonal Decoupling of Discovery Engine & Network Scanner Port Interface

## 1. Metadata
- **Phase**: Phase 36
- **Action**: DECOUPLE_DISCOVERY_ENGINE_SCANNER_PORT
- **Author/Engine**: Antigravity (Lead Systems/OT Engineer)
- **Date/Timestamp**: 2026-09-21T14:53:00-07:00

## 2. Structural Manifest
- **Created**:
  - `aetheris/core/ports/discovery_engine_port.py`
  - `aetheris/infrastructure/adapters/discovery/__init__.py`
  - `aetheris/infrastructure/adapters/discovery/network_scanner_adapter.py`
  - `tests/unit/test_discovery_engine_port.py`
  - `aetheris/receipts/Phase_36_Receipt.md`
- **Modified**:
  - `aetheris/core/discovery_engine.py`
- **Deprecated / Shims**:
  - Maintained `_MappingCompatibleModel` dictionary indexing compatibility interface (`__getitem__`, `__setitem__`, `get`, `__contains__`, `keys()`, `values()`, `items()`) on `DiscoverySweepConfig`, `DiscoveredDeviceNode`, `PortScanSummary`, and `DiscoveryRunSummary`.
  - Maintained dynamic backward-compatible default initialization of `NetworkScannerAdapter` within `DiscoveryEngine.__init__` when scanner parameter is omitted.
  - Retained `DiscoveryEngine.register_discovered_node` and all operational sweep hooks (`run_basic_sweep`, `run_passive`, `run_credentialed`, `run_adaptive`).

## 3. Hexagonal Boundary Attestation
- [x] **Zero Raw Sockets/Scapy in Core**: AST verification confirmed zero `socket`, `scapy`, or `aetheris.discovery` imports in `aetheris/core/discovery_engine.py` and `aetheris/core/ports/discovery_engine_port.py`.
- [x] **Decoupled Outbound Network Scanner Port**: Declared `@runtime_checkable class NetworkScannerPort(Protocol)` with `icmp_sweep`, `arp_scan`, `scan_ports`, `grab_banner`, `fingerprint_device`, and `get_common_ports`.
- [x] **Modular Infrastructure Adapter**: Materialized `NetworkScannerAdapter` in `aetheris/infrastructure/adapters/discovery/network_scanner_adapter.py` wrapping tools from `aetheris.discovery.*`.
- [x] **Pure Inbound Protocol Abstraction**: Declared `@runtime_checkable class DiscoveryEnginePort(Protocol)` implemented directly by `DiscoveryEngine`.
- [x] **Validated Pydantic Payloads**:
  - `DiscoverySweepConfig`: Validated network target, port lists, timeout, and concurrency bounds.
  - `DiscoveredDeviceNode`: Type-safe discovered device node record.
  - `PortScanSummary`: Responsive open port and banner manifest.
  - `DiscoveryRunSummary`: Validated sweep telemetry report model ($[0, \infty)$ bounds).
- [x] **Scope Enforcement & Transactional Safety**:
  - All target candidate IPs verified against `ScopeGuard.is_permitted` before probing.
  - Graph mutations executed within `self.graph.batch_transaction()` with concurrency locks.

## 4. Verification & Test Execution
- **Command**: `python -m pytest tests/unit/test_discovery_engine_port.py tests/test_discovery_pipeline.py tests/unit/test_dip_port.py tests/unit/test_device_classifier.py tests/test_device_classifier.py tests/test_device_classifier_engine.py -v`
- **Results**: 35 passed, 0 failed in 2.63s (100.0% pass rate).
  - `tests/unit/test_discovery_engine_port.py::test_discovery_engine_port_protocol_conformance` (PASSED)
  - `tests/unit/test_discovery_engine_port.py::test_network_scanner_port_protocol_conformance` (PASSED)
  - `tests/unit/test_discovery_engine_port.py::test_pydantic_discovery_models` (PASSED)
  - `tests/unit/test_discovery_engine_port.py::test_discovery_engine_sweep_with_injected_scanner` (PASSED)
  - `tests/test_discovery_pipeline.py::TestDiscoveryPipelineIntegration::test_pipeline_anchor_calibration_and_edge_persistence` (PASSED)
  - `tests/unit/test_dip_port.py` (6/6 PASSED)
  - `tests/unit/test_device_classifier.py` (7/7 PASSED)
  - `tests/test_device_classifier.py` (6/6 PASSED)
  - `tests/test_device_classifier_engine.py` (11/11 PASSED)
- **Boundary Check**: AST parsing confirmed 0 violations across `aetheris/core/ports/discovery_engine_port.py` and `aetheris/core/discovery_engine.py`.
- **Ledger Inscription**: Phase Milestone 36 (`DISCOVERY_ENGINE_HEXAGONAL_SCANNER_PORT_DECOUPLED`) committed to `spatial_ledger.db`.

