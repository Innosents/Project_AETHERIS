# Phase 17 Engineering Receipt: Mercury Security MSP Protocol Decoupling

## 1. Metadata
- **Phase**: Phase 17
- **Action**: DECOUPLE_L7_MERCURY_MSP
- **Author/Engine**: Antigravity (Lead Systems/OT Engineer)
- **Date/Timestamp**: 2026-09-21T13:10:00-07:00

## 2. Structural Manifest
- **Created**:
  - `aetheris/core/ports/l7_mercury_inbound.py` (`MercuryTelemetryPort`)
  - `aetheris/core/parsers/mercury_parser.py` (`parse_mercury_response`, `probe_mercury_panel`)
  - `aetheris/infrastructure/adapters/mercury_adapter.py` (`MercuryMspAdapter`)
  - `tests/unit/test_mercury_adapter.py`
  - `aetheris/receipts/Phase_17_Receipt.md`
- **Modified**:
  - Physical security discovery ingestion
- **Deprecated / Shims**:
  - Purged legacy `aetheris/core/probers/mercury_probe.py` monolith.
  - Registered dynamic compatibility bridging in `aetheris/core/probers/__init__.py` mapping `sys.modules["aetheris.core.probers.mercury_probe"]` to `mercury_parser`.
  - Dispatched telemetry to `aetheris:telemetry:physical_security`.

## 3. Hexagonal Boundary Attestation
- [x] **Domain Boundary Decoupling**: Extracted binary MSP command framing and multi-byte checksum calculation to stateless parser `mercury_parser.py`.
- [x] **Validated Pydantic Schemas**: Materialized immutable `MercuryTelemetryPort` validating `target_ip`, `model`, `firmware`, `serial_number`, `mac_address`, `baud_rate`, `device_type="access_controller"`, and non-negative latency constraints.
- [x] **OT Safety Guardrails**: Non-blocking TCP/serial parsing enforcing strict $\le 0.5\text{s}$ timeout ceiling and explicit `s.shutdown(socket.SHUT_RDWR)` socket closure.

## 4. Verification & Test Execution
- **Command**: `python -m pytest tests/unit/test_mercury_adapter.py tests/unit/test_probers.py -v`
- **Results**: 28 passed, 0 failed in 1.25s (100% pass rate).
  - `tests/unit/test_mercury_adapter.py`: 13/13 PASSED
  - `tests/unit/test_probers.py`: 15/15 PASSED
- **Ambient Blocker Status**: None in scope.
- **Ledger Inscription**: Phase Milestone 17 (`L7_MERCURY_HEXAGONAL_ADAPTER_DEPLOYED`) committed to `spatial_ledger.db`.
