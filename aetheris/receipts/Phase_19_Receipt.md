# Phase 19 Engineering Receipt: Mercury Security Panel Status Decoupling

## 1. Metadata
- **Phase**: Phase 19
- **Action**: DECOUPLE_MERCURY_PANEL_STATUS
- **Author/Engine**: Antigravity (Lead Systems/OT Engineer)
- **Date/Timestamp**: 2026-09-21T13:30:00-07:00

## 2. Structural Manifest
- **Created**:
  - `aetheris/core/ports/l7_mercury_panel_inbound.py` (`MercuryPanelTelemetryPort`)
  - `tests/unit/test_mercury_panel_adapter.py`
  - `aetheris/receipts/Phase_19_Receipt.md`
- **Modified**:
  - `aetheris/infrastructure/adapters/mercury_panel_adapter.py` (`MercuryPanelAdapter`)
  - `aetheris/core/parsers/mercury_parser.py`
- **Deprecated / Shims**:
  - Purged legacy `aetheris/core/probers/mercury_probe.py` monolith.
  - Registered dynamic compatibility bridging in `aetheris/core/probers/__init__.py`.
  - Dispatched telemetry to `aetheris:telemetry:physical_security`.

## 3. Hexagonal Boundary Attestation
- [x] **Domain Boundary Decoupling**: Isolated Mercury panel binary status inquiry (`0x02` poll) parsing in `mercury_parser.py`.
- [x] **Validated Pydantic Schemas**: Materialized `MercuryPanelTelemetryPort` validating panel online state, tamper alarm, battery status, AC power fail, and door status bitmasks.
- [x] **OT Safety Guardrails**: Strict $\le 0.5\text{s}$ socket timeout and guaranteed `SHUT_RDWR` close.

## 4. Verification & Test Execution
- **Command**: `python -m pytest tests/unit/test_mercury_panel_adapter.py tests/unit/test_mercury_adapter.py tests/unit/test_probers.py -v`
- **Results**: 41 passed, 0 failed in 1.62s (100% pass rate; 119/119 across decoupled probers).
  - `tests/unit/test_mercury_panel_adapter.py`: 13/13 PASSED
  - `tests/unit/test_mercury_adapter.py`: 13/13 PASSED
  - `tests/unit/test_probers.py`: 15/15 PASSED
- **Ambient Blocker Status**: None in scope.
- **Ledger Inscription**: Phase Milestone 19 (`L7_MERCURY_PANEL_HEXAGONAL_ADAPTER_DEPLOYED`) committed to `spatial_ledger.db`.
