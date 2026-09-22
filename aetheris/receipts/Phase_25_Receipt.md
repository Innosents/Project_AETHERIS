# Phase 25 Engineering Receipt: L3 TCP Zero-Window Buffer Exhaustion Decoupling

## 1. Metadata
- **Phase**: Phase 25
- **Action**: DECOUPLE_ZERO_WINDOW_PROBE
- **Author/Engine**: Antigravity (Lead Systems/OT Engineer)
- **Date/Timestamp**: 2026-09-21T14:30:00-07:00

## 2. Structural Manifest
- **Created**:
  - `aetheris/core/ports/l3_window_inbound.py` (`TcpZeroWindowTelemetryPort`)
  - `aetheris/core/parsers/tcp_window_parser.py` (`parse_window_advertisement`)
  - `aetheris/infrastructure/adapters/tcp_window_adapter.py` (`TcpZeroWindowAdapter`)
  - `tests/unit/test_tcp_zero_window.py`
  - `aetheris/receipts/Phase_25_Receipt.md`
- **Modified**:
  - TCP stack fingerprinting pipeline
- **Deprecated / Shims**:
  - Purged legacy `aetheris/core/probers/zero_window_probe.py`.
  - Registered dynamic compatibility bridge in `aetheris/core/probers/__init__.py`.

## 3. Hexagonal Boundary Attestation
- [x] **Domain Boundary Decoupling**: Isolated TCP Zero-Window probe emission and window scale analysis from domain core.
- [x] **Validated Pydantic Schemas**: Defined immutable `TcpZeroWindowTelemetryPort` bounding target IP, advertised window size, scale factor, and buffer exhaustion markers.
- [x] **OT Safety & Connection Discipline**: Bounded socket connect timeouts and enforced graceful TCP connection terminations.

## 4. Verification & Test Execution
- **Command**: `python -m pytest tests/unit/test_tcp_zero_window.py tests/unit/test_probers.py -v`
- **Results**: 19 passed, 0 failed in 1.14s (100% pass rate).
- **Ambient Blocker Status**: None in scope.
- **Ledger Inscription**: Phase Milestone 25 (`L3_TCP_ZERO_WINDOW_HEXAGONAL_ADAPTER_DEPLOYED`) committed to `spatial_ledger.db`.
