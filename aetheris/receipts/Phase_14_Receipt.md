# Phase 14 Engineering Receipt: Layer 3 ICMP TTL & Topological Depth Decoupling

## 1. Metadata
- **Phase**: Phase 14
- **Action**: DECOUPLE_L3_ICMP_TTL
- **Author/Engine**: Antigravity (Lead Systems/OT Engineer)
- **Date/Timestamp**: 2026-09-21T12:30:00-07:00

## 2. Structural Manifest
- **Created**:
  - `aetheris/core/ports/l3_ttl_inbound.py` (`TtlTelemetryPort`)
  - `aetheris/infrastructure/adapters/icmp_ttl_adapter.py` (`IcmpTtlAdapter`)
  - `tests/unit/test_icmp_ttl_adapter.py`
  - `aetheris/receipts/Phase_14_Receipt.md`
- **Modified**:
  - Topological depth calculation handlers
- **Deprecated / Shims**:
  - Purged legacy `ttl_interrogator.py` and `active_ttl_interrogator.py` from `aetheris/core/probers/l3_network/`.
  - Maintained dynamic module aliasing in `aetheris/core/probers/__init__.py`.
  - Dispatched telemetry to `aetheris:telemetry:l3_ttl_intel`.

## 3. Hexagonal Boundary Attestation
- [x] **Domain Boundary Decoupling**: Isolated raw ICMP socket operations (`SOCK_RAW`) and RFC 1071 checksum calculation from domain network models.
- [x] **Pure Protocol Abstraction**: Formalized `TtlTelemetryPort` enforcing initial baseline TTL heuristics (32, 64, 128, 255) and derived downstream hop counts ($h = \text{TTL}_{\text{base}} - \text{TTL}_{\text{obs}}$).
- [x] **Threadpool Offloading**: Deployed `IcmpTtlAdapter` offloading ICMP echo requests to worker threads and publishing topological depth vectors.

## 4. Verification & Test Execution
- **Command**: `python -m pytest tests/unit/test_icmp_ttl_adapter.py -v`
- **Results**: 5 passed, 0 failed in 0.61s (100% pass rate; 35/35 across related suites).
- **Ambient Blocker Status**: None in scope.
- **Ledger Inscription**: Phase Milestone 14 (`L3_TTL_HEXAGONAL_ADAPTER_DEPLOYED`) committed to `spatial_ledger.db`.
