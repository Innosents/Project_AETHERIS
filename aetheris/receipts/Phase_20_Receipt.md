# Phase 20 Engineering Receipt: ONVIF Surveillance Camera Prober Decoupling

## 1. Metadata
- **Phase**: Phase 20
- **Action**: DECOUPLE_ONVIF_PROBE
- **Author/Engine**: Antigravity (Lead Systems/OT Engineer)
- **Date/Timestamp**: 2026-09-21T13:40:00-07:00

## 2. Structural Manifest
- **Created**:
  - `aetheris/core/ports/l7_onvif_inbound.py` (`OnvifTelemetryPort`)
  - `aetheris/core/parsers/onvif_parser.py` (`parse_onvif_device_information_xml`, `probe_onvif_camera`)
  - `aetheris/infrastructure/adapters/onvif_adapter.py` (`OnvifAdapter`)
  - `tests/unit/test_onvif_adapter.py`
  - `aetheris/receipts/Phase_20_Receipt.md`
- **Modified**:
  - Surveillance camera discovery pipeline
- **Deprecated / Shims**:
  - Purged legacy `aetheris/core/probers/onvif_probe.py` monolith.
  - Registered dynamic compatibility bridging in `aetheris/core/probers/__init__.py` mapping `sys.modules["aetheris.core.probers.onvif_probe"]` to `onvif_parser`.
  - Dispatched telemetry to `aetheris:telemetry:camera_intelligence`.

## 3. Hexagonal Boundary Attestation
- [x] **Domain Boundary Decoupling**: Relocated stateless SOAP XML decoder `parse_onvif_device_information_xml` and envelope constant `ONVIF_SOAP_GET_DEVICE_INFORMATION` directly into `onvif_parser.py`.
- [x] **Validated Pydantic Schemas**: Defined immutable Pydantic v2 `OnvifTelemetryPort` validating `target_ip`, `vendor`, `model`, `firmware`, `serial_number`, `hardware_id`, `archetype="CCTV_VIDEO"`, and `type="camera"`.
- [x] **Non-Blocking Threadpool Execution**: Enforced socket timeouts strictly capped at $\le 0.5\text{s}$ with explicit `s.shutdown(socket.SHUT_RDWR)` teardown.

## 4. Verification & Test Execution
- **Command**: `python -m pytest tests/unit/test_onvif_adapter.py tests/unit/test_probers.py -v`
- **Results**: 27 passed, 0 failed in 1.15s (100% pass rate; 131/131 across decoupled probers).
  - `tests/unit/test_onvif_adapter.py`: 12/12 PASSED
  - `tests/unit/test_probers.py`: 15/15 PASSED
- **Ambient Blocker Status**: None in scope.
- **Ledger Inscription**: Phase Milestone 20 (`L7_ONVIF_HEXAGONAL_ADAPTER_DEPLOYED`) committed to `spatial_ledger.db`.
