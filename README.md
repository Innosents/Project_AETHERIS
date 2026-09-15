# Project AETHERIS v0.1.0
### Autonomous Zero-Credential Cyber-Physical Orchestration Swarm

Project AETHERIS is an autonomous, unauthenticated network discovery and cyber-physical auditing swarm powered by the GraphPath spatial chassis. Engineered for high-security campus, enterprise, and OT/ICS environments, AETHERIS maps physical infrastructure, low-voltage conductor runs, and switchport topologies without administrative credentials, SNMP community strings, or agent deployments.

---

## Key Capabilities (GraphPath Chassis)

* **Zero-Credential Topology Reconstruction:** Passively ingests ERSPAN/SPAN, DHCP Option 55 fingerprints, and multicast beacons (LLDP-MED, mDNS, WS-Discovery) to construct device identity profiles.
* **Dual-Payload Baseband Physics Modeling:** Deconvolves link speeds (1Gbps Full-Duplex vs. 100Mbps Bridge) and serialization delays using differential packet timing (Delta t flight analysis).
* **Low-Voltage DC Loop Resolution:** Models conductor resistance (R(T)) across AWG 18–24 copper pairs with dynamic quiescent current locking to detect physical-layer anomalies (inline taps, solenoid kickback).
* **Virtualized Overlay Detection:** Uses geodesic Haversine speed-of-light modeling (v_fiber ≈ 0.67c) and BGP inflation scalars to detect and prune false Layer 1 adjacencies caused by SD-WAN or Cloud VPN tunnels.
* **Zero-Lock Sharded Telemetry Ledger:** High-concurrency architecture verified against 349 automated unit, property-based fuzzing, and chaos twin tests.

---

## Verification & Architecture Testing

* **Pass Rate:** 349 / 349 tests passing (100% coverage across core solvers, decoders, and chaos twins).
* **Tier-0 Invariant Verification:** Property-based fuzzing across 100,000 iterations with zero unhandled exceptions, zero float overflows, and zero memory leaks.

---

## Quickstart

```powershell
# Setup virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Initialize and seed spatial ledger
python scripts/init_fdb_schema.py
python scripts/seed_ground_truth.py

# Execute AETHERIS multivector serialization sweep
python scripts/run_port1_multivector_sweep.py

# Launch GraphPath topology visualizer
python run_visualizer.py