# Project AETHERIS

[![Hexagonal Core CI](https://github.com/Innosents/Project_AETHERIS/actions/workflows/ci.yml/badge.svg)](https://github.com/Innosents/Project_AETHERIS/actions/workflows/ci.yml)
[![Architecture: Hexagonal](https://img.shields.io/badge/Architecture-Hexagonal%20Ports%20%26%20Adapters-blue.svg)](https://github.com/Innosents/Project_AETHERIS)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Project AETHERIS** is an automated OT/IT network spatial deconvolution, cyber-physical topology mapping, and empirical telemetry reconciliation engine. Operating at the boundary of physical layer kinetics and Layer 2/3 packet mechanics, AETHERIS solves physical cable run lengths, lumped switch propagation delay, and device archetypes directly from network flight times and protocol signals.

---

## 1. System Architecture

Project AETHERIS enforces a strict **Hexagonal Architecture (Ports & Adapters)**. Domain logic is completely decoupled from low-level transport drivers, network capture mechanisms, and concrete database storage.