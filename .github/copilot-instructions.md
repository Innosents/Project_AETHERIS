# Project AETHERIS - Core Architectural Directives

## 1. Architectural Style & Boundaries
- Strictly enforce Hexagonal Architecture (Ports and Adapters).
- Core domain modules (`aetheris/core/`) must never import concrete infrastructure, database clients, or network libraries (`redis`, `httpx`, `requests`, `socket`, `scapy`).
- All outbound communication must be mediated via abstract protocols defined under `aetheris/core/ports/`.
- Concrete implementations belong strictly in `aetheris/infrastructure/adapters/`.

## 2. Mathematical & Domain Invariants
- Layer 1 Spatial & Physical Conductor Invariants: Never treat 802.11 / RF AirLink media as deterministic spatial conductors[cite: 1].
- Candidate Qualification: Disqualify any node with empirical jitter > 25.0 µs, unverified switchports, or dynamic wireless archetypes[cite: 1].
- Pydantic Over Dictionaries: Always prefer immutable, validated Pydantic models over raw Python dictionaries for inter-layer data transfer.
- Non-Blocking Execution: Synchronous CPU-bound operations or C-bindings must yield via `asyncio.to_thread` or background executors.

## 3. Code Generation Rules
- Prohibit generic stubs, placeholders, or conversational filler inside source files.
- Ensure type hints are complete (`typing.Optional`, `typing.Dict`, `typing.List`, `typing.Tuple`, `typing.Protocol`, `@runtime_checkable`).
- Maintain backward compatibility exports when moving legacy modules.
- Scope Enforcement: All network sweeps and active probes must query `ScopeGuard.is_permitted(ip)` before emitting packets.

## 4. Walkthrough Receipt Protocol (Mandatory Output)
At the completion of EVERY task, modification, or phase refactor, generate a structured markdown walkthrough receipt titled `### Phase Walkthrough & Verification Receipt` containing:
1. **Target Phase & Action**: Stated clearly (e.g., `Phase 31: DECOUPLE_ACTIVE_SERVICE_PROBE`).
2. **Structural Manifest**:
   - `Created`: List of new files (ports, adapters, data models).
   - `Modified`: List of refactored files.
   - `Deprecated / Façaded`: Any legacy shim preserved for backward compatibility.
3. **Hexagonal Boundary Attestation**:
   - Verification that no concrete socket, OS, or network I/O leaked into `aetheris/core/ports/`.
   - Verification that all return types use validated Pydantic models.
4. **Verification & Test Execution Log**:
   - Explicit terminal command executed (e.g., `pytest tests/unit/test_active_probe.py`).
   - Summary of tests passed/failed.
   - Known ambient blockers (if any).

## 5. MCP Cluster Integration Directives
- **Architecture Role**: Model Context Protocol (MCP) servers act as secondary outbound infrastructure adapters under `aetheris/infrastructure/adapters/mcp/` or via dynamic tool registries.
- **Server Discovery & Tool Execution**:
  - Always resolve tool invocations against the active AETHERIS MCP cluster endpoints rather than generating synthetic mock data.
  - Core domain engines dispatching queries to MCP tools must interface through `aetheris/core/ports/mcp_port.py` (Protocol `MCPClusterPort`).
  - Strict input validation: Every payload transmitted across an MCP tool bridge must parse through a Pydantic `BaseModel` conforming to the specific MCP tool schema.
- **Hexagonal Boundary Enforcement**:
  - Never allow raw MCP JSON-RPC wire sockets or direct `FastMCP` stdio pipe handlers to be imported into `aetheris/core/`.
  - Treat all incoming MCP tool results as untrusted raw telemetry; sanitize payloads via `aetheris.core.parsers.sanitization` before passing them to core orchestrators or spatial normalization layers.
- **Canary Tool Targets**:
  - When referencing spatial topology, query the `spatial_topology_mcp` tool suite.
  - When triggering discovery, route through the registered network inspection tools governed by `ScopeGuard`.

## 6. Walkthrough Receipt Protocol (Mandatory File Persistence)
At the completion of EVERY task, modification, or phase refactor:
1. **File Destination**: Persist the receipt directly to disk under `.aetheris/receipts/PHASE_<ID>_<TIMESTAMP>_RECEIPT.md` (or write to the active tracking directory). DO NOT merely print the receipt to the chat stream.
2. **Standardized Schema**: Strictly follow this structure:

```markdown
# Phase Walkthrough & Verification Receipt

## 1. Metadata
- **Phase**: Phase 31 / 32
- **Action**: DECOUPLE_COMPAT_PROBERS
- **Author/Engine**: GPT-5.6 Luna / Copilot
- **Date/Timestamp**: 2026-09-21T14:05:00-07:00

## 2. Structural Manifest
- **Created**:
  - `aetheris/core/ports/legacy_probe_port.py`
  - `aetheris/infrastructure/adapters/compat/probers_bridge.py`
- **Modified**:
  - `aetheris/core/compat_probers.py`
- **Deprecated / Shims**:
  - Maintained `sys.modules["aetheris.core.probers"]` backward compatibility bridge.

## 3. Hexagonal Boundary Attestation
- [x] Zero raw sockets (`socket.socket`, `SOCK_RAW`, `IPPROTO_ICMP`) in `aetheris/core/`
- [x] Zero Scapy dependencies (`scapy.layers.*`) in `aetheris/core/ports/`
- [x] Pure Protocol/ABC abstractions implemented for core interfaces
- [x] Return payloads enforced via validated Pydantic models

## 4. Verification & Test Execution
- **Command**: `pytest tests/unit/test_compat_probers.py -v`
- **Results**: 12 passed, 0 failed
- **Ambient Blocker Status**: None in scope
```

## 7. Project AETHERIS Constitution (v2.4)

The Project AETHERIS Constitution (v2.4) is accepted as the governing project-level behavioral and analytical standard.

### 7.1 Terminology Invariant

- The string `GraphPath` and the phrase `Graph Path` are permanently deprecated. Do not generate, preserve, or introduce either form in code, documentation, identifiers, tests, telemetry, or receipts.
- When legacy input contains either deprecated form, identify the context and use the repository's current domain vocabulary; do not silently invent a replacement when the intended concept is ambiguous.

### 7.2 Research Gate Before Formatting

Before generating structured data, code, schemas, plans, or configuration:

1. Establish the controlling code path, authoritative data sources, assumptions, and invariants.
2. Complete edge-case and failure-state analysis, including boundary values, malformed inputs, concurrency, partial failure, compatibility, and security implications relevant to the stack layer.
3. State a falsifiable hypothesis and a discriminating validation check when investigating behavior.
4. Only after that analysis, emit the requested structure. Separate empirical facts, deductions, hypotheses, and unresolved questions.

### 7.3 Analytical and Communication Standard

- Use high-density, technically precise language. Omit conversational filler, generic encouragement, and unrequested summaries.
- Prefer empirical evidence: repository paths, test output, runtime observations, type contracts, measured values, and explicit confidence or uncertainty.
- Use Python or JSON data structures when they improve precision; use prose, Markdown tables, or diagrams when they communicate the result more accurately.
- Interrogate premises immediately when they are inconsistent with repository evidence, physical constraints, type contracts, or security assumptions. Explain the contradiction and identify the smallest corrective test.
- Stress-test architectural choices against zero-day vulnerability classes, experimental or beta framework behavior, adversarial inputs, and operational failure modes. Treat speculative or bleeding-edge claims as hypotheses until verified by documentation, source, tests, or runtime evidence.
- Recalibrate depth to the active layer, from physical hardware and RF constraints through transport, domain mathematics, storage, orchestration, and presentation. Do not simplify unless requested.
- Preserve the existing mandatory verification receipts and report ambient blockers explicitly; analytical density does not override required project workflow artifacts.
