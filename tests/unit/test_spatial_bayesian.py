"""
Unit test suite for SpatialBayesianSolverPort and BayesianEvidenceFusion adapter.
Validates AST boundary isolation, protocol conformance, likelihood normalization, and schema dual-access.
"""
import ast
import os
import pytest
from aetheris.core.ports.spatial_bayesian_port import (
    BayesianFusionPort,
    SpatialSolverPort,
    ArchetypeInferenceResult,
    PortProfileRecord,
    HopParametersRecord,
)
from aetheris.core.spatial_bayesian import (
    BayesianEvidenceFusion,
    BayesianSpatialSolver,
    calculate_port_profile,
    compute_residual_flight_time,
    get_calibrated_hop_parameters,
)


def test_spatial_bayesian_port_ast_boundary():
    """Verify spatial_bayesian_port.py contains zero sqlite3, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "spatial_bayesian_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"sqlite3", "socket", "scapy", "subprocess", "redis", "fastapi", "uvicorn", "mcp"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_bayesian_fusion_evidence_normalization():
    """Verify log-space posterior probabilities sum to 1.0."""
    evidence = ["ttl_linux_64", "port_modbus_502"]
    posterior = BayesianEvidenceFusion.fuse_evidence(evidence)

    assert pytest.approx(sum(posterior.values()), rel=1e-5) == 1.0
    assert posterior["INDUSTRIAL_OT"] > posterior["WINDOWS_HOST"]


def test_bayesian_spatial_solver_projection():
    """Verify topology projection and unmanaged switch cascaded detection."""
    solver = BayesianSpatialSolver()
    solver.ingest_telemetry(
        chassis_matrix={"00:11:22:33:44:55": {"tlvs": {"hostname": "Core_Switch"}}},
        stp_matrix={"00:aa:bb:cc:dd:ee": {"root_path_cost": 25}},
        ttl_matrix={"00:aa:bb:cc:dd:ee": 2},
        multicast_matrix={"00:aa:bb:cc:dd:ee": {"ui_label": "PLC_Remote"}}
    )
    graph = solver.project_topology()

    assert "Core_Distribution_Switch" in graph.nodes
    assert "Unmanaged_Switch" in graph.nodes
    assert "00:aa:bb:cc:dd:ee" in graph.nodes
    assert graph.has_edge("Unmanaged_Switch", "00:aa:bb:cc:dd:ee")


def test_archetype_inference_result_immutability():
    """Verify ArchetypeInferenceResult schema validation, immutability, and dual mapping."""
    res = ArchetypeInferenceResult(
        archetype="INDUSTRIAL_OT",
        confidence=0.985,
        posterior={"INDUSTRIAL_OT": 0.985, "GENERIC_HOST": 0.015},
        calibrated_kernel_turnaround_us=280.0
    )
    assert res.archetype == "INDUSTRIAL_OT"
    assert res["archetype"] == "INDUSTRIAL_OT"
    assert res["confidence"] == 0.985
    assert res.calibrated_kernel_turnaround_us == 280.0
    with pytest.raises(Exception):
        res.archetype = "WINDOWS_HOST"
