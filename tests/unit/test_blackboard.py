"""
Unit test suite for BlackboardPort and blackboard adapter.
Validates AST boundary isolation, protocol conformance, regression gating, and SHA-256 symmetry.
"""
import ast
import os
import json
import hashlib
import tempfile
from typing import Any, Dict, Optional, List
import pytest
from aetheris.core.ports.blackboard_port import (
    BlackboardPort,
    BlackboardMetricRecord,
    PhaseMilestoneRecord,
    BlackboardOperationResult,
)
from aetheris.mcp.blackboard import SqliteBlackboardBackend


class InMemoryBlackboard:
    """Mock in-memory blackboard satisfying BlackboardPort protocol."""
    def __init__(self):
        self._metrics = {}
        self._milestones = {}

    def write_metric(self, key: str, value: Any, scope: str = "session", strict_regression_tolerance: float = 0.05) -> BlackboardOperationResult:
        if isinstance(value, (int, float)) and key in self._metrics:
            old_val = self._metrics[key]["value"]
            if isinstance(old_val, (int, float)) and old_val > 0:
                if (value - old_val) / old_val > strict_regression_tolerance:
                    return BlackboardOperationResult(
                        success=False,
                        message=f"Error: Metric {key} regressed by more than {strict_regression_tolerance*100}%"
                    )
        self._metrics[key] = {"value": value, "scope": scope}
        return BlackboardOperationResult(success=True, message=f"Successfully persisted metric: '{key}'")

    def read_metric(self, key: str):
        if key in self._metrics:
            return self._metrics[key]["value"]
        return None

    def list_metrics(self, scope: str = None):
        if scope:
            return {k: v["value"] for k, v in self._metrics.items() if v["scope"] == scope}
        return {k: v["value"] for k, v in self._metrics.items()}

    def log_milestone(self, phase_id: int, phase_name: str, status: str, test_coverage: float = 0.0, payload: Any = None) -> BlackboardOperationResult:
        signoff_hash = ""
        if payload is not None:
            serialized = json.dumps(payload)
            if json.loads(serialized) != payload:
                return BlackboardOperationResult(success=False, message="Error: Payload violates Data Symmetry")
            signoff_hash = hashlib.sha256(serialized.encode()).hexdigest()

        self._milestones[phase_id] = {
            "phase_name": phase_name,
            "status": status,
            "test_coverage": test_coverage,
            "signoff_hash": signoff_hash
        }
        return BlackboardOperationResult(
            success=True,
            message=f"Logged Phase {phase_id} ({phase_name}) as {status}",
            signoff_hash=signoff_hash
        )


def test_blackboard_port_ast_boundary():
    """Verify blackboard_port.py contains zero sqlite3, mcp, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "blackboard_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"sqlite3", "mcp", "fastapi", "uvicorn", "socket", "scapy", "subprocess", "redis"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_blackboard_protocol_conformance():
    """Verify InMemoryBlackboard and SqliteBlackboardBackend satisfy BlackboardPort protocol."""
    board = InMemoryBlackboard()
    assert isinstance(board, BlackboardPort)

    with tempfile.TemporaryDirectory() as td:
        temp_db = os.path.join(td, "test.db")
        sqlite_board = SqliteBlackboardBackend(db_path=temp_db)
        assert isinstance(sqlite_board, BlackboardPort)


def test_blackboard_metric_write_and_read():
    """Verify standard metric storage and dual mapping on result."""
    board = InMemoryBlackboard()
    res = board.write_metric("phase_latency_ms", 12.4, scope="telemetry")
    assert res.success is True
    assert res["success"] is True

    val = board.read_metric("phase_latency_ms")
    assert val == 12.4


def test_blackboard_regression_tolerance_check():
    """Verify numeric regression gating prevents exceeding strict tolerances."""
    board = InMemoryBlackboard()
    board.write_metric("ping_rtt_us", 100.0, strict_regression_tolerance=0.05)

    # 10% increase exceeds 5% tolerance
    res_regressed = board.write_metric("ping_rtt_us", 110.0, strict_regression_tolerance=0.05)
    assert res_regressed.success is False
    assert "regressed" in res_regressed.message


def test_blackboard_milestone_crypto_signoff():
    """Verify SHA-256 signature calculation and payload symmetry enforcement."""
    board = InMemoryBlackboard()
    payload = {"phase": 81, "subsystem": "MCP_BLACKBOARD"}
    res = board.log_milestone(81, "BLACKBOARD_MIGRATION", "COMPLETED", test_coverage=100.0, payload=payload)

    assert res.success is True
    expected_hash = hashlib.sha256(json.dumps(payload).encode()).hexdigest()
    assert res.signoff_hash == expected_hash
    assert res["signoff_hash"] == expected_hash


def test_sqlite_blackboard_backend_integration():
    """Verify SqliteBlackboardBackend end-to-end execution, regression check, and sign-offs."""
    with tempfile.TemporaryDirectory() as td:
        temp_db = os.path.join(td, "test_integration.db")
        backend = SqliteBlackboardBackend(db_path=temp_db)

        # 1. Metric write and read
        w_res = backend.write_metric("scan_duration_sec", 4.5, scope="scan")
        assert w_res.success is True
        assert backend.read_metric("scan_duration_sec") == 4.5

        # 2. Metric regression check
        w_reg = backend.write_metric("scan_duration_sec", 5.5, scope="scan", strict_regression_tolerance=0.05)
        assert w_reg.success is False
        assert "regressed" in w_reg.message

        # 3. List metrics
        metrics = backend.list_metrics(scope="scan")
        assert "scan_duration_sec" in metrics

        # 4. Milestone logging and hash verification
        payload = {"phase_id": 81, "status": "VERIFIED"}
        m_res = backend.log_milestone(81, "PHASE_81", "VERIFIED", test_coverage=100.0, payload=payload)
        assert m_res.success is True
        expected_hash = hashlib.sha256(json.dumps(payload).encode()).hexdigest()
        assert m_res.signoff_hash == expected_hash
