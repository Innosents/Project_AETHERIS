"""
Unit test suite for TestGuardPort and testguard adapter.
Validates AST boundary isolation, protocol conformance, syntax linting, and schema dual-access.
"""
import ast
import os
import tempfile
import pytest
from aetheris.core.ports.testguard_port import (
    TestGuardPort,
    SyntaxLintResult,
    PytestExecutionResult,
    AsyncCleanupResult,
)
from aetheris.mcp.testguard import (
    TestGuardEngine,
    testguard_syntax_lint as run_syntax_lint,
    testguard_run_pytest as execute_sandboxed_pytest,
    testguard_check_async_cleanup as run_async_cleanup_check,
)


def test_testguard_port_ast_boundary():
    """Verify testguard_port.py contains zero subprocess, socket, py_compile, or mcp imports."""
    port_path = os.path.join("aetheris", "core", "ports", "testguard_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        content = f.read()
    if content.startswith("\ufeff"):
        content = content[1:]
    tree = ast.parse(content, filename=port_path)

    forbidden = {"subprocess", "socket", "py_compile", "mcp", "fastapi", "uvicorn", "sqlite3", "scapy"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_testguard_protocol_conformance():
    """Verify TestGuardEngine conforms to TestGuardPort protocol."""
    engine = TestGuardEngine()
    assert isinstance(engine, TestGuardPort)


def test_syntax_lint_valid_and_invalid_files():
    """Verify byte compilation verification passes valid code and catches syntax faults."""
    with tempfile.TemporaryDirectory() as tmpdir:
        good_path = os.path.join(tmpdir, "good.py")
        bad_path = os.path.join(tmpdir, "bad.py")
        with open(good_path, "w", encoding="utf-8") as f_good:
            f_good.write("def valid_syntax():\n    return 42\n")
        with open(bad_path, "w", encoding="utf-8") as f_bad:
            f_bad.write("def broken_syntax():\n    return <<<< BAD TOKEN\n")

        results = run_syntax_lint([good_path, bad_path])
        assert results[good_path]["status"] == "PASSED"
        assert results[bad_path]["status"] == "FAILED"
        assert "error" in results[bad_path]


def test_check_async_cleanup_nominal():
    """Verify async clean-up detector validates properly resolved coroutines."""
    snippet = "await asyncio.sleep(0.01)"
    res = run_async_cleanup_check(snippet)
    assert res["clean"] is True
    assert res["exit_code"] == 0


def test_pytest_execution_result_immutability():
    """Verify PytestExecutionResult schema validation, immutability, and dual mapping."""
    res = PytestExecutionResult(
        exit_code=0,
        passed=True,
        stdout="5 passed in 0.42s",
        stderr=""
    )
    assert res.passed is True
    assert res["passed"] is True
    assert res.exit_code == 0
    assert res["exit_code"] == 0
    with pytest.raises(Exception):
        res.passed = False
