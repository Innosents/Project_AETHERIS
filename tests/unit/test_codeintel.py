"""
Unit test suite for CodeIntelPort and codeintel adapter.
Validates AST boundary isolation, protocol conformance, surgical mutations, and schema dual-access.
"""
import ast
import os
import tempfile
import pytest
from aetheris.core.ports.codeintel_port import (
    CodeIntelPort,
    CodeSymbolRecord,
    SymbolMutationResult,
    SymbolSourceResult,
)
from aetheris.mcp.codeintel import (
    CodeIntelEngine,
    codeintel_find_symbols,
    codeintel_get_symbol_source,
    codeintel_replace_symbol_body,
    codeintel_get_symbol_signature,
)


def test_codeintel_port_ast_boundary():
    """Verify codeintel_port.py contains zero mcp, fastapi, socket, or OS transport imports."""
    port_path = os.path.join("aetheris", "core", "ports", "codeintel_port.py")
    assert os.path.exists(port_path), f"Missing port file at {port_path}"

    with open(port_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=port_path)

    forbidden = {"mcp", "fastapi", "uvicorn", "socket", "scapy", "subprocess", "sqlite3", "redis"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                assert base not in forbidden, f"Forbidden direct import: {alias.name}"
        elif isinstance(node, ast.ImportFrom) and node.module:
            base = node.module.split(".")[0]
            assert base not in forbidden, f"Forbidden from-import: {node.module}"


def test_codeintel_protocol_conformance():
    """Verify CodeIntelEngine conforms to CodeIntelPort protocol."""
    engine = CodeIntelEngine()
    assert isinstance(engine, CodeIntelPort)


def test_codeintel_find_symbols_indexing():
    """Verify AST symbol detection and line boundary resolution."""
    sample_code = (
        "class RouterController:\n"
        "    def sync(self):\n"
        "        pass\n"
        "\n"
        "def standalone_func():\n"
        "    return 42\n"
    )
    with tempfile.TemporaryDirectory() as td:
        temp_path = os.path.join(td, "sample.py")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(sample_code)

        symbols = codeintel_find_symbols(temp_path)
        names = [s["name"] for s in symbols]
        assert "RouterController" in names
        assert "sync" in names
        assert "standalone_func" in names


def test_codeintel_replace_symbol_body_success():
    """Verify surgical body replacement without mutating surrounding tokens."""
    sample_code = (
        "def compute_drop(v: float) -> float:\n"
        "    return v * 0.1\n"
    )
    with tempfile.TemporaryDirectory() as td:
        temp_path = os.path.join(td, "calc.py")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(sample_code)

        new_fn = (
            "def compute_drop(v: float) -> float:\n"
            "    return v * 0.2\n"
        )
        msg = codeintel_replace_symbol_body(temp_path, "compute_drop", new_fn)
        assert "Successfully modified" in msg

        with open(temp_path, "r", encoding="utf-8") as rf:
            updated = rf.read()
        assert "return v * 0.2" in updated


def test_codeintel_replace_symbol_body_syntax_gate():
    """Verify mutation refusal when invalid syntax is supplied."""
    sample_code = "def sample():\n    pass\n"
    with tempfile.TemporaryDirectory() as td:
        temp_path = os.path.join(td, "syntax.py")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(sample_code)

        bad_fn = "def sample():\n    return >>> BROKEN SYNTAX <<<\n"
        msg = codeintel_replace_symbol_body(temp_path, "sample", bad_fn)
        assert "Structural Mutation Refused" in msg


def test_symbol_models_schema_immutability():
    """Verify CodeSymbolRecord schema validation, immutability, and dual mapping."""
    sym = CodeSymbolRecord(
        name="parse_telemetry",
        type="function",
        lineno=10,
        end_lineno=25
    )
    assert sym.name == "parse_telemetry"
    assert sym["name"] == "parse_telemetry"
    assert sym["lineno"] == 10
    with pytest.raises(Exception):
        sym.name = "override_name"
