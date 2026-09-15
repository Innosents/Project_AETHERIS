"""AETHERIS CodeIntel MCP Microserver (mcp 2.x native).

Performs AST parsing, surgical function/class replacement, and symbol extraction
without context-saturating full-file dumps.
"""

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional
from mcp.server import FastMCP

try:
    # MCP v1.x / FastMCP standard
    from mcp.server import FastMCP as MCPServer
except (ImportError, ModuleNotFoundError):
    try:
        # MCP alternate / candidate namespace
        from mcp.server import FastMCP
    except (ImportError, ModuleNotFoundError):
        # Fallback to standard Server interface
        from mcp.server import Server as MCPServer
        
mcp = FastMCP("aetheris-codeintel")


@mcp.tool()
def codeintel_find_symbols(
    file_path: str, symbol_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Index classes and functions in a Python source file with exact line boundaries."""
    path = Path(file_path)
    if not path.is_file():
        return [{"error": f"File not found: {file_path}"}]

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    symbols = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if symbol_type in (None, "function"):
                symbols.append({
                    "name": node.name,
                    "type": (
                        "async_function"
                        if isinstance(node, ast.AsyncFunctionDef)
                        else "function"
                    ),
                    "lineno": node.lineno,
                    "end_lineno": getattr(node, "end_lineno", node.lineno),
                })
        elif isinstance(node, ast.ClassDef):
            if symbol_type in (None, "class"):
                symbols.append({
                    "name": node.name,
                    "type": "class",
                    "lineno": node.lineno,
                    "end_lineno": getattr(node, "end_lineno", node.lineno),
                })

    return sorted(symbols, key=lambda x: x["lineno"])


@mcp.tool()
def codeintel_get_symbol_source(file_path: str, symbol_name: str) -> str:
    """Extract only the exact AST body of a targeted class or function."""
    path = Path(file_path)
    if not path.is_file():
        return f"Error: File not found: {file_path}"

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    tree = ast.parse("".join(lines), filename=str(path))

    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            if node.name == symbol_name:
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno)
                return "".join(lines[start:end])

    return f"Error: Symbol '{symbol_name}' not located in {file_path}"


@mcp.tool()
def codeintel_replace_symbol_body(
    file_path: str, symbol_name: str, new_source: str
) -> str:
    """Surgically replace a class or function without rewriting the entire file."""
    path = Path(file_path)
    if not path.is_file():
        return f"Error: File not found: {file_path}"

    source = path.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    tree = ast.parse(source, filename=str(path))

    target_node = None
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            if node.name == symbol_name:
                target_node = node
                break

    if not target_node:
        return f"Error: Symbol '{symbol_name}' not found."

    start = target_node.lineno - 1
    end = getattr(target_node, "end_lineno", target_node.lineno)

    if not new_source.endswith("\n"):
        new_source += "\n"

    new_content = "".join(lines[:start]) + new_source + "".join(lines[end:])

    # Validate AST integrity prior to writing
    try:
        ast.parse(new_content)
    except SyntaxError as e:
        return f"Structural Mutation Refused: Induced SyntaxError: {e}"

    path.write_text(new_content, encoding="utf-8")
    return f"Successfully modified '{symbol_name}' in {file_path} (L{start + 1}-L{end})"


if __name__ == "__main__":
    mcp.run(transport="stdio")
