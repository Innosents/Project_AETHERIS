"""AETHERIS CodeIntel MCP Microserver (mcp 2.x native).

Performs AST parsing, surgical function/class replacement, and symbol extraction
without context-saturating full-file dumps.
"""

from typing import Any, Dict, List, Optional
from aetheris.mcp.codeintel import (
    CodeIntelEngine,
    default_codeintel,
    CodeIntelPort,
    CodeSymbolRecord,
    SymbolMutationResult,
    SymbolSourceResult,
    codeintel_find_symbols,
    codeintel_get_symbol_source,
    codeintel_replace_symbol_body,
    codeintel_get_symbol_signature,
)

try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("aetheris-codeintel")
except Exception:
    mcp = None


if mcp:
    @mcp.tool()
    def mcp_find_symbols(
        file_path: str, symbol_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Index classes and functions in a Python source file with exact line boundaries."""
        symbols = default_codeintel.find_symbols(file_path, symbol_type=symbol_type)
        return [s.model_dump() for s in symbols]

    @mcp.tool()
    def mcp_get_symbol_source(file_path: str, symbol_name: str) -> str:
        """Extract only the exact AST body of a targeted class or function."""
        return codeintel_get_symbol_source(file_path, symbol_name)

    @mcp.tool()
    def mcp_replace_symbol_body(
        file_path: str, symbol_name: str, new_source: str, dry_run: bool = False
    ) -> str:
        """Surgically replace a class or function without rewriting the entire file."""
        return codeintel_replace_symbol_body(file_path, symbol_name, new_source, dry_run=dry_run)

    @mcp.tool()
    def mcp_get_symbol_signature(file_path: str, symbol_name: str) -> str:
        """Extract only the exact AST signature/head of a targeted class or function."""
        return codeintel_get_symbol_signature(file_path, symbol_name)


if __name__ == "__main__" and mcp:
    mcp.run(transport="stdio")
