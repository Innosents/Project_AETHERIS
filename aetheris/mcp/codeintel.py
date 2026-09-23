"""
Project AETHERIS - CodeIntel AST Parser & Surgical Mutation Engine
Encapsulates AST symbol indexing, surgical replacement, and syntax verification conforming to CodeIntelPort.
"""

import ast
import copy
import difflib
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from aetheris.core.ports.codeintel_port import (
    CodeIntelPort,
    CodeSymbolRecord,
    SymbolMutationResult,
    SymbolSourceResult,
    _MappingCompatibleModel,
)


class CodeIntelEngine(CodeIntelPort):
    """Pure in-memory AST indexing and surgical mutation engine."""

    def find_symbols(
        self, file_path: str, symbol_type: Optional[str] = None
    ) -> List[CodeSymbolRecord]:
        """Index classes and functions in a Python source file with exact line boundaries."""
        path = Path(file_path)
        if not path.is_file():
            return [CodeSymbolRecord(name="error", type="error", lineno=0, end_lineno=0, error=f"File not found: {file_path}")]

        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except Exception as e:
            return [CodeSymbolRecord(name="error", type="error", lineno=0, end_lineno=0, error=f"Parse error: {str(e)}")]

        symbols: List[CodeSymbolRecord] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if symbol_type in (None, "function"):
                    symbols.append(CodeSymbolRecord(
                        name=node.name,
                        type="async_function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                        lineno=node.lineno,
                        end_lineno=getattr(node, "end_lineno", node.lineno),
                    ))
            elif isinstance(node, ast.ClassDef):
                if symbol_type in (None, "class"):
                    symbols.append(CodeSymbolRecord(
                        name=node.name,
                        type="class",
                        lineno=node.lineno,
                        end_lineno=getattr(node, "end_lineno", node.lineno),
                    ))

        return sorted(symbols, key=lambda x: x.lineno)

    def get_symbol_source(self, file_path: str, symbol_name: str) -> SymbolSourceResult:
        """Extract only the exact AST body of a targeted class or function."""
        path = Path(file_path)
        if not path.is_file():
            return SymbolSourceResult(
                symbol_name=symbol_name,
                found=False,
                error=f"File not found: {file_path}"
            )

        try:
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
            tree = ast.parse("".join(lines), filename=str(path))
        except Exception as e:
            return SymbolSourceResult(
                symbol_name=symbol_name,
                found=False,
                error=f"Parse error in {file_path}: {str(e)}"
            )

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == symbol_name:
                    start = node.lineno - 1
                    end = getattr(node, "end_lineno", node.lineno)
                    source_str = "".join(lines[start:end])
                    
                    # Generate signature
                    try:
                        node_copy = copy.deepcopy(node)
                        node_copy.body = [ast.Pass()]
                        sig = ast.unparse(node_copy)
                    except Exception:
                        sig = None

                    return SymbolSourceResult(
                        symbol_name=symbol_name,
                        source=source_str,
                        signature=sig,
                        found=True
                    )

        return SymbolSourceResult(
            symbol_name=symbol_name,
            found=False,
            error=f"Symbol '{symbol_name}' not located in {file_path}"
        )

    def get_symbol_signature(self, file_path: str, symbol_name: str) -> str:
        """Extract only the exact AST signature/head of a targeted class or function."""
        res = self.get_symbol_source(file_path, symbol_name)
        if res.found and res.signature:
            return res.signature
        if res.error:
            return f"Error: {res.error}"
        return f"Error: Symbol '{symbol_name}' not located in {file_path}"

    def replace_symbol_body(
        self,
        file_path: str,
        symbol_name: str,
        new_source: str,
        dry_run: bool = False
    ) -> SymbolMutationResult:
        """Surgically replace a class or function without rewriting the entire file."""
        path = Path(file_path)
        if not path.is_file():
            return SymbolMutationResult(
                success=False,
                message=f"Error: File not found: {file_path}"
            )

        try:
            source = path.read_text(encoding="utf-8")
            lines = source.splitlines(keepends=True)
            tree = ast.parse(source, filename=str(path))
        except Exception as e:
            return SymbolMutationResult(
                success=False,
                message=f"Error parsing source file: {str(e)}"
            )

        target_node = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == symbol_name:
                    target_node = node
                    break

        if not target_node:
            return SymbolMutationResult(
                success=False,
                message=f"Error: Symbol '{symbol_name}' not found."
            )

        start = target_node.lineno - 1
        end = getattr(target_node, "end_lineno", target_node.lineno)

        if not new_source.endswith("\n"):
            new_source += "\n"

        new_content = "".join(lines[:start]) + new_source + "".join(lines[end:])

        # Validate AST integrity prior to writing
        try:
            ast.parse(new_content)
        except SyntaxError as e:
            return SymbolMutationResult(
                success=False,
                message=f"Structural Mutation Refused: Induced SyntaxError: {e}"
            )

        diff_str = None
        if dry_run:
            diff = difflib.unified_diff(
                lines,
                new_content.splitlines(keepends=True),
                fromfile=str(path),
                tofile=str(path),
                lineterm=""
            )
            diff_str = "".join(diff)
            return SymbolMutationResult(
                success=True,
                message=diff_str,
                diff=diff_str,
                start_line=start + 1,
                end_line=end
            )

        path.write_text(new_content, encoding="utf-8")
        return SymbolMutationResult(
            success=True,
            message=f"Successfully modified '{symbol_name}' in {file_path} (L{start + 1}-L{end})",
            start_line=start + 1,
            end_line=end
        )


default_codeintel = CodeIntelEngine()


def codeintel_find_symbols(
    file_path: str, symbol_type: Optional[str] = None
) -> List[CodeSymbolRecord]:
    """Index classes and functions in a Python source file with exact line boundaries."""
    return default_codeintel.find_symbols(file_path, symbol_type=symbol_type)


def codeintel_get_symbol_source(file_path: str, symbol_name: str) -> str:
    """Extract only the exact AST body of a targeted class or function."""
    res = default_codeintel.get_symbol_source(file_path, symbol_name)
    if res.found and res.source:
        return res.source
    return f"Error: {res.error or 'Symbol not found'}"


def codeintel_replace_symbol_body(
    file_path: str, symbol_name: str, new_source: str, dry_run: bool = False
) -> str:
    """Surgically replace a class or function without rewriting the entire file."""
    res = default_codeintel.replace_symbol_body(file_path, symbol_name, new_source, dry_run=dry_run)
    return res.message


def codeintel_get_symbol_signature(file_path: str, symbol_name: str) -> str:
    """Extract only the exact AST signature/head of a targeted class or function."""
    return default_codeintel.get_symbol_signature(file_path, symbol_name)


__all__ = [
    "CodeIntelEngine",
    "CodeIntelPort",
    "CodeSymbolRecord",
    "SymbolMutationResult",
    "SymbolSourceResult",
    "default_codeintel",
    "codeintel_find_symbols",
    "codeintel_get_symbol_source",
    "codeintel_replace_symbol_body",
    "codeintel_get_symbol_signature",
    "_MappingCompatibleModel",
]

