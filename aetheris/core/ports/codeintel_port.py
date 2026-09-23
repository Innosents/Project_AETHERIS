"""
Project AETHERIS - CodeIntel AST Parser & Surgical Mutation Port Interface
Hexagonal Protocol defining Python AST symbol indexing, surgical body replacements,
and AST syntax integrity gates.
Strict zero-I/O boundary: Contains zero mcp, fastapi, uvicorn, socket, or network transport imports.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field


class _MappingCompatibleModel(dict):
    """Dual-mode structure supporting attribute lookups, dict access, CPython json.dumps, and frozen immutability."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        is_frozen = getattr(self.__class__, "_frozen", False) or getattr(self.__class__, "frozen", False)
        if hasattr(self.__class__, "model_config"):
            cfg = getattr(self.__class__, "model_config")
            if isinstance(cfg, dict) and cfg.get("frozen"):
                is_frozen = True
            elif getattr(cfg, "frozen", False):
                is_frozen = True
        if hasattr(self.__class__, "Config"):
            cfg_cls = getattr(self.__class__, "Config")
            if getattr(cfg_cls, "frozen", False):
                is_frozen = True
        object.__setattr__(self, "_is_frozen", is_frozen)

    def __getattribute__(self, item: str) -> Any:
        try:
            return self[item]
        except (KeyError, TypeError):
            pass
        return super().__getattribute__(item)

    def __setattr__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        self[item] = value

    def __setitem__(self, item: str, value: Any) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__setitem__(item, value)

    def __delattr__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        try:
            del self[item]
        except KeyError:
            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{item}'")

    def __delitem__(self, item: str) -> None:
        if getattr(self, "_is_frozen", False):
            raise TypeError(f"'{self.__class__.__name__}' is immutable and frozen")
        super().__delitem__(item)

    def get(self, item: str, default: Any = None) -> Any:
        return super().get(item, default)

    def model_dump(self) -> Dict[str, Any]:
        return dict(self)

    def dict(self) -> Dict[str, Any]:
        return dict(self)


class CodeSymbolRecord(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    name: str = Field(...)
    type: str = Field(default="function")
    lineno: int = Field(...)
    end_lineno: int = Field(...)
    error: Optional[str] = Field(default=None)


class SymbolMutationResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    success: bool = Field(...)
    message: str = Field(...)
    diff: Optional[str] = Field(default=None)
    start_line: Optional[int] = Field(default=None)
    end_line: Optional[int] = Field(default=None)


class SymbolSourceResult(_MappingCompatibleModel):
    model_config = ConfigDict(frozen=True)
    symbol_name: str = Field(...)
    source: Optional[str] = Field(default=None)
    signature: Optional[str] = Field(default=None)
    found: bool = Field(...)
    error: Optional[str] = Field(default=None)


@runtime_checkable
class CodeIntelPort(Protocol):
    """Hexagonal Protocol defining AST indexing and surgical mutation capabilities."""

    def find_symbols(self, file_path: str, symbol_type: Optional[str] = None) -> List[CodeSymbolRecord]:
        """Indexes classes and functions within a target Python source file."""
        ...

    def get_symbol_source(self, file_path: str, symbol_name: str) -> SymbolSourceResult:
        """Extracts the exact body or signature of an AST target."""
        ...

    def replace_symbol_body(
        self,
        file_path: str,
        symbol_name: str,
        new_source: str,
        dry_run: bool = False
    ) -> SymbolMutationResult:
        """Surgically mutates symbol definition with AST syntax validation."""
        ...

