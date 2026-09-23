"""AETHERIS TestGuard MCP Microserver (mcp 2.x native).

Executes tests in deterministic sandboxed subprocesses and detects
lingering unawaited coroutines or uncancelled tasks.
Delegates to decoupled TestGuardEngine implementation.
"""

from typing import Any, Dict, List

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    try:
        from mcp.server import FastMCP
    except (ImportError, ModuleNotFoundError):
        from mcp.server import FastMCP as MCPServer

from aetheris.mcp.testguard import (
    default_testguard_engine,
    testguard_syntax_lint as _syntax_lint,
    testguard_run_pytest as _run_pytest,
    testguard_check_async_cleanup as _check_async_cleanup,
)

mcp = FastMCP("aetheris-testguard")


@mcp.tool()
def testguard_syntax_lint(file_paths: List[str]) -> Dict[str, Any]:
    """Execute rapid zero-overhead byte compilation syntax checks."""
    res = _syntax_lint(file_paths)
    return {k: dict(v) for k, v in res.items()}


@mcp.tool()
def testguard_run_pytest(
    test_target: str, timeout_sec: float = 60.0
) -> Dict[str, Any]:
    """Execute pytest in an isolated subprocess with stdout/stderr capture."""
    res = _run_pytest(test_target, timeout_sec)
    return dict(res)


@mcp.tool()
def testguard_check_async_cleanup(script_one_liner: str) -> Dict[str, Any]:
    """Run an async snippet and catch unclosed event loops or lingering background tasks."""
    res = _check_async_cleanup(script_one_liner)
    return dict(res)


if __name__ == "__main__":
    mcp.run(transport="stdio")
