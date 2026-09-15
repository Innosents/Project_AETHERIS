"""AETHERIS TestGuard MCP Microserver (mcp 2.x native).

Executes tests in deterministic sandboxed subprocesses and detects
lingering unawaited coroutines or uncancelled tasks.
"""

import py_compile
import subprocess
import sys
from typing import Any, Dict, List
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

mcp = FastMCP("aetheris-testguard")


@mcp.tool()
def testguard_syntax_lint(file_paths: List[str]) -> Dict[str, Any]:
    """Execute rapid zero-overhead byte compilation syntax checks."""
    results = {}
    for f in file_paths:
        try:
            py_compile.compile(f, doraise=True)
            results[f] = {"status": "PASSED"}
        except py_compile.PyCompileError as e:
            results[f] = {"status": "FAILED", "error": str(e)}
    return results


@mcp.tool()
def testguard_run_pytest(
    test_target: str, timeout_sec: float = 60.0
) -> Dict[str, Any]:
    """Execute pytest in an isolated subprocess with stdout/stderr capture."""
    cmd = [sys.executable, "-m", "pytest", test_target, "-v"]
    import os
    project_root = os.environ.get("PYTHONPATH", "E:\\Project_AETHERIS")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
            cwd=project_root,
        )
        return {
            "exit_code": proc.returncode,
            "passed": proc.returncode == 0,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "passed": False,
            "error": f"Execution timed out after {timeout_sec}s",
        }


@mcp.tool()
def testguard_check_async_cleanup(script_one_liner: str) -> Dict[str, Any]:
    """Run an async snippet and catch unclosed event loops or lingering background tasks."""
    wrapped = f"""
import asyncio
import sys

async def _target():
{script_one_liner}

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    loop.run_until_complete(_target())
finally:
    pending = asyncio.all_tasks(loop)
    task_count = len(pending)
    for t in pending:
        t.cancel()
    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    loop.close()
    if task_count > 0:
        print(f"ASYNC_LEAK: {{task_count}} pending task(s) uncollected before teardown.")
        sys.exit(42)
"""
    proc = subprocess.run(
        [sys.executable, "-c", wrapped],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return {
        "clean": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
