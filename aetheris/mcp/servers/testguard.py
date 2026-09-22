"""AETHERIS TestGuard MCP Microserver (mcp 2.x native).

Executes tests in deterministic sandboxed subprocesses and detects
lingering unawaited coroutines or uncancelled tasks.
"""

import py_compile
import subprocess
import sys
from typing import Any, Dict, List


try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    try:
        from mcp.server import FastMCP
    except (ImportError, ModuleNotFoundError):
        from mcp.server import FastMCP as MCPServer

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
    interceptor_code = """
import socket
import sys

_orig_socket = socket.socket
_active_fds = set()

class OTSocket(_orig_socket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ot_tracked = False

    def connect(self, address):
        if isinstance(address, tuple) and address[1] in (102, 44818):
            self.settimeout(0.5)
            self._ot_tracked = True
            _active_fds.add(self.fileno())
        super().connect(address)

    def shutdown(self, how):
        if self._ot_tracked and self.fileno() in _active_fds:
            _active_fds.remove(self.fileno())
        super().shutdown(how)

    def __del__(self):
        if self._ot_tracked and getattr(self, 'fileno', lambda: -1)() in _active_fds:
            print(f"OT_SAFETY_VIOLATION: Socket FD {self.fileno()} garbage collected without SHUT_RDWR.", file=sys.stderr)
            sys.exit(44)
        super().__del__() if hasattr(super(), '__del__') else None

socket.socket = OTSocket
"""
    cmd = [
        sys.executable, "-c",
        interceptor_code + "\nimport pytest\nimport sys\nsys.exit(pytest.main([sys.argv[1], '-v']))",
        test_target
    ]
    import os
    project_root = os.environ.get("PYTHONPATH", "E:\\Project_AETHERIS")
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
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
    indented = "\n".join("    " + line for line in script_one_liner.strip().splitlines())
    wrapped = f"""
import asyncio
import sys
import tracemalloc
import gc

async def _target():
{indented}

gc.collect()
tracemalloc.start()
snap1 = tracemalloc.take_snapshot()

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
    
    gc.collect()
    snap2 = tracemalloc.take_snapshot()
    diff = snap2.compare_to(snap1, 'lineno')
    total_diff = sum(stat.size_diff for stat in diff)
    
    if task_count > 0:
        print(f"ASYNC_LEAK: {{task_count}} pending task(s) uncollected before teardown.")
        sys.exit(42)
    if total_diff > 4096:
        print(f"MEMORY_LEAK: Delta {{total_diff}} B exceeds 4096 B hysteresis ceiling.")
        sys.exit(43)
"""
    proc = subprocess.run(
        [sys.executable, "-c", wrapped],
        stdin=subprocess.DEVNULL,
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
