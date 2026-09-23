"""
Project AETHERIS - TestGuard MCP Microserver Engine & Sandboxed Test Execution Adapter
Implements TestGuardPort protocol for rapid syntax byte-compilation checks,
sandboxed pytest execution with OT socket shutdown auditing, and async cleanup validation.
"""

import os
import py_compile
import subprocess
import sys
from typing import Dict, List, Optional

from aetheris.core.ports.testguard_port import (
    TestGuardPort,
    SyntaxLintResult,
    PytestExecutionResult,
    AsyncCleanupResult,
    _MappingCompatibleModel,
)


class TestGuardEngine(TestGuardPort):
    """
    Sandboxed test execution and leak auditing engine conforming to TestGuardPort.
    """
    __test__ = False

    def syntax_lint(self, file_paths: List[str]) -> Dict[str, SyntaxLintResult]:
        """Execute rapid zero-overhead byte compilation syntax checks."""
        results: Dict[str, SyntaxLintResult] = {}
        for f in file_paths:
            try:
                py_compile.compile(f, doraise=True)
                results[f] = SyntaxLintResult(status="PASSED", error=None)
            except py_compile.PyCompileError as e:
                results[f] = SyntaxLintResult(status="FAILED", error=str(e))
            except Exception as e:
                results[f] = SyntaxLintResult(status="FAILED", error=str(e))
        return results

    def run_pytest(
        self, test_target: str, timeout_sec: float = 60.0
    ) -> PytestExecutionResult:
        """Execute pytest in an isolated subprocess with OTSocket shutdown auditing."""
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
            sys.executable,
            "-c",
            interceptor_code
            + "\nimport pytest\nimport sys\nsys.exit(pytest.main([sys.argv[1], '-v']))",
            test_target,
        ]
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
            return PytestExecutionResult(
                exit_code=proc.returncode,
                passed=proc.returncode == 0,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                error=None,
            )
        except subprocess.TimeoutExpired:
            return PytestExecutionResult(
                exit_code=-1,
                passed=False,
                stdout="",
                stderr="",
                error=f"Execution timed out after {timeout_sec}s",
            )
        except Exception as e:
            return PytestExecutionResult(
                exit_code=-1,
                passed=False,
                stdout="",
                stderr="",
                error=str(e),
            )

    def check_async_cleanup(self, script_one_liner: str) -> AsyncCleanupResult:
        """Run an async snippet and catch unclosed event loops or lingering background tasks."""
        indented = "\n".join("    " + line for line in script_one_liner.strip().splitlines())
        wrapped = f"""
import asyncio
import sys
import tracemalloc
import gc

async def _target():
{indented}

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

gc.collect()
tracemalloc.start()
snap1 = tracemalloc.take_snapshot()

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
    if total_diff > 8192:
        print(f"MEMORY_LEAK: Delta {{total_diff}} B exceeds 8192 B hysteresis ceiling.")
        sys.exit(43)
"""
        try:
            proc = subprocess.run(
                [sys.executable, "-c", wrapped],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return AsyncCleanupResult(
                clean=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
            )
        except Exception as e:
            return AsyncCleanupResult(
                clean=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
            )


default_testguard_engine = TestGuardEngine()


def testguard_syntax_lint(file_paths: List[str]) -> Dict[str, SyntaxLintResult]:
    """Execute rapid zero-overhead byte compilation syntax checks."""
    return default_testguard_engine.syntax_lint(file_paths)


def testguard_run_pytest(
    test_target: str, timeout_sec: float = 60.0
) -> PytestExecutionResult:
    """Execute pytest in an isolated subprocess with stdout/stderr capture."""
    return default_testguard_engine.run_pytest(test_target, timeout_sec)


def testguard_check_async_cleanup(script_one_liner: str) -> AsyncCleanupResult:
    """Run an async snippet and catch unclosed event loops or lingering background tasks."""
    return default_testguard_engine.check_async_cleanup(script_one_liner)


__all__ = [
    "TestGuardEngine",
    "default_testguard_engine",
    "testguard_syntax_lint",
    "testguard_run_pytest",
    "testguard_check_async_cleanup",
    "TestGuardPort",
    "SyntaxLintResult",
    "PytestExecutionResult",
    "AsyncCleanupResult",
    "_MappingCompatibleModel",
]

