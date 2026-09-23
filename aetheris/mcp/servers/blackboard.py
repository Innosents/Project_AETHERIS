"""AETHERIS - Blackboard MCP Microserver (mcp 2.x native).

Manages cross-turn persistence, ground-truth metrics, and phase milestones
in SQLite to avoid LLM context saturation.
"""

from typing import Any, Dict, Optional
from aetheris.mcp.blackboard import (
    SqliteBlackboardBackend,
    default_blackboard,
    BlackboardPort,
    BlackboardMetricRecord,
    PhaseMilestoneRecord,
    BlackboardOperationResult,
)

try:
    from mcp.server import FastMCP
    mcp = FastMCP("aetheris-blackboard")
except Exception:
    mcp = None


if mcp:
    @mcp.tool()
    def blackboard_write_metric(key: str, value: Any, scope: str = "session", strict_regression_tolerance: float = 0.05) -> str:
        """Store an ephemeral or ground-truth metric into the persistent blackboard."""
        res = default_blackboard.write_metric(key, value, scope=scope, strict_regression_tolerance=strict_regression_tolerance)
        return res.message

    @mcp.tool()
    def blackboard_read_metric(key: str) -> Optional[Any]:
        """Retrieve an environmental or operational metric by key."""
        return default_blackboard.read_metric(key)

    @mcp.tool()
    def blackboard_list_metrics(scope: Optional[str] = None) -> Dict[str, Any]:
        """List all stored operational metrics, optionally filtered by scope."""
        return default_blackboard.list_metrics(scope=scope)

    @mcp.tool()
    def blackboard_log_milestone(
        phase_id: int,
        phase_name: str,
        status: str,
        test_coverage: float = 0.0,
        payload: Any = None,
    ) -> str:
        """Log an engineering milestone sign-off."""
        res = default_blackboard.log_milestone(
            phase_id=phase_id,
            phase_name=phase_name,
            status=status,
            test_coverage=test_coverage,
            payload=payload,
        )
        return res.message


if __name__ == "__main__" and mcp:
    mcp.run(transport="stdio")
