"""AETHERIS - Blackboard MCP Microserver (mcp 2.x native).

Manages cross-turn persistence, ground-truth metrics, and phase milestones
in SQLite to avoid LLM context saturation.
"""

import json
import hashlib
import os
import sqlite3
from typing import Any, Dict, Optional
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

mcp = FastMCP("aetheris-blackboard")
DB_PATH = os.environ.get("AETHERIS_DB_PATH", "spatial_ledger.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_blackboard (
                key TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                payload TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS phase_milestones (
                phase_id INTEGER PRIMARY KEY,
                phase_name TEXT NOT NULL,
                status TEXT NOT NULL,
                test_coverage REAL,
                signoff_hash TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    return conn


@mcp.tool()
def blackboard_write_metric(key: str, value: Any, scope: str = "session", strict_regression_tolerance: float = 0.05) -> str:
    """Store an ephemeral or ground-truth metric into the persistent blackboard."""
    conn = _get_conn()
    if isinstance(value, (int, float)):
        cursor = conn.cursor()
        cursor.execute("SELECT payload FROM session_blackboard WHERE key = ?", (key,))
        row = cursor.fetchone()
        if row:
            old_val = json.loads(row["payload"])
            if isinstance(old_val, (int, float)) and old_val > 0:
                if (value - old_val) / old_val > strict_regression_tolerance:
                    conn.close()
                    return f"Error: Metric {key} regressed by more than {strict_regression_tolerance*100}% (Old: {old_val}, New: {value})"

    with conn:
        conn.execute(
            """
            INSERT INTO session_blackboard (key, scope, payload, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                scope=excluded.scope,
                payload=excluded.payload,
                updated_at=CURRENT_TIMESTAMP
        """,
            (key, scope, json.dumps(value)),
        )
    conn.close()
    return f"Successfully persisted metric: '{key}' [scope={scope}]"


@mcp.tool()
def blackboard_read_metric(key: str) -> Optional[Any]:
    """Retrieve an environmental or operational metric by key."""
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT payload FROM session_blackboard WHERE key = ?", (key,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return json.loads(row["payload"])


@mcp.tool()
def blackboard_list_metrics(scope: Optional[str] = None) -> Dict[str, Any]:
    """List all stored operational metrics, optionally filtered by scope."""
    conn = _get_conn()
    cursor = conn.cursor()
    if scope:
        cursor.execute(
            "SELECT key, payload FROM session_blackboard WHERE scope = ?",
            (scope,),
        )
    else:
        cursor.execute("SELECT key, payload FROM session_blackboard")
    rows = cursor.fetchall()
    conn.close()
    return {r["key"]: json.loads(r["payload"]) for r in rows}


@mcp.tool()
def blackboard_log_milestone(
    phase_id: int,
    phase_name: str,
    status: str,
    test_coverage: float = 0.0,
    payload: Any = None,
) -> str:
    """Log an engineering milestone sign-off."""
    signoff_hash = ""
    if payload is not None:
        serialized = json.dumps(payload)
        if json.loads(serialized) != payload:
            return "Error: Payload violates Data Symmetry (json.loads(json.dumps(res)) != res)"
        signoff_hash = hashlib.sha256(serialized.encode()).hexdigest()

    conn = _get_conn()
    with conn:
        conn.execute(
            """
            INSERT INTO phase_milestones (phase_id, phase_name, status, test_coverage, signoff_hash, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(phase_id) DO UPDATE SET
                phase_name=excluded.phase_name,
                status=excluded.status,
                test_coverage=excluded.test_coverage,
                signoff_hash=excluded.signoff_hash,
                updated_at=CURRENT_TIMESTAMP
        """,
            (phase_id, phase_name, status, test_coverage, signoff_hash),
        )
    conn.close()
    return f"Logged Phase {phase_id} ({phase_name}) as {status}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
