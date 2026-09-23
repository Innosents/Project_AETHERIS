"""
Project AETHERIS - Blackboard MCP Adapter & Persistent State Store
Encapsulates SQLite cross-turn execution state, regression-checked metrics,
and cryptographic milestone sign-offs behind BlackboardPort.
"""

import os
import json
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from aetheris.core.ports.blackboard_port import (
    BlackboardPort,
    BlackboardMetricRecord,
    PhaseMilestoneRecord,
    BlackboardOperationResult,
    _MappingCompatibleModel,
)


class SqliteBlackboardBackend(BlackboardPort):
    """SQLite-backed implementation of BlackboardPort."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = str(db_path)
        else:
            env_path = os.environ.get("AETHERIS_DB_PATH")
            if env_path:
                self.db_path = env_path
            else:
                self.db_path = str(Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db")
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        try:
            conn = self._get_conn()
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
            conn.close()
        except Exception:
            pass

    def write_metric(
        self,
        key: str,
        value: Any,
        scope: str = "session",
        strict_regression_tolerance: float = 0.05
    ) -> BlackboardOperationResult:
        """Stores a metric with optional numeric regression checks."""
        try:
            conn = self._get_conn()
            if isinstance(value, (int, float)):
                cursor = conn.cursor()
                cursor.execute("SELECT payload FROM session_blackboard WHERE key = ?", (key,))
                row = cursor.fetchone()
                if row:
                    try:
                        old_val = json.loads(row["payload"])
                        if isinstance(old_val, (int, float)) and old_val > 0:
                            if (value - old_val) / old_val > strict_regression_tolerance:
                                conn.close()
                                return BlackboardOperationResult(
                                    success=False,
                                    message=f"Error: Metric {key} regressed by more than {strict_regression_tolerance*100}% (Old: {old_val}, New: {value})"
                                )
                    except Exception:
                        pass

            with conn:
                conn.execute("""
                    INSERT INTO session_blackboard (key, scope, payload, updated_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET
                        scope=excluded.scope,
                        payload=excluded.payload,
                        updated_at=CURRENT_TIMESTAMP
                """, (key, scope, json.dumps(value)))
            conn.close()
            return BlackboardOperationResult(
                success=True,
                message=f"Successfully persisted metric: '{key}' [scope={scope}]"
            )
        except Exception as e:
            return BlackboardOperationResult(
                success=False,
                message=f"Database error writing metric {key}: {str(e)}"
            )

    def read_metric(self, key: str) -> Optional[Any]:
        """Retrieves a stored metric value by key."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT payload FROM session_blackboard WHERE key = ?", (key,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                return None
            return json.loads(row["payload"])
        except Exception:
            return None

    def list_metrics(self, scope: Optional[str] = None) -> Dict[str, Any]:
        """Lists stored operational metrics, optionally filtered by scope."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            if scope:
                cursor.execute("SELECT key, payload FROM session_blackboard WHERE scope = ?", (scope,))
            else:
                cursor.execute("SELECT key, payload FROM session_blackboard")
            rows = cursor.fetchall()
            conn.close()
            return {r["key"]: json.loads(r["payload"]) for r in rows}
        except Exception:
            return {}

    def log_milestone(
        self,
        phase_id: int,
        phase_name: str,
        status: str,
        test_coverage: float = 0.0,
        payload: Any = None
    ) -> BlackboardOperationResult:
        """Validates payload symmetry, computes SHA-256 sign-off, and logs milestone."""
        signoff_hash = ""
        if payload is not None:
            try:
                serialized = json.dumps(payload)
                if json.loads(serialized) != payload:
                    return BlackboardOperationResult(
                        success=False,
                        message="Error: Payload violates Data Symmetry (json.loads(json.dumps(res)) != res)"
                    )
                signoff_hash = hashlib.sha256(serialized.encode()).hexdigest()
            except Exception as e:
                return BlackboardOperationResult(
                    success=False,
                    message=f"Serialization failure for milestone payload: {str(e)}"
                )

        try:
            conn = self._get_conn()
            with conn:
                conn.execute("""
                    INSERT INTO phase_milestones (phase_id, phase_name, status, test_coverage, signoff_hash, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(phase_id) DO UPDATE SET
                        phase_name=excluded.phase_name,
                        status=excluded.status,
                        test_coverage=excluded.test_coverage,
                        signoff_hash=excluded.signoff_hash,
                        updated_at=CURRENT_TIMESTAMP
                """, (phase_id, phase_name, status, test_coverage, signoff_hash))
            conn.close()
            return BlackboardOperationResult(
                success=True,
                message=f"Logged Phase {phase_id} ({phase_name}) as {status}",
                signoff_hash=signoff_hash
            )
        except Exception as e:
            return BlackboardOperationResult(
                success=False,
                message=f"Database error logging milestone {phase_id}: {str(e)}"
            )


default_blackboard = SqliteBlackboardBackend()


def blackboard_write_metric(key: str, value: Any, scope: str = "session", strict_regression_tolerance: float = 0.05) -> str:
    res = default_blackboard.write_metric(key, value, scope=scope, strict_regression_tolerance=strict_regression_tolerance)
    return res.message


def blackboard_read_metric(key: str) -> Optional[Any]:
    return default_blackboard.read_metric(key)


def blackboard_list_metrics(scope: Optional[str] = None) -> Dict[str, Any]:
    return default_blackboard.list_metrics(scope=scope)


def blackboard_log_milestone(
    phase_id: int,
    phase_name: str,
    status: str,
    test_coverage: float = 0.0,
    payload: Any = None
) -> str:
    res = default_blackboard.log_milestone(phase_id, phase_name, status, test_coverage=test_coverage, payload=payload)
    return res.message


__all__ = [
    "SqliteBlackboardBackend",
    "BlackboardPort",
    "BlackboardMetricRecord",
    "PhaseMilestoneRecord",
    "BlackboardOperationResult",
    "default_blackboard",
    "blackboard_write_metric",
    "blackboard_read_metric",
    "blackboard_list_metrics",
    "blackboard_log_milestone",
    "_MappingCompatibleModel",
]

