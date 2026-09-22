"""
Project AETHERIS - Dual-Tier SQLite & Redis-Backed Telemetry Ledger & Spatial Experience Store
Maintains zero-connection-leak SQLite persistence for audit stability and MCP tools,
while providing high-throughput Redis caching and nanosecond flight-time telemetry (tau)
for MCMC and Bayesian solvers.
"""

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import redis

from aetheris.core.ports.telemetry_ledger_port import (
    ConvergenceRecordModel,
    TelemetryLedgerPort,
)

DEFAULT_REDIS_URL = "redis://localhost:6379/0"


ConvergenceRecord = ConvergenceRecordModel


class _ClosingConnection:
    """Context manager wrapper that auto-closes sqlite3 connections upon exit to prevent file descriptor leaks."""

    def __init__(self, db_path: str, existing_conn: Optional[sqlite3.Connection] = None):
        if existing_conn is not None:
            self.conn = existing_conn
            self._should_close = False
        else:
            self.conn = sqlite3.connect(db_path, timeout=5.0)
            self.conn.row_factory = sqlite3.Row
            self._should_close = True

    def __enter__(self) -> sqlite3.Connection:
        return self.conn.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            return self.conn.__exit__(exc_type, exc_val, exc_tb)
        finally:
            if self._should_close:
                self.conn.close()


class TelemetryLedger(TelemetryLedgerPort):
    """
    Persistent empirical experience store for AETHERIS spatial deconvolution.
    Aggregates runtime convergence to dynamically refine MCMC priors over time.
    Supports dual SQLite file-backed storage and Redis caching.
    """

    def __init__(
        self,
        redis_url: str = DEFAULT_REDIS_URL,
        redis_client: Optional[redis.Redis] = None,
        max_connections: int = 50,
        db_path: Optional[str] = None,
    ):
        self._memory_conn: Optional[sqlite3.Connection] = None
        if db_path:
            if str(db_path) == ":memory:":
                self.db_path = Path(":memory:")
                self._memory_conn = sqlite3.connect(":memory:", timeout=5.0)
                self._memory_conn.row_factory = sqlite3.Row
            else:
                self.db_path = Path(db_path)
            self.explicit_db = True
        else:
            env_db = os.environ.get("AETHERIS_DB_PATH")
            if env_db:
                self.db_path = Path(env_db)
            else:
                base_dir = Path(__file__).resolve().parent.parent.parent
                self.db_path = base_dir / "spatial_ledger.db"
            self.explicit_db = False

        self._init_db()

        self.redis_url = redis_url
        self.redis: Optional[redis.Redis] = None
        if not self.explicit_db or redis_client is not None:
            if redis_client is not None:
                self.redis = redis_client
            else:
                try:
                    self.pool = redis.ConnectionPool.from_url(
                        self.redis_url,
                        max_connections=max_connections,
                        decode_responses=True,
                    )
                    client = redis.Redis(connection_pool=self.pool)
                    client.ping()
                    self.redis = client
                except Exception:
                    pass

    def _get_connection(self) -> _ClosingConnection:
        if self._memory_conn is not None:
            return _ClosingConnection(str(self.db_path), existing_conn=self._memory_conn)
        return _ClosingConnection(str(self.db_path))

    def _init_db(self) -> None:
        if str(self.db_path) != ":memory:" and self.db_path.parent:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS convergence_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    mac TEXT,
                    oui TEXT,
                    ip TEXT,
                    archetype TEXT,
                    min_rtt_us REAL,
                    jitter_us REAL,
                    converged_distance_m REAL,
                    converged_kernel_us REAL,
                    variance_m2 REAL,
                    confidence_pct REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS calibration_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    anchor_count INTEGER,
                    calibrated_nvp REAL,
                    calibrated_switch_latency_s REAL,
                    wls_confidence REAL,
                    residuals_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scope_provenance_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    auth_ref TEXT,
                    provenance_token TEXT,
                    provenance_digest TEXT,
                    in_scope_cidrs_json TEXT,
                    do_not_scan_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS stp_topology_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    root_bridge_mac TEXT,
                    root_path_cost INTEGER,
                    designated_bridge_mac TEXT,
                    port_id INTEGER,
                    is_root_bridge INTEGER,
                    stp_version TEXT,
                    tc_flag INTEGER,
                    vlan_id INTEGER DEFAULT 0
                )
            """)
            try:
                conn.execute("ALTER TABLE stp_topology_ledger ADD COLUMN vlan_id INTEGER DEFAULT 0")
            except Exception:
                pass
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oui_arch ON convergence_ledger(oui, archetype)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_mac ON convergence_ledger(mac)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_convergence_mac_ts ON convergence_ledger(mac, timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_convergence_lower_mac_ts ON convergence_ledger(LOWER(mac), timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_stp_root_mac ON stp_topology_ledger(root_bridge_mac)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_stp_bridge_mac ON stp_topology_ledger(designated_bridge_mac)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_stp_root_vlan ON stp_topology_ledger(root_bridge_mac, vlan_id)")
            conn.commit()

    def record_calibration(
        self,
        anchor_count: int,
        calibrated_nvp: float,
        calibrated_switch_latency_s: float,
        wls_confidence: float,
        residuals: Optional[List[float]] = None,
    ) -> None:
        """Records an overdetermined WLS calibration milestone into the spatial ledger."""
        residuals_json = json.dumps(residuals or [])
        ts = time.time()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO calibration_ledger (
                    timestamp, anchor_count, calibrated_nvp,
                    calibrated_switch_latency_s, wls_confidence, residuals_json
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ts,
                int(anchor_count),
                float(calibrated_nvp),
                float(calibrated_switch_latency_s),
                float(wls_confidence),
                residuals_json,
            ))
            conn.commit()

        if self.redis is not None:
            try:
                record = {
                    "timestamp": ts,
                    "anchor_count": int(anchor_count),
                    "calibrated_nvp": float(calibrated_nvp),
                    "calibrated_switch_latency_s": float(calibrated_switch_latency_s),
                    "wls_confidence": float(wls_confidence),
                    "residuals": residuals or [],
                }
                pipe = self.redis.pipeline(transaction=False)
                pipe.lpush("aetheris:calibrations", json.dumps(record))
                pipe.zadd("aetheris:calibrations:temporal", {json.dumps(record): ts})
                pipe.execute()
            except Exception:
                pass

    def record_scope_provenance(
        self,
        auth_ref: str,
        provenance_token: str,
        provenance_digest: str,
        in_scope_cidrs: Optional[List[str]] = None,
        do_not_scan: Optional[List[str]] = None,
    ) -> None:
        """Records a cryptographic scope authorization provenance token into the spatial ledger."""
        ts = time.time()
        in_scope_json = json.dumps(in_scope_cidrs or [])
        do_not_scan_json = json.dumps(do_not_scan or [])
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO scope_provenance_ledger (
                    timestamp, auth_ref, provenance_token, provenance_digest,
                    in_scope_cidrs_json, do_not_scan_json
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ts,
                str(auth_ref),
                str(provenance_token),
                str(provenance_digest),
                in_scope_json,
                do_not_scan_json,
            ))
            conn.commit()

        if self.redis is not None:
            try:
                record = {
                    "timestamp": ts,
                    "auth_ref": str(auth_ref),
                    "provenance_token": str(provenance_token),
                    "provenance_digest": str(provenance_digest),
                    "in_scope_cidrs": in_scope_cidrs or [],
                    "do_not_scan": do_not_scan or [],
                }
                pipe = self.redis.pipeline(transaction=False)
                pipe.lpush("aetheris:scope_provenance", json.dumps(record))
                pipe.execute()
            except Exception:
                pass

    def record_stp_topology(
        self,
        root_bridge_mac: str,
        root_path_cost: int,
        designated_bridge_mac: str,
        port_id: int,
        is_root_bridge: bool,
        stp_version: str = "STP",
        tc_flag: bool = False,
        vlan_id: int = 0,
    ) -> None:
        """Records an STP BPDU topological tree boundary constraint into the spatial ledger."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO stp_topology_ledger (
                    timestamp, root_bridge_mac, root_path_cost,
                    designated_bridge_mac, port_id, is_root_bridge,
                    stp_version, tc_flag, vlan_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                time.time(),
                str(root_bridge_mac),
                int(root_path_cost),
                str(designated_bridge_mac),
                int(port_id),
                1 if is_root_bridge else 0,
                str(stp_version),
                1 if tc_flag else 0,
                int(vlan_id),
            ))
            conn.commit()

    def get_stp_topology(
        self,
        root_bridge_mac: Optional[str] = None,
        vlan_id: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves the latest matching STP BPDU topological tree record."""
        with self._get_connection() as conn:
            query = "SELECT * FROM stp_topology_ledger"
            params = []
            clauses = []
            if root_bridge_mac is not None:
                clauses.append("root_bridge_mac = ?")
                params.append(str(root_bridge_mac))
            if vlan_id is not None:
                clauses.append("vlan_id = ?")
                params.append(int(vlan_id))
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY timestamp DESC LIMIT 1"
            cursor = conn.execute(query, tuple(params))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_stp_topology_count(self) -> int:
        """Returns the total number of STP BPDU records stored in the ledger."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM stp_topology_ledger")
            row = cursor.fetchone()
            return int(row[0]) if row else 0

    def record_convergence(self, record: ConvergenceRecord) -> None:
        """Appends a validated sweep convergence state into the ledger."""
        conv_dist = max(0.5, float(record.converged_distance_m))
        clean_mac = record.mac.upper()
        clean_oui = record.oui.replace(":", "").replace("-", "").upper()[:6]

        if self.explicit_db or self.redis is None:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO convergence_ledger (
                        timestamp, mac, oui, ip, archetype, min_rtt_us,
                        jitter_us, converged_distance_m, converged_kernel_us,
                        variance_m2, confidence_pct
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.timestamp,
                    clean_mac,
                    clean_oui,
                    record.ip,
                    record.archetype,
                    record.min_rtt_us,
                    record.jitter_us,
                    conv_dist,
                    record.converged_kernel_us,
                    record.variance_m2,
                    record.confidence_pct,
                ))
                conn.commit()

        if self.redis is not None:
            try:
                rec_id = str(self.redis.incr("aetheris:convergence:seq"))
                tau_ns = record.tau_ns if record.tau_ns > 0 else float(conv_dist / (0.69 * 299792458.0) * 1e9)
                mapping = {
                    "id": rec_id,
                    "timestamp": str(record.timestamp),
                    "mac": clean_mac,
                    "oui": clean_oui,
                    "ip": str(record.ip),
                    "archetype": str(record.archetype),
                    "min_rtt_us": str(record.min_rtt_us),
                    "jitter_us": str(record.jitter_us),
                    "converged_distance_m": str(conv_dist),
                    "converged_kernel_us": str(record.converged_kernel_us),
                    "variance_m2": str(record.variance_m2),
                    "confidence_pct": str(record.confidence_pct),
                    "tau_ns": str(tau_ns),
                }
                pipe = self.redis.pipeline(transaction=False)
                pipe.hset(f"aetheris:convergence:{rec_id}", mapping=mapping)
                pipe.zadd("aetheris:convergence:temporal", {rec_id: record.timestamp})
                pipe.zadd(f"aetheris:convergence:mac:{clean_mac}", {rec_id: record.timestamp})
                pipe.zadd(f"aetheris:convergence:oui_arch:{clean_oui}:{record.archetype}", {rec_id: record.timestamp})
                pipe.execute()
            except Exception:
                pass

    def get_empirical_kernel_prior(self, oui: str, archetype: str) -> Optional[Tuple[float, float]]:
        """
        Returns (mu_log, sigma_log) for kernel latency prior in seconds.
        Requires at least 3 historical observations. Returns None if unlearned.
        """
        clean_oui = oui.replace(":", "").replace("-", "").upper()[:6]

        if self.explicit_db or self.redis is None:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT converged_kernel_us FROM convergence_ledger
                    WHERE (oui = ? OR archetype = ?) AND confidence_pct >= 50.0
                    ORDER BY timestamp DESC LIMIT 50
                """, (clean_oui, archetype))
                rows = cursor.fetchall()

            if len(rows) < 3:
                return None

            tk_samples_sec = np.array([r[0] * 1e-6 for r in rows], dtype=np.float64)
            tk_samples_sec = np.clip(tk_samples_sec, 1e-6, None)
            log_samples = np.log(tk_samples_sec)
            mu_log = float(np.mean(log_samples))
            sigma_log = float(np.clip(np.std(log_samples), 0.15, 0.8))
            return (mu_log, sigma_log)

        # Redis path
        index_key = f"aetheris:convergence:oui_arch:{clean_oui}:{archetype}"
        rec_ids = self.redis.zrevrange(index_key, 0, 49)
        if not rec_ids or len(rec_ids) < 3:
            return None

        pipe = self.redis.pipeline(transaction=False)
        for rid in rec_ids:
            pipe.hgetall(f"aetheris:convergence:{rid}")
        records = pipe.execute()

        valid_delays = []
        for r in records:
            if not r or "converged_kernel_us" not in r:
                continue
            conf = float(r.get("confidence_pct", 0.0))
            if conf >= 50.0:
                valid_delays.append(float(r["converged_kernel_us"]))

        if len(valid_delays) < 3:
            return None

        tk_samples_sec = np.array([d * 1e-6 for d in valid_delays], dtype=np.float64)
        tk_samples_sec = np.clip(tk_samples_sec, 1e-6, None)
        log_samples = np.log(tk_samples_sec)
        mu_log = float(np.mean(log_samples))
        sigma_log = float(np.clip(np.std(log_samples), 0.15, 0.8))
        return (mu_log, sigma_log)

    def get_raw_nanosecond_flight_times(self, mac: str) -> List[float]:
        """
        Extracts raw nanosecond flight times (tau) directly for MCMC and Bayesian solvers.
        """
        clean_mac = mac.upper()
        if not self.explicit_db and self.redis is not None:
            try:
                rec_ids = self.redis.zrevrange(f"aetheris:convergence:mac:{clean_mac}", 0, 99)
                if rec_ids:
                    pipe = self.redis.pipeline(transaction=False)
                    for rid in rec_ids:
                        pipe.hmget(f"aetheris:convergence:{rid}", ["tau_ns", "min_rtt_us"])
                    results = pipe.execute()
                    flight_times_ns: List[float] = []
                    for res in results:
                        if not res or not res[0]:
                            continue
                        tau = float(res[0])
                        if tau > 0:
                            flight_times_ns.append(tau)
                        elif res[1]:
                            flight_times_ns.append(float(res[1]) * 1000.0)
                    if flight_times_ns:
                        return flight_times_ns
            except Exception:
                pass

        # Fallback to SQLite
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT converged_distance_m, min_rtt_us FROM convergence_ledger
                WHERE mac = ? ORDER BY timestamp DESC LIMIT 100
            """, (clean_mac,))
            rows = cursor.fetchall()

        flight_times: List[float] = []
        for dist_m, min_rtt in rows:
            tau = float(dist_m / (0.69 * 299792458.0) * 1e9)
            flight_times.append(tau)
        return flight_times

    def get_ledger_summary(self) -> Dict[str, Any]:
        """Computes summary statistics across convergence ledger records."""
        if self.explicit_db or self.redis is None:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*), COUNT(DISTINCT mac), AVG(confidence_pct), AVG(variance_m2)
                    FROM convergence_ledger
                """)
                total, unique_macs, avg_conf, avg_var = cursor.fetchone()

            return {
                "total_records": total or 0,
                "unique_macs": unique_macs or 0,
                "avg_confidence": round(avg_conf or 0.0, 1),
                "avg_variance": round(avg_var or 0.0, 3),
            }

        # Redis path
        rec_ids = self.redis.zrange("aetheris:convergence:temporal", 0, -1)
        total = len(rec_ids)
        if total == 0:
            return {
                "total_records": 0,
                "unique_macs": 0,
                "avg_confidence": 0.0,
                "avg_variance": 0.0,
            }

        pipe = self.redis.pipeline(transaction=False)
        for rid in rec_ids:
            pipe.hmget(f"aetheris:convergence:{rid}", ["mac", "confidence_pct", "variance_m2"])
        results = pipe.execute()

        macs = set()
        conf_sum = 0.0
        var_sum = 0.0
        count = 0

        for r in results:
            if not r or len(r) < 3 or r[0] is None:
                continue
            macs.add(r[0])
            conf_sum += float(r[1] or 0.0)
            var_sum += float(r[2] or 0.0)
            count += 1

        avg_conf = (conf_sum / count) if count > 0 else 0.0
        avg_var = (var_sum / count) if count > 0 else 0.0

        return {
            "total_records": count,
            "unique_macs": len(macs),
            "avg_confidence": round(avg_conf, 1),
            "avg_variance": round(avg_var, 3),
        }

    def evict_older_than(self, max_age_seconds: float = 86400.0) -> int:
        """
        Evicts convergence records older than max_age_seconds.
        """
        cutoff = time.time() - max_age_seconds

        if not self.explicit_db and self.redis is not None:
            try:
                expired_ids = self.redis.zrangebyscore("aetheris:convergence:temporal", "-inf", cutoff)
                if expired_ids:
                    pipe = self.redis.pipeline(transaction=False)
                    for rid in expired_ids:
                        pipe.delete(f"aetheris:convergence:{rid}")
                    pipe.zremrangebyscore("aetheris:convergence:temporal", "-inf", cutoff)
                    pipe.execute()
                    return len(expired_ids)
                return 0
            except Exception:
                return 0

        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM convergence_ledger WHERE timestamp < ?", (cutoff,))
            deleted_count = cursor.rowcount
            conn.commit()
        return deleted_count
