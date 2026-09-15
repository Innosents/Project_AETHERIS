import sqlite3
import time
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass


@dataclass
class ConvergenceRecord:
    timestamp: float
    mac: str
    oui: str
    ip: str
    archetype: str
    min_rtt_us: float
    jitter_us: float
    converged_distance_m: float
    converged_kernel_us: float
    variance_m2: float
    confidence_pct: float


class _ClosingConnection:
    """Context manager wrapper that auto-closes sqlite3 connections upon exit to prevent file descriptor leaks."""
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path, timeout=5.0)

    def __enter__(self) -> sqlite3.Connection:
        return self.conn.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            return self.conn.__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.conn.close()


class TelemetryLedger:
    """
    Persistent empirical experience store for AETHERIS spatial deconvolution.
    Aggregates runtime convergence to dynamically refine MCMC priors over time.
    """
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.db_path = base_dir / "spatial_ledger.db"

        self._init_db()

    def _get_connection(self) -> _ClosingConnection:
        return _ClosingConnection(str(self.db_path))

    def _init_db(self) -> None:
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
        residuals: Optional[List[float]] = None
    ) -> None:
        """Records an overdetermined WLS calibration milestone into the spatial ledger."""
        import json
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO calibration_ledger (
                    timestamp, anchor_count, calibrated_nvp,
                    calibrated_switch_latency_s, wls_confidence, residuals_json
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                time.time(),
                int(anchor_count),
                float(calibrated_nvp),
                float(calibrated_switch_latency_s),
                float(wls_confidence),
                json.dumps(residuals or [])
            ))
            conn.commit()

    def record_scope_provenance(
        self,
        auth_ref: str,
        provenance_token: str,
        provenance_digest: str,
        in_scope_cidrs: Optional[List[str]] = None,
        do_not_scan: Optional[List[str]] = None,
    ) -> None:
        """Records a cryptographic scope authorization provenance token into the spatial ledger."""
        import json
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO scope_provenance_ledger (
                    timestamp, auth_ref, provenance_token, provenance_digest,
                    in_scope_cidrs_json, do_not_scan_json
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                time.time(),
                str(auth_ref),
                str(provenance_token),
                str(provenance_digest),
                json.dumps(in_scope_cidrs or []),
                json.dumps(do_not_scan or []),
            ))
            conn.commit()

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

    def record_convergence(self, record: ConvergenceRecord) -> None:
        """Appends a validated sweep convergence state into the ledger."""
        conv_dist = max(0.5, float(record.converged_distance_m))
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO convergence_ledger (
                    timestamp, mac, oui, ip, archetype, min_rtt_us,
                    jitter_us, converged_distance_m, converged_kernel_us,
                    variance_m2, confidence_pct
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.timestamp, record.mac.upper(), record.oui.upper(), record.ip,
                record.archetype, record.min_rtt_us, record.jitter_us,
                conv_dist, record.converged_kernel_us,
                record.variance_m2, record.confidence_pct
            ))
            conn.commit()

    def get_empirical_kernel_prior(self, oui: str, archetype: str) -> Optional[Tuple[float, float]]:
        """
        Returns (mu_log, sigma_log) for kernel latency prior in seconds.
        Requires at least 3 historical observations. Returns None if unlearned.
        """
        clean_oui = oui.replace(":", "").replace("-", "").upper()[:6]
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT converged_kernel_us FROM convergence_ledger
                WHERE (oui = ? OR archetype = ?) AND confidence_pct >= 50.0
                ORDER BY timestamp DESC LIMIT 50
            """, (clean_oui, archetype))
            rows = cursor.fetchall()

        if len(rows) < 3:
            return None

        # Convert µs -> seconds in log space
        tk_samples_sec = np.array([r[0] * 1e-6 for r in rows], dtype=np.float64)
        tk_samples_sec = np.clip(tk_samples_sec, 1e-6, None)
        
        log_samples = np.log(tk_samples_sec)
        mu_log = float(np.mean(log_samples))
        sigma_log = float(np.clip(np.std(log_samples), 0.15, 0.8))

        return (mu_log, sigma_log)

    def get_ledger_summary(self) -> Dict[str, Any]:
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
            "avg_variance": round(avg_var or 0.0, 3)
        }
