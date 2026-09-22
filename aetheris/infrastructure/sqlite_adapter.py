import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional

class SpatialLedgerAdapter:
    """
    Infrastructure Adapter for spatial_ledger.db.
    Executes raw SQL queries and transforms relational rows into 
    pure Python dictionaries for the mathematical domain.
    """

    def __init__(self, db_path: Optional[str | Path] = None):
        # Resolves to the project root unless explicitly overridden during testing
        if db_path is None:
            self.db_path = Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db"
        else:
            self.db_path = Path(db_path)

    def get_physical_ground_truth(self) -> Dict[str, Dict[str, Any]]:
        """
        Unifies physical_ground_truth and device_registry tables.
        Returns: { identifier: { 'device_label': ..., 'measured_length_m': ..., 'medium': ... } }
        """
        results = {}
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                cur = conn.cursor()
                
                # 1. Load explicit physical ground truth
                cur.execute("""
                    SELECT identifier, device_label, measured_length_m, medium
                    FROM physical_ground_truth
                """)
                for row in cur.fetchall():
                    entry = {
                        "identifier": row[0],
                        "device_label": row[1],
                        "measured_length_m": float(row[2]),
                        "medium": row[3]
                    }
                    results[row[0]] = entry
                    results[row[0].upper()] = entry
                    results[row[0].lower()] = entry

                # 2. Unify with device registry fallback
                tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                if "device_registry" in tables:
                    cur.execute("""
                        SELECT mac_address, canonical_name, ground_truth_m, interface_tier
                        FROM device_registry
                        WHERE ground_truth_m IS NOT NULL
                    """)
                    for row in cur.fetchall():
                        mac = row[0]
                        if mac:
                            entry = {
                                "identifier": mac,
                                "device_label": row[1],
                                "measured_length_m": float(row[2]),
                                "medium": row[3]
                            }
                            results[mac] = entry
                            results[mac.upper()] = entry
                            results[mac.lower()] = entry
        except sqlite3.Error as e:
            print(f"[SQLITE_FAULT] Ground truth extraction failed: {e}")
            
        return results

    def get_gateway_switchports(self) -> Dict[str, Dict[str, Any]]:
        """
        Loads gateway CAM switchport bindings.
        Returns: { ip/mac: { 'ip': ..., 'switchport': ..., 'port_type': ..., ... } }
        """
        results = {}
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                cur = conn.cursor()
                cols = [c[1] for c in cur.execute("PRAGMA table_info(gateway_switchports)").fetchall()]
                
                if "ip_address" in cols and "port_id" in cols:
                    cur.execute("""
                        SELECT ip_address, port_id, connection_type, hostname, mac_address, link_speed_mbps
                        FROM gateway_switchports
                    """)
                    for row in cur.fetchall():
                        ip_val, port_id, conn_type, host_val, mac_val, speed_val = row
                        
                        # Data Transformation Mapping
                        port_type = "DIRECT_DROP"
                        if port_id == "Port 1":
                            port_type = "TRUNK_BRIDGE"
                        elif port_id == "Port 3":
                            port_type = "DIRECT_DROP_100M"
                        elif port_id in ("WLAN", "WLAN_5GHZ", "WLAN_2.4GHZ"):
                            port_type = "WIRELESS_WLAN"

                        sw_label = "WLAN_5GHZ" if port_id == "WLAN" else port_id

                        entry = {
                            "ip": ip_val,
                            "switchport": sw_label,
                            "port_type": port_type,
                            "device_hint": host_val,
                            "mac": mac_val,
                            "medium": conn_type,
                            "link_speed_mbps": speed_val
                        }
                        if ip_val:
                            results[ip_val] = entry
                        if mac_val:
                            results[mac_val.upper()] = entry
                            results[mac_val.lower()] = entry
                            
                elif "ip" in cols and "switchport" in cols:
                    # Legacy table schema fallback
                    cur.execute("SELECT ip, switchport, port_type, device_hint FROM gateway_switchports")
                    for row in cur.fetchall():
                        results[row[0]] = {
                            "ip": row[0],
                            "switchport": row[1],
                            "port_type": row[2],
                            "device_hint": row[3]
                        }
        except sqlite3.Error as e:
            print(f"[SQLITE_FAULT] Gateway switchport mapping failed: {e}")
            
        return results

    def get_recent_convergence_records(self, identifiers: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieves the last 5 convergence telemetry records for the requested IP/MAC identifiers.
        """
        records = []
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                cur = conn.cursor()
                for ident in set(identifiers):
                    cur.execute("""
                        SELECT min_rtt_us, archetype, ip, mac 
                        FROM convergence_ledger
                        WHERE ip = ? OR mac = ?
                        ORDER BY timestamp DESC LIMIT 5
                    """, (ident, ident))
                    for row in cur.fetchall():
                        records.append({
                            "min_rtt_us": row[0],
                            "archetype": row[1],
                            "ip": row[2],
                            "mac": row[3]
                        })
        except sqlite3.Error as e:
            print(f"[SQLITE_FAULT] Convergence record extraction failed: {e}")
            
        return records

    def get_port_profile_data(self, ip_or_mac: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves specific interface metadata for deterministic delay calculations.
        """
        try:
            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                cur = conn.cursor()
                query = """
                    SELECT port_id, link_speed_mbps, connection_type, mac_address 
                    FROM gateway_switchports 
                    WHERE ip_address = ? OR LOWER(mac_address) = LOWER(?)
                    LIMIT 1
                """
                row = cur.execute(query, (ip_or_mac, ip_or_mac)).fetchone()
                
                if row:
                    return {
                        "port_id": row[0],
                        "link_speed_mbps": row[1],
                        "connection_type": row[2],
                        "mac_address": row[3]
                    }
        except sqlite3.Error as e:
            print(f"[SQLITE_FAULT] Port profile extraction failed: {e}")
            
        return None