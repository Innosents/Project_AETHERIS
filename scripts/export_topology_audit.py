import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("spatial_ledger.db")
OUTPUT_PATH = Path("topology_audit.json")

def build_audit_payload():
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database {DB_PATH} not found.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    payload = {
        "metadata": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "engine": "AETHERIS L1/L2 Spatial Sweep Engine",
            "database": str(DB_PATH),
            "gateway_root": "192.168.1.254"
        },
        "calibrated_constants": {
            "nvp_c": 0.6900,
            "phy_latency_us": 1.200,
            "t_hop_ns": 18.5,
            "serialization_penalties_us": {
                "1000BASE-T": 0.512,
                "100BASE-TX": 5.120,
                "WLAN": 0.000
            }
        },
        "switch_fabric_interfaces": {},
        "ground_truth_accuracy_audit": [],
        "converged_endpoints": []
    }

    # 1. Physical Switch Fabric & CAM Bindings
    cur.execute("""
        SELECT mac_address, hostname, ip_address, interface_name, 
               port_id, link_speed_mbps, duplex, connection_type, last_scraped
        FROM gateway_switchports
        ORDER BY port_id ASC
    """)
    for row in cur.fetchall():
        port = row["port_id"] or "UNASSIGNED"
        if port not in payload["switch_fabric_interfaces"]:
            payload["switch_fabric_interfaces"][port] = []
        payload["switch_fabric_interfaces"][port].append(dict(row))

    # 2. Authoritative Ground Truth vs Latest Convergence
    cur.execute("""
        SELECT canonical_name, mac_address, interface_tier, ground_truth_m,
               latest_estimate_m, delta_error_m, error_pct, sweep_timestamp
        FROM v_spatial_accuracy_history
    """)
    for row in cur.fetchall():
        payload["ground_truth_accuracy_audit"].append(dict(row))

    # 3. Dynamic Column Introspection for convergence_ledger
    cur.execute("PRAGMA table_info(convergence_ledger)")
    cl_columns = {col["name"] for col in cur.fetchall()}

    medium_col = next((c for c in ("connection_type", "medium", "medium_type", "interface_medium") if c in cl_columns), None)
    medium_select = f", {medium_col} AS medium" if medium_col else ", 'UNKNOWN' AS medium"

    cur.execute(f"""
        SELECT mac, ip, converged_distance_m, variance_m2, 
               confidence_pct{medium_select}, timestamp
        FROM convergence_ledger
        WHERE (mac, timestamp) IN (
            SELECT mac, MAX(timestamp) 
            FROM convergence_ledger 
            GROUP BY mac
        )
        ORDER BY converged_distance_m ASC
    """)
    for row in cur.fetchall():
        payload["converged_endpoints"].append(dict(row))

    conn.close()
    return payload

if __name__ == "__main__":
    audit_data = build_audit_payload()
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2)

    print(f"[+] Spatial topology audit exported successfully to {OUTPUT_PATH}")
    print(f"    - Switch Interfaces: {len(audit_data['switch_fabric_interfaces'])} ports mapped")
    print(f"    - Ground Truth Drops: {len(audit_data['ground_truth_accuracy_audit'])} verified")
    print(f"    - Converged Endpoints: {len(audit_data['converged_endpoints'])} records")