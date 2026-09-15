"""
Project AETHERIS - Clean-Slate Ledger Reset & Definitive Topology Seeder
Executes a schema-preserving purge of historical telemetry and re-seeds
the verified 3-drop physical ground-truth topology in spatial_ledger.db.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "spatial_ledger.db"


def reset_and_reseed():
    print(f"[*] Connecting to database at {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # 1. Schema-preserving purge of historical telemetry tables
    telemetry_tables = [
        "convergence_ledger",
        "serialization_telemetry",
        "inferred_os_profiles",
        "port1_multivector_analysis"
    ]

    for table in telemetry_tables:
        try:
            cur.execute(f"DELETE FROM {table}")
            print(f"[+] Purged table: {table}")
        except sqlite3.OperationalError as e:
            print(f"[-] Table {table} skipped: {e}")

    # Check if a table named 'spatial_ledger' exists and purge if so
    has_spatial_ledger = cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='spatial_ledger'"
    ).fetchone()
    if has_spatial_ledger:
        cur.execute("DELETE FROM spatial_ledger")
        print("[+] Purged table: spatial_ledger")

    # 2. Recreate composite indexes for optimal query efficiency
    cur.execute("CREATE INDEX IF NOT EXISTS idx_convergence_mac_ts ON convergence_ledger(mac, timestamp DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_convergence_lower_mac_ts ON convergence_ledger(LOWER(mac), timestamp DESC)")
    print("[+] Verified composite indexes on convergence_ledger.")

    # 3. Re-seed device_registry strictly with definitive physical topology
    cur.execute("""
        CREATE TABLE IF NOT EXISTS device_registry (
            mac_address TEXT PRIMARY KEY,
            canonical_name TEXT,
            interface_tier TEXT,
            ground_truth_m REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("DELETE FROM device_registry")

    device_registry_data = [
        ("24:4b:fe:96:1d:36", "Primary Workstation", "COPPER_DIRECT_P2", 27.00),
        ("bc:7e:8b:0d:82:ca", "Samsung TV (Living Room)", "COPPER_BRIDGE_P1", 28.52),
        ("d4:b9:2f:21:ec:bd", "PVR / STB (Living Room)", "COPPER_DIRECT_P3", 25.50),
        ("10:78:5b:3d:08:80", "Actiontec Q6000 (Wi-Fi Plus)", "COPPER_TRUNK", None),
        ("1c:ce:51:93:ba:90", "Jaxon Laptop", "WLAN_AIRLINK", None),
    ]

    cur.executemany("""
        INSERT INTO device_registry (mac_address, canonical_name, interface_tier, ground_truth_m)
        VALUES (?, ?, ?, ?)
    """, device_registry_data)
    print(f"[+] Re-seeded {len(device_registry_data)} devices in device_registry.")

    # 4. Re-seed physical_ground_truth
    cur.execute("""
        CREATE TABLE IF NOT EXISTS physical_ground_truth (
            identifier TEXT PRIMARY KEY,
            device_label TEXT,
            measured_length_m REAL,
            medium TEXT,
            verified_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("DELETE FROM physical_ground_truth")

    ground_truth_data = [
        ("192.168.1.86", "Workstation Surface", 27.00, "Cat6_Copper"),
        ("24:4B:FE:96:1D:36", "Workstation Surface (MAC)", 27.00, "Cat6_Copper"),
        ("192.168.1.65", "Samsung Smart TV", 28.52, "Cat5e_Copper"),
        ("BC:7E:8B:0D:82:CA", "Samsung Smart TV (MAC)", 28.52, "Cat5e_Copper"),
        ("SET_TOP_BOX", "Media Set-Top Box", 25.50, "Cat5e_Copper"),
        ("WIFI_PLUS", "Wi-Fi Plus Extender", 27.00, "Cat6_Copper"),
        ("ONT_TO_ISP", "WAN SFP-to-Gateway Riser", 34.00, "Cat5_Copper"),
    ]

    cur.executemany("""
        INSERT INTO physical_ground_truth (identifier, device_label, measured_length_m, medium)
        VALUES (?, ?, ?, ?)
    """, ground_truth_data)
    print(f"[+] Re-seeded {len(ground_truth_data)} entries in physical_ground_truth.")

    # 5. Recreate accuracy view v_spatial_accuracy_history
    cur.execute("DROP VIEW IF EXISTS v_spatial_accuracy_history")
    cur.execute("""
        CREATE VIEW v_spatial_accuracy_history AS
        SELECT 
            reg.canonical_name,
            reg.mac_address,
            reg.interface_tier,
            reg.ground_truth_m,
            cl.converged_distance_m AS latest_estimate_m,
            ROUND(cl.converged_distance_m - reg.ground_truth_m, 3) AS delta_error_m,
            ROUND(ABS(cl.converged_distance_m - reg.ground_truth_m) / reg.ground_truth_m * 100.0, 2) AS error_pct,
            CASE 
                WHEN cl.timestamp IS NULL THEN NULL
                WHEN typeof(cl.timestamp) = 'real' OR typeof(cl.timestamp) = 'integer' THEN datetime(cl.timestamp, 'unixepoch')
                ELSE strftime('%Y-%m-%d %H:%M:%S', cl.timestamp)
            END AS sweep_timestamp
        FROM device_registry reg
        LEFT JOIN (
            SELECT LOWER(mac) AS mac, converged_distance_m, timestamp
            FROM convergence_ledger
            WHERE (LOWER(mac), timestamp) IN (
                SELECT LOWER(mac), MAX(timestamp)
                FROM convergence_ledger
                GROUP BY LOWER(mac)
            )
        ) cl ON LOWER(reg.mac_address) = cl.mac
        WHERE reg.ground_truth_m IS NOT NULL
        ORDER BY (cl.converged_distance_m IS NULL) ASC, error_pct ASC;
    """)
    print("[+] Recreated v_spatial_accuracy_history view.")

    conn.commit()
    conn.close()
    print("[+] Clean-slate reset and reseed complete.\n")


if __name__ == "__main__":
    reset_and_reseed()

