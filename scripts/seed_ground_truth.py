import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent.parent / "spatial_ledger.db"
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# 1. Physical Ground Truth Table
cur.execute("""
    CREATE TABLE IF NOT EXISTS physical_ground_truth (
        identifier TEXT PRIMARY KEY,
        device_label TEXT,
        measured_length_m REAL,
        medium TEXT,
        verified_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

# Remove legacy / temporary .85 mapping if present
cur.execute("DELETE FROM physical_ground_truth WHERE identifier = '192.168.1.85'")

ground_truth_nodes = [
    ("192.168.1.70", "ThinkPad Anchor", 3.00, "Cat6_Copper"),
    ("192.168.1.86", "Workstation Surface", 27.00, "Cat6_Copper"),
    ("24:4B:FE:96:1D:36", "Workstation Surface (MAC)", 27.00, "Cat6_Copper"),
    ("192.168.1.80", "Media Set-Top Box", 25.50, "Cat5e_Copper"),
    ("D4:B9:2F:21:EC:BD", "Media Set-Top Box (MAC)", 25.50, "Cat5e_Copper"),
    ("SET_TOP_BOX", "Media Set-Top Box", 25.50, "Cat5e_Copper"),
    ("WIFI_PLUS", "Wi-Fi Plus Extender", 27.00, "Cat6_Copper"),
    ("192.168.1.65", "Samsung Smart TV", 28.52, "Cat5e_Copper"),
    ("BC:7E:8B:0D:82:CA", "Samsung Smart TV (MAC)", 28.52, "Cat5e_Copper"),
    ("ONT_TO_ISP", "WAN SFP-to-Gateway Riser", 34.00, "Cat5_Copper")
]

cur.executemany("""
    INSERT OR REPLACE INTO physical_ground_truth (identifier, device_label, measured_length_m, medium)
    VALUES (?, ?, ?, ?)
""", ground_truth_nodes)

# 2. Gateway Switchports (CAM / Bridge Binding) Table
cur.execute("""
    CREATE TABLE IF NOT EXISTS gateway_switchports (
        ip TEXT PRIMARY KEY,
        switchport TEXT,
        port_type TEXT,
        device_hint TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

gateway_switchports_data = [
    # Port 1 (Trunk/Bridge): intermediate switch hop
    ("192.168.1.64", "Port 1", "TRUNK_BRIDGE", "Trunk Endpoint"),
    ("192.168.1.65", "Port 1", "TRUNK_BRIDGE", "Samsung TV"),
    ("192.168.1.66", "Port 1", "TRUNK_BRIDGE", "WiFiPlus"),
    ("192.168.1.67", "Port 1", "TRUNK_BRIDGE", "Trunk Endpoint"),
    ("192.168.1.70", "Port 1", "TRUNK_BRIDGE", "ThinkPad"),
    ("192.168.1.72", "Port 1", "TRUNK_BRIDGE", "Trunk Endpoint"),
    ("192.168.1.73", "Port 1", "TRUNK_BRIDGE", "Trunk Endpoint"),
    ("192.168.1.77", "Port 1", "TRUNK_BRIDGE", "Trunk Endpoint"),
    ("192.168.1.79", "Port 1", "TRUNK_BRIDGE", "Roku"),
    ("192.168.1.87", "Port 1", "TRUNK_BRIDGE", "Trunk Endpoint"),
    # Port 2 (Dedicated Direct Drop)
    ("192.168.1.86", "Port 2", "DIRECT_DROP", "Workstation Surface (27.0m)"),
    # Port 3 (Dedicated Direct Drop - 100M)
    ("192.168.1.80", "Port 3", "DIRECT_DROP_100M", "DVR_ETH"),
    # WLAN (5GHz Path-Loss Prior)
    ("192.168.1.69", "WLAN_5GHZ", "WIRELESS_WLAN", "5GHz Path-Loss Prior"),
    ("192.168.1.78", "WLAN_5GHZ", "WIRELESS_WLAN", "5GHz Path-Loss Prior"),
    ("192.168.1.81", "WLAN_5GHZ", "WIRELESS_WLAN", "5GHz Path-Loss Prior"),
    ("192.168.1.84", "WLAN_5GHZ", "WIRELESS_WLAN", "5GHz Path-Loss Prior"),
    ("192.168.1.88", "WLAN_5GHZ", "WIRELESS_WLAN", "5GHz Path-Loss Prior"),
]

cur.executemany("""
    INSERT OR REPLACE INTO gateway_switchports (ip, switchport, port_type, device_hint)
    VALUES (?, ?, ?, ?)
""", gateway_switchports_data)

conn.commit()
conn.close()

print(f"[+] Successfully seeded {len(ground_truth_nodes)} ground-truth lengths.")
print(f"[+] Successfully seeded {len(gateway_switchports_data)} gateway switchport CAM entries.")
