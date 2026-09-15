import sqlite3
import os

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'spatial_ledger.db')
conn = sqlite3.connect(db_path)
cur = conn.cursor()

try:
    cur.execute("SELECT * FROM port1_multivector_analysis")
    rows = cur.fetchall()
    col_names = [description[0] for description in cur.description]
    print("[*] Detected columns:", col_names)
    
    for row in rows:
        # Position 0 is Target IP, last position is typically Inferred OS Profile
        ip = str(row[0])
        os_profile = str(row[-1]) if len(row) > 1 else "EMBEDDED_DEVICE"
        
        mac_suffix = ip.split('.')[-1]
        mac_address = f"aa:bb:cc:dd:ee:{int(mac_suffix):02x}"
        
        cur.execute("""
            INSERT OR IGNORE INTO switchport_mappings 
            (switch_ip, mac_address, port_name, alias, vlan_id, is_trunk) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('192.168.1.1', mac_address, 'Port-1', os_profile, 1, 0))
        
    conn.commit()
    print('[+] Visualizer bridge table synchronized successfully.')
except Exception as e:
    print('[-] Synchronization error:', e)
finally:
    conn.close()