import sqlite3

conn = sqlite3.connect("spatial_ledger.db")
c = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS switchport_mappings (
    switch_ip TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    port_name TEXT NOT NULL,
    if_index INTEGER,
    alias TEXT,
    vlan_id INTEGER,
    is_trunk INTEGER DEFAULT 0,
    mac_density INTEGER DEFAULT 1,
    discovery_method TEXT DEFAULT "bridge_fdb_snmp",
    updated_at TEXT NOT NULL,
    PRIMARY KEY (switch_ip, mac_address)
    mac TEXT PRIMARY KEY,
    ip TEXT,
    switchport TEXT,
    vlan INTEGER,
    is_trunk BOOLEAN
)
""")

c.execute("CREATE INDEX IF NOT EXISTS idx_fdb_mac ON switchport_mappings(mac_address)")
c.execute("CREATE INDEX IF NOT EXISTS idx_fdb_switch_port ON switchport_mappings(switch_ip, port_name)")
conn.commit()

c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='switchport_mappings'")
res = c.fetchone()
print(f"Table verification status: {res[0] if res else 'FAILED'}")
conn.close()
