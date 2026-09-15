import sqlite3
import os

# Resolve absolute path to prevent localized environment drift
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'spatial_ledger.db')

conn = sqlite3.connect(db_path)
c = conn.cursor()

# Strict SQLite DDL formatting (ensure opening parenthesis exists)
c.execute("""
    CREATE TABLE IF NOT EXISTS gateway_switchports (
        mac TEXT PRIMARY KEY,
        ip TEXT,
        switchport TEXT,
        vlan INTEGER,
        is_trunk BOOLEAN
    )
""")

conn.commit()
conn.close()
print("[+] Schema initialization complete. Zero tracebacks.")