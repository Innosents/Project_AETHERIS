import sqlite3

conn = sqlite3.connect("spatial_ledger.db")
cur = conn.cursor()

query = """
SELECT hostname, ip_address, port_id, link_speed_mbps, frequency, mac_address
FROM gateway_switchports
ORDER BY port_id, ip_address;
"""

rows = cur.fetchall() if cur.execute(query) else []

header = f"{'HOSTNAME':<26} {'IP ADDRESS':<16} {'PORT/BAND':<12} {'RATE':<10} {'MAC ADDRESS'}"
print("\n" + header)
print("-" * len(header))

for host, ip, port, speed, freq, mac in rows:
    rate = f"{speed}M" if speed else (freq or "-")
    print(f"{host:<26} {str(ip):<16} {port:<12} {rate:<10} {mac}")

print(f"\nTotal endpoints mapped: {len(rows)}\n")
conn.close()