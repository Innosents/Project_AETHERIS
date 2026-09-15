import re
import sqlite3
from pathlib import Path
from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup

DB_PATH = Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db"

def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS gateway_switchports (
            mac_address TEXT PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT,
            interface_name TEXT,
            port_id TEXT,
            link_speed_mbps INTEGER,
            duplex TEXT,
            frequency TEXT,
            connection_type TEXT,
            last_scraped TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

def parse_device_table_text(raw_text: str) -> List[Dict[str, Any]]:
    devices = []
    mac_regex = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
    matches = list(mac_regex.finditer(raw_text))

    for i, match in enumerate(matches):
        mac = match.group(1).lower()
        start_idx = match.start()
        end_idx = match.end()

        # The hostname precedes the MAC, strip leading metadata like DHCP / counts / timestamps
        preceding = raw_text[:start_idx]
        if i > 0:
            prev_end = matches[i - 1].end()
            preceding = raw_text[prev_end:start_idx]
        
        # Clean off trailing DHCP / IP tags from preceding text
        hostname = re.sub(r"^.*?DHCP", "", preceding).strip()
        hostname = re.sub(r"^\d{1,3}(?:\.\d{1,3}){3}", "", hostname).strip()
        if not hostname:
            hostname = f"node-{mac.replace(':', '')[-4:]}"

        # The parameters follow immediately after the MAC up to the next MAC (or end of file)
        trailing_limit = matches[i + 1].start() if i + 1 < len(matches) else len(raw_text)
        body = raw_text[end_idx:trailing_limit]

        # Parse IP
        ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", body)
        ip_address = ip_m.group(1) if ip_m else None

        # Identify connection type and port details
        if "Ethernet" in body:
            port_m = re.search(r"Port\s*(\d+)", body, re.IGNORECASE)
            speed_m = re.search(r"(\d+)\s*Mbps", body, re.IGNORECASE)
            duplex_m = re.search(r"(Full|Half)", body, re.IGNORECASE)
            
            devices.append({
                "hostname": hostname,
                "mac_address": mac,
                "connection_type": "Ethernet",
                "port_id": f"Port {port_m.group(1)}" if port_m else "Ethernet",
                "link_speed_mbps": int(speed_m.group(1)) if speed_m else 1000,
                "duplex": duplex_m.group(1) if duplex_m else "Full",
                "frequency": None,
                "ip_address": ip_address
            })
        elif "Wireless" in body or "Frequency" in body:
            freq_m = re.search(r"Frequency:\s*([0-9A-Za-z]+)", body)
            devices.append({
                "hostname": hostname,
                "mac_address": mac,
                "connection_type": "Wireless",
                "port_id": "WLAN",
                "link_speed_mbps": None,
                "duplex": None,
                "frequency": freq_m.group(1) if freq_m else "5G",
                "ip_address": ip_address
            })

    return devices

    # Regex capturing wireless drops: Name + MAC + Wireless + Frequency + IP
    wlan_pattern = re.compile(
        r"([A-Za-z0-9_\-\.]+?)"
        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
        r"Wireless"
        r"Frequency:\s*([0-9A-Za-z]+)"
        r"(\d{1,3}(?:\.\d{1,3}){3})"
    )
    for m in wlan_pattern.finditer(raw_text):
        devices.append({
            "hostname": m.group(1).strip(),
            "mac_address": m.group(2).lower(),
            "connection_type": "Wireless",
            "port_id": "WLAN",
            "link_speed_mbps": None,
            "duplex": None,
            "frequency": m.group(3),
            "ip_address": m.group(4)
        })

    return devices

def sync_to_ledger(devices: List[Dict[str, Any]]):
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    cur = conn.cursor()

    for dev in devices:
        cur.execute("""
            INSERT OR REPLACE INTO gateway_switchports (
                mac_address, hostname, ip_address, interface_name,
                port_id, link_speed_mbps, duplex, frequency, connection_type, last_scraped
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            dev["mac_address"],
            dev["hostname"],
            dev["ip_address"],
            dev["port_id"],
            dev["port_id"],
            dev["link_speed_mbps"],
            dev["duplex"],
            dev["frequency"],
            dev["connection_type"]
        ))

    conn.commit()
    conn.close()
    print(f"[+] Successfully synced {len(devices)} device interfaces to spatial_ledger.db")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        raw_data = Path(sys.argv[1]).read_text()
        devs = parse_device_table_text(raw_data)
        sync_to_ledger(devs)
    else:
        print("Usage: python -m graphpath.discovery.isp_gui_scraper <path_to_raw_dump.txt>")