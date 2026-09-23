"""
Project AETHERIS - Isp Gui Scraper
Parses edge gateway HTML payloads and raw ASCII device tables using regular expressions to extract MAC mappings, PHY link speeds, and interface duplex states. Persists structured port-level telemetry 
into the relational spatial ledger to anchor perimeter Layer-2 adjacency tables.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from aetheris.core.ports.isp_gui_scraper_port import (
    IspGuiScraperPort,
    GatewaySwitchportStoragePort,
    GatewaySwitchportRecord,
    IspScraperSummary,
    _MappingCompatibleModel,
)

DB_PATH = Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db"


def init_db(conn: sqlite3.Connection) -> None:
    """Initializes gateway_switchports table in relational spatial ledger."""
    try:
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
    except Exception:
        pass


def parse_device_table_text(raw_text: str) -> List[GatewaySwitchportRecord]:
    """
    Parses edge gateway ASCII / HTML table dumps into typed GatewaySwitchportRecord instances.
    Extracts MAC, Hostname, IP, Port ID, PHY speed, and connection types.
    """
    devices: List[GatewaySwitchportRecord] = []
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
        
        # The parameters follow immediately after the MAC up to the next MAC (or end of file)
        trailing_limit = matches[i + 1].start() if i + 1 < len(matches) else len(raw_text)
        body = raw_text[end_idx:trailing_limit]

        # Clean off trailing DHCP / IP tags from preceding text
        hostname = re.sub(r"^.*?DHCP(?:\s+Client)?", "", preceding, flags=re.IGNORECASE).strip()
        
        # Parse IP: Check preceding block first, fallback to body
        ip_matches = list(re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})", preceding))
        if ip_matches:
            ip_address = ip_matches[-1].group(1)
        else:
            ip_m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", body)
            ip_address = ip_m.group(1) if ip_m else None

        hostname = re.sub(r"\d{1,3}(?:\.\d{1,3}){3}", "", hostname).strip()
        hostname = re.sub(r"(?:Ethernet|Wireless|Port\s*\d+|Mbps|Full|Half|Frequency:\s*\S+).*", "", hostname, flags=re.IGNORECASE | re.DOTALL).strip()
        hostname = hostname.strip(" \r\n\t-_:")
        if not hostname:
            hostname = f"node-{mac.replace(':', '')[-4:]}"

        # Identify connection type and port details
        if "Ethernet" in body:
            port_m = re.search(r"Port\s*(\d+)", body, re.IGNORECASE)
            speed_m = re.search(r"(\d+)\s*Mbps", body, re.IGNORECASE)
            duplex_m = re.search(r"(Full|Half)", body, re.IGNORECASE)
            port_id_str = f"Port {port_m.group(1)}" if port_m else "Ethernet"
            
            devices.append(GatewaySwitchportRecord(
                hostname=hostname,
                mac_address=mac,
                connection_type="Ethernet",
                interface_name=port_id_str,
                port_id=port_id_str,
                link_speed_mbps=int(speed_m.group(1)) if speed_m else 1000,
                duplex=duplex_m.group(1) if duplex_m else "Full",
                frequency=None,
                ip_address=ip_address
            ))
        elif "Wireless" in body or "Frequency" in body:
            freq_m = re.search(r"Frequency:\s*([0-9A-Za-z]+)", body)
            devices.append(GatewaySwitchportRecord(
                hostname=hostname,
                mac_address=mac,
                connection_type="Wireless",
                interface_name="WLAN",
                port_id="WLAN",
                link_speed_mbps=None,
                duplex=None,
                frequency=freq_m.group(1) if freq_m else "5G",
                ip_address=ip_address
            ))

    return devices


def sync_to_ledger(devices: List[Union[GatewaySwitchportRecord, Dict[str, Any]]], db_path: Optional[Union[str, Path]] = None) -> None:
    """Persists parsed gateway switchport records into spatial_ledger.db with defensive guards."""
    target_db = Path(db_path) if db_path else DB_PATH
    try:
        with sqlite3.connect(str(target_db), timeout=5.0) as conn:
            init_db(conn)
            cur = conn.cursor()

            for dev in devices:
                mac = dev["mac_address"] if isinstance(dev, dict) else dev.mac_address
                hostname = dev["hostname"] if isinstance(dev, dict) else dev.hostname
                ip_address = dev.get("ip_address") if isinstance(dev, dict) else dev.ip_address
                port_id = dev["port_id"] if isinstance(dev, dict) else dev.port_id
                speed = dev.get("link_speed_mbps") if isinstance(dev, dict) else dev.link_speed_mbps
                duplex = dev.get("duplex") if isinstance(dev, dict) else dev.duplex
                freq = dev.get("frequency") if isinstance(dev, dict) else dev.frequency
                conn_type = dev.get("connection_type", "Ethernet") if isinstance(dev, dict) else dev.connection_type

                cur.execute("""
                    INSERT OR REPLACE INTO gateway_switchports (
                        mac_address, hostname, ip_address, interface_name,
                        port_id, link_speed_mbps, duplex, frequency, connection_type, last_scraped
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    mac,
                    hostname,
                    ip_address,
                    port_id,
                    port_id,
                    speed,
                    duplex,
                    freq,
                    conn_type
                ))

            conn.commit()
    except Exception:
        pass


class IspGuiScraper(IspGuiScraperPort):
    """Hexagonal Adapter coordinator for edge gateway table scraping."""

    @staticmethod
    def parse_text(raw_text: str) -> List[GatewaySwitchportRecord]:
        """Parses raw text dump into typed GatewaySwitchportRecord models."""
        return parse_device_table_text(raw_text)

    @staticmethod
    def summarize(raw_text: str) -> IspScraperSummary:
        """Parses and summarizes gateway switchports."""
        records = parse_device_table_text(raw_text)
        eth_count = sum(1 for r in records if r.connection_type == "Ethernet")
        wlan_count = sum(1 for r in records if r.connection_type == "Wireless")
        return IspScraperSummary(
            total_records=len(records),
            ethernet_count=eth_count,
            wireless_count=wlan_count,
            records=records
        )


class GatewaySwitchportLedger(GatewaySwitchportStoragePort):
    """Hexagonal persistence adapter for gateway switchport records."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = Path(db_path) if db_path else DB_PATH

    def sync_records(self, devices: List[Union[GatewaySwitchportRecord, Dict[str, Any]]]) -> None:
        """Persists switchport records into the perimeter ledger."""
        sync_to_ledger(devices, db_path=self.db_path)


__all__ = [
    "IspGuiScraper",
    "GatewaySwitchportLedger",
    "IspGuiScraperPort",
    "GatewaySwitchportStoragePort",
    "GatewaySwitchportRecord",
    "IspScraperSummary",
    "parse_device_table_text",
    "sync_to_ledger",
    "init_db",
    "_MappingCompatibleModel",
]


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        raw_data = Path(sys.argv[1]).read_text()
        devs = parse_device_table_text(raw_data)
        sync_to_ledger(devs)
    else:
        print("Usage: python -m aetheris.discovery.isp_gui_scraper <path_to_raw_dump.txt>")