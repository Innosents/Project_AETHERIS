"""
Project AETHERIS - Enterprise Bridge Forwarding Database (CAM Table) Crawler
Discovers exact switchport attachments (ifIndex, ifName, ifAlias, vlan_id) via:
1. Q-Bridge MIB dot1qTpFdbPort (1.3.6.1.2.1.17.7.1.2.2.1.2) - 802.1Q VLAN FDB
2. Bridge MIB dot1dTpFdbPort (1.3.6.1.2.1.17.4.3.1.2) - Standard Layer 2 FDB
3. Bridge Port to Interface Index mapping via dot1dBasePortIfIndex (1.3.6.1.2.1.17.1.4.1.2)
4. Canonical interface naming & aliases via ifName, ifDescr, and ifAlias (RFC 2863)
5. Physical drop density analytics & automatic trunk identification (>= 4 MACs)
6. Virtual MAC / Redundancy protocol filtering (VRRP, HSRP, NLB, Multicast)
7. Thread-isolated async execution to prevent event loop collision across sync/async boundaries
8. Fallback to ISP gateway / ARP cache for unmanaged switches
9. SQLite ledger persistence into switchport_mappings table in spatial_ledger.db

All returned dictionaries are recursively sanitized via sanitize_prober_payload.
"""

import asyncio
import concurrent.futures
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from aetheris.core.probers.sanitization import clean_ascii_string, sanitize_prober_payload

DB_PATH = Path(__file__).resolve().parent.parent.parent / "spatial_ledger.db"

# Standard SNMP MIB OIDs
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def _run_async_coro(coro):
    """
    Executes a coroutine in a dedicated worker thread with its own event loop.
    Prevents event loop collision in mixed synchronous/asynchronous CLI contexts.
    """
    def _worker():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_worker).result()


def oid_suffix_to_mac_and_vlan(full_oid: str, base_oid: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Extracts MAC address and VLAN ID from decimal OID suffixes:
    - dot1d: 6 decimal octets (<m1>..<m6>) -> returns (MAC, 1)
    - dot1q: 7 decimal octets (<vlan_id>.<m1>..<m6>) -> returns (MAC, vlan_id)
    """
    if not full_oid.startswith(base_oid):
        return None, None
    suffix = full_oid[len(base_oid):].strip(".")
    if not suffix:
        return None, None
    try:
        parts = [int(p) for p in suffix.split(".") if p]
    except ValueError:
        return None, None

    if len(parts) == 6:
        mac = ":".join(f"{x:02X}" for x in parts)
        return mac, 1
    elif len(parts) == 7:
        vlan = parts[0]
        mac = ":".join(f"{x:02X}" for x in parts[1:])
        return mac, vlan
    elif len(parts) > 7:
        mac = ":".join(f"{x:02X}" for x in parts[-6:])
        vlan = parts[-7]
        return mac, vlan
    return None, None


def is_virtual_or_multicast_mac(mac: str) -> bool:
    """
    Filters out link-layer multicast, broadcast, and router redundancy virtual MACs:
    - Multicast/Broadcast (01:00:5E, 33:33, FF:FF:FF:FF:FF:FF)
    - Spanning Tree / LLDP / LACP (01:80:C2)
    - Cisco HSRP (00:00:0C:07:AC, 00:00:0C:9F:F)
    - VRRP (00:00:5E:00:01, 00:00:5E:00:02)
    - Microsoft NLB (02:BF, 03:BF)
    - Cisco GLBP (00:07:B4)
    - Null MAC (00:00:00:00:00:00)
    """
    if not mac:
        return True
    clean = mac.strip().upper().replace("-", ":")
    if clean in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
        return True
    virtual_prefixes = (
        "01:00:5E:",
        "33:33:",
        "01:80:C2:",
        "00:00:0C:07:AC:",
        "00:00:0C:9F:F",
        "00:00:5E:00:01:",
        "00:00:5E:00:02:",
        "02:BF:",
        "03:BF:",
        "00:07:B4:",
    )
    for p in virtual_prefixes:
        if clean.startswith(p):
            return True
    return False


def get_switch_fdb_map(gateway_ip: str = "192.168.1.254", db_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Retrieves physical switchport bindings directly from the scraped
    gateway_switchports table in spatial_ledger.db.
    """
    port_map: Dict[str, Dict[str, Any]] = {}
    p = Path(db_path) if db_path else DB_PATH
    if not p.exists():
        return port_map

    conn = sqlite3.connect(p)
    cur = conn.cursor()
    try:
        rows = cur.execute("""
            SELECT LOWER(mac_address), port_id, connection_type 
            FROM gateway_switchports
        """).fetchall()
        for mac, port_id, conn_type in rows:
            clean_mac = mac.upper()
            is_trunk = (port_id == "Port 1")
            entry = {
                "mac": clean_mac,
                "port_name": port_id,
                "port": port_id,
                "switchport": port_id,
                "medium": conn_type,
                "is_trunk": is_trunk,
                "mac_density": 10 if is_trunk else 1,
                "source": "gateway_switchports_ledger"
            }
            port_map[clean_mac] = sanitize_prober_payload(entry)
            port_map[mac.lower()] = sanitize_prober_payload(entry)
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()

    return port_map


def save_to_ledger(
    mappings: Dict[str, Dict[str, Any]],
    switch_ip: str,
    switch_name: str = "",
    db_path: Optional[str] = None
) -> int:
    """
    Persists switchport CAM mappings into switchport_mappings table in spatial_ledger.db.
    """
    if not mappings:
        return 0
    p = Path(db_path) if db_path else DB_PATH
    if not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(p)
    cur = conn.cursor()
    saved = 0
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS switchport_mappings (
                switch_ip TEXT NOT NULL,
                switch_name TEXT,
                mac_address TEXT NOT NULL,
                port_name TEXT,
                if_index INTEGER,
                if_alias TEXT,
                vlan_id INTEGER,
                is_trunk BOOLEAN,
                mac_density INTEGER,
                source TEXT,
                updated_at REAL,
                PRIMARY KEY (switch_ip, mac_address)
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_fdb_mac ON switchport_mappings(mac_address)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_fdb_port ON switchport_mappings(switch_ip, port_name)")

        now = time.time()
        for mac, entry in mappings.items():
            if ":" not in mac or mac != mac.upper():
                continue

            cur.execute("""
                INSERT INTO switchport_mappings (
                    switch_ip, switch_name, mac_address, port_name, if_index, if_alias,
                    vlan_id, is_trunk, mac_density, source, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(switch_ip, mac_address) DO UPDATE SET
                    switch_name=excluded.switch_name,
                    port_name=excluded.port_name,
                    if_index=excluded.if_index,
                    if_alias=excluded.if_alias,
                    vlan_id=excluded.vlan_id,
                    is_trunk=excluded.is_trunk,
                    mac_density=excluded.mac_density,
                    source=excluded.source,
                    updated_at=excluded.updated_at
            """, (
                switch_ip,
                switch_name or "Switch",
                entry["mac"],
                entry.get("port_name", ""),
                entry.get("if_index"),
                entry.get("if_alias", ""),
                entry.get("vlan_id", 1),
                1 if entry.get("is_trunk") else 0,
                entry.get("mac_density", 1),
                entry.get("source", "SNMP-BridgeFDB"),
                now
            ))
            saved += 1
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()
    return saved


class BridgeFdbCrawler:
    """
    Crawls Layer 2 Forwarding Databases (FDB / CAM tables).
    Supports dual Q-Bridge / Bridge SNMP MIBs with bridge_port to ifIndex translation,
    and automated fallbacks for consumer ISP gateways and unmanaged switches.
    """

    def __init__(self, *args, community: str = "public", timeout: float = 1.0, retries: int = 0, **kwargs):
        if args and isinstance(args[0], str):
            self.community = args[0]
            self.graph = kwargs.get("graph_store", None)
        elif args:
            self.graph = args[0]
            self.community = kwargs.get("community", community)
        else:
            self.graph = kwargs.get("graph_store", None)
            self.community = community
        self.timeout = timeout
        self.retries = retries

    def get_switch_identity(self, switch_ip: str) -> str:
        """Determines a concise chassis label for the switch or gateway."""
        if switch_ip in ("192.168.1.1", "192.168.0.1", "10.0.0.1", "192.168.1.254"):
            return "Gateway-Core"
        try:
            host = socket.gethostbyaddr(switch_ip)[0]
            return host.split(".")[0]
        except Exception:
            return f"Switch-{switch_ip.replace('.', '_')}"

    async def crawl_snmp_async(self, switch_ip: str) -> Dict[str, Dict[str, Any]]:
        """
        Asynchronously walks dot1q and dot1d MIBs on the target switch.
        Resolves bridge ports to physical ifIndex, ifName, and ifAlias.
        """
        mappings: Dict[str, Dict[str, Any]] = {}

        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                CommunityData,
                ContextData,
                ObjectIdentity,
                ObjectType,
                SnmpEngine,
                UdpTransportTarget,
                get_cmd,
                walk_cmd,
            )
        except ImportError:
            return {}

        snmp_engine = SnmpEngine()
        try:
            auth_data = CommunityData(self.community, mpModel=1)  # SNMPv2c
            context = ContextData()

            try:
                if hasattr(UdpTransportTarget, "create"):
                    target = await UdpTransportTarget.create(
                        (switch_ip, 161),
                        timeout=min(self.timeout, 0.4),
                        retries=self.retries
                    )
                else:
                    target = UdpTransportTarget(
                        (switch_ip, 161),
                        timeout=min(self.timeout, 0.4),
                        retries=self.retries
                    )
            except Exception:
                return {}

            # 1. Fast Liveness Check on sysDescr.0
            try:
                err_ind, err_stat, _, _ = await get_cmd(
                    snmp_engine, auth_data, target, context,
                    ObjectType(ObjectIdentity(SYS_DESCR))
                )
                if err_ind or err_stat:
                    return {}
            except Exception:
                return {}

            # 2. Walk dot1dBasePortIfIndex (1.3.6.1.2.1.17.1.4.1.2)
            bridge_port_to_ifindex: Dict[int, int] = {}
            try:
                async for (err_ind, err_stat, _, var_binds) in walk_cmd(
                    snmp_engine, auth_data, target, context,
                    ObjectType(ObjectIdentity(DOT1D_BASE_PORT_IFINDEX))
                ):
                    if err_ind or err_stat:
                        break
                    for vb in var_binds:
                        oid_str = str(vb[0])
                        if not oid_str.startswith(DOT1D_BASE_PORT_IFINDEX):
                            break
                        suffix = oid_str[len(DOT1D_BASE_PORT_IFINDEX):].strip(".")
                        if suffix.isdigit():
                            bp = int(suffix)
                            try:
                                bridge_port_to_ifindex[bp] = int(vb[1])
                            except (ValueError, TypeError):
                                pass
            except Exception:
                pass

            # 3. Walk ifName, ifDescr, and ifAlias
            if_names: Dict[int, str] = {}
            if_descrs: Dict[int, str] = {}
            if_aliases: Dict[int, str] = {}

            for base_oid, target_dict in [
                (IF_NAME, if_names),
                (IF_DESCR, if_descrs),
                (IF_ALIAS, if_aliases)
            ]:
                try:
                    async for (err_ind, err_stat, _, var_binds) in walk_cmd(
                        snmp_engine, auth_data, target, context,
                        ObjectType(ObjectIdentity(base_oid))
                    ):
                        if err_ind or err_stat:
                            break
                        for vb in var_binds:
                            oid_str = str(vb[0])
                            if not oid_str.startswith(base_oid):
                                break
                            suffix = oid_str[len(base_oid):].strip(".")
                            if suffix.isdigit():
                                ifi = int(suffix)
                                raw_val = vb[1].prettyPrint() if hasattr(vb[1], "prettyPrint") else str(vb[1])
                                target_dict[ifi] = clean_ascii_string(raw_val)
                except Exception:
                    pass

            # 4. Walk FDB Tables: Q-Bridge first, then Bridge MIB
            fdb_records: List[Tuple[str, int, int]] = []
            seen_macs = set()

            for base_oid in (DOT1Q_TP_FDB_PORT, DOT1D_TP_FDB_PORT):
                try:
                    async for (err_ind, err_stat, _, var_binds) in walk_cmd(
                        snmp_engine, auth_data, target, context,
                        ObjectType(ObjectIdentity(base_oid))
                    ):
                        if err_ind or err_stat:
                            break
                        for vb in var_binds:
                            oid_str = str(vb[0])
                            if not oid_str.startswith(base_oid):
                                break
                            mac, vlan = oid_suffix_to_mac_and_vlan(oid_str, base_oid)
                            if not mac or is_virtual_or_multicast_mac(mac):
                                continue
                            try:
                                bp = int(vb[1])
                            except (ValueError, TypeError):
                                continue
                            if bp <= 0:
                                continue
                            if mac not in seen_macs:
                                seen_macs.add(mac)
                                fdb_records.append((mac, bp, vlan or 1))
                except Exception:
                    pass

            if not fdb_records:
                return {}

            # 5. Density Analytics & Trunk Classification
            port_to_macs: Dict[str, List[str]] = {}
            port_meta: Dict[str, Dict[str, Any]] = {}

            for mac, bp, vlan in fdb_records:
                ifi = bridge_port_to_ifindex.get(bp, bp)
                name = if_names.get(ifi) or if_descrs.get(ifi) or f"Port-{bp}"
                alias = if_aliases.get(ifi, "")
                port_to_macs.setdefault(name, []).append(mac)
                if name not in port_meta:
                    port_meta[name] = {
                        "if_index": ifi,
                        "if_alias": alias,
                        "bridge_port": bp
                    }

            for name, mac_list in port_to_macs.items():
                density = len(mac_list)
                alias = port_meta[name]["if_alias"]
                is_trunk = (
                    density >= 4
                    or "trunk" in name.lower()
                    or "uplink" in name.lower()
                    or "trunk" in alias.lower()
                    or "uplink" in alias.lower()
                    or "interconnect" in alias.lower()
                )
                port_meta[name]["is_trunk"] = is_trunk
                port_meta[name]["density"] = density

            # 6. Build Final Mappings
            for mac, bp, vlan in fdb_records:
                ifi = bridge_port_to_ifindex.get(bp, bp)
                name = if_names.get(ifi) or if_descrs.get(ifi) or f"Port-{bp}"
                meta = port_meta[name]
                entry = {
                    "mac": mac,
                    "port_name": name,
                    "port": name,
                    "switchport": name,
                    "if_index": meta["if_index"],
                    "if_alias": meta["if_alias"],
                    "vlan_id": vlan,
                    "is_trunk": meta["is_trunk"],
                    "mac_density": meta["density"],
                    "medium": "Ethernet",
                    "source": "SNMP-BridgeFDB",
                    "switch_ip": switch_ip
                }
                sanitized = sanitize_prober_payload(entry)
                mappings[mac] = sanitized
                mappings[mac.lower()] = sanitized

            return mappings
        finally:
            try:
                snmp_engine.close_dispatcher()
            except Exception:
                pass

    def crawl_snmp(self, switch_ip: str) -> Dict[str, Dict[str, Any]]:
        """Synchronously executes crawl_snmp_async in a thread-isolated event loop."""
        try:
            return _run_async_coro(self.crawl_snmp_async(switch_ip))
        except Exception:
            return {}

    def crawl(self, switch_ip: str) -> Dict[str, Dict[str, Any]]:
        """
        Retrieves MAC-to-port mappings:
        1. Seeds with gateway_switchports from spatial_ledger.db if gateway
        2. Tries SNMP Bridge & Q-Bridge MIB walk on switch_ip
        3. Falls back to ARP table cache if unmanaged switch
        """
        mappings: Dict[str, Dict[str, Any]] = {}
        is_gateway = switch_ip in ("192.168.1.254", "Gateway-Core")

        # 0. Gateway switchports ledger seed
        if is_gateway:
            try:
                persisted = get_switch_fdb_map(switch_ip)
                if persisted:
                    mappings.update(persisted)
            except Exception:
                pass

        # 1. Enterprise SNMP MIB Attempt
        try:
            snmp_results = self.crawl_snmp(switch_ip)
            if snmp_results:
                mappings.update(snmp_results)
                self.save_to_ledger(mappings, switch_ip, self.get_switch_identity(switch_ip))
        except Exception:
            pass

        # 2. Consumer Gateway / Host Routing Cache Fallback
        if not mappings:
            try:
                cmd = "arp -a"
                output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
                port_counter = 1
                for line in output.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip_candidate = parts[0]
                        mac_candidate = parts[1].replace("-", ":").upper()
                        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac_candidate):
                            mac_match = re.search(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}", line)
                            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                            if mac_match and ip_match:
                                raw_mac = mac_match.group(0).replace("-", ":").upper()
                                octets = [f"{int(x, 16):02X}" for x in raw_mac.split(":")]
                                mac_candidate = ":".join(octets)
                                ip_candidate = ip_match.group(0)

                        if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac_candidate):
                            if is_virtual_or_multicast_mac(mac_candidate):
                                continue
                            if mac_candidate not in mappings and mac_candidate.lower() not in mappings:
                                if ip_candidate.endswith(".1") or ip_candidate.endswith(".254") or ip_candidate == switch_ip:
                                    port_label = "Uplink-WAN"
                                    is_trunk = False
                                    conn_medium = "Ethernet"
                                elif is_gateway:
                                    port_label = "WLAN"
                                    is_trunk = False
                                    conn_medium = "Wireless"
                                else:
                                    port_label = f"Port-{port_counter}"
                                    port_counter += 1
                                    is_trunk = False
                                    conn_medium = "Ethernet"

                                entry = {
                                    "mac": mac_candidate,
                                    "port_name": port_label,
                                    "port": port_label,
                                    "switchport": port_label,
                                    "is_trunk": is_trunk,
                                    "mac_density": 1,
                                    "medium": conn_medium,
                                    "source": "L2-BridgeCache"
                                }
                                mappings[mac_candidate] = sanitize_prober_payload(entry)
                                mappings[mac_candidate.lower()] = sanitize_prober_payload(entry)
            except Exception:
                pass

        # 3. Topology Graph Edges
        if self.graph:
            try:
                for mac, entry in mappings.items():
                    if ":" not in mac or mac != mac.upper():
                        continue
                    port_name = entry.get("port_name", "Port-1")
                    is_trunk = entry.get("is_trunk", False)
                    with self.graph.batch_transaction():
                        self.graph.add_node(mac, {
                            "mac": mac,
                            "type": "endpoint",
                            "discovery_method": entry.get("source", "L2-BridgeCache")
                        })
                        self.graph.add_edge(switch_ip, mac, {
                            "layer": 2,
                            "label": f"âš¡ {port_name}",
                            "port": port_name,
                            "is_trunk": is_trunk,
                            "method": "bridge_fdb_cam_table"
                        })
            except Exception:
                pass

        return mappings

    def save_to_ledger(self, mappings: Dict[str, Dict[str, Any]], switch_ip: str, switch_name: str = "", db_path: Optional[str] = None) -> int:
        """Saves current mappings to spatial_ledger.db."""
        return save_to_ledger(mappings, switch_ip, switch_name, db_path=db_path)

    async def crawl_switch_fdb_async(self, switch_ip: str) -> List[Dict[str, Any]]:
        """Async compatibility method returning a list of deduplicated mapped entries."""
        res = self.crawl(switch_ip)
        unique_entries = {}
        for k, v in res.items():
            mac = v.get("mac", k)
            unique_entries[mac.upper()] = v
        return list(unique_entries.values())


def crawl_switch_fdb(switch_ip: str, community: str = "public", timeout: float = 1.0) -> Dict[str, Dict[str, Any]]:
    """Standalone entry point for crawling switch CAM tables."""
    crawler = BridgeFdbCrawler(community=community, timeout=timeout)
    return crawler.crawl(switch_ip)


# Compatibility alias
BridgeFDBCrawler = BridgeFdbCrawler

