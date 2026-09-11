"""
GraphPath Bridge Forwarding Database (CAM Table) & Switchport Wire Mapper
Crawls SNMP dot1dTpFdbTable (1.3.6.1.2.1.17.4.3.1.2) and dot1qTpFdbTable (1.3.6.1.2.1.17.7.1.2.2.1.2)
to accurately map every silent endpoint MAC address to its exact physical switch port (ifIndex/Port Name).
Works universally across Cisco, HP/Aruba, Juniper, Moxa, and Dell switches.
"""

import asyncio
from typing import Dict, List, Any, Optional
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, walk_cmd, get_cmd
)
from topology.graph_store import GraphStore

# Standard Bridge & Interface MIB OIDs (RFC 1493 / RFC 4188 / RFC 4363 / RFC 2863)
DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"         # dot1dTpFdbPort (MAC suffix -> Bridge Port)
DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"   # dot1dBasePortIfIndex (Bridge Port -> ifIndex)
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"                     # ifDescr (ifIndex -> "GigabitEthernet1/0/1")
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"                   # ifName (ifIndex -> "Gi1/0/1")
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"                 # ifAlias (ifIndex -> "CAM-NORTH-GATE-01")
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"     # dot1qTpFdbPort (VLAN.MAC -> Port)

def oid_suffix_to_mac(suffix: str) -> Optional[str]:
    """Converts decimal OID suffix (e.g. '0.17.34.51.68.85' or '10.0.17.34.51.68.85') into MAC."""
    parts = suffix.split('.')
    if len(parts) >= 6:
        # Last 6 octets represent the MAC address
        mac_octets = parts[-6:]
        try:
            return ":".join(f"{int(o):02X}" for o in mac_octets)
        except ValueError:
            return None
    return None

def oid_suffix_to_mac_and_vlan(suffix: str) -> tuple:
    """Extracts (mac_address, vlan_id) from dot1d or dot1q OID suffix."""
    parts = suffix.split('.')
    if len(parts) >= 7:
        try:
            vlan_id = int(parts[0])
            mac_octets = parts[-6:]
            mac = ":".join(f"{int(o):02X}" for o in mac_octets)
            return mac, vlan_id
        except (ValueError, IndexError):
            pass
    mac = oid_suffix_to_mac(suffix)
    return mac, None

class BridgeFdbCrawler:
    def __init__(self, graph_store: GraphStore, community: str = "public", timeout: float = 0.8):
        self.graph = graph_store
        self.community = community
        self.timeout = timeout

    async def _walk_oid_dict(self, snmp_engine, target, root_oid: str) -> Dict[str, str]:
        results = {}
        try:
            iterator = walk_cmd(
                snmp_engine,
                CommunityData(self.community),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(root_oid))
            )
            async for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication or errorStatus:
                    break
                for varBind in varBinds:
                    oid_str = str(varBind[0])
                    val_str = varBind[1].prettyPrint()
                    suffix = oid_str[len(root_oid):].lstrip('.')
                    results[suffix] = val_str
        except Exception:
            pass
        return results

    async def crawl_switch_fdb_async(self, switch_ip: str) -> List[Dict[str, Any]]:
        """Crawls the switch Forwarding Database (CAM table) and maps MACs to physical ports."""
        mappings = []
        snmp_engine = SnmpEngine()
        try:
            target = await UdpTransportTarget.create((switch_ip, 161), timeout=self.timeout, retries=0)

            # Gather FDB Table (standard dot1d and 802.1q), Bridge-Port mapping, interface names and aliases concurrently
            fdb_raw, dot1q_fdb_raw, base_ports, if_names, if_descrs, if_aliases = await asyncio.gather(
                self._walk_oid_dict(snmp_engine, target, DOT1D_TP_FDB_PORT),
                self._walk_oid_dict(snmp_engine, target, DOT1Q_TP_FDB_PORT),
                self._walk_oid_dict(snmp_engine, target, DOT1D_BASE_PORT_IF_INDEX),
                self._walk_oid_dict(snmp_engine, target, IF_NAME),
                self._walk_oid_dict(snmp_engine, target, IF_DESCR),
                self._walk_oid_dict(snmp_engine, target, IF_ALIAS),
                return_exceptions=True
            )

            if isinstance(fdb_raw, Exception): fdb_raw = {}
            if isinstance(dot1q_fdb_raw, Exception): dot1q_fdb_raw = {}
            if isinstance(base_ports, Exception): base_ports = {}
            if isinstance(if_names, Exception): if_names = {}
            if isinstance(if_descrs, Exception): if_descrs = {}
            if isinstance(if_aliases, Exception): if_aliases = {}

            # Map bridge port number to human-readable interface name and alias
            bridge_to_ifname: Dict[str, str] = {}
            bridge_to_alias: Dict[str, str] = {}
            for b_port, if_idx in base_ports.items():
                name = if_names.get(if_idx) or if_descrs.get(if_idx) or f"Port {b_port}"
                alias = if_aliases.get(if_idx, "").strip()
                bridge_to_ifname[b_port] = name
                if alias:
                    bridge_to_alias[b_port] = alias

            # Combine dot1d and dot1q entries
            combined_fdb = {}
            for s, bp in fdb_raw.items():
                mac, vlan = oid_suffix_to_mac_and_vlan(s)
                if mac:
                    combined_fdb[mac] = (bp, vlan)

            for s, bp in dot1q_fdb_raw.items():
                mac, vlan = oid_suffix_to_mac_and_vlan(s)
                if mac:
                    combined_fdb[mac] = (bp, vlan)

            # Track MAC counts per port to identify access ports vs trunk uplinks
            port_mac_counts: Dict[str, int] = {}
            parsed_entries = []

            for mac, (b_port, vlan_id) in combined_fdb.items():
                if not mac or mac == "00:00:00:00:00:00" or mac.startswith("FF:FF:FF"):
                    continue

                port_name = bridge_to_ifname.get(b_port, f"Port {b_port}")
                alias = bridge_to_alias.get(b_port, "")
                port_mac_counts[port_name] = port_mac_counts.get(port_name, 0) + 1
                parsed_entries.append({
                    "mac": mac,
                    "port": port_name,
                    "bridge_port": b_port,
                    "alias": alias,
                    "vlan_id": vlan_id
                })

            for item in parsed_entries:
                mac = item["mac"]
                port_name = item["port"]
                alias = item.get("alias", "")
                vlan_id = item.get("vlan_id")
                mac_count_on_port = port_mac_counts.get(port_name, 1)

                is_trunk = mac_count_on_port >= 4
                mapping_record = {
                    "switch_ip": switch_ip,
                    "mac": mac,
                    "port": port_name,
                    "alias": alias,
                    "vlan_id": vlan_id,
                    "is_trunk": is_trunk,
                    "mac_density": mac_count_on_port,
                    "discovery_method": "snmp_bridge_fdb"
                }
                mappings.append(mapping_record)

                # Format edge label
                if is_trunk:
                    label_str = f"⚡ {port_name} (Trunk)"
                elif alias:
                    label_str = f"⚡ {port_name} ({alias})"
                elif vlan_id:
                    label_str = f"⚡ {port_name} (VLAN {vlan_id})"
                else:
                    label_str = f"⚡ {port_name}"

                # Register in graph store
                with self.graph.batch_transaction():
                    node_attrs = {
                        "mac": mac,
                        "type": "endpoint",
                        "discovery_method": "snmp_bridge_fdb"
                    }
                    if vlan_id:
                        node_attrs["vlan_id"] = vlan_id
                    self.graph.add_node(mac, node_attrs)
                    
                    self.graph.add_edge(switch_ip, mac, {
                        "layer": 2,
                        "label": label_str,
                        "port": port_name,
                        "alias": alias,
                        "vlan_id": vlan_id,
                        "is_trunk": is_trunk,
                        "method": "bridge_fdb_cam_table"
                    })

            print(f"[Tier 2 FDB] Switch {switch_ip}: mapped {len(mappings)} MACs across physical switch ports.")
        except Exception as e:
            print(f"[Tier 2 FDB] Failed on {switch_ip}: {e}")
        finally:
            try:
                if hasattr(snmp_engine, "close_dispatcher"):
                    snmp_engine.close_dispatcher()
                elif hasattr(snmp_engine, "closeDispatcher"):
                    snmp_engine.closeDispatcher()
            except Exception:
                pass

        return mappings
