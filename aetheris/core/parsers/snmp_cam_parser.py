"""
Project AETHERIS - Core L2 SNMP CAM Table Parser
Stateless parser extracting Forwarding Database (FDB / CAM) relational bindings
between decimal MAC address OIDs, Bridge Port mappings, and physical interface names.
"""

from typing import Dict, Any


def parse_cam_table_oids(
    raw_cam_table: Dict[str, Any],
    raw_bridge_map: Dict[str, Any],
    raw_ifname_map: Dict[str, Any]
) -> Dict[str, str]:
    """
    Parses tripartite SNMP MIB tables into a normalized {MAC: InterfaceName} dictionary.
    
    Relational OIDs:
    1. dot1dTpFdbPort (1.3.6.1.2.1.17.4.3.1.2): MAC Decimal Suffix -> Bridge Port
    2. dot1dBasePortIfIndex (1.3.6.1.2.1.17.1.4.1.2): Bridge Port Suffix -> ifIndex
    3. ifName (1.3.6.1.2.1.31.1.1.1.1): ifIndex Suffix -> Physical Interface Name
    """
    bridge_to_ifindex = {
        oid.split('.')[-1]: str(val) for oid, val in raw_bridge_map.items()
    }
    ifindex_to_ifname = {
        oid.split('.')[-1]: str(val) for oid, val in raw_ifname_map.items()
    }
    cam_matrix: Dict[str, str] = {}
    for oid, bridge_port_obj in raw_cam_table.items():
        parts = oid.split('.')
        if len(parts) < 6:
            continue
        mac_decimal = parts[-6:]
        mac_hex = ':'.join(f'{int(octet):02x}' for octet in mac_decimal)
        bridge_port = str(bridge_port_obj)
        ifindex = bridge_to_ifindex.get(bridge_port)
        ifname = ifindex_to_ifname.get(ifindex, f'Unknown-IfIndex-{ifindex}')
        cam_matrix[mac_hex] = ifname
    return cam_matrix

