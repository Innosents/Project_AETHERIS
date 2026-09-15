"""
Project AETHERIS - Core Switchport and Network Infrastructure Crawlers
Provides specialized crawling utilities for Layer 2 Forwarding Databases (CAM tables),
bridge port-to-interface resolution, and network infrastructure topology mapping.
"""

from graphpath.core.crawlers.bridge_fdb import (
    BridgeFdbCrawler,
    BridgeFDBCrawler,
    crawl_switch_fdb,
    get_switch_fdb_map,
    save_to_ledger,
    oid_suffix_to_mac_and_vlan,
    is_virtual_or_multicast_mac,
)

__all__ = [
    "BridgeFdbCrawler",
    "BridgeFDBCrawler",
    "crawl_switch_fdb",
    "get_switch_fdb_map",
    "save_to_ledger",
    "oid_suffix_to_mac_and_vlan",
    "is_virtual_or_multicast_mac",
]

