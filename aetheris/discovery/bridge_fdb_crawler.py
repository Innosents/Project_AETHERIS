"""Compatibility exports for the Bridge FDB crawler adapter."""

from aetheris.core.crawlers.bridge_fdb import (
    BridgeFdbCrawler,
    BridgeFDBCrawler,
    crawl_switch_fdb,
    get_switch_fdb_map,
    save_to_ledger,
    oid_suffix_to_mac_and_vlan,
    is_virtual_or_multicast_mac,
    DB_PATH,
)

__all__ = [
    "BridgeFdbCrawler",
    "BridgeFDBCrawler",
    "crawl_switch_fdb",
    "get_switch_fdb_map",
    "save_to_ledger",
    "oid_suffix_to_mac_and_vlan",
    "is_virtual_or_multicast_mac",
    "DB_PATH",
]
