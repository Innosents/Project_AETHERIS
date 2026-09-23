"""
Project AETHERIS - DHCP Fingerprint Adapter
Passively sniffs and decodes BOOTP/DHCP transaction frames to extract RFC 2132 Option 55
parameter request vectors and Option 60 vendor class identifiers. Matches discrete option
sequence tuples against empirical OS signature tables to achieve passive operating system
fingerprinting. Implements DhcpFingerprintPort.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from aetheris.core.ports.dhcp_fingerprint_port import (
    DhcpClassification,
    DhcpFingerprintPort,
    DhcpFingerprintResult,
    _MappingCompatibleModel,
)

# Ensure correct root path registration across execution scopes
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from scapy.all import sniff
    from scapy.layers.dhcp import DHCP, BOOTP

    SCAPY_DHCP_AVAILABLE = True
except ImportError:
    SCAPY_DHCP_AVAILABLE = False
    DHCP = None
    BOOTP = None


class DhcpFingerprinter(DhcpFingerprintPort):
    """
    Passive DHCP Option 55 / Option 60 fingerprinter and classifier adapter.
    Implements DhcpFingerprintPort.
    """

    # Static database mapping Option 55 fingerprint hashes to known hardware identities
    FINGERPRINT_DB: Dict[str, Dict[str, str]] = {
        # Microsoft Windows 10/11
        "1,3,6,15,31,33,43,44,46,47,119,121,249,252": {
            "vendor": "Microsoft Corporation",
            "type": "workstation",
            "model": "Windows Host",
        },
        "1,3,6,15,31,33,43,44,46,47,121,249,252": {
            "vendor": "Microsoft Corporation",
            "type": "workstation",
            "model": "Windows 11 Laptop/PC",
        },
        # Apple iOS / iPadOS Mobile Devices
        "1,121,3,6,15,119,252": {
            "vendor": "Apple Inc.",
            "type": "mobile_ios",
            "model": "Apple iPhone (iOS 15-18)",
        },
        "1,3,6,15,119,252": {
            "vendor": "Apple Inc.",
            "type": "mobile_ios",
            "model": "Apple iPhone / iPad",
        },
        "1,28,2,3,15,6,119,12,44,47,26,121,42": {
            "vendor": "Apple Inc.",
            "type": "mobile_ios",
            "model": "Apple iOS Device",
        },
        "1,3,6,15,119,95,252,44,46": {
            "vendor": "Apple Inc.",
            "type": "tablet",
            "model": "Apple iPad",
        },
        # Google Android Smartphones & Tablets
        "1,3,6,15,26,28,51,58,59,43": {
            "vendor": "Google LLC",
            "type": "mobile_android",
            "model": "Android Smartphone",
        },
        "1,3,6,15,26,28,12,121,43": {
            "vendor": "Google LLC",
            "type": "mobile_android",
            "model": "Google Pixel / Android 13-14",
        },
        "1,3,6,12,15,26,28,121,33,43": {
            "vendor": "Samsung Electronics",
            "type": "mobile_android",
            "model": "Samsung Galaxy Device",
        },
        # Zebra & Honeywell Industrial Mobile Handhelds
        "1,3,6,15,26,28,43,121,119": {
            "vendor": "Zebra Technologies",
            "type": "industrial_mobile",
            "model": "Zebra Enterprise Mobile Computer",
        },
        "1,3,6,15,28,33,43,121": {
            "vendor": "Honeywell",
            "type": "industrial_mobile",
            "model": "Honeywell Dolphin / CT Mobile Scanner",
        },
        # Apple macOS Laptops (MacBook Pro / Air)
        "1,121,3,6,15,119,252,95,44,46": {
            "vendor": "Apple Inc.",
            "type": "laptop",
            "model": "Apple MacBook (macOS)",
        },
        "1,3,6,15,119,252,95,44,46,47": {
            "vendor": "Apple Inc.",
            "type": "laptop",
            "model": "Apple MacBook Air/Pro",
        },
        # Google ChromeOS Laptops
        "1,3,6,12,15,26,28,121,249,33": {
            "vendor": "Google LLC",
            "type": "laptop",
            "model": "Google Chromebook",
        },
        # Routers, Mesh Nodes & Wi-Fi Extenders
        "1,3,6,15,28,33,43,121,249": {
            "vendor": "TP-Link",
            "type": "router",
            "model": "TP-Link Archer/Deco Router",
        },
        "1,3,6,15,28,43,121": {
            "vendor": "Netgear",
            "type": "wifi_extender",
            "model": "Netgear Wi-Fi Extender/Orbi",
        },
        "1,3,6,12,15,28,42,43,121": {
            "vendor": "OpenWrt / Embedded",
            "type": "router",
            "model": "OpenWrt / DD-WRT Gateway",
        },
        "1,3,6,15,26,28,121,249": {
            "vendor": "Ubiquiti Networks",
            "type": "wlan_ap",
            "model": "Ubiquiti UniFi AP/Gateway",
        },
        # ISP TV Set-Top Boxes (ARRIS, Technicolor, Humax, Sagemcom, Pace, TiVo)
        "1,3,6,12,15,28,42,43,66,67,121": {
            "vendor": "ARRIS / CommScope",
            "type": "stb",
            "model": "ARRIS 4K IPTV Set-Top Box",
        },
        "1,3,6,15,28,33,43,60,121": {
            "vendor": "Technicolor",
            "type": "stb",
            "model": "Technicolor Android TV Box",
        },
        "1,3,6,12,15,26,28,42,43,60,121": {
            "vendor": "Sagemcom",
            "type": "stb",
            "model": "Sagemcom Fibe TV Receiver",
        },
        "1,3,6,15,28,42,43,119,121": {
            "vendor": "Humax",
            "type": "stb",
            "model": "Humax IPTV STB",
        },
        "1,3,6,15,28,33,43,121,66,67": {
            "vendor": "TiVo Inc.",
            "type": "stb",
            "model": "TiVo Stream 4K / DVR",
        },
        # Smart TVs & Streaming Devices (Samsung, LG, Roku, Fire TV, Apple TV)
        "1,3,6,15,28,33,43,119,121,252": {
            "vendor": "Samsung Electronics",
            "type": "smart_tv",
            "model": "Samsung Tizen Smart TV",
        },
        "1,3,6,15,26,28,33,43,121,249": {
            "vendor": "LG Electronics",
            "type": "smart_tv",
            "model": "LG webOS Smart TV",
        },
        "1,3,6,15,26,28,33,43,121,252": {
            "vendor": "Sony",
            "type": "smart_tv",
            "model": "Sony Bravia Smart TV",
        },
        "1,3,6,15,28,43,121,249": {
            "vendor": "Roku Inc.",
            "type": "media_device",
            "model": "Roku Streaming Device / TV",
        },
        "1,3,6,15,26,28,33,43,119,121": {
            "vendor": "Amazon",
            "type": "media_device",
            "model": "Amazon Fire TV Stick / Cube",
        },
        # Linux & IoT
        "1,3,6,12,15,26,28,42,121": {
            "vendor": "Generic Linux",
            "type": "server",
            "model": "Linux Endpoint",
        },
        "1,3,6,15,28,33": {
            "vendor": "Espressif Systems",
            "type": "iot",
            "model": "ESP32/ESP8266 IoT Node",
        },
    }

    def __init__(self) -> None:
        self.fingerprint_db = dict(self.FINGERPRINT_DB)

    @classmethod
    def classify_fingerprint(
        cls, fingerprint_hash: str, vendor_class_id: str = ""
    ) -> DhcpClassification:
        """Pure classification helper matching Option 55 sequence or Option 60 vendor class."""
        if fingerprint_hash and fingerprint_hash in cls.FINGERPRINT_DB:
            entry = cls.FINGERPRINT_DB[fingerprint_hash]
            return DhcpClassification(
                vendor=entry.get("vendor", "Unknown Vendor"),
                type=entry.get("type", "unknown"),
                model=entry.get("model", "Generic DHCP Client"),
            )

        vendor_string = (vendor_class_id or "").lower()
        if "arris" in vendor_string or "vip56" in vendor_string or "vip78" in vendor_string:
            return DhcpClassification(
                vendor="ARRIS / CommScope", type="stb", model="ARRIS 4K IPTV Set-Top Box"
            )
        if "technicolor" in vendor_string or "uiw4054" in vendor_string:
            return DhcpClassification(
                vendor="Technicolor", type="stb", model="Technicolor Android TV STB"
            )
        if "sagemcom" in vendor_string or "diw387" in vendor_string:
            return DhcpClassification(
                vendor="Sagemcom", type="stb", model="Sagemcom Fibe TV Box"
            )
        if "humax" in vendor_string:
            return DhcpClassification(
                vendor="Humax", type="stb", model="Humax IPTV STB"
            )
        if "tivo" in vendor_string:
            return DhcpClassification(
                vendor="TiVo Inc.", type="stb", model="TiVo Stream / DVR"
            )
        if "tizen" in vendor_string or ("samsung" in vendor_string and "tv" in vendor_string):
            return DhcpClassification(
                vendor="Samsung Electronics", type="smart_tv", model="Samsung Smart TV"
            )
        if "webos" in vendor_string or ("lg" in vendor_string and "tv" in vendor_string):
            return DhcpClassification(
                vendor="LG Electronics", type="smart_tv", model="LG webOS Smart TV"
            )
        if "bravia" in vendor_string or ("sony" in vendor_string and "tv" in vendor_string):
            return DhcpClassification(
                vendor="Sony", type="smart_tv", model="Sony Bravia Smart TV"
            )
        if "vizio" in vendor_string:
            return DhcpClassification(
                vendor="Vizio", type="smart_tv", model="Vizio SmartCast TV"
            )
        if "roku" in vendor_string:
            return DhcpClassification(
                vendor="Roku Inc.", type="media_device", model="Roku Streaming Player / TV"
            )
        if "firetv" in vendor_string or "aft" in vendor_string:
            return DhcpClassification(
                vendor="Amazon", type="media_device", model="Amazon Fire TV Device"
            )
        if "macbook" in vendor_string:
            return DhcpClassification(
                vendor="Apple Inc.", type="laptop", model="Apple MacBook"
            )
        if "chromebook" in vendor_string or "cros" in vendor_string:
            return DhcpClassification(
                vendor="Google LLC", type="laptop", model="Chromebook"
            )
        if "android" in vendor_string or "dhcpcd" in vendor_string:
            return DhcpClassification(
                vendor="Google LLC",
                type="mobile_android",
                model="Android Smartphone/Tablet",
            )
        if "apple" in vendor_string or "iphone" in vendor_string or "ipad" in vendor_string:
            return DhcpClassification(
                vendor="Apple Inc.", type="mobile_ios", model="Apple iOS Mobile"
            )
        if "zebra" in vendor_string or "symbol" in vendor_string:
            return DhcpClassification(
                vendor="Zebra Technologies",
                type="industrial_mobile",
                model="Zebra Mobile Scanner",
            )
        if "honeywell" in vendor_string:
            return DhcpClassification(
                vendor="Honeywell",
                type="industrial_mobile",
                model="Honeywell Mobile Computer",
            )
        if "extender" in vendor_string or "repeater" in vendor_string:
            return DhcpClassification(
                vendor="Wi-Fi Infrastructure",
                type="wifi_extender",
                model="Wi-Fi Range Extender",
            )
        if "tplink" in vendor_string or "tp-link" in vendor_string:
            return DhcpClassification(
                vendor="TP-Link", type="router", model="TP-Link Gateway"
            )
        if "netgear" in vendor_string or "nighthawk" in vendor_string or "orbi" in vendor_string:
            return DhcpClassification(
                vendor="Netgear", type="router", model="Netgear Router / Mesh"
            )
        if "ubiquiti" in vendor_string:
            return DhcpClassification(
                vendor="Ubiquiti Networks", type="wlan_ap", model="UniFi Node"
            )
        if "msft" in vendor_string:
            return DhcpClassification(
                vendor="Microsoft Corporation", type="workstation", model="Windows Host"
            )

        return DhcpClassification()

    def parse_dhcp_options(self, packet: Any) -> Optional[DhcpFingerprintResult]:
        """
        Extracts structural hardware characteristics out of live bootstrap frame requests.
        Returns typed DhcpFingerprintResult or None.
        """
        if not SCAPY_DHCP_AVAILABLE or DHCP is None:
            return None

        if not hasattr(packet, "haslayer") or not packet.haslayer(DHCP):
            return None

        options = packet.getlayer(DHCP).options
        extracted_options: Dict[int, Any] = {}

        for item in options:
            if isinstance(item, tuple) and len(item) >= 2:
                opt_code = item[0]
                opt_value = item[1]
                if isinstance(opt_code, int):
                    extracted_options[opt_code] = opt_value

        # Option 53 captures message type. We evaluate 'Request' messages (value: 3)
        if extracted_options.get(53) != 3:
            return None

        # Build structural fingerprint sequences from Option 55
        opt_55_raw = extracted_options.get(55)
        fingerprint_hash = ""
        if isinstance(opt_55_raw, bytes):
            fingerprint_hash = ",".join(str(b) for b in opt_55_raw)
        elif isinstance(opt_55_raw, list):
            fingerprint_hash = ",".join(str(x) for x in opt_55_raw)

        # Grab Vendor Class Identifier string from Option 60
        opt_60_raw = extracted_options.get(60, b"")
        vendor_string = (
            opt_60_raw.decode(errors="ignore")
            if isinstance(opt_60_raw, bytes)
            else str(opt_60_raw)
        )

        classification = self.classify_fingerprint(fingerprint_hash, vendor_string)

        mac = "00:00:00:00:00:00"
        if BOOTP is not None and packet.haslayer(BOOTP):
            bootp = packet.getlayer(BOOTP)
            if hasattr(bootp, "chaddr") and bootp.chaddr:
                mac = bootp.chaddr[:6].hex(":").upper()

        return DhcpFingerprintResult(
            mac=mac,
            fingerprint_hash=fingerprint_hash,
            vendor_class_id=vendor_string,
            classification=classification,
            discovery_method="passive_dhcp_fingerprint",
        )


def start_dhcp_sniffer(
    graph_store: Any, interface: Optional[str] = None, timeout: float = 10.0
) -> None:
    """Passively binds to local interfaces to map boot allocations into the central graph."""
    if not SCAPY_DHCP_AVAILABLE:
        print("[DHCP Sniffer] Missing Scapy framework dependencies. Skipping tier initialization.")
        return

    parser = DhcpFingerprinter()

    def packet_handler(pkt: Any) -> None:
        try:
            result = parser.parse_dhcp_options(pkt)
            if result and graph_store:
                # Safely commit classification directly into the central transaction registry
                with graph_store.batch_transaction():
                    graph_store.add_node(result["mac"], dict(result["classification"]))
                print(
                    f" • [Discovered Tier 3] DHCP Fingerprinted Host: {result['mac']} -> {result['classification']['model']}"
                )
        except Exception as e:
            print(f"[DHCP Sniffer] Processing anomaly encountered: {e}")

    print(f"[Tier 3] Engaging passive DHCP fingerprint sniffer filter loop ({timeout}s)...")
    try:
        sniff(
            filter="udp port 67 or udp port 68",
            prn=packet_handler,
            iface=interface,
            store=False,
            timeout=timeout,
        )
    except Exception as e:
        print(f"[DHCP Sniffer] Critical interface acquisition crash: {e}")


__all__ = [
    "DhcpFingerprinter",
    "DhcpFingerprintPort",
    "DhcpClassification",
    "DhcpFingerprintResult",
    "_MappingCompatibleModel",
    "start_dhcp_sniffer",
]