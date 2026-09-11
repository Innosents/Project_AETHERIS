import os
import sys
from typing import Dict, List, Optional, Any

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

class DhcpFingerprinter:
    def __init__(self) -> None:
        # Static database mapping Option 55 fingerprint hashes to known hardware identities
        self.fingerprint_db: Dict[str, Dict[str, str]] = {
            # Microsoft Windows 10/11
            "1,3,6,15,31,33,43,44,46,47,119,121,249,252": {
                "vendor": "Microsoft Corporation", "type": "workstation", "model": "Windows Host"
            },
            "1,3,6,15,31,33,43,44,46,47,121,249,252": {
                "vendor": "Microsoft Corporation", "type": "workstation", "model": "Windows 11 Laptop/PC"
            },
            # Apple iOS / iPadOS Mobile Devices
            "1,121,3,6,15,119,252": {
                "vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iPhone (iOS 15-18)"
            },
            "1,3,6,15,119,252": {
                "vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iPhone / iPad"
            },
            "1,28,2,3,15,6,119,12,44,47,26,121,42": {
                "vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Device"
            },
            "1,3,6,15,119,95,252,44,46": {
                "vendor": "Apple Inc.", "type": "tablet", "model": "Apple iPad"
            },
            # Google Android Smartphones & Tablets
            "1,3,6,15,26,28,51,58,59,43": {
                "vendor": "Google LLC", "type": "mobile_android", "model": "Android Smartphone"
            },
            "1,3,6,15,26,28,12,121,43": {
                "vendor": "Google LLC", "type": "mobile_android", "model": "Google Pixel / Android 13-14"
            },
            "1,3,6,12,15,26,28,121,33,43": {
                "vendor": "Samsung Electronics", "type": "mobile_android", "model": "Samsung Galaxy Device"
            },
            # Zebra & Honeywell Industrial Mobile Handhelds
            "1,3,6,15,26,28,43,121,119": {
                "vendor": "Zebra Technologies", "type": "industrial_mobile", "model": "Zebra Enterprise Mobile Computer"
            },
            "1,3,6,15,28,33,43,121": {
                "vendor": "Honeywell", "type": "industrial_mobile", "model": "Honeywell Dolphin / CT Mobile Scanner"
            },
            # Apple macOS Laptops (MacBook Pro / Air)
            "1,121,3,6,15,119,252,95,44,46": {
                "vendor": "Apple Inc.", "type": "laptop", "model": "Apple MacBook (macOS)"
            },
            "1,3,6,15,119,252,95,44,46,47": {
                "vendor": "Apple Inc.", "type": "laptop", "model": "Apple MacBook Air/Pro"
            },
            # Google ChromeOS Laptops
            "1,3,6,12,15,26,28,121,249,33": {
                "vendor": "Google LLC", "type": "laptop", "model": "Google Chromebook"
            },
            # Routers, Mesh Nodes & Wi-Fi Extenders
            "1,3,6,15,28,33,43,121,249": {
                "vendor": "TP-Link", "type": "router", "model": "TP-Link Archer/Deco Router"
            },
            "1,3,6,15,28,43,121": {
                "vendor": "Netgear", "type": "wifi_extender", "model": "Netgear Wi-Fi Extender/Orbi"
            },
            "1,3,6,12,15,28,42,43,121": {
                "vendor": "OpenWrt / Embedded", "type": "router", "model": "OpenWrt / DD-WRT Gateway"
            },
            "1,3,6,15,26,28,121,249": {
                "vendor": "Ubiquiti Networks", "type": "wlan_ap", "model": "Ubiquiti UniFi AP/Gateway"
            },
            # ISP TV Set-Top Boxes (ARRIS, Technicolor, Humax, Sagemcom, Pace, TiVo)
            "1,3,6,12,15,28,42,43,66,67,121": {
                "vendor": "ARRIS / CommScope", "type": "stb", "model": "ARRIS 4K IPTV Set-Top Box"
            },
            "1,3,6,15,28,33,43,60,121": {
                "vendor": "Technicolor", "type": "stb", "model": "Technicolor Android TV Box"
            },
            "1,3,6,12,15,26,28,42,43,60,121": {
                "vendor": "Sagemcom", "type": "stb", "model": "Sagemcom Fibe TV Receiver"
            },
            "1,3,6,15,28,42,43,119,121": {
                "vendor": "Humax", "type": "stb", "model": "Humax IPTV STB"
            },
            "1,3,6,15,28,33,43,121,66,67": {
                "vendor": "TiVo Inc.", "type": "stb", "model": "TiVo Stream 4K / DVR"
            },
            # Smart TVs & Streaming Devices (Samsung, LG, Roku, Fire TV, Apple TV)
            "1,3,6,15,28,33,43,119,121,252": {
                "vendor": "Samsung Electronics", "type": "smart_tv", "model": "Samsung Tizen Smart TV"
            },
            "1,3,6,15,26,28,33,43,121,249": {
                "vendor": "LG Electronics", "type": "smart_tv", "model": "LG webOS Smart TV"
            },
            "1,3,6,15,26,28,33,43,121,252": {
                "vendor": "Sony", "type": "smart_tv", "model": "Sony Bravia Smart TV"
            },
            "1,3,6,15,28,43,121,249": {
                "vendor": "Roku Inc.", "type": "media_device", "model": "Roku Streaming Device / TV"
            },
            "1,3,6,15,26,28,33,43,119,121": {
                "vendor": "Amazon", "type": "media_device", "model": "Amazon Fire TV Stick / Cube"
            },
            # Linux & IoT
            "1,3,6,12,15,26,28,42,121": {
                "vendor": "Generic Linux", "type": "server", "model": "Linux Endpoint"
            },
            "1,3,6,15,28,33": {
                "vendor": "Espressif Systems", "type": "iot", "model": "ESP32/ESP8266 IoT Node"
            }
        }

    def parse_dhcp_options(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Extracts structural hardware characteristics out of live bootstrap frame requests.
        """
        if not packet.haslayer(DHCP):
            return None

        options = packet.getlayer(DHCP).options
        extracted_options: Dict[int, Any] = {}
        
        for item in options:
            if isinstance(item, tuple) and len(item) >= 2:
                opt_code = item[0]
                opt_value = item[1]
                if isinstance(opt_code, int):
                    extracted_options[opt_code] = opt_value

        # Option 53 captures message type. We want to evaluate 'Request' messages (value: 3)
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
        vendor_string = opt_60_raw.decode(errors="ignore").lower() if isinstance(opt_60_raw, bytes) else str(opt_60_raw).lower()

        # Execute cascading lookup evaluations
        classification = {"vendor": "Unknown Vendor", "type": "unknown", "model": "Generic DHCP Client"}
        
        if fingerprint_hash in self.fingerprint_db:
            classification.update(self.fingerprint_db[fingerprint_hash])
        elif "arris" in vendor_string or "vip56" in vendor_string or "vip78" in vendor_string:
            classification.update({"vendor": "ARRIS / CommScope", "type": "stb", "model": "ARRIS 4K IPTV Set-Top Box"})
        elif "technicolor" in vendor_string or "uiw4054" in vendor_string:
            classification.update({"vendor": "Technicolor", "type": "stb", "model": "Technicolor Android TV STB"})
        elif "sagemcom" in vendor_string or "diw387" in vendor_string:
            classification.update({"vendor": "Sagemcom", "type": "stb", "model": "Sagemcom Fibe TV Box"})
        elif "humax" in vendor_string:
            classification.update({"vendor": "Humax", "type": "stb", "model": "Humax IPTV STB"})
        elif "tivo" in vendor_string:
            classification.update({"vendor": "TiVo Inc.", "type": "stb", "model": "TiVo Stream / DVR"})
        elif "tizen" in vendor_string or ("samsung" in vendor_string and "tv" in vendor_string):
            classification.update({"vendor": "Samsung Electronics", "type": "smart_tv", "model": "Samsung Smart TV"})
        elif "webos" in vendor_string or ("lg" in vendor_string and "tv" in vendor_string):
            classification.update({"vendor": "LG Electronics", "type": "smart_tv", "model": "LG webOS Smart TV"})
        elif "bravia" in vendor_string or ("sony" in vendor_string and "tv" in vendor_string):
            classification.update({"vendor": "Sony", "type": "smart_tv", "model": "Sony Bravia Smart TV"})
        elif "vizio" in vendor_string:
            classification.update({"vendor": "Vizio", "type": "smart_tv", "model": "Vizio SmartCast TV"})
        elif "roku" in vendor_string:
            classification.update({"vendor": "Roku Inc.", "type": "media_device", "model": "Roku Streaming Player / TV"})
        elif "firetv" in vendor_string or "aft" in vendor_string:
            classification.update({"vendor": "Amazon", "type": "media_device", "model": "Amazon Fire TV Device"})
        elif "macbook" in vendor_string:
            classification.update({"vendor": "Apple Inc.", "type": "laptop", "model": "Apple MacBook"})
        elif "chromebook" in vendor_string or "cros" in vendor_string:
            classification.update({"vendor": "Google LLC", "type": "laptop", "model": "Chromebook"})
        elif "android" in vendor_string or "dhcpcd" in vendor_string:
            classification.update({"vendor": "Google LLC", "type": "mobile_android", "model": "Android Smartphone/Tablet"})
        elif "apple" in vendor_string or "iphone" in vendor_string or "ipad" in vendor_string:
            classification.update({"vendor": "Apple Inc.", "type": "mobile_ios", "model": "Apple iOS Mobile"})
        elif "zebra" in vendor_string or "symbol" in vendor_string:
            classification.update({"vendor": "Zebra Technologies", "type": "industrial_mobile", "model": "Zebra Mobile Scanner"})
        elif "honeywell" in vendor_string:
            classification.update({"vendor": "Honeywell", "type": "industrial_mobile", "model": "Honeywell Mobile Computer"})
        elif "extender" in vendor_string or "repeater" in vendor_string:
            classification.update({"vendor": "Wi-Fi Infrastructure", "type": "wifi_extender", "model": "Wi-Fi Range Extender"})
        elif "tplink" in vendor_string or "tp-link" in vendor_string:
            classification.update({"vendor": "TP-Link", "type": "router", "model": "TP-Link Gateway"})
        elif "netgear" in vendor_string or "nighthawk" in vendor_string or "orbi" in vendor_string:
            classification.update({"vendor": "Netgear", "type": "router", "model": "Netgear Router / Mesh"})
        elif "ubiquiti" in vendor_string:
            classification.update({"vendor": "Ubiquiti Networks", "type": "wlan_ap", "model": "UniFi Node"})
        elif "msft" in vendor_string:
            classification.update({"vendor": "Microsoft Corporation", "type": "workstation", "model": "Windows Host"})
            
        return {
            "mac": packet.getlayer(BOOTP).chaddr[:6].hex(":").upper() if packet.haslayer(BOOTP) else "00:00:00:00:00:00",
            "fingerprint_hash": fingerprint_hash,
            "vendor_class_id": vendor_string,
            "classification": classification,
            "discovery_method": "passive_dhcp_fingerprint"
        }

def start_dhcp_sniffer(graph_store: Any, interface: Optional[str] = None, timeout: float = 10.0) -> None:
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
                    graph_store.add_node(result["mac"], result["classification"])
                print(f" • [Discovered Tier 3] DHCP Fingerprinted Host: {result['mac']} -> {result['classification']['model']}")
        except Exception as e:
            print(f"[DHCP Sniffer] Processing anomaly encountered: {e}")

    print(f"[Tier 3] Engaging passive DHCP fingerprint sniffer filter loop ({timeout}s)...")
    try:
        sniff(
            filter="udp port 67 or udp port 68",
            prn=packet_handler,
            iface=interface,
            store=False,
            timeout=timeout
        )
    except Exception as e:
        print(f"[DHCP Sniffer] Critical interface acquisition crash: {e}")