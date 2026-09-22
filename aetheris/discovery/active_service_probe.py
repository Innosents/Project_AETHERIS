"""
Project AETHERIS - Active Service Prober (mDNS, SSDP, NetBIOS, WSD)
Elicits responses from otherwise silent mobile devices, laptops, routers,
Smart TVs, and ISP TV Set-Top Boxes (STBs: ARRIS, Technicolor, Humax, Sagemcom, Roku, Apple TV, Fire TV).
"""

import socket
import struct
import time
import select
import re
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from loguru import logger

class ActiveServiceProber:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    # =========================================================================
    # 1. mDNS Multicast Query (UDP 5353 -> 224.0.0.251)
    # =========================================================================
    def probe_mdns(self) -> List[Dict[str, Any]]:
        """
        Broadcasts mDNS queries for Mobile Devices, Laptops, Mesh Routers, Smart TVs,
        and ISP Set-Top Boxes (STBs).
        """
        discovered = []
        mdns_group = ('224.0.0.251', 5353)
        
        # Build mDNS PTR Queries for TV, STB, media, mobile, and laptop services
        services = [
            b"\x0b_googlecast\x04_tcp\x05local\x00",
            b"\x08_airplay\x04_tcp\x05local\x00",
            b"\x05_raop\x04_tcp\x05local\x00",
            b"\x11_dial-multiscreen\x04_tcp\x05local\x00",
            b"\x12_android-tv-remote\x04_tcp\x05local\x00",
            b"\x0e_mediaremotetv\x04_tcp\x05local\x00",
            b"\x0f_spotify-connect\x04_tcp\x05local\x00",
            b"\x0b_amzn-wplay\x04_tcp\x05local\x00",
            b"\x0c_device-info\x04_tcp\x05local\x00",
            b"\x0f_apple-mobdev2\x04_tcp\x05local\x00",
            b"\x0f_companion-link\x04_tcp\x05local\x00",
            b"\x0c_tivo-remote\x04_tcp\x05local\x00",
            b"\x04_smb\x04_tcp\x05local\x00",
            b"\x05_mesh\x04_tcp\x05local\x00",
            b"\x04_ipp\x04_tcp\x05local\x00"
        ]

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(0.2)

            for svc in services:
                header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
                footer = struct.pack(">HH", 12, 1)
                packet = header + svc + footer
                try:
                    sock.sendto(packet, mdns_group)
                except Exception:
                    pass

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                ready = select.select([sock], [], [], 0.2)
                if ready[0]:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    parsed = self._parse_mdns_payload(data)
                    if parsed:
                        parsed["ip"] = ip
                        parsed["source"] = "active_mdns"
                        discovered.append(parsed)
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return discovered

    def _parse_mdns_payload(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Extracts text strings and model identifiers from mDNS response payload."""
        text_repr = data.decode("latin1", errors="ignore")
        lowered = text_repr.lower()

        vendor = "generic"
        device_type = "unknown"
        model = "Network Endpoint"

        # 1. ISP TV Set-Top Boxes (STBs) & Cable/IPTV Receivers
        if "arris" in lowered or "vip56" in lowered or "vip78" in lowered or "vip22" in lowered or "commscope" in lowered:
            vendor = "ARRIS / CommScope"
            device_type = "stb"
            model = "ARRIS 4K IPTV Set-Top Box"
        elif "technicolor" in lowered or "vantiva" in lowered or "uiw4054" in lowered or "dciw" in lowered:
            vendor = "Technicolor"
            device_type = "stb"
            model = "Technicolor Android TV STB"
        elif "humax" in lowered or "hmr" in lowered:
            vendor = "Humax"
            device_type = "stb"
            model = "Humax IPTV Set-Top Box"
        elif "sagemcom" in lowered or "diw387" in lowered or "diw377" in lowered:
            vendor = "Sagemcom"
            device_type = "stb"
            model = "Sagemcom 4K TV Receiver"
        elif "pace" in lowered or "pace-hd" in lowered:
            vendor = "Pace plc"
            device_type = "stb"
            model = "Pace IPTV Set-Top Box"
        elif "tivo" in lowered:
            vendor = "TiVo Inc."
            device_type = "stb"
            model = "TiVo DVR / Stream 4K"
        elif "amino" in lowered:
            vendor = "Amino Communications"
            device_type = "stb"
            model = "Amino Enterprise IPTV STB"

        # 2. Smart TVs & Media Streaming Players
        elif "bravia" in lowered or ("sony" in lowered and "tv" in lowered):
            vendor = "Sony"
            device_type = "smart_tv"
            model = "Sony Bravia Smart TV (Google TV)"
        elif "webos" in lowered or "lg tv" in lowered or "lgwebostv" in lowered:
            vendor = "LG Electronics"
            device_type = "smart_tv"
            model = "LG webOS Smart TV"
        elif "tizen" in lowered or ("samsung" in lowered and "tv" in lowered):
            vendor = "Samsung Electronics"
            device_type = "smart_tv"
            model = "Samsung Tizen Smart TV"
        elif "vizio" in lowered or "smartcast" in lowered:
            vendor = "Vizio"
            device_type = "smart_tv"
            model = "Vizio SmartCast TV"
        elif "tcl" in lowered and "tv" in lowered:
            vendor = "TCL"
            device_type = "smart_tv"
            model = "TCL Smart TV"
        elif "hisense" in lowered and "tv" in lowered:
            vendor = "Hisense"
            device_type = "smart_tv"
            model = "Hisense Smart TV"
        elif "appletv" in lowered or "apple tv" in lowered or "_mediaremotetv" in lowered:
            vendor = "Apple Inc."
            device_type = "media_device"
            model = "Apple TV 4K / HD"
        elif "firetv" in lowered or "aft" in lowered or "fire tv" in lowered or "_amzn-wplay" in lowered:
            vendor = "Amazon"
            device_type = "media_device"
            model = "Amazon Fire TV Stick/Cube"
        elif "roku" in lowered:
            vendor = "Roku Inc."
            device_type = "media_device" if "tv" not in lowered else "smart_tv"
            model = "Roku Streaming Player" if "tv" not in lowered else "Roku Smart TV"
        elif "googlecast" in lowered or "chromecast" in lowered or "_android-tv-remote" in lowered:
            vendor = "Google LLC"
            device_type = "media_device"
            model = "Google Chromecast / Android TV"

        # 3. Laptops & Portable Workstations
        elif "macbook" in lowered:
            vendor = "Apple Inc."
            device_type = "laptop"
            model = "Apple MacBook"
        elif "thinkpad" in lowered:
            vendor = "Lenovo"
            device_type = "laptop"
            model = "Lenovo ThinkPad Laptop"
        elif "surface" in lowered:
            vendor = "Microsoft Corporation"
            device_type = "laptop"
            model = "Microsoft Surface Laptop/Pro"
        elif "latitude" in lowered or "xps" in lowered or "inspiron" in lowered:
            vendor = "Dell Technologies"
            device_type = "laptop"
            model = "Dell Latitude/XPS Laptop"
        elif "elitebook" in lowered or "spectre" in lowered or "envy" in lowered or "probook" in lowered:
            vendor = "HP Inc."
            device_type = "laptop"
            model = "HP EliteBook/ProBook Laptop"
        elif "chromebook" in lowered:
            vendor = "Google LLC"
            device_type = "laptop"
            model = "Google Chromebook"

        # 4. Mobile Phones & Tablets
        elif "iphone" in lowered:
            vendor = "Apple Inc."
            device_type = "mobile_ios"
            model = "Apple iPhone"
        elif "ipad" in lowered:
            vendor = "Apple Inc."
            device_type = "tablet"
            model = "Apple iPad"
        elif "_apple-mobdev" in lowered or "airplay" in lowered or (bool(re.search(r'\b(?:ios\s*(?:\d+|device|sdk)?|apple-mobdev)\b', lowered)) and not any(k in lowered for k in ["netbios", "cisco ios", "cisco-ios", "bios", "audiostream", "scenarios"])):
            vendor = "Apple Inc."
            device_type = "mobile_ios"
            model = "Apple iOS Device"
        elif "galaxy" in lowered or "android" in lowered:
            vendor = "Samsung Electronics" if "galaxy" in lowered else "Google LLC"
            device_type = "mobile_android"
            model = "Android Mobile Endpoint"

        # 5. Industrial Handhelds
        elif "zebra" in lowered or "symbol" in lowered or "tc5" in lowered or "tc7" in lowered:
            vendor = "Zebra Technologies"
            device_type = "industrial_mobile"
            model = "Zebra Enterprise Handheld"
        elif "honeywell" in lowered or "dolphin" in lowered or "ct60" in lowered or "ct40" in lowered:
            vendor = "Honeywell"
            device_type = "industrial_mobile"
            model = "Honeywell Industrial Mobile Computer"

        # 6. Routers, Mesh Satellites & Wi-Fi Extenders
        elif "orbi" in lowered:
            vendor = "Netgear"
            device_type = "wifi_extender" if "satellite" in lowered else "router"
            model = "Netgear Orbi Mesh Node"
        elif "nighthawk" in lowered:
            vendor = "Netgear"
            device_type = "router"
            model = "Netgear Nighthawk Gateway"
        elif "deco" in lowered:
            vendor = "TP-Link"
            device_type = "router"
            model = "TP-Link Deco Mesh Unit"
        elif "extender" in lowered or "repeater" in lowered or "re200" in lowered or "re450" in lowered:
            vendor = "TP-Link" if "tp-link" in lowered else "Wi-Fi Infrastructure"
            device_type = "wifi_extender"
            model = "Wi-Fi Range Extender / Booster"
        elif "eero" in lowered:
            vendor = "Amazon Eero"
            device_type = "router"
            model = "Eero Mesh Node"
        elif "asuswrt" in lowered or "aimesh" in lowered or "rt-ax" in lowered or "rt-ac" in lowered:
            vendor = "ASUS"
            device_type = "router"
            model = "ASUS Router / AiMesh Gateway"
        elif "unifi" in lowered or "amplifi" in lowered:
            vendor = "Ubiquiti Networks"
            device_type = "wlan_ap"
            model = "Ubiquiti UniFi Access Point"
        elif "mikrotik" in lowered or "routeros" in lowered:
            vendor = "MikroTik"
            device_type = "router"
            model = "MikroTik RouterOS Gateway"
        else:
            return None

        return {
            "vendor": vendor,
            "type": device_type,
            "model": model,
            "raw_mdns": text_repr[:120]
        }

    # =========================================================================
    # 2. SSDP / UPnP M-SEARCH Probe (UDP 1900 -> 239.255.255.250)
    # =========================================================================
    def probe_ssdp(self) -> List[Dict[str, Any]]:
        """
        Sends UPnP M-SEARCH multicast discovery to identify Smart TVs, ISP Set-Top Boxes,
        Gateway Routers, Wi-Fi Extenders, Mesh Nodes, and Laptops.
        """
        discovered = []
        ssdp_target = ('239.255.255.250', 1900)
        
        msearch_msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
        ).encode("utf-8")

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(msearch_msg, ssdp_target)

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                ready = select.select([sock], [], [], 0.2)
                if ready[0]:
                    data, addr = sock.recvfrom(2048)
                    ip = addr[0]
                    text = data.decode("utf-8", errors="ignore")
                    parsed = self._parse_ssdp_payload(text)
                    if parsed:
                        parsed["ip"] = ip
                        parsed["source"] = "active_ssdp"
                        discovered.append(parsed)
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return discovered

    def _parse_ssdp_payload(self, text: str) -> Optional[Dict[str, Any]]:
        lowered = text.lower()
        server_line = ""
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                server_line = line.split(":", 1)[1].strip()

        vendor = "generic"
        device_type = "unknown"
        model = "UPnP Device"

        # 1. ISP STBs & Set-Top Boxes
        if "arris" in lowered or "commscope" in lowered or "vip56" in lowered or "vip78" in lowered:
            vendor = "ARRIS / CommScope"
            device_type = "stb"
            model = "ARRIS 4K IPTV Set-Top Box"
        elif "technicolor" in lowered or "vantiva" in lowered or "uiw4054" in lowered:
            vendor = "Technicolor"
            device_type = "stb"
            model = "Technicolor Set-Top Box"
        elif "humax" in lowered:
            vendor = "Humax"
            device_type = "stb"
            model = "Humax IPTV Set-Top Box"
        elif "sagemcom" in lowered:
            vendor = "Sagemcom"
            device_type = "stb"
            model = "Sagemcom 4K TV Receiver"
        elif "pace" in lowered:
            vendor = "Pace plc"
            device_type = "stb"
            model = "Pace Set-Top Box"
        elif "tivo" in lowered:
            vendor = "TiVo Inc."
            device_type = "stb"
            model = "TiVo Media Box"

        # 2. Mobile Phones & Tablets (Samsung Galaxy, Google Pixel, iPhone)
        elif "sec_hhp" in lowered or "samsung mobile" in lowered or ("samsung" in lowered and ("phone" in lowered or "galaxy" in lowered or "mobile" in lowered or "tab" in lowered or "sm-" in lowered)):
            vendor = "Samsung Electronics"
            device_type = "mobile_android"
            model = "Samsung Galaxy Mobile Device"
        elif "pixel" in lowered or ("android" in lowered and "tv" not in lowered and "box" not in lowered):
            vendor = "Google LLC"
            device_type = "mobile_android"
            model = "Android Mobile Device"
        elif "iphone" in lowered:
            vendor = "Apple Inc."
            device_type = "mobile_ios"
            model = "Apple iPhone"
        elif "ipad" in lowered:
            vendor = "Apple Inc."
            device_type = "tablet"
            model = "Apple iPad"
        elif bool(re.search(r'\b(?:ios\s*(?:\d+|device|sdk)?|apple-mobdev)\b', lowered)) and not any(k in lowered for k in ["netbios", "cisco ios", "cisco-ios", "bios", "audiostream", "scenarios"]):
            vendor = "Apple Inc."
            device_type = "mobile_ios"
            model = "Apple iPhone"

        # 3. Smart TVs & Dedicated Media Renderers (DIAL / UPnP)
        elif "samsung" in lowered and ("tv" in lowered or "maintvserver" in lowered or "tizen" in lowered):
            vendor = "Samsung Electronics"
            device_type = "smart_tv"
            model = "Samsung Tizen Smart TV"
        elif "lg electronics" in lowered or "webos" in lowered or "udap" in lowered:
            vendor = "LG Electronics"
            device_type = "smart_tv"
            model = "LG webOS Smart TV"
        elif "bravia" in lowered or ("sony" in lowered and "tv" in lowered):
            vendor = "Sony"
            device_type = "smart_tv"
            model = "Sony Bravia Smart TV"
        elif "vizio" in lowered or "smartcast" in lowered:
            vendor = "Vizio"
            device_type = "smart_tv"
            model = "Vizio SmartCast TV"
        elif "mediarenderer" in lowered or "dial" in lowered:
            if "roku" in lowered:
                vendor = "Roku Inc."
                device_type = "smart_tv" if "tv" in lowered else "media_device"
                model = "Roku Media Device"
            elif "firetv" in lowered or "aft" in lowered or "amazon" in lowered:
                vendor = "Amazon"
                device_type = "media_device"
                model = "Amazon Fire TV Device"
            else:
                device_type = "media_device"
                model = "UPnP Media Renderer"

        # 3. Routers & Wi-Fi Extenders
        elif "internetgatewaydevice" in lowered or "wanconnectiondevice" in lowered:
            device_type = "router"
            if "netgear" in lowered or "readyshare" in lowered:
                vendor = "Netgear"
                model = "Netgear Gateway Router"
            elif "tp-link" in lowered or "deco" in lowered:
                vendor = "TP-Link"
                model = "TP-Link Router / Mesh"
            elif "asus" in lowered:
                vendor = "ASUS"
                model = "ASUS Gateway Router"
            elif "linksys" in lowered:
                vendor = "Linksys"
                model = "Linksys Smart Router"
            else:
                vendor = "Gateway Appliance"
                model = "Internet Gateway Router (UPnP)"
        elif "wlanaccesspoint" in lowered or "accesspoint" in lowered:
            device_type = "wlan_ap"
            vendor = "Wi-Fi Infrastructure"
            model = "Wireless Access Point"
        elif "extender" in lowered or "repeater" in lowered or "booster" in lowered:
            device_type = "wifi_extender"
            vendor = "Wi-Fi Infrastructure"
            model = "Wi-Fi Range Extender"

        # 4. Laptops & Workstations
        elif "macbook" in lowered:
            vendor = "Apple Inc."
            device_type = "laptop"
            model = "Apple MacBook"
        elif "surface" in lowered:
            vendor = "Microsoft Corporation"
            device_type = "laptop"
            model = "Microsoft Surface"
        elif "windows" in lowered:
            vendor = "Microsoft Corporation"
            device_type = "workstation"
            model = "Windows Host"
        else:
            return None

        return {
            "vendor": vendor,
            "type": device_type,
            "model": model,
            "server_header": server_line
        }

    # =========================================================================
    # 3. NetBIOS Node Status Query (UDP 137)
    # =========================================================================
    def probe_netbios(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Unicasts a NetBIOS Name Query to grab NetBIOS name and workstation/laptop role.
        """
        nbstat_query = (
            b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        )
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)
            sock.sendto(nbstat_query, (target_ip, 137))
            data, _ = sock.recvfrom(1024)
            if len(data) > 56:
                num_names = data[56]
                names = []
                offset = 57
                for _ in range(num_names):
                    if offset + 18 <= len(data):
                        name_bytes = data[offset:offset+15].strip()
                        names.append(name_bytes.decode(errors="ignore"))
                        offset += 18
                if names:
                    primary_name = names[0]
                    lower_name = primary_name.lower()
                    
                    dev_type = "workstation"
                    dev_model = "Windows Host"
                    dev_vendor = "Microsoft Corporation"
                    
                    if "stb" in lower_name or "iptv" in lower_name or "box" in lower_name:
                        dev_type = "stb"
                        dev_model = "IPTV Set-Top Box"
                    elif "tv" in lower_name:
                        dev_type = "smart_tv"
                        dev_model = "Smart TV"
                    elif "laptop-" in lower_name or "thinkpad" in lower_name or "macbook" in lower_name or "surface" in lower_name:
                        dev_type = "laptop"
                        if "thinkpad" in lower_name:
                            dev_vendor = "Lenovo"
                            dev_model = "Lenovo ThinkPad Laptop"
                        elif "surface" in lower_name:
                            dev_model = "Microsoft Surface Laptop"
                        elif "macbook" in lower_name:
                            dev_vendor = "Apple Inc."
                            dev_model = "Apple MacBook"
                        else:
                            dev_model = "Windows Portable Laptop"

                    return {
                        "ip": target_ip,
                        "hostname": primary_name,
                        "vendor": dev_vendor,
                        "type": dev_type,
                        "model": dev_model,
                        "source": "netbios_137"
                    }
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return None

    # =========================================================================
    # 4. Web Services on Devices (WSD / WS-Discovery Probe on UDP 3702)
    # =========================================================================
    def probe_ws_discovery(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Unicasts a WS-Discovery SOAP Probe to UDP 3702 to identify Windows 10/11 endpoints,
        smart devices, printers, and scanners that block standard TCP ports.
        """
        import uuid
        msg_id = str(uuid.uuid4())
        wsd_probe_xml = (
            f'<?xml version="1.0" encoding="utf-8"?>'
            f'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            f'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            f'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
            f'<soap:Header>'
            f'<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
            f'<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
            f'<wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>'
            f'</soap:Header>'
            f'<soap:Body><wsd:Probe/></soap:Body>'
            f'</soap:Envelope>'
        ).encode('utf-8')

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.4)
            sock.sendto(wsd_probe_xml, (target_ip, 3702))
            data, _ = sock.recvfrom(4096)

            text = data.decode("latin1", errors="ignore")
            lowered = text.lower()

            vendor = "generic"
            dev_type = "workstation"
            model = "Network Endpoint"
            friendly_name = ""

            import re
            mfg_match = re.search(r'<[a-zA-Z0-9:]*manufacturer[^>]*>([^<]+)<', text, re.IGNORECASE)
            model_match = re.search(r'<[a-zA-Z0-9:]*modelname[^>]*>([^<]+)<', text, re.IGNORECASE)
            name_match = re.search(r'<[a-zA-Z0-9:]*friendlyname[^>]*>([^<]+)<', text, re.IGNORECASE)

            if mfg_match:
                vendor = mfg_match.group(1).strip()
            if model_match:
                model = model_match.group(1).strip()
            if name_match:
                friendly_name = name_match.group(1).strip()

            if "print" in lowered or "ipp" in lowered or "prt" in lowered or "copier" in lowered:
                dev_type = "printer"
                if vendor == "generic":
                    if "kyocera" in lowered: vendor = "Kyocera Document Solutions"
                    elif "hp" in lowered or "hewlett" in lowered: vendor = "HP Inc."
                    elif "canon" in lowered: vendor = "Canon"
                    elif "brother" in lowered: vendor = "Brother"
                    elif "xerox" in lowered: vendor = "Xerox"
                    elif "ricoh" in lowered: vendor = "Ricoh"
                    elif "epson" in lowered: vendor = "Epson"
                    elif "lexmark" in lowered: vendor = "Lexmark"
                    else: vendor = "Network Printer"
                if model == "Network Endpoint":
                    model = "Multifunction Network Printer (MFP)"
            elif "scan" in lowered:
                dev_type = "scanner"
                model = "Network Scanner"
            elif "camera" in lowered or "onvif" in lowered:
                dev_type = "camera"
                model = "IP Camera"
            elif "windows" in lowered or "ws-transfer" in lowered:
                dev_type = "workstation"
                vendor = "Microsoft Corporation"
                model = "Windows Endpoint"

            return {
                "ip": target_ip,
                "vendor": vendor,
                "type": dev_type,
                "model": model,
                "friendly_name": friendly_name,
                "hostname": friendly_name,
                "source": "ws_discovery_3702"
            }
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return None

    # =========================================================================
    # 5. Link-Local Multicast Name Resolution (LLMNR on UDP 5355)
    # =========================================================================
    def probe_llmnr(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Unicasts an LLMNR reverse PTR query to UDP 5355 for target_ip.
        """
        sock = None
        try:
            octets = target_ip.split(".")
            rev_name = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
            parts = rev_name.split(".")
            qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"

            # Transaction ID: 0x1234, Flags: Standard Query (0x0000), QDCOUNT: 1
            query = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.35)
            sock.sendto(query, (target_ip, 5355))
            data, _ = sock.recvfrom(1024)

            # Parse answer name from response
            text = data.decode("latin1", errors="ignore")
            # Extract plain alphanumeric tokens
            import re
            tokens = re.findall(r'[A-Za-z0-9\-]{3,32}', text[12:])
            hostname = ""
            for tok in tokens:
                if tok.lower() not in ["in-addr", "arpa", "local"]:
                    hostname = tok
                    break

            if hostname:
                return {
                    "ip": target_ip,
                    "hostname": hostname,
                    "source": "llmnr_5355"
                }
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        return None

    # =========================================================================
    # 6. Intel AMT / vPro Out-of-Band Engine (TCP 16992 / 16993)
    # =========================================================================
    def probe_intel_amt(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Probes Intel AMT web interface on TCP 16992 (HTTP) or 16993 (HTTPS).
        """
        for port in [16992, 16993]:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((target_ip, port)) == 0:
                    req = f"GET / HTTP/1.1\r\nHost: {target_ip}:{port}\r\nUser-Agent: Aetheris-DPI\r\n\r\n".encode()
                    s.sendall(req)
                    resp = s.recv(1024).decode("latin1", errors="ignore")
                    if "intel" in resp.lower() or "amt" in resp.lower() or "active management" in resp.lower() or "realm=\"intel" in resp.lower():
                        return {
                            "ip": target_ip,
                            "vendor": "Intel Corporation",
                            "type": "workstation",
                            "model": "Intel Core Enterprise PC (Intel AMT/vPro Active)",
                            "os_version": "Intel ME/AMT Management Engine",
                            "source": f"intel_amt_{port}"
                        }
            except Exception:
                pass
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
        return None

    # =========================================================================
    # 7. Comprehensive Stealth Endpoint Interrogator
    # =========================================================================
    def probe_stealth_endpoint(self, target_ip: str) -> Dict[str, Any]:
        """
        Executes all stealth variances concurrently (NetBIOS UDP 137, WSD UDP 3702,
        LLMNR UDP 5355, Intel AMT TCP 16992) to unmask hidden/stealth nodes.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        summary = {"ip": target_ip, "banners": {}, "stealth_probes": {}}

        with ThreadPoolExecutor(max_workers=5) as executor:
            fut_nb = executor.submit(self.probe_netbios, target_ip)
            fut_wsd = executor.submit(self.probe_ws_discovery, target_ip)
            fut_llmnr = executor.submit(self.probe_llmnr, target_ip)
            fut_amt = executor.submit(self.probe_intel_amt, target_ip)

            for fut in [fut_nb, fut_wsd, fut_llmnr, fut_amt]:
                try:
                    res = fut.result(timeout=0.6)
                    if res:
                        src = res.get("source", "probe")
                        summary["stealth_probes"][src] = res
                        if res.get("hostname") and not summary.get("hostname"):
                            summary["hostname"] = res["hostname"]
                        if res.get("vendor") and not summary.get("vendor"):
                            summary["vendor"] = res["vendor"]
                        if res.get("type") and not summary.get("type"):
                            summary["type"] = res["type"]
                        if res.get("model") and not summary.get("model"):
                            summary["model"] = res["model"]
                        if res.get("os_version") and not summary.get("os_version"):
                            summary["os_version"] = res["os_version"]
                except Exception:
                    pass

        return summary

    # =========================================================================
    # 8. Composite Sweep: Probe all active services
    # =========================================================================
    def execute_active_probe_sweep(self) -> Dict[str, Dict[str, Any]]:
        """
        Executes active mDNS and SSDP probes and returns a merged map of {ip: device_profile}.
        """
        results = {}
        for dev in self.probe_mdns():
            ip = dev.get("ip")
            if ip:
                results[ip] = dev

        for dev in self.probe_ssdp():
            ip = dev.get("ip")
            if ip and ip not in results:
                results[ip] = dev

        return results

    # =========================================================================
    # 9. Targeted Device Profile Probing & Pre-Flight Verification
    # =========================================================================
    def probe_device_profile(self, ip: str, open_ports: list) -> Dict[str, Any]:
        """Dispatches protocol-specific probes based on active port fingerprinting."""
        enrichment: Dict[str, Any] = {}

        # 1. Roku ECP (Port 8060)
        if 8060 in open_ports:
            roku_info = self._probe_roku_ecp(ip)
            if roku_info:
                enrichment.update(roku_info)

        # 2. Samsung Smart TV / Tizen Remote (Ports 8001 / 8002)
        if 8001 in open_ports or 8002 in open_ports:
            enrichment.update({
                "type": "smart_tv",
                "vendor": "Samsung Electronics",
                "model": "Samsung Smart TV (Tizen OS)",
                "discovery_method": "samsung_multiscreen_port"
            })

        # 3. IPP / JetDirect Printer (Ports 631 / 9100)
        if 631 in open_ports or 9100 in open_ports:
            printer_info = self._probe_printer_attributes(ip, open_ports)
            if printer_info:
                enrichment.update(printer_info)

        return enrichment

    def _probe_roku_ecp(self, ip: str) -> Optional[Dict[str, Any]]:
        """Queries Roku External Control Protocol REST API for hardware info."""
        url = f"http://{ip}:8060/query/device-info"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Aetheris-Discovery"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    xml_data = resp.read()
                    root = ET.fromstring(xml_data)
                    model = root.findtext("model-name") or "Roku Streaming Device"
                    vendor = root.findtext("vendor-name") or "Roku"
                    serial = root.findtext("serial-number") or ""
                    return {
                        "type": "media_device",
                        "vendor": vendor,
                        "model": model,
                        "serial_number": serial,
                        "discovery_method": "roku_ecp_rest"
                    }
        except Exception:
            pass
        return None

    def _probe_printer_attributes(self, ip: str, open_ports: list) -> Dict[str, Any]:
        """Queries HTTP management banners to extract printer vendor and model."""
        meta = {
            "type": "printer",
            "vendor": "Network Printer",
            "model": "Network Multifunction Printer",
            "discovery_method": "raw_jetdirect_ipp"
        }
        if 80 in open_ports or 443 in open_ports:
            port = 80 if 80 in open_ports else 443
            proto = "http" if port == 80 else "https"
            try:
                url = f"{proto}://{ip}:{port}/"
                with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                    page = resp.read().decode("utf-8", errors="ignore").lower()
                    if "brother" in page:
                        meta["vendor"] = "Brother Industries"
                    elif "hp" in page or "hewlett-packard" in page:
                        meta["vendor"] = "HP Inc."
                    elif "canon" in page:
                        meta["vendor"] = "Canon"
                    elif "xerox" in page:
                        meta["vendor"] = "Xerox"
            except Exception:
                pass
        return meta

    @staticmethod
    def is_snmp_active(ip: str, timeout: float = 0.4) -> bool:
        """Non-blocking UDP pre-flight check to verify if SNMP is responding before crawling."""
        # SNMPv2c GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0) with community 'public'
        snmp_probe = bytes([
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
            0x63, 0xa0, 0x19, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00,
            0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01,
            0x02, 0x01, 0x05, 0x00
        ])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(snmp_probe, (ip, 161))
                data, _ = s.recvfrom(1024)
                return len(data) > 0
            except Exception:
                return False

