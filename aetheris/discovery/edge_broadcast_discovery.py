"""
Project AETHERIS - Edge Node Broadcast & Multicast Discovery Engine
Dispatches targeted protocol broadcasts (SIP PnP, WS-Discovery/ONVIF, SSDP, mDNS, 
Ubiquiti/MikroTik discovery, BACnet, EtherNet/IP) based on identified device profiles 
to uncover dormant or silent edge nodes on the network segment.
"""

import socket
import struct
import time
import select
import ipaddress
from typing import Dict, List, Any, Optional


class EdgeBroadcastEngine:
    """Dispatches targeted broadcast and multicast probes based on identified device contexts."""

    def __init__(self, timeout: float = 1.2):
        self.timeout = timeout

    def broadcast_targeted_cluster_probe(
        self, 
        device_type: str = "generic", 
        vendor: str = "generic", 
        target_subnet: str = "10.10.4.0/24"
    ) -> List[Dict[str, Any]]:
        """
        Executes targeted protocol broadcasts tailored to the identified device's category.
        Returns newly discovered responding edge nodes.
        """
        discovered = []
        dev_type = (device_type or "").lower()
        dev_vendor = (vendor or "").lower()

        # Calculate broadcast address for the target subnet
        bcast_ip = "255.255.255.255"
        try:
            net = ipaddress.ip_network(target_subnet, strict=False)
            bcast_ip = str(net.broadcast_address)
        except Exception:
            pass

        # 1. VoIP Telephony Cluster (SIP PnP & Multicast OPTIONS)
        if any(k in dev_type for k in ["voip", "phone", "pbx", "sip"]) or any(k in dev_vendor for k in ["grandstream", "yealink", "polycom", "cisco", "snom", "mitel"]):
            discovered.extend(self._probe_voip_cluster(bcast_ip))

        # 2. IP Video / CCTV / NVR Cluster (WS-Discovery ONVIF & Security Multicast)
        if any(k in dev_type for k in ["camera", "cctv", "nvr", "dvr"]) or any(k in dev_vendor for k in ["axis", "hikvision", "dahua", "flir", "tiandy", "hanwha"]):
            discovered.extend(self._probe_camera_cluster(bcast_ip))

        # 3. Network Infrastructure Cluster (Ubiquiti, MikroTik, Switch Discovery)
        if any(k in dev_type for k in ["switch", "router", "gateway", "ap", "wlan_ap"]) or any(k in dev_vendor for k in ["ubiquiti", "mikrotik", "cisco", "moxa", "aruba", "tp-link"]):
            discovered.extend(self._probe_network_infra_cluster(bcast_ip))

        # 4. Industrial OT Cluster (BACnet, EtherNet/IP)
        if any(k in dev_type for k in ["plc", "hmi", "ot", "scada", "modbus", "access_control"]) or any(k in dev_vendor for k in ["rockwell", "allen-bradley", "siemens", "schneider", "mercury"]):
            discovered.extend(self._probe_industrial_cluster(bcast_ip))

        # 5. Always run universal SSDP & mDNS edge query
        discovered.extend(self._probe_universal_edge(bcast_ip))

        # Deduplicate results by IP
        unique_nodes = {}
        for item in discovered:
            ip = item.get("ip")
            if ip and ip not in unique_nodes:
                unique_nodes[ip] = item

        return list(unique_nodes.values())

    # =========================================================================
    # VoIP SIP PnP & Multicast Probe
    # =========================================================================
    def _probe_voip_cluster(self, bcast_ip: str) -> List[Dict[str, Any]]:
        results = []
        # SIP PnP Multicast Groups: 224.0.1.75:5060, 239.255.255.245:5060, Broadcast:5060
        targets = [
            ("224.0.1.75", 5060),
            ("239.255.255.245", 5060),
            (bcast_ip, 5060),
        ]

        sip_options_packet = (
            b"OPTIONS sip:ping@224.0.1.75 SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK-aetheris-probe\r\n"
            b"Max-Forwards: 70\r\n"
            b"From: <sip:aetheris@discovery.local>;tag=gp001\r\n"
            b"To: <sip:ping@224.0.1.75>\r\n"
            b"Call-ID: aetheris-pnp-discovery\r\n"
            b"CSeq: 1 OPTIONS\r\n"
            b"User-Agent: Aetheris-VoIP-Discovery/2.0\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(0.25)

            for target in targets:
                try:
                    sock.sendto(sip_options_packet, target)
                except Exception:
                    pass

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                ready = select.select([sock], [], [], 0.2)
                if ready[0]:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    text = data.decode("latin1", errors="ignore")
                    user_agent = "SIP Telephony Endpoint"
                    vendor = "Grandstream / Yealink VoIP"
                    model = "VoIP Phone"

                    for line in text.splitlines():
                        if line.lower().startswith("user-agent:") or line.lower().startswith("server:"):
                            ua = line.split(":", 1)[1].strip()
                            user_agent = ua
                            if "grandstream" in ua.lower():
                                vendor = "Grandstream Networks"
                                model = ua
                            elif "yealink" in ua.lower():
                                vendor = "Yealink"
                                model = ua
                            elif "cisco" in ua.lower():
                                vendor = "Cisco"
                                model = ua

                    results.append({
                        "ip": ip,
                        "type": "voip_phone",
                        "vendor": vendor,
                        "model": model,
                        "protocol": "SIP PnP / Multicast",
                        "banner": user_agent,
                        "open_ports": [5060]
                    })
            sock.close()
        except Exception:
            pass

        return results

    # =========================================================================
    # IP Camera & Video Surveillance WS-Discovery (ONVIF) Probe
    # =========================================================================
    def _probe_camera_cluster(self, bcast_ip: str) -> List[Dict[str, Any]]:
        results = []
        ws_discovery_group = ("239.255.255.250", 3702)
        
        ws_probe_msg = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            '<soap:Header>'
            '<wsa:MessageID>uuid:aetheris-wsd-probe-01</wsa:MessageID>'
            '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
            '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
            '</soap:Header>'
            '<soap:Body>'
            '<wsd:Probe>'
            '<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>'
            '</wsd:Probe>'
            '</soap:Body>'
            '</soap:Envelope>'
        ).encode("utf-8")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(0.25)

            sock.sendto(ws_probe_msg, ws_discovery_group)
            try:
                sock.sendto(ws_probe_msg, (bcast_ip, 3702))
            except Exception:
                pass

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                ready = select.select([sock], [], [], 0.2)
                if ready[0]:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    text = data.decode("utf-8", errors="ignore")
                    vendor = "ONVIF IP Camera"
                    model = "Network Video Device"
                    lowered = text.lower()

                    if "axis" in lowered:
                        vendor = "Axis Communications"
                        model = "AXIS Network Camera"
                    elif "hikvision" in lowered:
                        vendor = "Hikvision"
                        model = "Hikvision IP Camera"
                    elif "dahua" in lowered:
                        vendor = "Dahua Technology"
                        model = "Dahua IP Camera"
                    elif "tiandy" in lowered:
                        vendor = "Tiandy"
                        model = "Tiandy Security Device"

                    results.append({
                        "ip": ip,
                        "type": "camera",
                        "vendor": vendor,
                        "model": model,
                        "protocol": "ONVIF / WS-Discovery",
                        "banner": "WS-Discovery ONVIF ProbeMatch",
                        "open_ports": [80, 554]
                    })
            sock.close()
        except Exception:
            pass

        return results

    # =========================================================================
    # Network Infrastructure (Ubiquiti / MikroTik / NAS) Probe
    # =========================================================================
    def _probe_network_infra_cluster(self, bcast_ip: str) -> List[Dict[str, Any]]:
        results = []
        from discovery.dpi_parser import UbntDiscoveryDecoder, MikrotikMndpDecoder, SynologyQnapDecoder
        
        # 1. Ubiquiti Discovery Probe (UDP 10001)
        ubnt_probe = b"\x01\x00\x00\x00"
        try:
            s_ubnt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_ubnt.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s_ubnt.settimeout(0.25)
            s_ubnt.sendto(ubnt_probe, (bcast_ip, 10001))
            s_ubnt.sendto(ubnt_probe, ("255.255.255.255", 10001))

            start_time = time.time()
            while time.time() - start_time < 0.6:
                ready = select.select([s_ubnt], [], [], 0.15)
                if ready[0]:
                    data, addr = s_ubnt.recvfrom(2048)
                    decoded = UbntDiscoveryDecoder.decode(data)
                    vendor = decoded.get("vendor", "Ubiquiti Inc.") if decoded else "Ubiquiti Networks"
                    model = decoded.get("model", "UniFi / EdgeSwitch Infrastructure") if decoded else "UniFi Device"
                    dev_type = decoded.get("type", "wlan_ap") if decoded else "switch"
                    results.append({
                        "ip": addr[0],
                        "type": dev_type,
                        "vendor": vendor,
                        "model": model,
                        "hostname": decoded.get("hostname", "") if decoded else "",
                        "protocol": "UBNT-Discovery-10001",
                        "open_ports": [22, 443]
                    })
            s_ubnt.close()
        except Exception:
            pass

        # 2. MikroTik MNDP Probe (UDP 5678)
        try:
            s_mndp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_mndp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s_mndp.settimeout(0.25)
            s_mndp.sendto(b"\x00\x00\x00\x00", (bcast_ip, 5678))

            start_time = time.time()
            while time.time() - start_time < 0.5:
                ready = select.select([s_mndp], [], [], 0.12)
                if ready[0]:
                    data, addr = s_mndp.recvfrom(2048)
                    decoded = MikrotikMndpDecoder.decode(data)
                    results.append({
                        "ip": addr[0],
                        "type": decoded.get("type", "router") if decoded else "router",
                        "vendor": "MikroTik",
                        "model": decoded.get("model", "MikroTik RouterOS") if decoded else "MikroTik Router",
                        "hostname": decoded.get("hostname", "") if decoded else "",
                        "protocol": "MNDP-Discovery-5678",
                        "open_ports": [80, 8291, 22]
                    })
            s_mndp.close()
        except Exception:
            pass

        # 3. Synology / QNAP Assistant Broadcast Probes (UDP 9999 / 8097)
        for nas_port in (9999, 8097):
            try:
                s_nas = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s_nas.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s_nas.settimeout(0.2)
                s_nas.sendto(b"DISCOVER", (bcast_ip, nas_port))

                start_time = time.time()
                while time.time() - start_time < 0.4:
                    ready = select.select([s_nas], [], [], 0.1)
                    if ready[0]:
                        data, addr = s_nas.recvfrom(2048)
                        decoded = SynologyQnapDecoder.decode(data, nas_port)
                        results.append({
                            "ip": addr[0],
                            "type": "nas",
                            "vendor": decoded.get("vendor", "Synology / QNAP") if decoded else "NAS Storage",
                            "model": decoded.get("model", "DiskStation / Turbo NAS") if decoded else "NAS Storage Server",
                            "protocol": f"NAS-Broadcast-{nas_port}",
                            "open_ports": [5000, 5001]
                        })
                s_nas.close()
            except Exception:
                pass

        return results

    # =========================================================================
    # Industrial OT (BACnet Who-Is / EtherNet/IP CIP) Probe
    # =========================================================================
    def _probe_industrial_cluster(self, bcast_ip: str) -> List[Dict[str, Any]]:
        results = []
        from discovery.dpi_parser import BacnetIpDecoder, EthernetIpCipDecoder

        # 1. BACnet Who-Is Broadcast (UDP 47808)
        bacnet_whois = b"\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"
        try:
            s_bac = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_bac.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s_bac.settimeout(0.25)
            s_bac.sendto(bacnet_whois, (bcast_ip, 47808))

            start_time = time.time()
            while time.time() - start_time < 0.6:
                ready = select.select([s_bac], [], [], 0.15)
                if ready[0]:
                    data, addr = s_bac.recvfrom(2048)
                    decoded = BacnetIpDecoder.decode(data)
                    results.append({
                        "ip": addr[0],
                        "type": "iot",
                        "vendor": decoded.get("vendor", "BACnet Building Automation") if decoded else "BACnet Device",
                        "model": decoded.get("model", "BACnet Field Controller") if decoded else "BACnet Controller",
                        "protocol": "BACnet/IP (Port 47808)",
                        "open_ports": [47808]
                    })
            s_bac.close()
        except Exception:
            pass

        # 2. EtherNet/IP CIP List Identity Broadcast (UDP 44818)
        # Encapsulation Header: Command 0x0063 (List Identity), Length 0, Session 0, Status 0, SenderContext 8B, Options 0
        cip_list_identity = b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00GraphPth\x00\x00\x00\x00"
        try:
            s_cip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_cip.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s_cip.settimeout(0.25)
            s_cip.sendto(cip_list_identity, (bcast_ip, 44818))

            start_time = time.time()
            while time.time() - start_time < 0.6:
                ready = select.select([s_cip], [], [], 0.15)
                if ready[0]:
                    data, addr = s_cip.recvfrom(2048)
                    decoded = EthernetIpCipDecoder.decode(data)
                    vendor = decoded.get("vendor", "Rockwell Automation / Allen-Bradley") if decoded else "Allen-Bradley"
                    model = decoded.get("model", "ControlLogix / CompactLogix PLC") if decoded else "Industrial PLC"
                    results.append({
                        "ip": addr[0],
                        "type": "plc",
                        "vendor": vendor,
                        "model": model,
                        "protocol": "EtherNet/IP CIP (Port 44818)",
                        "open_ports": [44818, 2222]
                    })
            s_cip.close()
        except Exception:
            pass

        return results

    # =========================================================================
    # Universal SSDP M-SEARCH Edge Query
    # =========================================================================
    def _probe_universal_edge(self, bcast_ip: str) -> List[Dict[str, Any]]:
        results = []
        ssdp_request = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(0.25)

            sock.sendto(ssdp_request, ("239.255.255.250", 1900))
            start_time = time.time()
            while time.time() - start_time < 0.8:
                ready = select.select([sock], [], [], 0.15)
                if ready[0]:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    text = data.decode("latin1", errors="ignore")
                    server_hdr = ""
                    for line in text.splitlines():
                        if line.lower().startswith("server:"):
                            server_hdr = line.split(":", 1)[1].strip()
                    results.append({
                        "ip": ip,
                        "type": "iot",
                        "vendor": "UPnP / SSDP Node",
                        "model": server_hdr or "UPnP Smart Device",
                        "protocol": "SSDP M-SEARCH",
                        "open_ports": [1900]
                    })
            sock.close()
        except Exception:
            pass

        return results

