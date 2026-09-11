"""
GraphPath Unified Geolocation, LLDP-MED Dissection and Spatial Path Routing Engine
Correlates macro WAN GPS coordinates, LLDP-MED/CDP Civic Addresses (Building/Floor/Room/Jack),
and physical network switch-port graph paths into unified spatial telemetry.
"""

import os
import sys
import json
import time
import socket
import struct
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

try:
    from core.path_utils import get_data_dir
except ImportError:
    def get_data_dir() -> Path:
        return Path(__file__).resolve().parent.parent


class PublicGeoIpResolver:
    """Resolves and caches public WAN IP GPS coordinates, city, region, ISP, and ASN."""

    _cached_result: Optional[Dict[str, Any]] = None
    _last_lookup_time: float = 0.0
    _CACHE_TTL_SECONDS: float = 86400.0  # 24 hours

    @classmethod
    def get_cache_file_path(cls) -> Path:
        return Path(get_data_dir()) / "geoip_cache.json"

    @classmethod
    def resolve(cls, force_refresh: bool = False) -> Dict[str, Any]:
        """Queries public GeoIP metadata with disk and in-memory caching."""
        now = time.time()
        
        # 0. Check Offline Mode / Air-Gap Policy
        if os.environ.get("GRAPHPATH_OFFLINE") == "1" or os.environ.get("GRAPHPATH_DISABLE_GEOIP") == "1":
            return cls._get_fallback_location()

        # 1. In-Memory Cache Check
        if not force_refresh and cls._cached_result and (now - cls._last_lookup_time < cls._CACHE_TTL_SECONDS):
            return cls._cached_result

        # 2. Disk Cache Check
        cache_file = cls.get_cache_file_path()
        if not force_refresh and cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    if now - cached.get("timestamp", 0) < cls._CACHE_TTL_SECONDS:
                        cls._cached_result = cached.get("data", {})
                        cls._last_lookup_time = cached.get("timestamp", now)
                        return cls._cached_result
            except Exception:
                pass

        # 3. Live WAN Lookup (Encrypted HTTPS JSON endpoint with strict timeout)
        geo_data = cls._fetch_live_geoip()
        if geo_data:
            cls._cached_result = geo_data
            cls._last_lookup_time = now
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump({"timestamp": now, "data": geo_data}, f, indent=2)
            except Exception:
                pass
            return geo_data

        # 4. Fallback Default Location
        return cls._get_fallback_location()

    @classmethod
    def _fetch_live_geoip(cls) -> Optional[Dict[str, Any]]:
        # Enforce HTTPS-only to prevent cleartext disclosure of client network metadata
        endpoints = [
            "https://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            "https://ipinfo.io/json"
        ]

        for url in endpoints:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "GraphPath-Discovery-Engine/2.0 (Spatial Network Topology)"}
                )
                with urllib.request.urlopen(req, timeout=1.8) as response:
                    if response.status == 200:
                        payload = json.loads(response.read().decode("utf-8"))
                        if "lat" in payload and "lon" in payload:
                            return {
                                "public_ip": payload.get("query") or payload.get("ip", "Dynamic WAN"),
                                "country": payload.get("country", "United States"),
                                "country_code": payload.get("countryCode", "US"),
                                "region": payload.get("regionName") or payload.get("region", ""),
                                "city": payload.get("city", "Local Site"),
                                "postal_code": payload.get("zip") or payload.get("postal", ""),
                                "latitude": float(payload.get("lat", 0.0)),
                                "longitude": float(payload.get("lon", 0.0)),
                                "timezone": payload.get("timezone", "UTC"),
                                "isp": payload.get("isp") or payload.get("org", "Enterprise ISP Uplink"),
                                "asn": payload.get("as") or payload.get("org", "AS-Corporate"),
                                "source": "ip_geolocation_api"
                            }
                        elif "loc" in payload:
                            lat_str, lon_str = payload["loc"].split(",", 1)
                            return {
                                "public_ip": payload.get("ip", "Dynamic WAN"),
                                "country": payload.get("country", "US"),
                                "country_code": payload.get("country", "US"),
                                "region": payload.get("region", ""),
                                "city": payload.get("city", "Local Site"),
                                "postal_code": payload.get("postal", ""),
                                "latitude": float(lat_str.strip()),
                                "longitude": float(lon_str.strip()),
                                "timezone": payload.get("timezone", "UTC"),
                                "isp": payload.get("org", "Enterprise ISP Uplink"),
                                "asn": payload.get("org", "AS-Corporate"),
                                "source": "ipinfo_api"
                            }
            except Exception:
                continue

        return None

    @classmethod
    def _get_fallback_location(cls) -> Dict[str, Any]:
        return {
            "public_ip": "10.10.7.1",
            "country": "United States",
            "country_code": "US",
            "region": "Corporate Site",
            "city": "HQ Office",
            "postal_code": "00000",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "timezone": "America/Los_Angeles",
            "isp": "Fortinet Secure Gateway Uplink",
            "asn": "AS-Internal-Gateway",
            "source": "environment_profile_fallback"
        }


class LldpMedLocationDecoder:
    """
    Decodes ANSI/TIA-1057 (LLDP-MED) Location Identification TLVs:
    - Format 1: Coordinate-based LCI (Latitude, Longitude, Altitude, Datum WGS84)
    - Format 2: Civic Address LCI (Country, State, City, Street, Building, Floor, Room, Jack)
    - Format 3: ELIN (Emergency Location Identification Number)
    """

    CA_TYPE_MAP = {
        0: "language",
        1: "state_province",
        2: "county",
        3: "city",
        4: "district",
        5: "block",
        6: "street",
        19: "building",
        20: "unit",
        21: "floor",
        22: "room",
        23: "wall_jack",
        24: "postal_code",
        25: "po_box",
        26: "additional_info",
        27: "desk_number"
    }

    @classmethod
    def decode_location_tlv(cls, payload: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "format": "unknown",
            "raw_hex": payload.hex()
        }

        if len(payload) < 1:
            return result

        loc_format = payload[0]

        if loc_format == 1 and len(payload) >= 16:
            result["format"] = "coordinate_lci"
            try:
                lat_raw = struct.unpack(">i", payload[1:5])[0]
                lon_raw = struct.unpack(">i", payload[6:10])[0]
                lat = lat_raw / (1 << 22)
                lon = lon_raw / (1 << 22)
                datum_code = payload[15] if len(payload) > 15 else 1
                datum = {1: "WGS84", 2: "NAD83", 3: "WGS84_MLLW"}.get(datum_code, "WGS84")

                result["coordinates"] = {
                    "latitude": round(lat, 6),
                    "longitude": round(lon, 6),
                    "datum": datum
                }
            except Exception as e:
                result["parse_error"] = str(e)

        elif loc_format == 2 and len(payload) >= 4:
            result["format"] = "civic_address"
            try:
                ca_len = payload[1]
                ca_what = payload[2]
                country = payload[3:5].decode("ascii", errors="ignore").upper()
                
                civic_fields = {"country": country, "target_type": "client" if ca_what == 0 else "network_element"}
                
                pos = 5
                end_pos = min(len(payload), 3 + ca_len)
                while pos + 2 <= end_pos:
                    ca_type = payload[pos]
                    field_len = payload[pos + 1]
                    pos += 2
                    
                    if pos + field_len > len(payload):
                        break
                        
                    field_val = payload[pos:pos + field_len].decode("utf-8", errors="ignore").strip("\x00\r\n\t ")
                    pos += field_len
                    
                    field_name = cls.CA_TYPE_MAP.get(ca_type, f"ca_type_{ca_type}")
                    civic_fields[field_name] = field_val

                result["civic_address"] = civic_fields
            except Exception as e:
                result["parse_error"] = str(e)

        elif loc_format == 3 and len(payload) > 1:
            result["format"] = "elin"
            result["elin"] = payload[1:].decode("utf-8", errors="ignore").strip("\x00\r\n\t ")

        return result


class SpatialPathReasoner:
    """
    Computes human-readable spatial connection paths and matches physical locations:
    [Device] -> [Wall Jack / BSSID] -> [Switch Port] -> [Patch Panel / Rack] -> [Gateway] -> [WAN Coordinates]
    """

    @staticmethod
    def compute_spatial_path(
        node_id: str,
        node_meta: Dict[str, Any],
        all_nodes: Dict[str, Dict[str, Any]],
        edges: List[Tuple[str, str, Dict[str, Any]]],
        macro_geo: Dict[str, Any]
    ) -> Dict[str, Any]:
        dev_name = node_meta.get("label") or node_meta.get("hostname") or node_meta.get("model") or node_id
        dev_ip = node_meta.get("ip", node_id)
        
        civic: Dict[str, Any] = {}
        if "civic_location" in node_meta and isinstance(node_meta["civic_location"], dict):
            civic.update(node_meta["civic_location"])

        path_steps = []
        path_steps.append(f"Device: {dev_name} ({dev_ip})")

        port_assigned = node_meta.get("port") or node_meta.get("port_id")
        if port_assigned:
            civic["wall_jack"] = f"Jack-{port_assigned}"
            path_steps.append(f"Wall Jack: Jack-{port_assigned}")
            path_steps.append(f"Switch Port: {port_assigned}")

        connected_switches = [
            u if v == node_id else v
            for u, v, _ in edges
            if (u == node_id or v == node_id)
        ]
        for sw_id in connected_switches:
            sw_meta = all_nodes.get(sw_id, {})
            sw_type = sw_meta.get("type", "").lower()
            if sw_type in ("switch", "router", "gateway", "firewall", "managed_switch", "core_switch") or "switch" in sw_id.lower():
                sw_name = sw_meta.get("label") or sw_meta.get("model") or sw_meta.get("hostname") or sw_id
                path_steps.append(f"Distribution Switch: {sw_name}")
                break

        gateway = macro_geo.get("gateway")
        if gateway:
            path_steps.append(f"Core Gateway: {gateway}")
        
        city = macro_geo.get("city")
        region = macro_geo.get("region", "")
        country = macro_geo.get("country_code", "")
        isp = macro_geo.get("isp")
        
        geo_parts = [p for p in [city, region, country] if p]
        geo_str = ", ".join(geo_parts)
        
        if isp or geo_str:
            wan_label = f"Public WAN Gateway: {isp or 'Enterprise Uplink'}"
            if geo_str:
                wan_label += f" ({geo_str})"
            path_steps.append(wan_label)

        lat = macro_geo.get("latitude")
        lon = macro_geo.get("longitude")
        coords = None
        if lat is not None and lon is not None:
            coords = {
                "latitude": float(lat),
                "longitude": float(lon),
                "datum": "WGS84",
                "accuracy_level": "building_level" if "room" in civic else "city_level"
            }

        return {
            "macro_location": macro_geo,
            "civic_location": civic,
            "coordinates": coords,
            "spatial_path_trail": path_steps,
            "accuracy_estimate_meters": 5.0 if "wall_jack" in civic or "desk_or_station" in civic else (25.0 if coords else None)
        }


class GeolocationProtocolsLibrary:
    """
    Queryable Knowledge Base of all 11 network geolocation, physical tracking,
    and indoor positioning protocols utilized across enterprise, IoT, and OT networks.
    """

    PROTOCOLS = [
        {
            "id": "lldp_med",
            "name": "LLDP-MED Location Identification",
            "standard": "ANSI/TIA-1057 / IEEE 802.1AB",
            "layer": "Layer 2 (EtherType 0x88CC)",
            "mechanism": "Organizationally Specific TLV (OUI 00:12:BB, Subtype 3)",
            "resolution": "Room, Desk, Wall Jack, Coordinate LCI, ELIN (Emergency 911)",
            "devices": ["Enterprise Switches", "VoIP IP Phones", "Wi-Fi Access Points", "Smart Lighting"],
            "dissection_method": "Native LLDP sniffer decodes Coordinate LCI, Civic Address, and ELIN TLVs."
        },
        {
            "id": "cisco_cdp_location",
            "name": "Cisco CDP Location & Physical Port TLVs",
            "standard": "Cisco Proprietary",
            "layer": "Layer 2 (SNAP 0x2000 / Multicast 01:00:0C:CC:CC:CC)",
            "mechanism": "CDP Type 0x0017 (Location TLV) & Type 0x0003 (Port ID)",
            "resolution": "Switch Chassis, Slot, Port, Physical Wall Jack Jack-ID",
            "devices": ["Cisco Catalyst Switches", "Cisco Nexus", "Cisco IP Phones CP-78xx/88xx"],
            "dissection_method": "Dissects CDP TLV 0x0003 for Port Name and TLV 0x0017 for Civic Room."
        },
        {
            "id": "dhcp_option_82",
            "name": "DHCP Option 82 (Relay Agent Information)",
            "standard": "IETF RFC 3046",
            "layer": "Layer 7 (UDP 67 / 68)",
            "mechanism": "Sub-option 1 (Agent Circuit ID) & Sub-option 2 (Agent Remote ID)",
            "resolution": "VLAN ID, Switch Module, Switch Port, DSLAM/OLT Chassis MAC",
            "devices": ["Edge Switches", "Core DHCP Relay Routers", "ISP DSLAM / GPON OLT"],
            "dissection_method": "Intercepts DHCP Discover/Request frames injected by Layer 2 relay switches."
        },
        {
            "id": "snmp_syslocation",
            "name": "SNMP MIB-II sysLocation",
            "standard": "IETF RFC 1213 / RFC 3418",
            "layer": "Layer 7 (UDP 161 / SNMPv2c / SNMPv3)",
            "mechanism": "OID 1.3.6.1.2.1.1.6.0 (sysLocation.0)",
            "resolution": "Configured Civic String (e.g. 'Bldg 4, Floor 2, Rack 12, MDF')",
            "devices": ["Managed Switches", "Firewalls", "Routers", "Network Printers", "UPSs"],
            "dissection_method": "Queries sysLocation OID during SNMP crawling passes."
        },
        {
            "id": "wifi_rtt_ftm",
            "name": "Wi-Fi RTT / Fine Timing Measurement (802.11mc / 802.11az)",
            "standard": "IEEE 802.11mc / 802.11az",
            "layer": "Layer 2 (802.11 Action Frames)",
            "mechanism": "Nanosecond round-trip time time-of-flight (ToF) measurement across APs",
            "resolution": "Sub-meter Indoor Coordinates (Accuracy: 0.5m – 1.0m)",
            "devices": ["Enterprise Wi-Fi 6/6E APs (Aruba, Cisco, Fortinet)", "Smartphones", "Laptops"],
            "dissection_method": "Correlates multi-AP FTM ranging matrix."
        },
        {
            "id": "wifi_rssi_trilateration",
            "name": "Wi-Fi BSSID Association & RSSI Trilateration",
            "standard": "IEEE 802.11k / 802.11v",
            "layer": "Layer 2 (802.11 Beacon & Probe Responses)",
            "mechanism": "Received Signal Strength Indicator (RSSI) path-loss modeling",
            "resolution": "Indoor Room / Zone Positioning (Accuracy: 2m – 5m)",
            "devices": ["Wireless Clients", "Smartphones", "Tablets", "IoT Sensors"],
            "dissection_method": "Calculates log-distance path loss across detected BSSIDs."
        },
        {
            "id": "ble_indoor_beacons",
            "name": "Bluetooth Low Energy (BLE) / iBeacon / Eddystone",
            "standard": "Bluetooth SIG / Apple iBeacon / Google Eddystone",
            "layer": "Layer 1 / Layer 2 (2.4 GHz ISM Advertising Channels 37, 38, 39)",
            "mechanism": "UUID + Major + Minor + Measured Power at 1 meter",
            "resolution": "Zone / Proximity (Immediate <0.5m, Near 1-3m, Far >3m)",
            "devices": ["Asset Tracking Tags", "Badge Readers", "Medical Equipment", "Forklifts"],
            "dissection_method": "Maps BLE Major/Minor IDs to architectural floorplan CAD coordinates."
        },
        {
            "id": "bgp_wan_geoip",
            "name": "Public WAN IP BGP ASN & GeoIP2 Mapping",
            "standard": "IETF RFC 4271 / MaxMind GeoIP2 / IPinfo",
            "layer": "Layer 3 (Public IPv4 / IPv6)",
            "mechanism": "Regional Internet Registry (RIR) BGP routing prefixes & GeoIP databases",
            "resolution": "City, Region, Country, ISP, Autonomous System, Macro GPS Coordinates",
            "devices": ["Border Gateways", "WAN Routers", "Cloud VPC Endpoints"],
            "dissection_method": "Automated BGP Autonomous System and GeoIP coordinate resolution."
        },
        {
            "id": "ad_sites_subnets",
            "name": "Active Directory Sites and Services Subnets",
            "standard": "Microsoft Windows Server Directory Services",
            "layer": "Layer 7 (LDAP / Kerberos / DNS)",
            "mechanism": "Subnet-to-Site Object Mapping (e.g. 10.10.7.0/24 -> 'Site-SanFrancisco-HQ')",
            "resolution": "Campus, Facility, Building Site",
            "devices": ["Domain Controllers", "Windows Workstations", "Enterprise Servers"],
            "dissection_method": "DNS SRV queries (_ldap._tcp.<Site>._sites.dc._msdcs.<Domain>)."
        },
        {
            "id": "mdns_dnssd_loc",
            "name": "mDNS / DNS-SD Service Location TXT Records",
            "standard": "IETF RFC 6762 / RFC 6763",
            "layer": "Layer 7 (UDP 5353 -> 224.0.0.251)",
            "mechanism": "DNS TXT record attributes: 'locdescription=', 'geo=', 'paperload='",
            "resolution": "Department, Room, Printer Bay",
            "devices": ["Apple AirPrint Printers", "Google Cast TVs", "Smart Displays"],
            "dissection_method": "Dissects mDNS PTR and TXT payload strings during active service sweeps."
        },
        {
            "id": "upnp_location_xml",
            "name": "UPnP / SSDP Device Description XML Location",
            "standard": "UPnP Forum / ISO/IEC 29341",
            "layer": "Layer 7 (HTTP / XML via UDP 1900 SSDP)",
            "mechanism": "LOCATION header URL pointing to XML element <room>, <friendlyName>, <UDN>",
            "resolution": "Home / Office Room Name (e.g. 'Conference Room 402 TV')",
            "devices": ["Smart TVs", "Set-Top Boxes", "AV Receivers", "Smart Speakers"],
            "dissection_method": "Fetches UPnP XML description file to parse room and friendly naming tags."
        }
    ]

    @classmethod
    def get_all_protocols(cls) -> List[Dict[str, Any]]:
        return cls.PROTOCOLS

    @classmethod
    def get_protocol_by_id(cls, proto_id: str) -> Optional[Dict[str, Any]]:
        for p in cls.PROTOCOLS:
            if p["id"] == proto_id:
                return p
        return None
