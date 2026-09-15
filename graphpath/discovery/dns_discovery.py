"""
Project AETHERIS - DNS Discovery & Domain Enumeration Engine
Performs reverse DNS PTR sweeps, Active Directory SRV record lookups,
and BGP latency overlay detection to unmask virtualized SD-WAN and Cloud VPN adjacencies.
"""

import socket
from typing import Dict, List, Any, Optional, Set

try:
    from graphpath.discovery.geolocation_engine import PublicGeoIpResolver
except ImportError:
    try:
        from discovery.geolocation_engine import PublicGeoIpResolver
    except ImportError:
        PublicGeoIpResolver = None


class DnsDiscoveryEngine:
    """
    DNS Discovery & Domain Enumeration Engine.
    Performs reverse DNS PTR sweeps, Active Directory SRV record lookups,
    and BGP latency overlay detection to unmask virtualized SD-WAN and Cloud VPN adjacencies.
    """

    ON_PREM_PATTERNS: Set[str] = {
        ".corp.internal", ".local", ".lan", ".internal", ".corp",
        ".priv", ".intranet", ".site", "core-sw", "dist-sw", "access-sw",
        "plc-", "hmi-", "bms-", "nvr-", "pdu-"
    }

    def __init__(self, dns_server: Optional[str] = None, timeout: float = 0.8):
        self.dns_server = dns_server
        self.timeout = timeout

    def sweep_ptr_records(self, ips: List[str]) -> Dict[str, str]:
        """Performs reverse DNS PTR lookups for a list of IP addresses."""
        results = {}
        socket.setdefaulttimeout(self.timeout)
        for ip in ips:
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                if hostname:
                    results[ip] = hostname
            except Exception:
                pass
        return results

    def discover_srv_records(self, domain: str) -> List[Dict[str, Any]]:
        """Discovers SRV records for domain controllers and VoIP services."""
        # Standard placeholder for SRV queries; can be expanded with dnspython if installed
        return []

    def evaluate_overlay_path(
        self,
        ip: str,
        ptr_hostname: str = "",
        empirical_rtt_ms: float = 0.0,
        sensor_geo: Optional[Dict[str, Any]] = None,
        target_geo: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Integrates Haversine geodesic distance and authoritative BGP ASN resolution
        to evaluate virtualized network adjacencies and unmask SD-WAN/VPN overlays.
        """
        if not PublicGeoIpResolver:
            return {
                "ip": ip,
                "ptr_hostname": ptr_hostname,
                "flags": [],
                "is_overlay": False
            }

        s_geo = sensor_geo or PublicGeoIpResolver.resolve()
        t_geo = target_geo or PublicGeoIpResolver.resolve_ip(ip)

        s_lat = float(s_geo.get("latitude", 0.0))
        s_lon = float(s_geo.get("longitude", 0.0))
        t_lat = float(t_geo.get("latitude", 0.0))
        t_lon = float(t_geo.get("longitude", 0.0))

        # 1. Compute geodesic distance using Haversine formula
        d_geodesic_km = PublicGeoIpResolver.calculate_haversine_distance_km(
            s_lat, s_lon, t_lat, t_lon
        )

        # 2. Compute minimum RTT scaled by 1.5x BGP asymmetric path inflation scalar
        rtt_min_ms = PublicGeoIpResolver.calculate_rtt_min_ms(
            distance_km=d_geodesic_km,
            inflation_scalar=PublicGeoIpResolver.BGP_PATH_INFLATION_SCALAR
        )

        flags: List[str] = []
        rtt_delta_ms = 0.0

        # 3. Evaluate FLAG_SD_WAN_TUNNEL_OVERLAY: empirical flight time exceeds inflated RTT_min by > 15ms
        if empirical_rtt_ms > 0:
            rtt_delta_ms = round(empirical_rtt_ms - rtt_min_ms, 3)
            if rtt_delta_ms > 15.0:
                flags.append("FLAG_SD_WAN_TUNNEL_OVERLAY")

        # 4. Evaluate FLAG_CLOUD_VPN_ENCAPSULATED: hyperscaler ASN with on-prem PTR name
        target_asn_str = str(t_geo.get("asn", "")).upper()
        is_hyperscaler = any(asn in target_asn_str for asn in PublicGeoIpResolver.HYPERSCALER_ASNS)

        hostname_lower = (ptr_hostname or "").lower()
        is_on_prem_name = any(pat in hostname_lower for pat in self.ON_PREM_PATTERNS)

        if is_hyperscaler and is_on_prem_name:
            flags.append("FLAG_CLOUD_VPN_ENCAPSULATED")

        cloud_provider = ""
        if "16509" in target_asn_str:
            cloud_provider = "AWS"
        elif "8075" in target_asn_str:
            cloud_provider = "Azure"
        elif "15169" in target_asn_str:
            cloud_provider = "GCP"
        elif "13335" in target_asn_str:
            cloud_provider = "Cloudflare"

        return {
            "ip": ip,
            "ptr_hostname": ptr_hostname,
            "sensor_geo": {
                "latitude": s_lat,
                "longitude": s_lon,
                "city": s_geo.get("city", ""),
                "country": s_geo.get("country", "")
            },
            "target_geo": {
                "latitude": t_lat,
                "longitude": t_lon,
                "city": t_geo.get("city", ""),
                "country": t_geo.get("country", ""),
                "asn": t_geo.get("asn", ""),
                "isp": t_geo.get("isp", "")
            },
            "geodesic_distance_km": d_geodesic_km,
            "rtt_min_ms": rtt_min_ms,
            "empirical_rtt_ms": float(empirical_rtt_ms),
            "rtt_delta_ms": rtt_delta_ms,
            "flags": flags,
            "is_overlay": len(flags) > 0,
            "cloud_provider": cloud_provider
        }