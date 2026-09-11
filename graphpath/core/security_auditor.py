"""
GraphPath Passive Security Posture & Hardening Advisory Engine
Analyzes discovered device DNA, OUI vendors, service banners, and exposed ports
to identify unhardened management interfaces, cleartext protocols, and factory-default risks
without performing intrusive attacks or automated login attempts.
"""

from typing import Dict, List, Any, Optional

# Static repository of known factory configuration profiles & hardening guidelines
FACTORY_POSTURE_PROFILES: Dict[str, Dict[str, Any]] = {
    "grandstream": {
        "vendor_name": "Grandstream Networks",
        "category": "VoIP / IP Telephony",
        "common_defaults": "Factory default credentials historically 'admin' / 'admin' or random printed barcode password on newer firmware.",
        "risk_summary": "Exposed Grandstream web administration or SIP signaling interfaces require configuration verification.",
        "hardening_steps": [
            "Verify factory default admin password has been rotated to a strong passphrase.",
            "Enforce HTTPS (Port 443) only and disable cleartext HTTP (Port 80) web administration.",
            "Isolate phone onto a dedicated Voice VLAN (802.1Q tagged) with restricted ACL access.",
            "Enforce SIPS (TLS Port 5061) and SRTP for encrypted voice signaling and audio media streams.",
            "Restrict configuration auto-provisioning to authenticated HTTPS / mutual TLS."
        ]
    },
    "yealink": {
        "vendor_name": "Yealink Network Technology",
        "category": "VoIP / IP Telephony",
        "common_defaults": "Factory default credentials historically 'admin' / 'admin'.",
        "risk_summary": "Yealink SIP phone management interface detected. Ensure access control and credentials are hardened.",
        "hardening_steps": [
            "Change default 'admin' user password immediately in Web GUI (Settings -> Password).",
            "Disable unencrypted HTTP web server; enable HTTPS-only web access with trusted TLS certificate.",
            "Segment device traffic onto dedicated Voice VLAN with switchport 802.1p CoS priority.",
            "Disable unneeded remote management services (such as unauthenticated PC-port access).",
            "Ensure remote provisioning files (y0000000000xx.cfg) are transmitted via HTTPS with AES encryption."
        ]
    },
    "polycom": {
        "vendor_name": "Poly (Polycom)",
        "category": "VoIP / Conference Telephony",
        "common_defaults": "Factory default admin password '456' / user password '123'.",
        "risk_summary": "Polycom telephony endpoint management interface identified.",
        "hardening_steps": [
            "Change factory default admin password ('456') and user password ('123').",
            "Restrict Web Configuration Utility access to internal management subnet.",
            "Enable TLS 1.2+ for SIP signaling and provisioning server communication."
        ]
    },
    "cisco": {
        "vendor_name": "Cisco Systems",
        "category": "Network Infrastructure",
        "common_defaults": "Factory default 'cisco' / 'cisco' on unconfigured switches/routers.",
        "risk_summary": "Cisco network infrastructure element identified.",
        "hardening_steps": [
            "Ensure 'enable secret' and SSH v2 keys (min 2048-bit RSA / ECDSA) are configured.",
            "Disable Telnet (Port 23) and cleartext HTTP (Port 80) server in Cisco IOS.",
            "Replace default SNMP community strings ('public'/'private') with SNMPv3 authenticated/encrypted users.",
            "Implement Control Plane Policing (CoPP) and management ACLs on VTY lines."
        ]
    },
    "axis": {
        "vendor_name": "Axis Communications",
        "category": "CCTV / Physical Security",
        "common_defaults": "Older firmware used 'root' / 'pass'; newer firmware enforces password initialization.",
        "risk_summary": "Network security camera management interface exposed.",
        "hardening_steps": [
            "Verify strong root password initialization and disable guest/anonymous ONVIF viewing.",
            "Place camera onto an isolated CCTV/Physical Security VLAN with no direct internet outbound egress.",
            "Enable HTTPS and 802.1X network port authentication.",
            "Disable unused network protocols (Bonjour/mDNS, UPnP, FTP) in camera settings."
        ]
    },
    "hikvision": {
        "vendor_name": "Hikvision Digital Technology",
        "category": "CCTV / NVR",
        "common_defaults": "Historical default 'admin' / '12345'; modern firmware requires activation password.",
        "risk_summary": "Hikvision video surveillance node identified.",
        "hardening_steps": [
            "Ensure device activation password meets complexity guidelines.",
            "Block direct Internet port forwarding (UPnP / NAT-PMP) on ports 80, 8000, 554.",
            "Isolate NVR and IP cameras within a non-routable video surveillance VLAN.",
            "Update firmware to latest vendor release to patch legacy vulnerabilities."
        ]
    },
    "fortinet": {
        "vendor_name": "Fortinet",
        "category": "Gateway Firewall / Security Appliance",
        "common_defaults": "Default user 'admin' with blank password on initial setup.",
        "risk_summary": "Security appliance management endpoint detected.",
        "hardening_steps": [
            "Ensure admin account has a complex passphrase and Multi-Factor Authentication (MFA/2FA) enabled.",
            "Disable HTTP/HTTPS administrative access on external/WAN interfaces.",
            "Enforce Trusted Hosts restrictions for administrative logins in FortiOS.",
            "Keep FortiOS firmware updated against known CVE advisories."
        ]
    },
    "generic_router": {
        "vendor_name": "Generic Network Router / Gateway",
        "category": "Routing & Gateway",
        "common_defaults": "Common factory defaults 'admin' / 'admin' or 'admin' / 'password'.",
        "risk_summary": "Network gateway management service detected on LAN.",
        "hardening_steps": [
            "Verify unique administrative password is in place.",
            "Disable WAN-side remote management and WPS (Wi-Fi Protected Setup).",
            "Disable UPnP IGD if not required by network applications."
        ]
    }
}


class SecurityAuditor:
    """Evaluates network telemetry and generates passive security posture advisories."""

    @classmethod
    def audit_device(cls, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspects device DNA (vendor, model, open ports, banners) and returns
        a comprehensive Security Advisory object.
        """
        open_ports = [int(p) for p in device_data.get("open_ports", []) if str(p).isdigit()]
        scan_status = device_data.get("port_scan_status", "unknown")
        vendor = (device_data.get("vendor") or "").lower()
        model = (device_data.get("model") or "").lower()
        dev_type = (device_data.get("type") or "").lower()
        banners = device_data.get("banners", {})
        snmp_oids = device_data.get("snmp_oids", [])

        findings: List[Dict[str, Any]] = []
        hardening_steps: List[str] = []
        risk_score = 0

        # 1. Cleartext Management Protocols (High / Critical Risk)
        if 23 in open_ports:
            risk_score += 35
            findings.append({
                "severity": "HIGH",
                "title": "Cleartext Telnet Service Exposed (Port 23)",
                "description": "Telnet transmits authentication credentials and commands in unencrypted plaintext across the local network."
            })
            hardening_steps.append("Disable Telnet service (Port 23) in favor of encrypted SSH (Port 22).")

        if 21 in open_ports:
            risk_score += 15
            findings.append({
                "severity": "MEDIUM",
                "title": "Cleartext FTP Service Exposed (Port 21)",
                "description": "FTP transmits login credentials and transferred files without cryptographic protection."
            })
            hardening_steps.append("Disable FTP in favor of SFTP / SCP or HTTPS provisioning.")

        # 2. Web Management Interfaces
        if 80 in open_ports:
            risk_score += 20
            findings.append({
                "severity": "MEDIUM",
                "title": "Unencrypted HTTP Web Management (Port 80)",
                "description": "Administrative sessions over HTTP are vulnerable to local network sniffing and session hijacking."
            })
            hardening_steps.append("Redirect or disable HTTP (Port 80) and enforce TLS/HTTPS (Port 443) only.")

        if 443 in open_ports:
            risk_score += 10
            findings.append({
                "severity": "LOW",
                "title": "HTTPS Web Management Active (Port 443)",
                "description": "Web management interface is reachable. Ensure strong credentials and access restrictions are in place."
            })

        # 3. VoIP Specific Risks
        if 5060 in open_ports or dev_type in ("voip_phone", "voip_pbx", "ip_phone", "pbx"):
            if 5060 in open_ports:
                risk_score += 15
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Unencrypted SIP Signaling Active (Port 5060)",
                    "description": "Standard SIP on UDP/TCP 5060 sends caller identity and call signaling without TLS encryption."
                })
                hardening_steps.append("Migrate SIP signaling to TLS (SIPS Port 5061) and enable SRTP voice encryption.")

        # 4. Industrial Protocol Exposure
        if 502 in open_ports or dev_type in ("plc", "hmi"):
            risk_score += 30
            findings.append({
                "severity": "HIGH",
                "title": "Unauthenticated Modbus/TCP Exposed (Port 502)",
                "description": "Industrial OT fieldbus protocol lacks built-in cryptographic authentication and should not be reachable from general IT hosts."
            })
            hardening_steps.append("Isolate Modbus PLC behind an industrial firewall (IEC 62443 / Purdue Level 1/2).")

        # 5. Vendor Specific Profile Matching & Hardening Steps
        matched_profile_key = None
        for key in FACTORY_POSTURE_PROFILES:
            if key in vendor or key in model:
                matched_profile_key = key
                break

        if not matched_profile_key:
            if dev_type in ("router", "gateway"):
                matched_profile_key = "generic_router"

        if matched_profile_key and matched_profile_key in FACTORY_POSTURE_PROFILES:
            profile = FACTORY_POSTURE_PROFILES[matched_profile_key]
            if 80 in open_ports or 443 in open_ports or 22 in open_ports or 23 in open_ports:
                risk_score += 15
                findings.append({
                    "severity": "MEDIUM",
                    "title": f"Factory Default Configuration Risk ({profile['vendor_name']})",
                    "description": profile["risk_summary"] + " " + profile["common_defaults"]
                })
            for step in profile["hardening_steps"]:
                if step not in hardening_steps:
                    hardening_steps.append(step)

        # 6. SNMP Community Checks
        for oid in snmp_oids:
            val_str = str(oid.get("value", "")).lower()
            if "public" in val_str or "private" in val_str:
                risk_score += 25
                findings.append({
                    "severity": "HIGH",
                    "title": "Default SNMP Community String Detected",
                    "description": "Device responds to standard default community strings ('public' or 'private')."
                })
                hardening_steps.append("Change SNMP community strings to unique complex strings or upgrade to SNMPv3.")
                break

        # Determine Assessment Status
        is_assessed = bool(open_ports or snmp_oids or banners or scan_status == "completed")

        # Calculate Overall Risk Level
        risk_score = min(100, risk_score)
        if risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        elif risk_score > 0:
            risk_level = "LOW"
        elif not is_assessed or (scan_status in ("not_run", "unavailable", "failed", "unknown") and not snmp_oids and not open_ports):
            risk_level = "NOT_ASSESSED"
        else:
            risk_level = "NONE"

        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "findings_count": len(findings),
            "findings": findings,
            "hardening_checklist": hardening_steps,
            "vendor_posture": matched_profile_key or "generic",
            "assessed": is_assessed
        }

