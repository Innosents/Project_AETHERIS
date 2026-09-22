"""
Project AETHERIS - Passive Security Posture & Hardening Advisory Engine
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


from aetheris.core.ports.security_auditor_port import (
    AuditFindingRecord,
    DeviceAuditReport,
    SecurityAuditorPort,
    VendorPostureRecord,
)


class SecurityAuditor(SecurityAuditorPort):
    """Evaluates network telemetry and generates passive security posture advisories."""

    @classmethod
    def audit_device(cls, device_data: Dict[str, Any]) -> DeviceAuditReport:
        """
        Inspects device DNA (vendor, model, open ports, banners, and physical/spatial telemetry)
        and returns a comprehensive security advisory object.
        """
        open_ports = [int(p) for p in device_data.get("open_ports", []) if str(p).isdigit()]
        scan_status = device_data.get("port_scan_status", "unknown")
        vendor = (device_data.get("vendor") or "").lower()
        model = (device_data.get("model") or "").lower()
        dev_type = (device_data.get("type") or "").lower()
        banners = device_data.get("banners", {})
        snmp_oids = device_data.get("snmp_oids", [])

        findings: List[AuditFindingRecord] = []
        hardening_steps: List[str] = []
        risk_score = 0.0

        def add_finding(
            finding_type: str,
            severity: str,
            title: str,
            description: str,
            remediation: Optional[str] = None,
        ) -> AuditFindingRecord:
            record = AuditFindingRecord(
                finding_type=finding_type,
                severity=severity,
                title=title,
                description=description,
                remediation=remediation,
            )
            findings.append(record)
            return record

        # 1. Cleartext Management Protocols (High / Critical Risk)
        if 23 in open_ports:
            risk_score += 35.0
            add_finding(
                "CLEARTEXT_TELNET_EXPOSED",
                "HIGH",
                "Cleartext Telnet Service Exposed (Port 23)",
                "Telnet transmits authentication credentials and commands in unencrypted plaintext across the local network.",
                "Disable Telnet service (Port 23) in favor of encrypted SSH (Port 22).",
            )
            hardening_steps.append("Disable Telnet service (Port 23) in favor of encrypted SSH (Port 22).")

        if 21 in open_ports:
            risk_score += 15.0
            add_finding(
                "CLEARTEXT_FTP_EXPOSED",
                "MEDIUM",
                "Cleartext FTP Service Exposed (Port 21)",
                "FTP transmits login credentials and transferred files without cryptographic protection.",
                "Disable FTP in favor of SFTP / SCP or HTTPS provisioning.",
            )
            hardening_steps.append("Disable FTP in favor of SFTP / SCP or HTTPS provisioning.")

        # 2. Web Management Interfaces
        if 80 in open_ports:
            risk_score += 20.0
            add_finding(
                "UNENCRYPTED_HTTP_MANAGEMENT",
                "MEDIUM",
                "Unencrypted HTTP Web Management (Port 80)",
                "Administrative sessions over HTTP are vulnerable to local network sniffing and session hijacking.",
                "Redirect or disable HTTP (Port 80) and enforce TLS/HTTPS (Port 443) only.",
            )
            hardening_steps.append("Redirect or disable HTTP (Port 80) and enforce TLS/HTTPS (Port 443) only.")

        if 443 in open_ports:
            risk_score += 10.0
            add_finding(
                "HTTPS_MANAGEMENT_ACTIVE",
                "LOW",
                "HTTPS Web Management Active (Port 443)",
                "Web management interface is reachable. Ensure strong credentials and access restrictions are in place.",
                "Enforce strong credential policies and restrict management access to trusted subnets.",
            )

        # 3. VoIP Specific Risks
        if 5060 in open_ports or dev_type in ("voip_phone", "voip_pbx", "ip_phone", "pbx"):
            if 5060 in open_ports:
                risk_score += 15.0
                add_finding(
                    "UNENCRYPTED_SIP_SIGNALING",
                    "MEDIUM",
                    "Unencrypted SIP Signaling Active (Port 5060)",
                    "Standard SIP on UDP/TCP 5060 sends caller identity and call signaling without TLS encryption.",
                    "Migrate SIP signaling to TLS (SIPS Port 5061) and enable SRTP voice encryption.",
                )
                hardening_steps.append("Migrate SIP signaling to TLS (SIPS Port 5061) and enable SRTP voice encryption.")

        # 4. Industrial Protocol Exposure
        if 502 in open_ports or dev_type in ("plc", "hmi"):
            risk_score += 30.0
            add_finding(
                "UNAUTHENTICATED_MODBUS_EXPOSED",
                "HIGH",
                "Unauthenticated Modbus/TCP Exposed (Port 502)",
                "Industrial OT fieldbus protocol lacks built-in cryptographic authentication and should not be reachable from general IT hosts.",
                "Isolate Modbus PLC behind an industrial firewall (IEC 62443 / Purdue Level 1/2).",
            )
            hardening_steps.append("Isolate Modbus PLC behind an industrial firewall (IEC 62443 / Purdue Level 1/2).")

        # 5. Vendor Specific Profile Matching & Hardening Steps
        matched_profile_key = None
        matched_profile = None
        for key in FACTORY_POSTURE_PROFILES:
            if key in vendor or key in model:
                matched_profile_key = key
                break

        if not matched_profile_key:
            if dev_type in ("router", "gateway"):
                matched_profile_key = "generic_router"

        if matched_profile_key and matched_profile_key in FACTORY_POSTURE_PROFILES:
            matched_profile = FACTORY_POSTURE_PROFILES[matched_profile_key]
            if 80 in open_ports or 443 in open_ports or 22 in open_ports or 23 in open_ports:
                risk_score += 15.0
                add_finding(
                    "FACTORY_DEFAULT_CONFIGURATION_RISK",
                    "MEDIUM",
                    f"Factory Default Configuration Risk ({matched_profile['vendor_name']})",
                    matched_profile["risk_summary"] + " " + matched_profile["common_defaults"],
                    "Rotate default credentials, restrict administrative access, and enforce strong identity controls.",
                )
            for step in matched_profile["hardening_steps"]:
                if step not in hardening_steps:
                    hardening_steps.append(step)

        # 6. SNMP Community Checks
        for oid in snmp_oids:
            val_str = str(oid.get("value", "")).lower()
            if "public" in val_str or "private" in val_str:
                risk_score += 25.0
                add_finding(
                    "DEFAULT_SNMP_COMMUNITY_DETECTED",
                    "HIGH",
                    "Default SNMP Community String Detected",
                    "Device responds to standard default community strings ('public' or 'private').",
                    "Change SNMP community strings to unique complex strings or upgrade to SNMPv3.",
                )
                hardening_steps.append("Change SNMP community strings to unique complex strings or upgrade to SNMPv3.")
                break

        # 7. Physical Layer & Low-Voltage Conductor Constraints
        peripherals = device_data.get("peripherals", [])
        if isinstance(peripherals, dict):
            peripherals = list(peripherals.values())
        spatial_metrics = device_data.get("spatial_metrics", {})
        if not isinstance(spatial_metrics, dict):
            spatial_metrics = {}

        # 7a. Inline Physical Tap Detection (High Resistance Anomaly or Divergence > 35%)
        has_tap_anomaly = bool(
            device_data.get("high_resistance_anomaly")
            or device_data.get("baud_divergence_ratio", 0.0) > 0.35
            or device_data.get("divergence_ratio", 0.0) > 0.35
            or spatial_metrics.get("high_resistance_anomaly")
            or spatial_metrics.get("baud_divergence_ratio", 0.0) > 0.35
            or any(
                p.get("high_resistance_anomaly")
                or p.get("baud_divergence_ratio", 0.0) > 0.35
                or p.get("divergence_ratio", 0.0) > 0.35
                for p in peripherals
                if isinstance(p, dict)
            )
        )
        if has_tap_anomaly:
            risk_score += 40.0
            add_finding(
                "PHYSICAL_LAYER_INLINE_TAP_SUSPECTED",
                "HIGH",
                "PHYSICAL_LAYER_INLINE_TAP_SUSPECTED",
                "Conductor DC drop distance diverges from physical serial baud-rate expected latency by more than 35%, indicating spliced hardware, parasitic inline tap (e.g. ESPKey, BLE sniffer), or severe terminal oxidation.",
                "Physically inspect peripheral sub-bus wiring conduits between controller and reader for unauthorized inline taps, spliced bugging devices, or high-resistance terminal connections.",
            )
            hardening_steps.append("Physically inspect peripheral sub-bus wiring conduits between controller and reader for unauthorized inline taps, spliced bugging devices, or high-resistance terminal connections.")

        # 7b. Access Bus Over-Extension (> 152.4m / > 500ft)
        def _check_over_extension(item: Dict[str, Any]) -> bool:
            dist_m = (
                item.get("total_physical_path_distance_m")
                or item.get("total_cable_path_m")
                or item.get("d_total_m")
                or item.get("sub_peripheral_distance_m")
                or item.get("distance_m")
            )
            if dist_m is not None and float(dist_m) > 152.4:
                return True
            dist_ft = (
                item.get("total_physical_path_distance_feet")
                or item.get("d_total_feet")
                or item.get("sub_peripheral_distance_feet")
                or item.get("distance_feet")
            )
            if dist_ft is not None and float(dist_ft) > 500.0:
                return True
            return False

        has_bus_overextension = bool(
            _check_over_extension(device_data)
            or _check_over_extension(spatial_metrics)
            or any(_check_over_extension(p) for p in peripherals if isinstance(p, dict))
        )
        if has_bus_overextension:
            risk_score += 25.0
            add_finding(
                "ACCESS_PERIPHERAL_BUS_OVER_EXTENSION",
                "MEDIUM",
                "ACCESS_PERIPHERAL_BUS_OVER_EXTENSION",
                "Access peripheral physical conductor length exceeds standard 152.4m (500ft) threshold for low-voltage serial sub-buses, causing transmission degradation and potential out-of-perimeter line exposure.",
                "Install optical isolation repeaters or transition downstream bus to encrypted OSDP v2.2 with secure channel profile for long-run peripherals exceeding 152.4m.",
            )
            hardening_steps.append("Install optical isolation repeaters or transition downstream bus to encrypted OSDP v2.2 with secure channel profile for long-run peripherals exceeding 152.4m.")

        # 7c. Solenoid Inductive Tamper or Absent Flyback (>= 3 transient rejections in 60s)
        def _check_transient_rejections(item: Dict[str, Any]) -> bool:
            count = (
                item.get("transient_rejections_60s")
                or item.get("transient_rejection_count")
                or item.get("transient_events_count")
            )
            if count is not None and int(count) >= 3:
                return True
            timestamps = item.get("transient_rejection_timestamps") or item.get("transient_events")
            if isinstance(timestamps, list) and len(timestamps) >= 3:
                return True
            return False

        has_inductive_tamper = bool(
            _check_transient_rejections(device_data)
            or _check_transient_rejections(spatial_metrics)
            or any(_check_transient_rejections(p) for p in peripherals if isinstance(p, dict))
        )
        if has_inductive_tamper:
            risk_score += 30.0
            add_finding(
                "SOLENOID_INDUCTIVE_TAMPER_OR_FLYBACK_ABSENT",
                "HIGH",
                "SOLENOID_INDUCTIVE_TAMPER_OR_FLYBACK_ABSENT",
                "Observed 3 or more transient voltage drop rejections within 60 seconds on inductive access peripheral, indicating physical strike relay manipulation, actuator buzzing, or missing reverse-biased flyback clamping diode.",
                "Install 1N4004/1N5408 reverse-biased clamping flyback diode across inductive strike terminals and inspect locking hardware for mechanical tamper or relay buzzing.",
            )
            hardening_steps.append("Install 1N4004/1N5408 reverse-biased clamping flyback diode across inductive strike terminals and inspect locking hardware for mechanical tamper or relay buzzing.")

        # 7d. Access Controller Spatial Impersonation (TCP flight time > 2000µs)
        tcp_flight_us = (
            device_data.get("tcp_flight_time_us")
            or device_data.get("tcp_flight_us")
            or device_data.get("flight_us")
            or device_data.get("net_flight_us")
            or spatial_metrics.get("tcp_flight_time_us")
            or spatial_metrics.get("net_flight_us")
            or spatial_metrics.get("flight_us")
        )
        is_controller_node = bool(
            device_data.get("is_controller", True)
            or "controller" in dev_type
            or "mercury" in vendor
            or "mercury" in model
            or "lp1502" in model
            or "ep1502" in model
            or "controller_id" in device_data
        )
        if tcp_flight_us is not None and float(tcp_flight_us) > 2000.0 and is_controller_node:
            risk_score += 50.0
            add_finding(
                "ACCESS_CONTROLLER_SPATIAL_IMPERSONATION",
                "CRITICAL",
                "ACCESS_CONTROLLER_SPATIAL_IMPERSONATION",
                f"Access controller TCP flight time ({float(tcp_flight_us):.1f} microseconds) exceeds the 2000 microsecond physical local LAN limit, indicating an off-path rogue proxy, WAN overlay redirection, or spatial identity impersonation.",
                "Enforce 802.1X switchport security and strict ARP inspection; verify physical presence of Mercury access controller on local management VLAN.",
            )
            hardening_steps.append("Enforce 802.1X switchport security and strict ARP inspection; verify physical presence of Mercury access controller on local management VLAN.")

        # Determine Assessment Status
        has_physical_telemetry = bool(
            findings
            or peripherals
            or spatial_metrics
            or "high_resistance_anomaly" in device_data
            or "tcp_flight_time_us" in device_data
            or "tcp_flight_us" in device_data
            or "total_physical_path_distance_m" in device_data
            or "total_physical_path_distance_feet" in device_data
            or "transient_rejections_60s" in device_data
            or "transient_rejection_count" in device_data
        )
        is_assessed = bool(
            open_ports or snmp_oids or banners or scan_status == "completed" or has_physical_telemetry
        )

        # Calculate Overall Risk Level
        risk_score = min(100.0, risk_score)
        if any(f.severity == "CRITICAL" for f in findings):
            risk_level = "CRITICAL"
        elif risk_score >= 60.0:
            risk_level = "HIGH"
        elif risk_score >= 30.0:
            risk_level = "MEDIUM"
        elif risk_score > 0.0:
            risk_level = "LOW"
        elif not is_assessed or (scan_status in ("not_run", "unavailable", "failed", "unknown") and not snmp_oids and not open_ports and not has_physical_telemetry):
            risk_level = "NOT_ASSESSED"
        else:
            risk_level = "NONE"

        vendor_posture = None
        if matched_profile:
            vendor_posture = VendorPostureRecord(profile_key=matched_profile_key, **matched_profile)

        return DeviceAuditReport(
            risk_level=risk_level,
            risk_score=risk_score,
            findings_count=len(findings),
            findings=findings,
            hardening_checklist=hardening_steps,
            vendor_posture=vendor_posture,
            assessed=is_assessed,
        )


from aetheris.infrastructure.edge_auditor import EdgeSecurityAuditor
__all__ = ["SecurityAuditor", "EdgeSecurityAuditor", "FACTORY_POSTURE_PROFILES"]

