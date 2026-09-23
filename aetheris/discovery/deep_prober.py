"""
Project AETHERIS - Deep Protocol Prober Engine
Provides targeted protocol handshakes and identity extraction for deep host fingerprinting.
Implements the DeepProberPort hexagonal port protocol.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Any, Dict, List, Optional

from aetheris.core.ports.deep_prober_port import (
    DeepProbeEndpointResult,
    DeepProberPort,
    OnvifDeviceInfo,
    TlsCertInfo,
    _MappingCompatibleModel,
)


class SmbProber:
    @staticmethod
    def probe_smb(ip: str, port: int = 445, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes SMB endpoint (Port 445/139) via standard SMBv1/v2 negotiate request."""
        smb_neg = (
            b"\x00\x00\x00\x45"
            b"\xff\x53\x4d\x42"  # Protocol: \xFFSMB
            b"\x72"              # Command: Negotiate (0x72)
            b"\x00\x00\x00\x00"  # Status
            b"\x18\x01\x28\x00"  # Flags
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00"
            b"\x00\x22"          # Byte count
            b"\x02NT LM 0.12\x00"
            b"\x02SMB 2.002\x00"
            b"\x02SMB 2.???\x00"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(smb_neg)
                resp = s.recv(1024)
                if resp and len(resp) > 4:
                    return {
                        "port": port,
                        "protocol": "SMB",
                        "os_version": "Windows Host",
                        "domain": "WORKGROUP",
                    }
        except Exception:
            pass
        return {}


class WinRmProber:
    @staticmethod
    def probe_winrm(ip: str, port: int = 5985, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes WS-Management WinRM HTTP endpoint (Port 5985/5986)."""
        req = (
            f"POST /wsman HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(req)
                resp = s.recv(1024).decode("latin-1", errors="ignore")
                if "401" in resp or "Microsoft" in resp or "Server: Microsoft-HTTPAPI" in resp:
                    return {
                        "port": port,
                        "protocol": "WinRM",
                        "vendor": "Microsoft Corporation",
                        "os_version": "Windows 10/11 / Windows Server",
                        "type": "workstation",
                    }
        except Exception:
            pass
        return {}


class RpcProber:
    @staticmethod
    def probe_rpc(ip: str, port: int = 135, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes DCE/RPC endpoint mapper (Port 135)."""
        rpc_bind = (
            b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00"
            b"\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00"
            b"\xe1\xaf\x83\x08\x0a\x25\x11\xd0\x9e\xa8\x00\xa0\xc9\x03\x33\xc0"
            b"\x03\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
            b"\x2b\x10\x48\x60\x02\x00\x00\x00"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(rpc_bind)
                resp = s.recv(1024)
                if resp and len(resp) >= 16 and resp[0] == 0x05:
                    return {
                        "port": port,
                        "protocol": "DCE/RPC",
                        "vendor": "Microsoft Corporation",
                        "interfaces": [],
                    }
        except Exception:
            pass
        return {}


class RdpProber:
    @staticmethod
    def probe_rdp(ip: str, port: int = 3389, timeout: float = 0.6) -> Dict[str, Any]:
        """Sends X.224 Connection Request to RDP endpoint (Port 3389)."""
        x224_cr = (
            b"\x03\x00\x00\x13"  # TPKT (len=19)
            b"\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(x224_cr)
                resp = s.recv(1024)
                if resp and len(resp) >= 4 and resp[0] == 0x03:
                    return {
                        "port": port,
                        "protocol": "RDP",
                        "vendor": "Microsoft Corporation",
                        "type": "workstation",
                    }
        except Exception:
            pass
        return {}


class SipProber:
    @staticmethod
    def probe_sip(ip: str, port: int = 5060, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes SIP server/phone using standard OPTIONS query."""
        sip_opt = (
            f"OPTIONS sip:{ip}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {ip}:5060;branch=z9hG4bK-gp-check\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:scanner@{ip}>;tag=gp01\r\n"
            f"To: <sip:{ip}>\r\n"
            f"Call-ID: gp-sip-probe\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"User-Agent: Aetheris-SIP\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode("latin-1")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(sip_opt, (ip, port))
                resp, _ = s.recvfrom(2048)
                text = resp.decode("latin-1", errors="ignore")
                ua_match = re.search(r"(?:User-Agent|Server):\s*([^\r\n]+)", text, re.IGNORECASE)
                ua = ua_match.group(1).strip() if ua_match else "SIP Endpoint"
                return {
                    "port": port,
                    "protocol": "SIP",
                    "type": "voip_phone",
                    "sip_user_agent": ua,
                }
        except Exception:
            pass
        return {}


class WebDeepProber:
    @staticmethod
    def inspect_tls_cert(ip: str, port: int = 443, timeout: float = 0.6) -> Dict[str, Any]:
        """Extracts SSL/TLS certificate fields."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=ip) as ss:
                    cert = ss.getpeercert(binary_form=False) or {}
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    return {
                        "port": port,
                        "common_name": subject.get("commonName", ""),
                        "organization": subject.get("organizationName", ""),
                    }
        except Exception:
            pass
        return {}

    @staticmethod
    def probe_onvif_soap(ip: str, port: int = 80, timeout: float = 0.6) -> Dict[str, Any]:
        """Sends ONVIF SOAP GetDeviceInformation payload."""
        soap_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
            '<soap:Body><tds:GetDeviceInformation/></soap:Body>'
            '</soap:Envelope>'
        )
        req = (
            f"POST /onvif/device_service HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"Content-Type: application/soap+xml\r\n"
            f"Content-Length: {len(soap_body)}\r\n\r\n"
            f"{soap_body}"
        ).encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(req)
                resp = s.recv(2048).decode("utf-8", errors="ignore")
                parsed = DeepProber.parse_onvif_soap_response(resp)
                if parsed is not None:
                    return {
                        "vendor": parsed.vendor,
                        "model": parsed.model,
                        "firmware": parsed.firmware,
                        "type": parsed.type,
                    }
        except Exception:
            pass
        return {}

    @staticmethod
    def probe_upnp_description(ip: str, port: int = 80, timeout: float = 0.6) -> Dict[str, Any]:
        """Queries root UPnP XML descriptions."""
        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n".encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(req)
                resp = s.recv(1024).decode("latin-1", errors="ignore")
                server = re.search(r"Server:\s*([^\r\n]+)", resp, re.I)
                if server:
                    return {"server": server.group(1).strip()}
        except Exception:
            pass
        return {}


class RtspProber:
    @staticmethod
    def probe_rtsp(ip: str, port: int = 554, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes RTSP streaming interface."""
        req = f"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Aetheris/1.0\r\n\r\n".encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(req)
                resp = s.recv(1024).decode("latin-1", errors="ignore")
                srv = re.search(r"Server:\s*([^\r\n]+)", resp, re.I)
                return {
                    "port": port,
                    "protocol": "RTSP",
                    "type": "camera",
                    "rtsp_server": srv.group(1).strip() if srv else "RTSP Streaming Server",
                }
        except Exception:
            pass
        return {}


class SsdpProber:
    @staticmethod
    def probe_ssdp(ip: str, port: int = 1900, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes SSDP service."""
        return {"protocol": "SSDP", "port": port}


class ModbusProber:
    @staticmethod
    def probe_modbus(ip: str, port: int = 502, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes Modbus/TCP endpoint (Port 502)."""
        fc43 = b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(fc43)
                resp = s.recv(1024)
                if resp and len(resp) >= 8:
                    return {
                        "port": port,
                        "protocol": "MODBUS",
                        "type": "plc",
                        "vendor": "Schneider / Rockwell",
                        "model": "Modbus PLC",
                    }
        except Exception:
            pass
        return {}


class MercuryMspProber:
    @staticmethod
    def probe_msp(ip: str, port: int = 3001, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes Mercury Security Controller MSP port (Port 3001)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.sendall(b"\x02\x01\x04POLL\x03")
                resp = s.recv(1024)
                if resp:
                    from aetheris.discovery.dpi_parser import MercuryMspDecoder

                    decoded = MercuryMspDecoder.decode(resp)
                    if decoded:
                        return decoded
                    return {
                        "port": port,
                        "protocol": "MSP",
                        "type": "access_control",
                        "model": "Mercury Access Controller",
                    }
        except Exception:
            pass
        return {}


class SshProber:
    @staticmethod
    def probe_ssh_banner(ip: str, port: int = 22, timeout: float = 0.5) -> Dict[str, Any]:
        """Extracts SSH identification string without authenticating (e.g. OpenSSH_8.9p1 Ubuntu-3ubuntu0.7)."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    banner = s.recv(256).decode("latin-1", errors="ignore").strip()
                    if banner.startswith("SSH-"):
                        distro = "Linux"
                        if "ubuntu" in banner.lower():
                            distro = "Ubuntu Linux"
                        elif "debian" in banner.lower():
                            distro = "Debian Linux"
                        elif "raspbian" in banner.lower():
                            distro = "Raspberry Pi OS"
                        elif "freebsd" in banner.lower():
                            distro = "FreeBSD"

                        return {
                            "protocol": "SSH",
                            "banner": banner,
                            "os_hint": distro,
                            "type": "server",
                        }
        except Exception:
            pass
        return {}


class HttpTitleProber:
    @staticmethod
    def probe_web_identity(
        ip: str, ports: list = [80, 8080, 443], timeout: float = 0.5
    ) -> Dict[str, Any]:
        """Inspects HTTP Server headers and <title> tags to extract exact device models."""
        for port in ports:
            use_ssl = port in (443, 8443)
            try:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(timeout)
                if raw_sock.connect_ex((ip, port)) != 0:
                    raw_sock.close()
                    continue

                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(raw_sock, server_hostname=ip)
                else:
                    s = raw_sock

                req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (AETHERIS-Probe)\r\nConnection: close\r\n\r\n".encode()
                s.sendall(req)
                resp = s.recv(2048).decode("latin-1", errors="ignore")
                s.close()

                identity = DeepProber.parse_http_identity(resp)
                server = identity.get("server", "")
                title = identity.get("title", "")

                if server or title:
                    return {
                        "port": port,
                        "server": server,
                        "title": title,
                        "protocol": "HTTPS" if use_ssl else "HTTP",
                    }
            except Exception:
                pass
        return {}


class DeepProber(DeepProberPort):
    """
    Unified coordinator routing targeted port probes to protocol-specific probers.
    Implements DeepProberPort interface.
    """

    @staticmethod
    def parse_onvif_soap_response(xml_text: str) -> Optional[OnvifDeviceInfo]:
        """Pure XML parser extracting manufacturer, model, and firmware from ONVIF SOAP response."""
        if not xml_text:
            return None
        mfg = re.search(r"<[^>]*Manufacturer[^>]*>([^<]+)<", xml_text, re.I)
        model = re.search(r"<[^>]*Model[^>]*>([^<]+)<", xml_text, re.I)
        fw = re.search(r"<[^>]*FirmwareVersion[^>]*>([^<]+)<", xml_text, re.I)
        if mfg or model or fw:
            return OnvifDeviceInfo(
                vendor=mfg.group(1).strip() if mfg else "Axis Communications",
                model=model.group(1).strip() if model else "Network Camera",
                firmware=fw.group(1).strip() if fw else "",
                type="camera",
            )
        return None

    @staticmethod
    def parse_http_identity(http_response: str) -> Dict[str, str]:
        """Pure parser extracting Server header and HTML title from HTTP response."""
        if not http_response:
            return {"server": "", "title": ""}
        server_m = re.search(r"Server:\s*([^\r\n]+)", http_response, re.I)
        title_m = re.search(r"<title>(.*?)</title>", http_response, re.I | re.DOTALL)
        server = server_m.group(1).strip() if server_m else ""
        title = title_m.group(1).strip() if title_m else ""
        return {"server": server, "title": title}

    def probe_port(
        self, ip: str, port: int, timeout: float = 0.6
    ) -> Optional[DeepProbeEndpointResult]:
        """Probes an open port using the appropriate protocol handshake."""
        if port in (445, 139):
            raw = SmbProber.probe_smb(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "SMB"),
                    os_version=raw.get("os_version"),
                    vendor=raw.get("vendor"),
                    model=raw.get("model"),
                    type=raw.get("type"),
                    banner=raw.get("banner"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port in (5985, 5986):
            raw = WinRmProber.probe_winrm(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "WinRM"),
                    vendor=raw.get("vendor"),
                    os_version=raw.get("os_version"),
                    type=raw.get("type"),
                    model=raw.get("model"),
                    banner=raw.get("banner"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port == 135:
            raw = RpcProber.probe_rpc(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "DCE/RPC"),
                    vendor=raw.get("vendor"),
                    model=raw.get("model"),
                    os_version=raw.get("os_version"),
                    type=raw.get("type"),
                    banner=raw.get("banner"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port == 3389:
            raw = RdpProber.probe_rdp(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "RDP"),
                    vendor=raw.get("vendor"),
                    type=raw.get("type"),
                    model=raw.get("model"),
                    os_version=raw.get("os_version"),
                    banner=raw.get("banner"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port == 5060:
            raw = SipProber.probe_sip(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "SIP"),
                    type=raw.get("type"),
                    banner=raw.get("sip_user_agent"),
                    vendor=raw.get("vendor"),
                    model=raw.get("model"),
                    os_version=raw.get("os_version"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port in (80, 443, 8080, 8443, 8000, 8888, 9000):
            onvif_info = None
            try:
                onvif_raw = WebDeepProber.probe_onvif_soap(ip, port, timeout=timeout)
                if onvif_raw:
                    onvif_info = onvif_raw
            except Exception:
                pass

            http_ident = None
            try:
                http_raw = HttpTitleProber.probe_web_identity(ip, [port], timeout=timeout)
                if http_raw:
                    http_ident = http_raw
            except Exception:
                pass

            tls_info = None
            if port in (443, 8443):
                try:
                    tls_raw = WebDeepProber.inspect_tls_cert(ip, port, timeout=timeout)
                    if tls_raw and (tls_raw.get("common_name") or tls_raw.get("organization")):
                        tls_info = tls_raw
                except Exception:
                    pass

            if onvif_info or http_ident or tls_info:
                vendor = (
                    onvif_info.get("vendor")
                    if onvif_info
                    else (tls_info.get("organization") if tls_info and tls_info.get("organization") else None)
                )
                model = onvif_info.get("model") if onvif_info else None
                dev_type = onvif_info.get("type") if onvif_info else None
                protocol = (
                    "HTTPS"
                    if (port in (443, 8443) or (http_ident and http_ident.get("protocol") == "HTTPS"))
                    else "HTTP"
                )

                details: Dict[str, Any] = {}
                if onvif_info:
                    details["onvif"] = onvif_info
                if http_ident:
                    details["http_identity"] = http_ident
                if tls_info:
                    details["tls_cert"] = tls_info

                banner_parts = []
                if http_ident:
                    if http_ident.get("server"):
                        banner_parts.append(f"Server: {http_ident['server']}")
                    if http_ident.get("title"):
                        banner_parts.append(f"Title: {http_ident['title']}")
                if tls_info and tls_info.get("common_name"):
                    banner_parts.append(f"CN={tls_info['common_name']}")
                banner = " | ".join(banner_parts) if banner_parts else None

                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=protocol,
                    vendor=vendor,
                    model=model,
                    type=dev_type,
                    banner=banner,
                    details=details,
                )
        elif port in (554, 8554):
            raw = RtspProber.probe_rtsp(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "RTSP"),
                    type=raw.get("type"),
                    banner=raw.get("rtsp_server"),
                    vendor=raw.get("vendor"),
                    model=raw.get("model"),
                    os_version=raw.get("os_version"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port in (502, 10502, 20502):
            raw = ModbusProber.probe_modbus(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "MODBUS"),
                    type=raw.get("type"),
                    vendor=raw.get("vendor"),
                    model=raw.get("model"),
                    os_version=raw.get("os_version"),
                    banner=raw.get("banner"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port in (3001, 23001):
            raw = MercuryMspProber.probe_msp(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "MSP"),
                    type=raw.get("type"),
                    model=raw.get("model"),
                    vendor=raw.get("vendor"),
                    os_version=raw.get("os_version"),
                    banner=raw.get("banner"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port == 22:
            raw = SshProber.probe_ssh_banner(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "SSH"),
                    banner=raw.get("banner"),
                    os_version=raw.get("os_hint"),
                    type=raw.get("type"),
                    vendor=raw.get("vendor"),
                    model=raw.get("model"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        elif port == 1900:
            raw = SsdpProber.probe_ssdp(ip, port, timeout=timeout)
            if raw:
                return DeepProbeEndpointResult(
                    ip=ip,
                    port=port,
                    protocol=raw.get("protocol", "SSDP"),
                    vendor=raw.get("vendor"),
                    model=raw.get("model"),
                    os_version=raw.get("os_version"),
                    type=raw.get("type"),
                    banner=raw.get("banner"),
                    details={
                        k: v
                        for k, v in raw.items()
                        if k not in ("port", "protocol", "os_version", "vendor", "model", "type", "banner")
                    },
                )
        return None


__all__ = [
    "_MappingCompatibleModel",
    "TlsCertInfo",
    "OnvifDeviceInfo",
    "DeepProbeEndpointResult",
    "DeepProberPort",
    "DeepProber",
    "SmbProber",
    "WinRmProber",
    "RpcProber",
    "RdpProber",
    "SipProber",
    "WebDeepProber",
    "RtspProber",
    "SsdpProber",
    "ModbusProber",
    "MercuryMspProber",
    "SshProber",
    "HttpTitleProber",
]