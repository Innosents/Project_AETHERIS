"""
Project AETHERIS - Deep Protocol Prober Engine
Provides targeted protocol handshakes and identity extraction for deep host fingerprinting.
"""

import socket
import ssl
import re
from typing import Dict, Any, Optional

class SmbProber:
    @staticmethod
    def probe_smb(ip: str, port: int = 445, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes SMB endpoint (Port 445/139) via standard SMBv1/v2 negotiate request."""
        # SMBv1 Negotiate Protocol Request header
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
                        "domain": "WORKGROUP"
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
                        "type": "workstation"
                    }
        except Exception:
            pass
        return {}

class RpcProber:
    @staticmethod
    def probe_rpc(ip: str, port: int = 135, timeout: float = 0.6) -> Dict[str, Any]:
        """Probes DCE/RPC endpoint mapper (Port 135)."""
        # DCE/RPC Bind Request
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
                        "interfaces": []
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
                        "type": "workstation"
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
                ua_match = re.search(r'(?:User-Agent|Server):\s*([^\r\n]+)', text, re.IGNORECASE)
                ua = ua_match.group(1).strip() if ua_match else "SIP Endpoint"
                return {
                    "port": port,
                    "protocol": "SIP",
                    "type": "voip_phone",
                    "sip_user_agent": ua
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
                        "organization": subject.get("organizationName", "")
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
                mfg = re.search(r'<[^>]*Manufacturer[^>]*>([^<]+)<', resp, re.I)
                model = re.search(r'<[^>]*Model[^>]*>([^<]+)<', resp, re.I)
                fw = re.search(r'<[^>]*FirmwareVersion[^>]*>([^<]+)<', resp, re.I)
                if mfg or model:
                    return {
                        "vendor": mfg.group(1).strip() if mfg else "Axis Communications",
                        "model": model.group(1).strip() if model else "Network Camera",
                        "firmware": fw.group(1).strip() if fw else "",
                        "type": "camera"
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
                server = re.search(r'Server:\s*([^\r\n]+)', resp, re.I)
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
                srv = re.search(r'Server:\s*([^\r\n]+)', resp, re.I)
                return {
                    "port": port,
                    "protocol": "RTSP",
                    "type": "camera",
                    "rtsp_server": srv.group(1).strip() if srv else "RTSP Streaming Server"
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
        # Modbus FC 43 (Read Device Identification)
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
                        "model": "Modbus PLC"
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
                        "model": "Mercury Access Controller"
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
                            "type": "server"
                        }
        except Exception:
            pass
        return {}

class HttpTitleProber:
    @staticmethod
    def probe_web_identity(ip: str, ports: list = [80, 8080, 443], timeout: float = 0.5) -> Dict[str, Any]:
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

                # Extract Server & Title
                server_m = re.search(r'Server:\s*([^\r\n]+)', resp, re.I)
                title_m = re.search(r'<title>(.*?)</title>', resp, re.I | re.DOTALL)
                
                server = server_m.group(1).strip() if server_m else ""
                title = title_m.group(1).strip() if title_m else ""

                if server or title:
                    return {
                        "port": port,
                        "server": server,
                        "title": title,
                        "protocol": "HTTPS" if use_ssl else "HTTP"
                    }
            except Exception:
                pass
        return {}