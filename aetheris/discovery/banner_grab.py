"""
Project AETHERIS - Banner Grab Adapter
Extracts application-layer identity vectors across HTTP, TLS, industrial OT,
VoIP, camera, and streaming protocols through defensive transport probes.
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Optional

from aetheris.core.ports.banner_grab_port import (
    BannerGrabPort,
    BannerGrabResult,
    ParsedBannerTokens,
)


class BannerGrabber(BannerGrabPort):
    """Concrete adapter for application-layer service identity extraction."""

    @staticmethod
    def parse_http_descriptors(raw_text: str) -> ParsedBannerTokens:
        """Extract HTTP headers and HTML title text without network I/O."""
        title_match = re.search(
            r"<title>(.*?)</title>", raw_text, re.IGNORECASE | re.DOTALL
        )
        server_match = re.search(r"Server:\s*([^\r\n]+)", raw_text, re.IGNORECASE)
        cookie_match = re.search(
            r"Set-Cookie:\s*([^\r\n;]+)", raw_text, re.IGNORECASE
        )
        return ParsedBannerTokens(
            server=server_match.group(1).strip() if server_match else None,
            title=title_match.group(1).strip() if title_match else None,
            cookie=cookie_match.group(1).strip() if cookie_match else None,
            raw_snippet=raw_text[:256] if raw_text else None,
        )

    @staticmethod
    def _result(
        ip: str,
        port: int,
        banner: str,
        protocol_hint: Optional[str] = None,
        tokens: Optional[ParsedBannerTokens] = None,
    ) -> BannerGrabResult:
        return BannerGrabResult(
            ip=ip,
            port=port,
            banner=banner[:256],
            protocol_hint=protocol_hint,
            tokens=tokens,
        )

    @staticmethod
    def _protocol_hint(port: int) -> Optional[str]:
        if port in (80, 8080, 8088, 8000, 8888, 9000):
            return "http"
        if port in (554, 15554, 15555):
            return "rtsp"
        if port == 5060:
            return "sip"
        if port in (502, 10502, 20502):
            return "modbus"
        if port == 102:
            return "s7comm"
        if port == 44818:
            return "ethernet_ip"
        return None

    def grab(self, ip: str, port: int, timeout: float = 1.0) -> Optional[BannerGrabResult]:
        """Probe a service and return a validated result or ``None`` on failure."""
        tls_ports = (443, 8443, 28082, 28084, 18082, 18084)
        if port in tls_ports:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as secure_sock:
                        certificate_tokens = []
                        try:
                            certificate = secure_sock.getpeercert(binary_form=False)
                            if certificate:
                                for rdn in certificate.get("subject", ()):
                                    for key, value in rdn:
                                        if key in ("commonName", "organizationName"):
                                            certificate_tokens.append(f"{key}={value}")
                        except Exception:
                            pass

                        secure_sock.sendall(
                            f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
                            "User-Agent: Mozilla/5.0 (Aetheris)\r\n"
                            "Connection: close\r\n\r\n".encode()
                        )
                        secure_sock.settimeout(timeout)
                        response = secure_sock.recv(2048).decode(errors="ignore")
                        tokens = self.parse_http_descriptors(response)
                        tokens = tokens.model_copy(
                            update={
                                "tls_subject": ", ".join(certificate_tokens) or None,
                            }
                        )
                        parts = []
                        if certificate_tokens:
                            parts.append(f"TLS: {', '.join(certificate_tokens)}")
                        if tokens.server:
                            parts.append(f"Server: {tokens.server}")
                        if tokens.title:
                            parts.append(f"Title: {tokens.title}")
                        if tokens.cookie:
                            parts.append(f"Cookie: {tokens.cookie}")
                        banner = " | ".join(parts) if parts else f"HTTPS: {response[:120].strip()}"
                        if banner:
                            return self._result(ip, port, banner, "https", tokens)
            except (OSError, ssl.SSLError, socket.timeout):
                pass
            except Exception:
                pass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))

                if port in (502, 10502, 20502):
                    try:
                        from aetheris.discovery.modbus_discovery import query_modbus_device_id
                        modbus_info = query_modbus_device_id(ip, port, timeout)
                        if modbus_info.get("vendor") and modbus_info["vendor"] != "Industrial PLC / Generic Modbus":
                            banner = (
                                f"Modbus/TCP PLC | Vendor: {modbus_info['vendor']} | "
                                f"Model: {modbus_info['model']} | Rev: {modbus_info['firmware']}"
                            )
                            return self._result(ip, port, banner, "modbus")
                        if modbus_info.get("holding_registers"):
                            return self._result(
                                ip,
                                port,
                                f"Modbus/TCP Industrial Node (Active Holding Registers: {len(modbus_info['holding_registers'])})",
                                "modbus",
                            )
                    except Exception:
                        pass
                    return self._result(ip, port, "Modbus/TCP Industrial Controller", "modbus")

                if port == 102:
                    try:
                        cotp_cr = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
                        sock.sendall(cotp_cr)
                        sock.settimeout(timeout)
                        cc_response = sock.recv(1024)
                        if cc_response and len(cc_response) >= 4:
                            s7_szl = b"\x03\x00\x00\x21\x02\xf0\x80\x32\x01\x00\x00\x00\x01\x00\x0e\x00\x00\x04\x01\x12\x04\x11\x44\x01\x00\xff\x09\x00\x04\x00\x11\x00\x01"
                            sock.sendall(s7_szl)
                            s7_response = sock.recv(2048)
                            text = s7_response.decode(errors="ignore") if s7_response else ""
                            if "Siemens" in text or "S7-" in text:
                                return self._result(
                                    ip,
                                    port,
                                    f"Siemens S7Comm | {text[text.find('Siemens'):text.find('Siemens') + 160].strip()}",
                                    "s7comm",
                                )
                        return self._result(ip, port, "Siemens S7Comm / ISO-on-TCP (Port 102)", "s7comm")
                    except Exception:
                        return self._result(ip, port, "Siemens S7Comm / ISO-on-TCP (Port 102)", "s7comm")

                if port == 44818:
                    try:
                        cip_probe = b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                        sock.sendall(cip_probe)
                        sock.settimeout(timeout)
                        cip_response = sock.recv(1024)
                        if cip_response and len(cip_response) > 24:
                            cip_text = cip_response.decode(errors="ignore")
                            if any(name in cip_text for name in ("PanelView", "Rockwell", "Allen-Bradley")):
                                return self._result(ip, port, f"EtherNet/IP CIP | {cip_text[24:].strip()[:150]}", "ethernet_ip")
                            return self._result(ip, port, "EtherNet/IP CIP Industrial Node", "ethernet_ip")
                    except Exception:
                        return self._result(ip, port, "EtherNet/IP CIP Industrial Node", "ethernet_ip")

                if port in (38880, 38881):
                    sock.sendall(b"AVIGILON_ACC_PING\r\n")
                elif port == 5060:
                    sock.sendall(b"OPTIONS sip:local SIP/2.0\r\nVia: SIP/2.0/TCP local;branch=z9hG4bK\r\n\r\n")
                elif port in (3001, 23001):
                    sock.sendall(b"\x02\x01\x04POLL\x03")
                elif port in (80, 8080, 8088, 8000, 8888, 9000, 28081, 28083, 18081, 18083):
                    sock.sendall(
                        f"GET / HTTP/1.1\r\nHost: {ip}\r\n"
                        "User-Agent: Mozilla/5.0 (Aetheris)\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                elif port in (5985, 5986, 25985, 15985):
                    sock.sendall(b"POST /wsman HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n")
                elif port in (554, 15554, 15555):
                    sock.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Aetheris/1.0\r\n\r\n")
                elif port in (37777, 27777):
                    sock.sendall(b"\xa0\x00\x00\x00\x01\x00\x04\x00PROB\x00")
                elif port not in (21, 22):
                    sock.sendall(b"\r\n")

                sock.settimeout(timeout)
                data = sock.recv(2048)
                if not data:
                    return None

                text = data.decode(errors="ignore").strip()
                tokens = self.parse_http_descriptors(text)
                descriptors = []
                if tokens.server:
                    descriptors.append(f"Server: {tokens.server}")
                if tokens.title:
                    descriptors.append(f"Title: {tokens.title}")
                if tokens.cookie:
                    descriptors.append(f"Cookie: {tokens.cookie}")
                banner = " | ".join(descriptors) if descriptors else text[:256]
                return self._result(ip, port, banner, self._protocol_hint(port), tokens)
        except (OSError, ssl.SSLError, socket.timeout):
            return None
        except Exception:
            return None


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """Backward-compatible string-returning banner probe alias."""
    result = BannerGrabber().grab(ip, port, timeout)
    return result.banner if result is not None else None
