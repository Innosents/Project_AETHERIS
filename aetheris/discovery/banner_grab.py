"""
Project AETHERIS - Banner Grab
Extracts application-layer identity vectors across open transport sockets using protocol-specific handshakes spanning TLS certificates, HTTP headers, and industrial OT descriptors. Sanitizes and 
concatenates cryptographic and service identity tokens into deterministic signatures for downstream device archetype classification.
"""

import socket
import ssl
import re
import struct
from typing import Optional

def grab_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """
    Safely extracts service banners and protocol identities from an open network port.
    Supports TLS/HTTPS certificate extraction, HTTP Server & Title banners, Modbus FC43 IDs,
    Siemens S7Comm SZL, EtherNet/IP CIP identities, RTSP, and Grandstream/Yealink VoIP signatures.
    """
    # Dedicated HTTPS / TLS Banner & Certificate Inspection
    if port in [443, 8443, 28082, 28084, 18082, 18084]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=ip) as ss:
                    cert_summary = []
                    try:
                        cert = ss.getpeercert(binary_form=False)
                        if cert:
                            for rdn in cert.get('subject', ()):
                                for key, val in rdn:
                                    if key in ('commonName', 'organizationName'):
                                        cert_summary.append(f"{key}={val}")
                    except Exception:
                        pass

                    ss.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (Aetheris)\r\nConnection: close\r\n\r\n".encode())
                    ss.settimeout(timeout)
                    resp = ss.recv(2048).decode(errors="ignore")

                    title_match = re.search(r'<title>(.*?)</title>', resp, re.IGNORECASE | re.DOTALL)
                    title = title_match.group(1).strip() if title_match else ""
                    server_match = re.search(r'Server:\s*([^\r\n]+)', resp, re.IGNORECASE)
                    server = server_match.group(1).strip() if server_match else ""
                    cookie_match = re.search(r'Set-Cookie:\s*([^\r\n;]+)', resp, re.IGNORECASE)
                    cookie = cookie_match.group(1).strip() if cookie_match else ""

                    parts = []
                    if cert_summary: parts.append(f"TLS: {', '.join(cert_summary)}")
                    if server: parts.append(f"Server: {server}")
                    if title: parts.append(f"Title: {title}")
                    if cookie: parts.append(f"Cookie: {cookie}")

                    if parts:
                        return " | ".join(parts)[:256]
                    if resp:
                        return f"HTTPS: {resp[:120].strip()}"
        except Exception:
            pass

    # Standard TCP & Industrial Protocol Banner Probe
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # 1. Proactively dispatch application-layer payloads based on well-known ports
            if port in [502, 10502, 20502]:
                # Dedicated Industrial Modbus Device Identification (FC 43 / MEI 14)
                try:
                    from aetheris.discovery.modbus_discovery import query_modbus_device_id
                    modbus_info = query_modbus_device_id(ip, port, timeout)
                    if modbus_info.get("vendor") and modbus_info["vendor"] != "Industrial PLC / Generic Modbus":
                        return f"Modbus/TCP PLC | Vendor: {modbus_info['vendor']} | Model: {modbus_info['model']} | Rev: {modbus_info['firmware']}"
                    elif modbus_info.get("holding_registers"):
                        return f"Modbus/TCP Industrial Node (Active Holding Registers: {len(modbus_info['holding_registers'])})"
                except Exception:
                    pass
                return "Modbus/TCP Industrial Controller"

            elif port == 102:
                # Siemens S7Comm ISO-on-TCP COTP Connection Request Probe
                try:
                    cotp_cr = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
                    s.sendall(cotp_cr)
                    s.settimeout(timeout)
                    cc_resp = s.recv(1024)
                    if cc_resp and len(cc_resp) >= 4:
                        s7_szl = b"\x03\x00\x00\x21\x02\xf0\x80\x32\x01\x00\x00\x00\x01\x00\x0e\x00\x00\x04\x01\x12\x04\x11\x44\x01\x00\xff\x09\x00\x04\x00\x11\x00\x01"
                        s.sendall(s7_szl)
                        s7_resp = s.recv(2048)
                        if s7_resp:
                            text_s7 = s7_resp.decode(errors="ignore")
                            if "Siemens" in text_s7 or "S7-" in text_s7:
                                return f"Siemens S7Comm | {text_s7[text_s7.find('Siemens'):text_s7.find('Siemens')+160].strip()}"
                        return "Siemens S7Comm / ISO-on-TCP (Port 102)"
                except Exception:
                    return "Siemens S7Comm / ISO-on-TCP (Port 102)"

            elif port == 44818:
                # EtherNet/IP CIP ListIdentity Probe
                try:
                    cip_list_id = b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    s.sendall(cip_list_id)
                    s.settimeout(timeout)
                    cip_resp = s.recv(1024)
                    if cip_resp and len(cip_resp) > 24:
                        cip_text = cip_resp.decode(errors="ignore")
                        if "PanelView" in cip_text or "Rockwell" in cip_text or "Allen-Bradley" in cip_text:
                            return f"EtherNet/IP CIP | {cip_text[24:].strip()[:150]}"
                        return "EtherNet/IP CIP Industrial Node"
                except Exception:
                    return "EtherNet/IP CIP Industrial Node"

            elif port in [38880, 38881]:
                s.sendall(b"AVIGILON_ACC_PING\r\n")
            elif port == 5060:
                s.sendall(b"OPTIONS sip:local SIP/2.0\r\nVia: SIP/2.0/TCP local;branch=z9hG4bK\r\n\r\n")
            elif port in [3001, 23001]:
                s.sendall(b"\x02\x01\x04POLL\x03")
            elif port in [80, 8080, 8088, 8000, 8888, 9000, 28081, 28083, 18081, 18083]:
                s.sendall(f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (Aetheris)\r\nConnection: close\r\n\r\n".encode())
            elif port in [5985, 5986, 25985, 15985]:
                s.sendall(b"POST /wsman HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n")
            elif port in [554, 15554, 15555]:
                s.sendall(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Aetheris/1.0\r\n\r\n")
            elif port in [37777, 27777]:
                s.sendall(b"\xa0\x00\x00\x00\x01\x00\x04\x00PROB\x00")
            elif port in [21, 22]:
                pass
            else:
                s.sendall(b"\r\n")
                
            # 2. Enforce an internal socket read validation check
            s.settimeout(timeout) 
            data = s.recv(2048)
            
            if not data:
                return None
                
            text = data.decode(errors="ignore").strip()
            
            # Extract HTML Title if available
            title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
            server_match = re.search(r'Server:\s*([^\r\n]+)', text, re.IGNORECASE)
            cookie_match = re.search(r'Set-Cookie:\s*([^\r\n;]+)', text, re.IGNORECASE)

            descriptors = []
            if server_match: descriptors.append(f"Server: {server_match.group(1).strip()}")
            if title_match: descriptors.append(f"Title: {title_match.group(1).strip()}")
            if cookie_match: descriptors.append(f"Cookie: {cookie_match.group(1).strip()}")

            if descriptors:
                return " | ".join(descriptors)[:256]
            
            return text[:256] if text else None
            
    except Exception:
        return None