"""
Project AETHERIS - Multi-Variance Stealth Prober Suite (Phase 1)
Elicits discovery responses from dormant, firewalled endpoints that drop ICMP and TCP sweeps:
1. NetBIOS Node Status (UDP 137) - Computer name, workgroup, and RFC 1002 hardware MAC address
2. WS-Discovery (UDP 3702) - SOAP probe for Windows 10/11, network printers, scanners, and ONVIF devices
3. LLMNR Reverse PTR (UDP 5355) - Unicast reverse name resolution for local hostnames
4. Composite Stealth Host Interrogator - Concurrent multi-vector orchestration with bounded timeouts

All outputs are defensively sanitized via sanitize_prober_payload to guarantee zero raw bytes leakage.
"""

import re
import socket
import struct
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from graphpath.core.probers.sanitization import clean_ascii_string, sanitize_prober_payload

# NetBIOS Node Status Query Payload (RFC 1002):
# TransID 0x8000, Query 1, QDCOUNT 1, Name: '*' (encoded as 0x20 + 32 half-ASCII 'A's), Type: 0x0021 (NBSTAT), Class: 0x0001 (IN)
NETBIOS_NBSTAT_QUERY = (
    b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
)


def probe_netbios(ip: str, port: int = 137, timeout: float = 0.3) -> Dict[str, Any]:
    """
    Unicasts a NetBIOS Node Status query to UDP 137.
    Extracts unique computer name, workgroup, and the 6-byte RFC 1002 hardware MAC address.
    Measures kernel turnaround time (t_kernel) using time.perf_counter_ns().
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)

            t_start = time.perf_counter_ns()
            s.sendto(NETBIOS_NBSTAT_QUERY, (ip, port))
            data, _ = s.recvfrom(2048)
            t_end = time.perf_counter_ns()

            if not data or len(data) <= 56:
                return {}

            num_names = data[56]
            names: List[str] = []
            computer_name = ""
            workgroup = ""
            offset = 57

            for _ in range(num_names):
                if offset + 18 <= len(data):
                    name_bytes = data[offset : offset + 15]
                    suffix_type = data[offset + 15]
                    flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
                    is_group = bool(flags & 0x8000)

                    clean_name = clean_ascii_string(name_bytes.decode("utf-8", errors="replace"))
                    if clean_name:
                        names.append(clean_name)
                        if is_group:
                            if not workgroup:
                                workgroup = clean_name
                        else:
                            if not computer_name and suffix_type in (0x00, 0x20):
                                computer_name = clean_name

                    offset += 18

            if not names and not computer_name:
                return {}

            primary_name = computer_name or (names[0] if names else "")

            # Extract RFC 1002 Unit ID (Hardware MAC address) following the name table
            mac_str = ""
            mac_offset = 57 + (num_names * 18)
            if mac_offset + 6 <= len(data):
                mac_bytes = data[mac_offset : mac_offset + 6]
                if mac_bytes not in (b"\x00" * 6, b"\xff" * 6):
                    mac_str = ":".join(f"{b:02X}" for b in mac_bytes)

            lower_name = primary_name.lower()
            dev_type = "workstation"
            dev_model = "Windows Host"
            dev_vendor = "Microsoft Corporation"

            if "stb" in lower_name or "iptv" in lower_name or "box" in lower_name:
                dev_type = "stb"
                dev_model = "IPTV Set-Top Box"
                dev_vendor = "Generic STB"
            elif "tv" in lower_name:
                dev_type = "smart_tv"
                dev_model = "Smart TV"
                dev_vendor = "Smart TV Vendor"
            elif "laptop-" in lower_name or "thinkpad" in lower_name or "macbook" in lower_name or "surface" in lower_name:
                dev_type = "laptop"
                if "thinkpad" in lower_name:
                    dev_vendor = "Lenovo"
                    dev_model = "Lenovo ThinkPad Laptop"
                elif "surface" in lower_name:
                    dev_vendor = "Microsoft Corporation"
                    dev_model = "Microsoft Surface Laptop"
                elif "macbook" in lower_name:
                    dev_vendor = "Apple Inc."
                    dev_model = "Apple MacBook"
                else:
                    dev_model = "Windows Portable Laptop"

            turnaround_ns = max(1, t_end - t_start)
            turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6

            payload = {
                "ip": ip,
                "hostname": primary_name,
                "computer_name": primary_name,
                "workgroup": workgroup,
                "mac": mac_str,
                "vendor": dev_vendor,
                "type": dev_type,
                "model": dev_model,
                "protocol": "NetBIOS Node Status (UDP 137)",
                "port": port,
                "is_active": True,
                "kernel_turnaround_us": round(turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": data.hex(),
            }
            return sanitize_prober_payload(payload)
    except Exception:
        return {}


def probe_ws_discovery(ip: str, port: int = 3702, timeout: float = 0.4) -> Dict[str, Any]:
    """
    Unicasts a WS-Discovery SOAP Probe to UDP 3702.
    Parses device metadata (Manufacturer, ModelName, FriendlyName, Types) for Windows endpoints,
    network printers, scanners, and ONVIF surveillance cameras.
    Measures kernel turnaround time (t_kernel) using time.perf_counter_ns().
    """
    msg_id = str(uuid.uuid4())
    wsd_probe_xml = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        f'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        f'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        f"<soap:Header>"
        f"<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
        f"<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
        f"<wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>"
        f"</soap:Header>"
        f"<soap:Body><wsd:Probe/></soap:Body>"
        f"</soap:Envelope>"
    ).encode("utf-8")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)

            t_start = time.perf_counter_ns()
            s.sendto(wsd_probe_xml, (ip, port))
            data, _ = s.recvfrom(4096)
            t_end = time.perf_counter_ns()

            if not data:
                return {}

            text = data.decode("utf-8", errors="replace")
            lowered = text.lower()

            if "probematches" not in lowered and "envelope" not in lowered:
                return {}

            vendor = "generic"
            dev_type = "workstation"
            model = "Network Endpoint"
            friendly_name = ""
            endpoint_uuid = ""
            wsd_types = ""

            # Extract fields via regex for namespace-agnostic resilience
            mfg_match = re.search(r"<[a-zA-Z0-9:]*manufacturer[^>]*>([^<]+)<", text, re.IGNORECASE)
            model_match = re.search(r"<[a-zA-Z0-9:]*modelname[^>]*>([^<]+)<", text, re.IGNORECASE)
            name_match = re.search(r"<[a-zA-Z0-9:]*friendlyname[^>]*>([^<]+)<", text, re.IGNORECASE)
            uuid_match = re.search(r"<[a-zA-Z0-9:]*Address[^>]*>\s*urn:uuid:([0-9a-fA-F\-]{36})", text, re.IGNORECASE) or re.search(r"urn:uuid:([0-9a-fA-F\-]{36})", text, re.IGNORECASE)
            types_match = re.search(r"<[a-zA-Z0-9:]*types[^>]*>([^<]+)<", text, re.IGNORECASE)

            if mfg_match:
                vendor = clean_ascii_string(mfg_match.group(1))
            if model_match:
                model = clean_ascii_string(model_match.group(1))
            if name_match:
                friendly_name = clean_ascii_string(name_match.group(1))
            if uuid_match:
                endpoint_uuid = uuid_match.group(1).lower()
            if types_match:
                wsd_types = clean_ascii_string(types_match.group(1))

            # Infer hardware archetype
            if "print" in lowered or "ipp" in lowered or "prt" in lowered or "copier" in lowered:
                dev_type = "printer"
                if vendor == "generic":
                    if "kyocera" in lowered:
                        vendor = "Kyocera Document Solutions"
                    elif "hp" in lowered or "hewlett" in lowered:
                        vendor = "HP Inc."
                    elif "canon" in lowered:
                        vendor = "Canon"
                    elif "brother" in lowered:
                        vendor = "Brother"
                    elif "xerox" in lowered:
                        vendor = "Xerox"
                    elif "ricoh" in lowered:
                        vendor = "Ricoh"
                    elif "epson" in lowered:
                        vendor = "Epson"
                    elif "lexmark" in lowered:
                        vendor = "Lexmark"
                    else:
                        vendor = "Network Printer"
                if model == "Network Endpoint":
                    model = "Multifunction Network Printer (MFP)"
            elif "scan" in lowered:
                dev_type = "scanner"
                model = "Network Scanner"
            elif "camera" in lowered or "onvif" in lowered or "networkvideotransmitter" in lowered:
                dev_type = "camera"
                model = "IP Surveillance Camera"
            elif "windows" in lowered or "ws-transfer" in lowered or "device" in lowered:
                dev_type = "workstation"
                if vendor == "generic":
                    vendor = "Microsoft Corporation"
                if model == "Network Endpoint":
                    model = "Windows Endpoint"

            turnaround_ns = max(1, t_end - t_start)
            turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6

            payload = {
                "ip": ip,
                "vendor": vendor,
                "type": dev_type,
                "model": model,
                "friendly_name": friendly_name,
                "hostname": friendly_name or model,
                "endpoint_uuid": endpoint_uuid,
                "wsd_types": wsd_types,
                "protocol": "WS-Discovery (UDP 3702)",
                "port": port,
                "is_active": True,
                "kernel_turnaround_us": round(turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": data.hex(),
            }
            return sanitize_prober_payload(payload)
    except Exception:
        return {}


def probe_llmnr(ip: str, port: int = 5355, timeout: float = 0.35) -> Dict[str, Any]:
    """
    Unicasts an LLMNR reverse PTR query to UDP 5355 for <ip>.in-addr.arpa.
    Dissects the answer section to extract the alphanumeric hostname.
    Measures kernel turnaround time (t_kernel) using time.perf_counter_ns().
    """
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return {}
        rev_name = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
        parts = rev_name.split(".")
        qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"

        # Transaction ID: 0x1234, Flags: Standard Query (0x0000), QDCOUNT: 1, Type: 12 (PTR), Class: 1 (IN)
        query = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)

            t_start = time.perf_counter_ns()
            s.sendto(query, (ip, port))
            data, _ = s.recvfrom(2048)
            t_end = time.perf_counter_ns()

            if not data or len(data) < 12:
                return {}

            # Attempt to skip Question section using QDCOUNT
            idx = 12
            try:
                qdcount = struct.unpack(">H", data[4:6])[0]
                for _ in range(qdcount):
                    while idx < len(data):
                        length = data[idx]
                        if length == 0:
                            idx += 1
                            break
                        elif (length & 0xC0) == 0xC0:
                            idx += 2
                            break
                        else:
                            idx += 1 + length
                    idx += 4  # skip QTYPE and QCLASS
            except Exception:
                idx = 12

            ans_bytes = data[idx:] if idx < len(data) else data[12:]
            text = ans_bytes.decode("utf-8", errors="replace")
            tokens = re.findall(r"[A-Za-z0-9\-]{3,32}", text)
            hostname = ""
            for tok in tokens:
                clean_tok = clean_ascii_string(tok)
                if (
                    clean_tok.lower() not in ("in-addr", "arpa", "local", "ptr")
                    and any(c.isalpha() for c in clean_tok)
                ):
                    hostname = clean_tok
                    break

            if not hostname:
                return {}

            turnaround_ns = max(1, t_end - t_start)
            turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6

            payload = {
                "ip": ip,
                "hostname": hostname,
                "protocol": "LLMNR PTR (UDP 5355)",
                "port": port,
                "is_active": True,
                "kernel_turnaround_us": round(turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": data.hex(),
            }
            return sanitize_prober_payload(payload)
    except Exception:
        return {}


def probe_stealth_host(
    ip: str,
    timeout: float = 0.5,
    netbios_port: int = 137,
    wsd_port: int = 3702,
    llmnr_port: int = 5355,
) -> Dict[str, Any]:
    """
    Composite orchestrator executing NetBIOS (137), WS-Discovery (3702), and LLMNR (5355)
    concurrently against a target endpoint. Consolidates surfaced metadata into a unified host profile.
    Guarantees deterministic JSON-serializable output via sanitize_prober_payload.
    """
    sub_probes: Dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        fut_nb = executor.submit(probe_netbios, ip, port=netbios_port, timeout=min(timeout, 0.35))
        fut_wsd = executor.submit(probe_ws_discovery, ip, port=wsd_port, timeout=min(timeout, 0.4))
        fut_llmnr = executor.submit(probe_llmnr, ip, port=llmnr_port, timeout=min(timeout, 0.35))

        try:
            res_nb = fut_nb.result(timeout=timeout)
            if res_nb:
                sub_probes["netbios"] = res_nb
        except Exception:
            pass

        try:
            res_wsd = fut_wsd.result(timeout=timeout)
            if res_wsd:
                sub_probes["ws_discovery"] = res_wsd
        except Exception:
            pass

        try:
            res_llmnr = fut_llmnr.result(timeout=timeout)
            if res_llmnr:
                sub_probes["llmnr"] = res_llmnr
        except Exception:
            pass

    if not sub_probes:
        return {}

    # Extract primary hostname: NetBIOS > WSD > LLMNR
    hostname = (
        sub_probes.get("netbios", {}).get("hostname")
        or sub_probes.get("ws_discovery", {}).get("hostname")
        or sub_probes.get("llmnr", {}).get("hostname")
        or ""
    )

    # Extract hardware MAC from NetBIOS Unit ID if surfaced
    mac_addr = sub_probes.get("netbios", {}).get("mac", "")

    # Extract device vendor & model
    vendor = (
        sub_probes.get("ws_discovery", {}).get("vendor")
        or sub_probes.get("netbios", {}).get("vendor")
        or "generic"
    )
    dev_type = (
        sub_probes.get("ws_discovery", {}).get("type")
        or sub_probes.get("netbios", {}).get("type")
        or "workstation"
    )
    model = (
        sub_probes.get("ws_discovery", {}).get("model")
        or sub_probes.get("netbios", {}).get("model")
        or "Network Endpoint"
    )

    # Compute minimal kernel turnaround time across responding vectors
    turnarounds = [
        p["kernel_turnaround_us"]
        for p in sub_probes.values()
        if isinstance(p.get("kernel_turnaround_us"), (int, float)) and p["kernel_turnaround_us"] > 0
    ]
    min_tk = min(turnarounds) if turnarounds else 150.0

    summary = {
        "ip": ip,
        "is_active": True,
        "hostname": hostname,
        "mac": mac_addr,
        "vendor": vendor,
        "type": dev_type,
        "model": model,
        "kernel_turnaround_us": round(min_tk, 2),
        "probes": sub_probes,
    }
    return sanitize_prober_payload(summary)

