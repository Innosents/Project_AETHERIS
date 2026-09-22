"""
Project AETHERIS - Core L3 Stealth Protocol Parser
Stateless protocol decoders and packet builders for NetBIOS Node Status (UDP 137),
WS-Discovery (UDP 3702), and LLMNR Reverse PTR (UDP 5355).
"""

import re
import socket
import struct
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

from aetheris.core.parsers.sanitization import clean_ascii_string, sanitize_prober_payload

NETBIOS_NBSTAT_QUERY: bytes = (
    b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
)


def build_wsd_probe() -> Tuple[bytes, str]:
    """Generates a WS-Discovery SOAP Probe XML envelope with a unique MessageID."""
    msg_id = str(uuid.uuid4())
    payload = (
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
    return payload, msg_id


def build_llmnr_query(ip: str) -> bytes:
    """Encodes an LLMNR reverse PTR query buffer for <ip>.in-addr.arpa."""
    octets = ip.split(".")
    if len(octets) != 4:
        return b""
    rev_name = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
    parts = rev_name.split(".")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"
    return struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)


def parse_netbios_response(data: bytes) -> Dict[str, Any]:
    """Dissects a NetBIOS Node Status response extracting hostname, workgroup, and RFC 1002 MAC."""
    if not data or len(data) <= 56:
        return {}
    num_names = data[56]
    names: List[str] = []
    computer_name = ""
    workgroup = ""
    offset = 57
    for _ in range(num_names):
        if offset + 18 <= len(data):
            name_bytes = data[offset:offset + 15]
            suffix_type = data[offset + 15]
            flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
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
    primary_name = computer_name or (names[0] if names else "")
    if not primary_name:
        return {}
    mac_str = ""
    mac_offset = 57 + (num_names * 18)
    if mac_offset + 6 <= len(data):
        mac_bytes = data[mac_offset:mac_offset + 6]
        if mac_bytes not in (b"\x00" * 6, b"\xff" * 6):
            mac_str = ":".join(f"{b:02X}" for b in mac_bytes)
    lower_name = primary_name.lower()
    dev_type = "workstation"
    dev_model = "Windows Host"
    dev_vendor = "Microsoft Corporation"
    if any(k in lower_name for k in ("stb", "iptv", "box")):
        dev_type, dev_model, dev_vendor = "stb", "IPTV Set-Top Box", "Generic STB"
    elif "tv" in lower_name:
        dev_type, dev_model, dev_vendor = "smart_tv", "Smart TV", "Smart TV Vendor"
    elif any(k in lower_name for k in ("laptop-", "thinkpad", "macbook", "surface")):
        dev_type = "laptop"
        if "thinkpad" in lower_name:
            dev_vendor, dev_model = "Lenovo", "Lenovo ThinkPad Laptop"
        elif "surface" in lower_name:
            dev_vendor, dev_model = "Microsoft Corporation", "Microsoft Surface Laptop"
        elif "macbook" in lower_name:
            dev_vendor, dev_model = "Apple Inc.", "Apple MacBook"
        else:
            dev_model = "Windows Portable Laptop"
    return {
        "hostname": primary_name,
        "computer_name": primary_name,
        "workgroup": workgroup,
        "mac": mac_str,
        "vendor": dev_vendor,
        "type": dev_type,
        "model": dev_model,
    }


def parse_wsd_response(data: bytes) -> Dict[str, Any]:
    """Parses WS-Discovery SOAP ProbeMatches response extracting device metadata."""
    text = data.decode("utf-8", errors="replace")
    lowered = text.lower()
    if "probematches" not in lowered and "envelope" not in lowered:
        return {}
    vendor, dev_type, model = "generic", "workstation", "Network Endpoint"
    friendly_name, endpoint_uuid, wsd_types = "", "", ""
    mfg_m = re.search(r"<[a-zA-Z0-9:]*manufacturer[^>]*>([^<]+)<", text, re.IGNORECASE)
    mod_m = re.search(r"<[a-zA-Z0-9:]*modelname[^>]*>([^<]+)<", text, re.IGNORECASE)
    fn_m = re.search(r"<[a-zA-Z0-9:]*friendlyname[^>]*>([^<]+)<", text, re.IGNORECASE)
    uuid_m = re.search(r"<[a-zA-Z0-9:]*Address[^>]*>urn:uuid:([0-9a-fA-F\-]{36})", text, re.IGNORECASE)
    if not uuid_m:
        uuid_m = re.search(r"urn:uuid:([0-9a-fA-F\-]{36})", text, re.IGNORECASE)
    type_m = re.search(r"<[a-zA-Z0-9:]*types[^>]*>([^<]+)<", text, re.IGNORECASE)
    if mfg_m:
        vendor = clean_ascii_string(mfg_m.group(1))
    if mod_m:
        model = clean_ascii_string(mod_m.group(1))
    if fn_m:
        friendly_name = clean_ascii_string(fn_m.group(1))
    if uuid_m:
        endpoint_uuid = uuid_m.group(1).lower()
    if type_m:
        wsd_types = clean_ascii_string(type_m.group(1))
    if any(k in lowered for k in ("print", "ipp", "prt", "copier")):
        dev_type = "printer"
        model = "Multifunction Network Printer (MFP)" if model == "Network Endpoint" else model
    elif "scan" in lowered:
        dev_type, model = "scanner", "Network Scanner"
    elif any(k in lowered for k in ("camera", "onvif", "networkvideotransmitter")):
        dev_type, model = "camera", "IP Surveillance Camera"
    elif any(k in lowered for k in ("windows", "ws-transfer", "device")) and vendor == "generic":
        vendor, model = "Microsoft Corporation", "Windows Endpoint"
    return {
        "vendor": vendor,
        "type": dev_type,
        "model": model,
        "friendly_name": friendly_name,
        "hostname": friendly_name or model,
        "endpoint_uuid": endpoint_uuid,
        "wsd_types": wsd_types,
    }


def parse_llmnr_response(data: bytes) -> Dict[str, Any]:
    """Parses LLMNR DNS response answer section to extract reverse PTR hostname."""
    if not data or len(data) < 12:
        return {}
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
            idx += 4
    except Exception:
        idx = 12
    ans_bytes = data[idx:] if idx < len(data) else data[12:]
    text = ans_bytes.decode("utf-8", errors="replace")
    tokens = re.findall(r"[A-Za-z0-9\-]{3,32}", text)
    for tok in tokens:
        clean_tok = clean_ascii_string(tok)
        if clean_tok.lower() not in ("in-addr", "arpa", "local", "ptr") and any(c.isalpha() for c in clean_tok):
            return {"hostname": clean_tok}
    return {}


# =========================================================================
# Backward Compatibility Synchronous Probers
# =========================================================================

def probe_netbios(ip: str, port: int = 137, timeout: float = 0.3) -> Dict[str, Any]:
    """Synchronous NetBIOS prober for legacy harnesses."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t_start = time.perf_counter_ns()
            s.sendto(NETBIOS_NBSTAT_QUERY, (ip, port))
            data, _ = s.recvfrom(2048)
            t_end = time.perf_counter_ns()
            res = parse_netbios_response(data)
            if not res:
                return {}
            turnaround_ns = max(1, t_end - t_start)
            turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6
            res.update({
                "ip": ip,
                "port": port,
                "protocol": "NetBIOS Node Status (UDP 137)",
                "is_active": True,
                "kernel_turnaround_us": round(turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": data.hex(),
            })
            return sanitize_prober_payload(res)
    except Exception:
        return {}


def probe_ws_discovery(ip: str, port: int = 3702, timeout: float = 0.4) -> Dict[str, Any]:
    """Synchronous WS-Discovery prober for legacy harnesses."""
    try:
        payload, _ = build_wsd_probe()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t_start = time.perf_counter_ns()
            s.sendto(payload, (ip, port))
            data, _ = s.recvfrom(4096)
            t_end = time.perf_counter_ns()
            res = parse_wsd_response(data)
            if not res:
                return {}
            turnaround_ns = max(1, t_end - t_start)
            turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6
            res.update({
                "ip": ip,
                "port": port,
                "protocol": "WS-Discovery (UDP 3702)",
                "is_active": True,
                "kernel_turnaround_us": round(turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": data.hex(),
            })
            return sanitize_prober_payload(res)
    except Exception:
        return {}


def probe_llmnr(ip: str, port: int = 5355, timeout: float = 0.35) -> Dict[str, Any]:
    """Synchronous LLMNR prober for legacy harnesses."""
    try:
        query = build_llmnr_query(ip)
        if not query:
            return {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            t_start = time.perf_counter_ns()
            s.sendto(query, (ip, port))
            data, _ = s.recvfrom(2048)
            t_end = time.perf_counter_ns()
            res = parse_llmnr_response(data)
            if not res:
                return {}
            turnaround_ns = max(1, t_end - t_start)
            turnaround_us = turnaround_ns / 1000.0
            latency_ms = turnaround_ns / 1e6
            res.update({
                "ip": ip,
                "port": port,
                "protocol": "LLMNR PTR (UDP 5355)",
                "is_active": True,
                "kernel_turnaround_us": round(turnaround_us, 2),
                "latency_ms": round(latency_ms, 2),
                "turnaround_ns": turnaround_ns,
                "raw_response": data.hex(),
            })
            return sanitize_prober_payload(res)
    except Exception:
        return {}


def probe_stealth_host(
    ip: str,
    timeout: float = 0.5,
    netbios_port: int = 137,
    wsd_port: int = 3702,
    llmnr_port: int = 5355,
) -> Dict[str, Any]:
    """Composite synchronous multi-variance prober for legacy sweeps."""
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

    hostname = (
        sub_probes.get("netbios", {}).get("hostname")
        or sub_probes.get("ws_discovery", {}).get("hostname")
        or sub_probes.get("llmnr", {}).get("hostname")
        or ""
    )
    mac_addr = sub_probes.get("netbios", {}).get("mac", "")
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
