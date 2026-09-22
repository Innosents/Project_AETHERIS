"""
Project AETHERIS - Connectionless LDAP (CLDAP) Parser & Active Directory Engine
MS-ADTS 6.3.5 / RFC 1798 UDP Port 389 Protocol Parsing

Implements zero-credential ASN.1 BER searchRequest generation and dissection of the
authoritative NETLOGON_SAM_LOGON_RESPONSE_EX binary structure.
"""

import re
import socket
import select
import struct
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from aetheris.core.probers.sanitization import sanitize_prober_payload, clean_ascii_string

# MS-ADTS 6.3.5 / MS-NRPC 2.2.1.4.3 Constants
CLDAP_DEFAULT_PORT: int = 389
NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE: int = 18       # 0x0012
NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE_EX: int = 23    # 0x0017

# Server capabilities bitmask flags (MS-NRPC 2.2.1.4.3)
DS_PDC_FLAG: int = 0x00000001
DS_GC_FLAG: int = 0x00000004
DS_LDAP_FLAG: int = 0x00000002
DS_DS_FLAG: int = 0x00000010
DS_KDC_FLAG: int = 0x00000400
DS_TIMESERV_FLAG: int = 0x00000020
DS_CLOSEST_FLAG: int = 0x00000040
DS_WRITABLE_FLAG: int = 0x00000100
DS_GOOD_TIMESERV_FLAG: int = 0x00000200
DS_NDNC_FLAG: int = 0x00000800
DS_SELECT_SECRET_DOMAIN_6_FLAG: int = 0x00000400
DS_FULL_SECRET_DOMAIN_6_FLAG: int = 0x00000800
DS_WS_FLAG: int = 0x00001000
DS_DS_8_FLAG: int = 0x00002000
DS_DS_9_FLAG: int = 0x00004000
DS_DS_10_FLAG: int = 0x00008000
DS_PING_FLAGS: int = 0x40000000


def _ber_tag(tag: int, payload: bytes) -> bytes:
    """Encodes an ASN.1 BER TLV (Tag-Length-Value) element."""
    length = len(payload)
    if length < 128:
        return bytes([tag, length]) + payload
    elif length < 256:
        return bytes([tag, 0x81, length]) + payload
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + payload


def build_cldap_netlogon_ping(domain: str = "") -> bytes:
    """
    Constructs an ASN.1 BER encoded LDAP Message ID 1 searchRequest (tag 0x63).
    Target Base DN: ""
    Scope: baseObject (0x00)
    Filter: (&(DnsDomain=<domain>)(NtVer=\\x06\\x00\\x00\\x20)) or (NtVer=\\x06\\x00\\x00\\x20)
    Attributes: ["netlogon"]
    """
    msg_id = _ber_tag(0x02, b"\x01")

    base_dn = _ber_tag(0x04, b"")
    scope = _ber_tag(0x0a, b"\x00")
    deref = _ber_tag(0x0a, b"\x00")
    size_limit = _ber_tag(0x02, b"\x00")
    time_limit = _ber_tag(0x02, b"\x00")
    types_only = _ber_tag(0x01, b"\x00")

    ntver_attr = _ber_tag(0x04, b"NtVer")
    ntver_val = _ber_tag(0x04, b"\x06\x00\x00\x20")
    ntver_filter = _ber_tag(0xa3, ntver_attr + ntver_val)

    if domain:
        domain_attr = _ber_tag(0x04, b"DnsDomain")
        domain_val = _ber_tag(0x04, domain.encode("utf-8"))
        domain_filter = _ber_tag(0xa3, domain_attr + domain_val)
        filter_bytes = _ber_tag(0xa0, domain_filter + ntver_filter)
    else:
        filter_bytes = _ber_tag(0xa0, _ber_tag(0x87, b"objectClass") + ntver_filter)

    attr_list = _ber_tag(0x30, _ber_tag(0x04, b"netlogon"))

    search_req = _ber_tag(
        0x63,
        base_dn + scope + deref + size_limit + time_limit + types_only + filter_bytes + attr_list
    )

    return _ber_tag(0x30, msg_id + search_req)


def _read_null_terminated_string(buf: bytes, offset: int) -> Tuple[str, int]:
    """Extracts a null-terminated UTF-8 / ASCII string from a buffer."""
    if offset >= len(buf):
        return "", offset
    null_idx = buf.find(b"\x00", offset)
    if null_idx == -1:
        val = buf[offset:].decode("utf-8", errors="replace").strip()
        return val, len(buf)
    val = buf[offset:null_idx].decode("utf-8", errors="replace").strip()
    return val, null_idx + 1


def _extract_fallback_tokens(data: bytes) -> Dict[str, Any]:
    raw_tokens: List[str] = []
    for part in re.split(rb"[\x00-\x1f\x7f-\xff]+", data):
        if len(part) >= 2:
            try:
                decoded = part.decode("utf-8", errors="ignore").strip()
                if decoded:
                    raw_tokens.append(decoded)
            except Exception:
                pass

    if not raw_tokens:
        for part in re.split(rb"(?:\x00\x00)+", data):
            try:
                decoded = part.decode("utf-16le", errors="ignore").strip()
                if len(decoded) >= 2:
                    raw_tokens.append(decoded)
            except Exception:
                pass

    domain = ""
    hostname = ""
    netbios = ""

    for token in raw_tokens:
        if not domain and "." in token and re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$", token):
            domain = token
        elif token.lower() not in ("netlogon", "samlogon", "response", "ntver"):
            if not hostname and re.match(r"^[a-zA-Z0-9\-_]{2,32}$", token):
                hostname = token
            elif not netbios and token.isupper() and len(token) <= 15:
                netbios = token

    return {
        "is_ad_controller": True,
        "type": "server",
        "role": "Active Directory Domain Controller",
        "vendor": "Microsoft Corporation",
        "model": "Windows Server Domain Controller (AD DS)",
        "domain": domain,
        "forest": domain,
        "dc_hostname": hostname,
        "netbios_domain": netbios,
        "netbios_computer_name": hostname,
        "dc_site": "Default-First-Site-Name",
        "client_site": "Default-First-Site-Name",
        "domain_guid": str(uuid.UUID(int=0)),
        "flags": 0,
        "flags_hex": "0x00000000",
        "is_pdc": False,
        "is_gc": False,
        "is_kdc": False,
        "is_writable": False,
        "parsing_mode": "fallback_token_scan"
    }


def parse_cldap_response(data: bytes) -> Optional[Dict[str, Any]]:
    if not data or len(data) < 24:
        return None

    raw_netlogon = None

    if len(data) >= 24 and struct.unpack_from("<H", data, 0)[0] in (
        NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE_EX,
        NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE
    ):
        raw_netlogon = data
    else:
        lower_data = data.lower()
        idx = lower_data.find(b"netlogon")
        if idx != -1:
            attr_offset = idx + len(b"netlogon")
            found_tag = False
            for probe_pos in range(attr_offset, min(len(data), attr_offset + 16)):
                if data[probe_pos] == 0x04 and probe_pos + 2 < len(data):
                    len_byte = data[probe_pos + 1]
                    if len_byte < 128:
                        val_start = probe_pos + 2
                        val_len = len_byte
                    elif len_byte == 0x81:
                        val_start = probe_pos + 3
                        val_len = data[probe_pos + 2]
                    elif len_byte == 0x82 and probe_pos + 3 < len(data):
                        val_start = probe_pos + 4
                        val_len = (data[probe_pos + 2] << 8) | data[probe_pos + 3]
                    else:
                        continue

                    if val_len >= 24 and val_start + val_len <= len(data) + 1:
                        raw_netlogon = data[val_start:val_start + val_len]
                        found_tag = True
                        break
            if not found_tag:
                raw_netlogon = data[attr_offset:]

    if not raw_netlogon or len(raw_netlogon) < 24:
        if b"netlogon" in data.lower():
            return sanitize_prober_payload(_extract_fallback_tokens(data))
        return None

    opcode, sbz, flags = struct.unpack_from("<HHI", raw_netlogon, 0)

    if opcode == NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE_EX:
        raw_guid = raw_netlogon[8:24]
        try:
            domain_guid = str(uuid.UUID(bytes_le=raw_guid))
        except Exception:
            domain_guid = str(uuid.UUID(int=0))

        offset = 24
        forest, offset = _read_null_terminated_string(raw_netlogon, offset)
        domain, offset = _read_null_terminated_string(raw_netlogon, offset)
        dc_hostname, offset = _read_null_terminated_string(raw_netlogon, offset)
        netbios_domain, offset = _read_null_terminated_string(raw_netlogon, offset)
        netbios_computer, offset = _read_null_terminated_string(raw_netlogon, offset)
        user_name, offset = _read_null_terminated_string(raw_netlogon, offset)
        dc_site, offset = _read_null_terminated_string(raw_netlogon, offset)
        client_site, offset = _read_null_terminated_string(raw_netlogon, offset)

        is_pdc = bool(flags & DS_PDC_FLAG)
        is_gc = bool(flags & DS_GC_FLAG)
        is_kdc = bool(flags & DS_KDC_FLAG)
        is_writable = bool(flags & DS_WRITABLE_FLAG)

        res = {
            "is_ad_controller": True,
            "type": "server",
            "role": "Active Directory Domain Controller",
            "vendor": "Microsoft Corporation",
            "model": "Windows Server Domain Controller (AD DS)",
            "domain": clean_ascii_string(domain),
            "forest": clean_ascii_string(forest),
            "dc_hostname": clean_ascii_string(dc_hostname),
            "netbios_domain": clean_ascii_string(netbios_domain),
            "netbios_computer_name": clean_ascii_string(netbios_computer),
            "user_name": clean_ascii_string(user_name),
            "dc_site": clean_ascii_string(dc_site or "Default-First-Site-Name"),
            "client_site": clean_ascii_string(client_site or "Default-First-Site-Name"),
            "domain_guid": domain_guid,
            "flags": int(flags),
            "flags_hex": f"0x{flags:08X}",
            "is_pdc": is_pdc,
            "is_gc": is_gc,
            "is_kdc": is_kdc,
            "is_writable": is_writable,
            "parsing_mode": "ms_adts_6_3_5_response_ex"
        }
        return sanitize_prober_payload(res)

    elif opcode == NETLOGON_OPCODE_LOGON_SAM_LOGON_RESPONSE:
        tokens = _extract_fallback_tokens(raw_netlogon[8:])
        tokens["flags"] = int(flags)
        tokens["flags_hex"] = f"0x{flags:08X}"
        tokens["is_pdc"] = bool(flags & DS_PDC_FLAG)
        tokens["is_gc"] = bool(flags & DS_GC_FLAG)
        tokens["parsing_mode"] = "ms_adts_legacy_response"
        return sanitize_prober_payload(tokens)

    else:
        tokens = _extract_fallback_tokens(raw_netlogon)
        return sanitize_prober_payload(tokens)


def probe_cldap_endpoint(
    ip: str,
    port: int = CLDAP_DEFAULT_PORT,
    timeout: float = 0.4,
    domain_hint: str = ""
) -> Dict[str, Any]:
    """
    Performs a connectionless LDAP ping over UDP port 389 to query the Active Directory Netlogon profile.
    Guarantees non-blocking execution with bounded timeout (<= 0.4s) and zero socket leakage.
    Returns sanitized telemetry dictionary with microsecond turnaround timing.
    """
    timeout = min(0.4, max(0.05, float(timeout)))
    ping_payload = build_cldap_netlogon_ping(domain_hint)
    sock = None
    t_start = time.perf_counter()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.sendto(ping_payload, (ip, port))

        ready, _, _ = select.select([sock], [], [], timeout)
        if ready:
            data, _ = sock.recvfrom(4096)
            t_end = time.perf_counter()
            rtt_us = (t_end - t_start) * 1e6
            parsed = parse_cldap_response(data)
            if parsed:
                parsed["kernel_turnaround_us"] = round(rtt_us, 2)
                parsed["rtt_ms"] = round(rtt_us / 1000.0, 3)
                parsed["target_ip"] = ip
                parsed["target_port"] = port
                return sanitize_prober_payload(parsed)

    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return sanitize_prober_payload({
        "is_ad_controller": False,
        "target_ip": ip,
        "target_port": port,
        "error": "timeout"
    })

