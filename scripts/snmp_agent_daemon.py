"""
Project AETHERIS - Local SNMP Agent Daemon (UDP Port 161)
Listens on UDP 161 (0.0.0.0) and responds to SNMP GetRequests with standard MIB-II values.
Enables local testing of SNMP interrogation, BridgeFDBCrawler, and telemetry polling.
"""

import sys
import time
import socket
import argparse
from typing import Dict, Any

try:
    from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind
except ImportError:
    print("Error: Scapy is required to run the SNMP daemon.")
    sys.exit(1)


MIB_TREE: Dict[str, Any] = {
    "1.3.6.1.2.1.1.1.0": "AETHERIS Core Switch / Managed Gateway v2.4 (Physical Layer)",
    "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.8072.3.2.10",
    "1.3.6.1.2.1.1.3.0": 1234567,
    "1.3.6.1.2.1.1.4.0": "admin@aetheris.lan",
    "1.3.6.1.2.1.1.5.0": "Core-Gateway-01",
    "1.3.6.1.2.1.1.6.0": "IDF-01 Rack 4, Port 1-4 Bridge",
}


def run_snmp_daemon(host: str = "0.0.0.0", port: int = 161, community: str = "public"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        print(f"[+] SNMP Daemon successfully active and listening on {host}:{port}/UDP")
        print(f"[+] Accepted Community: '{community}'")
        print(f"[+] Registered MIBs:")
        for oid, val in MIB_TREE.items():
            print(f"      {oid} -> {val}")
        print("\n[*] Ready to serve incoming SNMP requests. Press Ctrl+C to terminate.")
    except PermissionError:
        print(f"[-] Permission denied binding to {host}:{port}. Run terminal as Administrator or specify a port > 1024.")
        return
    except Exception as e:
        print(f"[-] Error binding to {host}:{port}: {e}")
        return

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            print(f"[*] Received {len(data)} bytes from {addr}")
            try:
                pkt = SNMP(data)
                raw_comm = getattr(pkt.community, "val", pkt.community)
                req_community = raw_comm.decode("utf-8", errors="ignore") if isinstance(raw_comm, bytes) else str(raw_comm)
                print(f"[*] Community: '{req_community}', PDU type: {type(pkt.PDU).__name__}")
                if community and req_community != community:
                    print(f"[-] Community mismatch: expected '{community}', got '{req_community}'")
                    continue

                req_id = pkt.PDU.id
                req_varbinds = getattr(pkt.PDU, "varbindlist", [])
                resp_varbinds = []

                for vb in req_varbinds:
                    raw_oid = getattr(vb.oid, "val", vb.oid)
                    oid_str = str(raw_oid).lstrip(".")
                    val = MIB_TREE.get(oid_str, MIB_TREE["1.3.6.1.2.1.1.1.0"])
                    resp_varbinds.append(SNMPvarbind(oid=oid_str, value=val))

                if not resp_varbinds:
                    resp_varbinds = [SNMPvarbind(oid="1.3.6.1.2.1.1.1.0", value=MIB_TREE["1.3.6.1.2.1.1.1.0"])]

                resp = SNMP(
                    version=pkt.version,
                    community=req_community.encode("utf-8"),
                    PDU=SNMPresponse(
                        id=req_id,
                        error=0,
                        error_index=0,
                        varbindlist=resp_varbinds
                    )
                )
                sock.sendto(bytes(resp), addr)
                print(f"[>] Responded to SNMP request from {addr[0]}:{addr[1]} for {len(resp_varbinds)} OID(s)")
            except Exception as ex:
                print(f"[-] Exception processing packet from {addr}: {ex}")
    except KeyboardInterrupt:
        print("\n[*] Shutting down SNMP daemon.")
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AETHERIS Local SNMP Agent Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="Listening IP (default: 0.0.0.0)")
    parser.add_argument("--port", "-p", type=int, default=161, help="Listening UDP port (default: 161)")
    parser.add_argument("--community", "-c", default="public", help="SNMP community string (default: public)")
    args = parser.parse_args()
    run_snmp_daemon(host=args.host, port=args.port, community=args.community)
