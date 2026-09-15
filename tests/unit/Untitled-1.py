"""
SNMP Port 161 Query Utility (PySNMP 7.x compatible)
Queries sysDescr (1.3.6.1.2.1.1.1.0) on target host.
"""

import asyncio
from pysnmp.hlapi.v3arch.asyncio import (
    get_cmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity
)


async def query_snmp(ip: str = "192.168.1.1", port: int = 161, community: str = "public", timeout: float = 1.0):
    """Asynchronously queries an SNMP agent on UDP port 161."""
    target = await UdpTransportTarget.create((ip, port), timeout=timeout, retries=1)
    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # SNMPv2c
        target,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0"))  # sysDescr
    )

    if errorIndication:
        print(f"Closed/Filtered: {errorIndication}")
        return False, str(errorIndication)
    elif errorStatus:
        err = f"Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
        print(err)
        return False, err
    else:
        print(f"[+] SNMP Active on {ip}:{port}")
        for varBind in varBinds:
            print(f"    {varBind[0]} = {varBind[1]}")
        return True, varBinds


def sync_query_snmp(ip: str = "192.168.1.1", port: int = 161, community: str = "public"):
    """Synchronous wrapper for quick script execution."""
    return asyncio.run(query_snmp(ip=ip, port=port, community=community))


if __name__ == "__main__":
    import sys
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 161
    comm = sys.argv[3] if len(sys.argv) > 3 else "public"
    print(f"[*] Probing SNMP agent at {target_ip}:{target_port} (community: {comm})...")
    sync_query_snmp(target_ip, target_port, comm)