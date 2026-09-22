import asyncio
import logging
from typing import Dict, Any

# pysnmp-lextudio (or standard pysnmp) async high-level API
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    UsmUserData,
    usmHMACSHAAuthProtocol,
    usmAesCfb128Protocol,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    bulkCmd
)

from aetheris.core.interfaces import SNMPAdapterInterface

class GatewaySNMPAdapter(SNMPAdapterInterface):
    """
    Infrastructure Adapter for SNMPv3 gateway interrogation.
    Extracts Content Addressable Memory (CAM) tables and ARP caches to bind
    IP addresses to MAC addresses and physical edge switchports.
    """

    def __init__(
        self, 
        target_ip: str, 
        v3_user: str, 
        v3_auth: str, 
        v3_priv: str,
        timeout: float = 2.0,
        retries: int = 1
    ):
        self.target_ip = target_ip
        self.timeout = timeout
        self.retries = retries
        
        # Instantiate the isolated SNMP engine
        self.snmp_engine = SnmpEngine()
        
        # Configure SNMPv3 Cryptographic Context (SHA Auth / AES-128 Priv)
        self.user_data = UsmUserData(
            userName=v3_user,
            authKey=v3_auth,
            privKey=v3_priv,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol
        )
        
        self.transport = UdpTransportTarget(
            (self.target_ip, 161), 
            timeout=self.timeout, 
            retries=self.retries
        )
        self.context = ContextData()

        # Core OIDs for Edge Mapping
        # 1.3.6.1.2.1.4.22.1.2 (ipNetToMediaPhysAddress) -> Binds IP to MAC
        # 1.3.6.1.2.1.17.4.3.1.2 (dot1dTpFdbPort) -> Binds MAC to Bridge Port
        self.arp_oid = "1.3.6.1.2.1.4.22.1.2"
        self.cam_oid = "1.3.6.1.2.1.17.4.3.1.2"

    async def _walk_oid(self, start_oid: str) -> Dict[str, str]:
        """
        Executes an asynchronous SNMP BULK walk against the target OID.
        Returns a dictionary mapping the returned OID suffix to its extracted value.
        """
        results = {}
        try:
            # Execute async SNMP Bulk command
            iterator = bulkCmd(
                self.snmp_engine,
                self.user_data,
                self.transport,
                self.context,
                0, 25,  # nonRepeaters=0, maxRepetitions=25
                ObjectType(ObjectIdentity(start_oid)),
                lexicographicMode=False
            )

            async for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication:
                    logging.warning(f"[SNMP_ADAPTER] Engine error on {self.target_ip}: {errorIndication}")
                    break
                elif errorStatus:
                    logging.warning(f"[SNMP_ADAPTER] Agent error on {self.target_ip}: {errorStatus.prettyPrint()}")
                    break
                else:
                    for varBind in varBinds:
                        oid = str(varBind[0])
                        val = varBind[1]
                        
                        # Handle HexString MACs cleanly
                        if hasattr(val, "asOctets"):
                            val_str = ":".join([f"{x:02x}" for x in val.asOctets()]).upper()
                        else:
                            val_str = str(val)
                            
                        results[oid] = val_str

        except Exception as e:
            logging.error(f"[SNMP_ADAPTER] Fatal execution error during walk of {start_oid}: {e}")

        return results

    async def extract_cam_tables(self) -> Dict[str, Any]:
        """
        Implementation of SNMPAdapterInterface.
        Correlates the ARP cache and CAM table into a unified physical port map.
        """
        logging.info(f"[SNMP_ADAPTER] Initiating CAM extraction against {self.target_ip}")
        
        arp_task = asyncio.create_task(self._walk_oid(self.arp_oid))
        cam_task = asyncio.create_task(self._walk_oid(self.cam_oid))
        
        arp_data, cam_data = await asyncio.gather(arp_task, cam_task)

        edge_port_mapping = {}

        # Parse ARP Table (IP -> MAC)
        # OID structure: 1.3.6.1.2.1.4.22.1.2.[IfIndex].[IP1].[IP2].[IP3].[IP4]
        ip_to_mac = {}
        for oid, mac in arp_data.items():
            ip_suffix = ".".join(oid.split('.')[-4:])
            ip_to_mac[ip_suffix] = mac

        # Parse CAM Table (MAC -> Port)
        # OID structure: 1.3.6.1.2.1.17.4.3.1.2.[MAC1(dec)].[MAC2(dec)]...
        mac_to_port = {}
        for oid, port in cam_data.items():
            mac_dec = oid.split('.')[-6:]
            if len(mac_dec) == 6:
                mac_hex = ":".join([f"{int(x):02x}" for x in mac_dec]).upper()
                mac_to_port[mac_hex] = port

        # Correlate Matrix
        for ip, mac in ip_to_mac.items():
            port = mac_to_port.get(mac, "UNKNOWN")
            edge_port_mapping[ip] = {
                "mac": mac,
                "port_index": port,
                "ip": ip
            }

        return {
            "edge_port_mapping": edge_port_mapping
        }