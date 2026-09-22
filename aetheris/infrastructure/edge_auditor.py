"""
Project AETHERIS - Passive Security Posture & Hardening Advisory Engine
Analyzes discovered device DNA, OUI vendors, service banners, and exposed ports
to identify unhardened management interfaces, cleartext protocols, and factory-default risks
without performing intrusive attacks or automated login attempts.
"""

import asyncio
import re
import socket
from typing import Dict, Any, List, Optional

import httpx

from aetheris.core.interfaces import HardwareAuditorInterface

class EdgeHardwareAdapter(HardwareAuditorInterface):
    """
    NIST SP 800-82 Compliant Edge Security Adapter.
    Executes non-destructive, read-only interrogations against OT/Physical Security
    endpoints. Completely isolated from file I/O and graph state.
    """

    def __init__(self, concurrency_limit: int = 5):
        # Enforces maximum concurrent socket bindings to prevent OT switch port exhaustion
        self.semaphore = asyncio.Semaphore(concurrency_limit)

    async def audit_hardware_target(self, ip: str, port: int, protocol: str) -> Dict[str, Any]:
        """
        Implementation of HardwareAuditorInterface.
        Routes the target to the correct hardware interrogation payload under strict concurrency limits.
        """
        async with self.semaphore:
            proto = protocol.lower()
            if proto in ("vapix", "axis", "onvif"):
                return await self._check_axis_cve(ip)
            elif proto in ("mercury", "msp"):
                return await self._check_mercury_msp(ip)
            elif proto == "modbus":
                return await self._check_modbus_fc43(ip)
            else:
                return {
                    "audit_status": "SKIPPED",
                    "cve_exposure": "NONE",
                    "cve_notes": f"Protocol '{protocol}' not supported for active hardware audit."
                }

    async def _check_axis_cve(self, ip: str) -> Dict[str, str]:
        """Read-only VAPIX parameter extraction targeting firmware version."""
        url = f"http://{ip}/axis-cgi/param.cgi?action=list&group=Properties.Firmware.Version"
        timeout = httpx.Timeout(0.5)

        try:
            limits = httpx.Limits(max_connections=5, max_keepalive_connections=5)
            async with httpx.AsyncClient(timeout=timeout, verify=False, limits=limits) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    match = re.search(r"Properties\.Firmware\.Version=([0-9\.]+)", response.text)
                    if match:
                        fw_version = match.group(1)
                        if fw_version.startswith("9.") or fw_version.startswith("8."):
                            return {'audit_status': 'COMPLETED', 'cve_exposure': 'CRITICAL', 'cve_notes': f'VAPIX FW v{fw_version} vulnerable to CVE-2023-21406'}
                        return {'audit_status': 'COMPLETED', 'cve_exposure': 'LOW', 'cve_notes': f'VAPIX FW v{fw_version} authenticated'}

                elif response.status_code in (401, 403):
                    return {'audit_status': 'COMPLETED', 'cve_exposure': 'LOW', 'cve_notes': 'VAPIX read requires authentication (Hardened)'}

                return {'audit_status': 'COMPLETED', 'cve_exposure': 'UNKNOWN', 'cve_notes': f'VAPIX anomalous status: {response.status_code}'}

        except (httpx.ConnectTimeout, httpx.ReadTimeout):
            return {'audit_status': 'TIMEOUT', 'cve_exposure': 'UNKNOWN', 'cve_notes': '0.5s VAPIX timeout exceeded'}
        except httpx.RequestError:
            return {'audit_status': 'FAILED', 'cve_exposure': 'UNKNOWN', 'cve_notes': 'VAPIX connection refused (Port 80 closed)'}

    async def _check_mercury_msp(self, ip: str) -> Dict[str, str]:
        """Non-destructive MSP diagnostic poll on TCP 3001."""
        diagnostic_payload = b"\x02\x0B\x00\x00\x00\x00\x00\x03"
        sock = None
        writer = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 3001),
                timeout=0.5
            )
            sock = writer.get_extra_info('socket')

            writer.write(diagnostic_payload)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=0.5)

            match = re.search(rb"(?:LP|EP)1502[_-]?v?(\d{1,2}\.\d{1,2}\.\d{1,2})", response)
            if match:
                fw_version = match.group(1).decode('utf-8', errors='ignore')
                if fw_version.startswith("1.28") or fw_version.startswith("1.27"):
                    return {'audit_status': 'COMPLETED', 'cve_exposure': 'CRITICAL', 'cve_notes': f'MSP Plaintext Active, FW v{fw_version}'}
                return {'audit_status': 'COMPLETED', 'cve_exposure': 'MEDIUM', 'cve_notes': f'MSP Plaintext Active, FW v{fw_version}'}

            if response:
                return {'audit_status': 'COMPLETED', 'cve_exposure': 'HIGH', 'cve_notes': 'MSP port 3001 unencrypted, version unverified'}

            return {'audit_status': 'COMPLETED', 'cve_exposure': 'UNKNOWN', 'cve_notes': 'Connection established but zero-byte payload returned'}

        except asyncio.TimeoutError:
            return {'audit_status': 'TIMEOUT', 'cve_exposure': 'UNKNOWN', 'cve_notes': '0.5s MSP timeout (Port 3001 filtered)'}
        except ConnectionRefusedError:
            return {'audit_status': 'SECURED', 'cve_exposure': 'LOW', 'cve_notes': 'Port 3001 closed (TLS/Secure Mode enforced)'}
        except Exception as e:
            return {'audit_status': 'ERROR', 'cve_exposure': 'UNKNOWN', 'cve_notes': f'Exception: {str(e)}'}
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _check_modbus_fc43(self, ip: str) -> Dict[str, str]:
        """NIST 800-82 compliant Modbus FC 43 (Read Device Identification)."""
        fc43_payload = b"\x00\x01\x00\x00\x00\x05\x01\x2B\x0E\x01\x00"
        sock = None
        writer = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 502),
                timeout=0.5
            )
            sock = writer.get_extra_info('socket')

            writer.write(fc43_payload)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=0.5)

            if len(response) > 8 and response[7] == 0x2B and response[8] == 0x0E:
                ascii_strings = [chunk.decode('ascii', errors='ignore') for chunk in response[14:].split(b'\x00') if chunk]
                vendor_data = " ".join(re.sub(r'[^\x20-\x7E]', '', s).strip() for s in ascii_strings if len(s) > 2)

                if "Schneider" in vendor_data or "Siemens" in vendor_data:
                    return {'audit_status': 'COMPLETED', 'cve_exposure': 'HIGH', 'cve_notes': f'Modbus FC43: {vendor_data} (Evaluate Default Credentials)'}
                return {'audit_status': 'COMPLETED', 'cve_exposure': 'MEDIUM', 'cve_notes': f'Modbus FC43 Active: {vendor_data}'}

            elif len(response) > 8 and response[7] == 0xAB:
                exception_code = response[8]
                return {'audit_status': 'COMPLETED', 'cve_exposure': 'LOW', 'cve_notes': f'FC43 Rejected (Modbus Exception {exception_code})'}

            return {'audit_status': 'COMPLETED', 'cve_exposure': 'UNKNOWN', 'cve_notes': 'Modbus 502 active, unrecognized response'}

        except asyncio.TimeoutError:
            return {'audit_status': 'TIMEOUT', 'cve_exposure': 'UNKNOWN', 'cve_notes': '0.5s Modbus timeout (Port 502 filtered/dropped)'}
        except ConnectionRefusedError:
            return {'audit_status': 'SECURED', 'cve_exposure': 'LOW', 'cve_notes': 'Port 502 closed'}
        except Exception as e:
            return {'audit_status': 'ERROR', 'cve_exposure': 'UNKNOWN', 'cve_notes': f'Modbus Exception: {str(e)}'}
        finally:
            if sock:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass


class EdgeSecurityAuditor(EdgeHardwareAdapter):
    """
    Fleet-level edge security auditor orchestrating targeted CVE interrogations.
    """

    def __init__(self, concurrency_limit: int = 5, nodes: Optional[List[Dict[str, Any]]] = None):
        super().__init__(concurrency_limit=concurrency_limit)
        self.audit_ledger: Dict[str, Dict[str, Any]] = {}
        self.nodes = nodes or [
            {"mac": "00:50:56:99:A1:01", "ip": "10.50.99.10", "type": "axis"},
            {"mac": "00:50:56:99:A1:02", "ip": "10.50.99.20", "type": "mercury"},
        ]

    async def execute_fleet_audit(self) -> Dict[str, Any]:
        """
        Executes audit checks across registered fleet nodes without intrusive packet flooding.
        """
        for node in self.nodes:
            mac = node.get("mac")
            ip = node.get("ip")
            node_type = node.get("type", "").lower()
            if "axis" in node_type or "vapix" in node_type:
                res = await self._check_axis_cve(ip)
            elif "mercury" in node_type or "msp" in node_type:
                res = await self._check_mercury_msp(ip)
            elif "modbus" in node_type:
                res = await self._check_modbus_fc43(ip)
            else:
                res = {"audit_status": "SKIPPED", "cve_exposure": "NONE", "cve_notes": "Unrecognized node type"}
            self.audit_ledger[mac] = res

        return {
            "status": "AUDIT_COMPLETE",
            "nodes_processed": len(self.audit_ledger),
            "audit_ledger": self.audit_ledger,
        }