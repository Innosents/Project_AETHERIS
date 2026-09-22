import asyncio
import ipaddress
import logging
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from aetheris.core.interfaces import L3ActiveAdapterInterface

class ActiveTTLAdapter(L3ActiveAdapterInterface):
    """
    Infrastructure Adapter for L3 network interrogation.
    Encapsulates raw ICMP/UDP socket execution and hardware TTL extraction.
    Thread-isolated to prevent raw socket blocking on the asyncio event loop.
    """

    def __init__(self, max_workers: int = 50, timeout_sec: float = 0.5):
        self.timeout_sec = timeout_sec
        # Constrain thread pool to prevent ephemeral port exhaustion during /24 sweeps
        self._thread_pool = ThreadPoolExecutor(max_workers=max_workers)

    def _expand_target_subnet(self, target_subnet: str) -> List[str]:
        """Deterministically expands CIDR notation into a bounded list of target IPs."""
        try:
            if "/" in target_subnet:
                net = ipaddress.ip_network(target_subnet, strict=False)
                hosts = list(net.hosts())
                # Hard clamp at /24 equivalent to prevent runaway execution in testing environments
                return [str(ip) for ip in (hosts[:254] if len(hosts) > 254 else hosts)]
            return [target_subnet]
        except ValueError as e:
            logging.error(f"[L3_ADAPTER] CIDR expansion fault on {target_subnet}: {e}")
            return [target_subnet]

    def _execute_raw_ping(self, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Synchronous raw socket execution.
        Constructs and transmits an ICMP Echo Request, parses the IP header of the 
        Echo Reply to extract the initial hardware TTL.
        """
        icmp_proto = socket.getprotobyname("icmp")
        try:
            # Requires root (Linux) or Administrator (Windows) privileges
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto) as sock:
                sock.settimeout(self.timeout_sec)
                
                # Standard ICMP Echo Request Header (Type 8, Code 0, Checksum, ID, Seq)
                # Dummy payload for checksum calculation omission in this simplified block. 
                # (Assuming OS handles checksum or pre-calculated static header is used).
                packet_id = int(time.time() * 1000) & 0xFFFF
                header = struct.pack("!BBHHH", 8, 0, 0, packet_id, 1)
                
                # RFC 1071 Checksum calculation (omitted for density; assume standard implementation)
                checksum = self._calculate_checksum(header)
                header = struct.pack("!BBHHH", 8, 0, checksum, packet_id, 1)
                
                start_ns = time.perf_counter_ns()
                sock.sendto(header, (target_ip, 0))
                
                raw_data, addr = sock.recvfrom(1024)
                end_ns = time.perf_counter_ns()
                
                if addr[0] == target_ip:
                    # Unpack IP header (first 20 bytes) to extract returned TTL at byte index 8
                    ip_header = raw_data[:20]
                    ttl = ip_header[8]
                    
                    return {
                        "ip": target_ip,
                        "returned_ttl": ttl,
                        "rtt_ns": end_ns - start_ns
                    }
        except (socket.timeout, PermissionError, OSError) as e:
            logging.debug(f"[L3_ADAPTER] Interrogation failed for {target_ip}: {e}")
        
        return None

    def _calculate_checksum(self, source_string: bytes) -> int:
        """RFC 1071 ICMP checksum calculation."""
        sum = 0
        max_count = (len(source_string) // 2) * 2
        count = 0
        while count < max_count:
            val = source_string[count + 1] * 256 + source_string[count]
            sum = sum + val
            sum = sum & 0xffffffff
            count = count + 2
        if max_count < len(source_string):
            sum = sum + source_string[len(source_string) - 1]
            sum = sum & 0xffffffff
        sum = (sum >> 16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    async def interrogate_subnet(self, target_subnet: str) -> Dict[str, Any]:
        """
        Asynchronous interface implementation.
        Dispatches raw socket tasks to the thread pool and constructs the L3 matrix.
        """
        logging.info(f"[L3_ADAPTER] Commencing active L3 sweep on {target_subnet}")
        target_ips = self._expand_target_subnet(target_subnet)
        
        loop = asyncio.get_running_loop()
        
        # Fan-out execution across the thread pool
        tasks = [
            loop.run_in_executor(self._thread_pool, self._execute_raw_ping, ip)
            for ip in target_ips
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        ttl_matrix = {}
        for result in results:
            if isinstance(result, dict) and result is not None:
                ttl_matrix[result["ip"]] = {
                    "ttl": result["returned_ttl"],
                    "rtt_ns": result["rtt_ns"]
                }

        return {
            "l3_hop_intelligence": ttl_matrix
        }