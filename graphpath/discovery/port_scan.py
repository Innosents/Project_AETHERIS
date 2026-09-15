"""
Project AETHERIS - High-Performance Port Scanner & Common Ports Repository
"""

import socket
import concurrent.futures
from typing import List, Tuple, Dict, Any

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 502, 554, 
    631, 993, 995, 1433, 1521, 3306, 3389, 5060, 5432, 5985, 5986, 8080, 8443, 37777, 44818
]

def scan_single_port(ip: str, port: int, timeout: float = 0.4) -> Tuple[int, bool]:
    """Tests if a single TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return port, (result == 0)
    except Exception:
        return port, False

def scan_ports_with_status(ip: str, ports: List[int] = COMMON_PORTS, timeout: float = 0.4, max_workers: int = 50) -> Tuple[List[int], str]:
    """Scans a list of ports concurrently and returns open ports and scan status."""
    open_ports = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_single_port, ip, p, timeout): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
        return sorted(open_ports), "completed"
    except Exception:
        return [], "failed"