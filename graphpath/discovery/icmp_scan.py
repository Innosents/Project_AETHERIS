import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import List

def ping_host_native(ip: str) -> bool:
    """
    Executes an OS-validated native ICMP echo lookup block.
    Cross-platform safe configuration for both Windows and Unix execution targets.
    """
    try:
        # Determine host system OS matrix dynamically
        if sys.platform.startswith("win"):
            # Windows: -n (count), -w (timeout in ms)
            cmd = ["ping", "-n", "1", "-w", "300", ip]
        else:
            # Unix/Linux: -c (count), -W (timeout in seconds)
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return proc.returncode == 0
    except Exception:
        return False

def icmp_sweep(hosts: List[str], max_workers: int = 60) -> List[str]:
    """Executes an optimized high-density network sweep using native OS threads."""
    reachable_ips = []
    
    # Maximize thread pool utilization for fast subnet discoveries
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(ping_host_native, hosts)
        for ip, is_active in zip(hosts, results):
            if is_active:
                reachable_ips.append(ip)
                print(f"[Tier 4 Diagnostics] Discovered live active subnet node: {ip}")
                
    return reachable_ips