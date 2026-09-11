import paramiko
import re
from typing import Dict, Any
from graphpath.topology.graph_store import GraphStore

class LinuxEndpointCrawler:
    def __init__(self, graph_store: GraphStore, timeout: float = 1.5) -> None:
        self.graph = graph_store
        self.timeout = timeout

    def _execute_command(self, client: paramiko.SSHClient, command: str) -> str:
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            return stdout.read().decode(errors="ignore").strip()
        except Exception:
            return ""

    def crawl_linux_server(self, ip: str, credentials: Dict[str, str]) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        username = credentials.get("username", "admin")
        password = credentials.get("password", "")

        try:
            print(f"[Tier 2 Linux] Attempting SSH authentication to {ip}...")
            client.connect(
                hostname=ip,
                port=22,
                username=username,
                password=password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            print(f"[+] Authenticated to Linux server: {ip}")

            telemetry = {
                "type": "server",
                "os": "Linux",
                "discovery_method": "tier_2_linux_ssh"
            }

            # 1. OS & Distribution
            os_release = self._execute_command(client, "cat /etc/os-release")
            pretty_name = re.search(r'PRETTY_NAME="([^"]+)"', os_release)
            if pretty_name:
                telemetry["os_version"] = pretty_name.group(1)
            else:
                telemetry["os_version"] = self._execute_command(client, "uname -srm")

            # 2. Hardware / Memory
            mem_info = self._execute_command(client, "free -m | grep Mem")
            if mem_info:
                parts = mem_info.split()
                if len(parts) >= 2:
                    telemetry["total_ram_mb"] = parts[1]

            # 3. Running Services (Listening Ports)
            ss_out = self._execute_command(client, "ss -tulpn | grep LISTEN")
            services = []
            for line in ss_out.splitlines():
                if not line.strip(): continue
                # Parse output like: tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))
                match = re.search(r'(:[0-9]+)\s+.*users:\(\("([^"]+)"', line)
                if match:
                    port = match.group(1).replace(':', '')
                    app = match.group(2)
                    services.append(f"{app}:{port}")
            if services:
                telemetry["running_services"] = ", ".join(list(set(services)))

            # 4. Expand Topology (ARP cache)
            arp_out = self._execute_command(client, "arp -a")
            for line in arp_out.splitlines():
                # Format: ? (10.10.7.50) at aa:bb:cc:dd:ee:ff [ether] on eth0
                match = re.search(r'\(([\d\.]+)\) at ([0-9a-fA-F:]+)', line)
                if match:
                    neighbor_ip, neighbor_mac = match.group(1), match.group(2).upper()
                    if neighbor_mac != "00:00:00:00:00:00":
                        # Register the neighbor node
                        self.graph.add_node(neighbor_ip, {
                            "ip": neighbor_ip,
                            "mac": neighbor_mac,
                            "discovery_method": "linux_arp_cache"
                        })
                        # Draw an edge mapping the server's broadcast domain
                        self.graph.add_edge(ip, neighbor_ip, {
                            "layer": 3,
                            "method": "linux_arp_cache"
                        })

            # Update the graph with the rich Linux telemetry
            self.graph.add_node(ip, telemetry)
            print(f" [✓] Profiled Linux Server {ip}: {telemetry.get('os_version', 'Unknown')}")
            if "running_services" in telemetry:
                print(f"     Services: {telemetry['running_services']}")

        except paramiko.AuthenticationException:
            print(f"[Tier 2 Linux] Auth failed on host {ip}")
        except Exception as e:
            print(f"[Tier 2 Linux] Failed to crawl {ip}: {e}")
        finally:
            client.close()

def run_linux_crawler(graph_store: GraphStore, targets: list, credentials: Dict[str, str]) -> None:
    crawler = LinuxEndpointCrawler(graph_store)
    for ip in targets:
        crawler.crawl_linux_server(ip, credentials)

