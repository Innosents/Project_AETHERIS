"""
Project AETHERIS - Traffic Matrix & Dependency Flow Engine
Subsystem II Bleeding-Edge Refactor.

Aggregates packet streams into directional conversation pairs, computes flow statistics,
identifies top talkers, and infers client-server roles based on traffic patterns.

Refactored to 32-way sharded, lock-free hash partitioning with background sliding-window
LRU flow eviction to eliminate global mutex contention under high-throughput capture.
"""

from __future__ import annotations
import threading
import time
from collections import OrderedDict
from typing import Dict, Any, List, Optional, Tuple, Set

from aetheris.core.ports.traffic_matrix_port import (
    TrafficMatrixPort,
    TrafficRoleClassifierPort,
)

try:
    from aetheris.discovery.geolocation_engine import LldpMedLocationDecoder
except ImportError:
    try:
        from discovery.geolocation_engine import LldpMedLocationDecoder
    except ImportError:
        LldpMedLocationDecoder = None


class ShardedCivicCache:
    """
    32-partition LRU lookaside cache mapping IP addresses to LLDP-MED Civic Address vectors.
    Partitioning eliminates mutex contention under concurrent packet ingestion across worker threads.
    """

    def __init__(self, num_shards: int = 32, max_entries_per_shard: int = 1024):
        self.num_shards = num_shards
        self.max_entries_per_shard = max_entries_per_shard
        self._locks = [threading.Lock() for _ in range(num_shards)]
        self._partitions: List[OrderedDict[str, Dict[str, Any]]] = [
            OrderedDict() for _ in range(num_shards)
        ]

    def _get_shard_idx(self, ip: str) -> int:
        return hash(ip) % self.num_shards

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached civic vector for given IP with LRU promotion under localized partition lock."""
        if not ip:
            return None
        shard_idx = self._get_shard_idx(ip)
        with self._locks[shard_idx]:
            partition = self._partitions[shard_idx]
            if ip in partition:
                partition.move_to_end(ip)
                return dict(partition[ip])
            return None

    def set(self, ip: str, civic: Dict[str, Any]) -> None:
        """Stores or updates civic vector for given IP with LRU eviction under localized partition lock."""
        if not ip or not isinstance(civic, dict):
            return
        shard_idx = self._get_shard_idx(ip)
        with self._locks[shard_idx]:
            partition = self._partitions[shard_idx]
            if ip in partition:
                partition.move_to_end(ip)
                partition[ip] = dict(civic)
            else:
                if len(partition) >= self.max_entries_per_shard:
                    partition.popitem(last=False)
                partition[ip] = dict(civic)

    def clear(self) -> None:
        """Flushes all civic cache partitions."""
        for i in range(self.num_shards):
            with self._locks[i]:
                self._partitions[i].clear()

    def size(self) -> int:
        """Returns total entries across all partitions."""
        total = 0
        for i in range(self.num_shards):
            with self._locks[i]:
                total += len(self._partitions[i])
        return total

    def all_entries(self) -> Dict[str, Dict[str, Any]]:
        """Returns a snapshot of all cached IP to civic vector mappings."""
        combined: Dict[str, Dict[str, Any]] = {}
        for i in range(self.num_shards):
            with self._locks[i]:
                combined.update(dict(self._partitions[i]))
        return combined


class TrafficFlowShard:
    """Independent traffic flow bucket with isolated lock scope."""

    def __init__(self, max_flows: int):
        self.lock = threading.Lock()
        self.max_flows = max_flows
        # Key: (src_ip, dst_ip, port, proto) -> Flow Entry
        self.flows: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}
        # Per-host statistics within this shard
        self.host_stats: Dict[str, Dict[str, int]] = {}

    def evict_oldest(self, count: int = 50) -> None:
        """Evicts oldest flows within this shard."""
        if len(self.flows) <= self.max_flows:
            return
        sorted_keys = sorted(
            self.flows.keys(),
            key=lambda k: self.flows[k].get("last_seen", 0)
        )
        for k in sorted_keys[:count]:
            flow = self.flows.pop(k, None)
            if flow:
                src = flow.get("src_ip")
                dst = flow.get("dst_ip")
                if src and src in self.host_stats and self.host_stats[src]["conns_out"] > 0:
                    self.host_stats[src]["conns_out"] -= 1
                if dst and dst in self.host_stats and self.host_stats[dst]["conns_in"] > 0:
                    self.host_stats[dst]["conns_in"] -= 1

    def prune_expired(self, cutoff_time: float) -> int:
        """Removes flows not seen since cutoff_time."""
        expired = [
            k for k, flow in self.flows.items()
            if flow.get("last_seen", 0) < cutoff_time
        ]
        for k in expired:
            flow = self.flows.pop(k, None)
            if flow:
                src = flow.get("src_ip")
                dst = flow.get("dst_ip")
                if src and src in self.host_stats and self.host_stats[src]["conns_out"] > 0:
                    self.host_stats[src]["conns_out"] -= 1
                if dst and dst in self.host_stats and self.host_stats[dst]["conns_in"] > 0:
                    self.host_stats[dst]["conns_in"] -= 1
        return len(expired)


class TrafficMatrixTracker(TrafficMatrixPort):
    """
    High-throughput collector for Layer 4-7 traffic flows and node conversation metrics.
    Partitions flows across 32 independent shards to eliminate cross-thread lock contention.
    Enriched with 32-partition LRU lookaside civic address caching and physical spatial vector tracking.
    """

    NUM_SHARDS: int = 32

    def __init__(self, max_flows: int = 50000, flow_ttl_seconds: float = 3600.0):
        self.max_flows = max_flows
        self.flow_ttl_seconds = flow_ttl_seconds
        self._lock = threading.RLock()  # Backward compatibility reentrant lock

        shard_capacity = max(100, max_flows // self.NUM_SHARDS)
        self._shards: List[TrafficFlowShard] = [
            TrafficFlowShard(max_flows=shard_capacity) for _ in range(self.NUM_SHARDS)
        ]
        self._civic_cache = ShardedCivicCache(
            num_shards=self.NUM_SHARDS,
            max_entries_per_shard=1024
        )

        # Background eviction daemon
        self._stop_eviction = threading.Event()
        self._eviction_thread = threading.Thread(
            target=self._eviction_worker,
            name="TrafficMatrix-EvictionWorker",
            daemon=True
        )
        self._eviction_thread.start()

    def stop(self) -> None:
        """Signals background eviction thread to terminate."""
        self._stop_eviction.set()

    def _get_shard(self, flow_key: Tuple[str, str, int, str]) -> TrafficFlowShard:
        """Hash partitions connection 4-tuple to designated shard."""
        shard_idx = hash(flow_key) % self.NUM_SHARDS
        return self._shards[shard_idx]

    def _eviction_worker(self) -> None:
        """Background worker periodically trimming expired flows across shards."""
        while not self._stop_eviction.wait(timeout=5.0):
            cutoff = time.time() - self.flow_ttl_seconds
            for shard in self._shards:
                with shard.lock:
                    shard.prune_expired(cutoff)

    def register_civic_location(self, ip: str, civic: Dict[str, Any]) -> None:
        """Registers or updates decoded LLDP-MED civic location for an IP address into lookaside cache."""
        if not ip or not isinstance(civic, dict):
            return
        if LldpMedLocationDecoder:
            norm_civic = LldpMedLocationDecoder.normalize_civic_address(civic)
        else:
            norm_civic = dict(civic)
        self._civic_cache.set(ip, norm_civic)

    def get_civic_location(self, ip: str) -> Optional[Dict[str, Any]]:
        """Retrieves cached civic location vector for an IP address."""
        return self._civic_cache.get(ip)

    def clear_civic_cache(self) -> None:
        """Flushes all entries from lookaside civic cache."""
        self._civic_cache.clear()

    @property
    def flows(self) -> Dict[Tuple[str, str, int, str], Dict[str, Any]]:
        """Aggregates all active flows across all shards for backward-compatible read access."""
        aggregated: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}
        for shard in self._shards:
            with shard.lock:
                aggregated.update(shard.flows)
        return aggregated

    @property
    def host_stats(self) -> Dict[str, Dict[str, int]]:
        """Aggregates per-host statistics across all shards."""
        combined: Dict[str, Dict[str, int]] = {}
        for shard in self._shards:
            with shard.lock:
                for ip, stats in shard.host_stats.items():
                    if ip not in combined:
                        combined[ip] = {
                            "tx_packets": 0,
                            "tx_bytes": 0,
                            "rx_packets": 0,
                            "rx_bytes": 0,
                            "conns_out": 0,
                            "conns_in": 0
                        }
                    target = combined[ip]
                    target["tx_packets"] += stats.get("tx_packets", 0)
                    target["tx_bytes"] += stats.get("tx_bytes", 0)
                    target["rx_packets"] += stats.get("rx_packets", 0)
                    target["rx_bytes"] += stats.get("rx_bytes", 0)
                    target["conns_out"] += stats.get("conns_out", 0)
                    target["conns_in"] += stats.get("conns_in", 0)
        return combined

    def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
        proto: str,
        byte_count: int = 0,
        app_proto: str = "",
        domain: str = "",
        hostname: str = "",
        src_civic: Optional[Dict[str, Any]] = None,
        dst_civic: Optional[Dict[str, Any]] = None,
        latency_us: float = 0.0
    ) -> None:
        """
        Records an active packet flow between two endpoints into designated shard.
        Acquires only the localized shard lock, guaranteeing zero lock contention
        across disparate connection hashes.
        Enriches flow with LLDP-MED civic location vectors and evaluates spatial anomalies.
        """
        if not src_ip or not dst_ip or src_ip == dst_ip:
            return

        # 1. Update / retrieve civic vectors via zero-lock sharded lookaside cache
        if src_civic and isinstance(src_civic, dict):
            if LldpMedLocationDecoder:
                src_civic = LldpMedLocationDecoder.normalize_civic_address(src_civic)
            self._civic_cache.set(src_ip, src_civic)
        else:
            src_civic = self._civic_cache.get(src_ip)

        if dst_civic and isinstance(dst_civic, dict):
            if LldpMedLocationDecoder:
                dst_civic = LldpMedLocationDecoder.normalize_civic_address(dst_civic)
            self._civic_cache.set(dst_ip, dst_civic)
        else:
            dst_civic = self._civic_cache.get(dst_ip)

        # 2. Compute spatial physical vector if both civic endpoints are known
        physical_vector = None
        spatial_flags: List[str] = []
        if src_civic and dst_civic and LldpMedLocationDecoder:
            physical_vector = LldpMedLocationDecoder.compute_physical_vector(
                src_civic=src_civic,
                dst_civic=dst_civic,
                latency_us=latency_us,
                byte_count=byte_count
            )
            spatial_flags = physical_vector.get("flags", [])

        flow_key = (src_ip, dst_ip, port, proto)
        shard = self._get_shard(flow_key)
        now = time.time()

        with shard.lock:
            is_new_flow = flow_key not in shard.flows
            if is_new_flow:
                if len(shard.flows) >= shard.max_flows:
                    shard.evict_oldest(max(10, int(shard.max_flows * 0.1)))
                shard.flows[flow_key] = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": port,
                    "proto": proto,
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": now,
                    "last_seen": now,
                    "app_proto": app_proto,
                    "domain": domain,
                    "hostname": hostname,
                    "src_civic": src_civic,
                    "dst_civic": dst_civic,
                    "physical_vector": physical_vector,
                    "spatial_flags": list(spatial_flags),
                    "latency_us": float(latency_us)
                }

            entry = shard.flows[flow_key]
            entry["packets"] += 1
            entry["bytes"] += byte_count
            entry["last_seen"] = now
            if app_proto and not entry["app_proto"]:
                entry["app_proto"] = app_proto
            if domain and not entry["domain"]:
                entry["domain"] = domain
            if hostname and not entry["hostname"]:
                entry["hostname"] = hostname
            if latency_us > 0:
                entry["latency_us"] = float(latency_us)

            # Re-evaluate or update physical spatial vector if newly available
            if src_civic and not entry.get("src_civic"):
                entry["src_civic"] = src_civic
            if dst_civic and not entry.get("dst_civic"):
                entry["dst_civic"] = dst_civic

            eff_src = entry.get("src_civic") or src_civic
            eff_dst = entry.get("dst_civic") or dst_civic
            if eff_src and eff_dst and LldpMedLocationDecoder:
                eff_lat = float(latency_us) if latency_us > 0 else float(entry.get("latency_us", 0.0))
                pv = LldpMedLocationDecoder.compute_physical_vector(
                    src_civic=eff_src,
                    dst_civic=eff_dst,
                    latency_us=eff_lat,
                    byte_count=entry["bytes"]
                )
                entry["physical_vector"] = pv
                entry["spatial_flags"] = pv.get("flags", [])

            # Update localized host statistics
            if src_ip not in shard.host_stats:
                shard.host_stats[src_ip] = {
                    "tx_packets": 0, "tx_bytes": 0, "rx_packets": 0, "rx_bytes": 0,
                    "conns_out": 0, "conns_in": 0
                }
            if dst_ip not in shard.host_stats:
                shard.host_stats[dst_ip] = {
                    "tx_packets": 0, "tx_bytes": 0, "rx_packets": 0, "rx_bytes": 0,
                    "conns_out": 0, "conns_in": 0
                }

            shard.host_stats[src_ip]["tx_packets"] += 1
            shard.host_stats[src_ip]["tx_bytes"] += byte_count

            shard.host_stats[dst_ip]["rx_packets"] += 1
            shard.host_stats[dst_ip]["rx_bytes"] += byte_count

            # Only increment connection tallies on discrete new flow allocation,
            # not per-packet. After TTL eviction, re-seen 4-tuples re-allocate.
            if is_new_flow:
                shard.host_stats[src_ip]["conns_out"] += 1
                shard.host_stats[dst_ip]["conns_in"] += 1

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns top communicating hosts by total bytes transmitted across all shards."""
        stats = self.host_stats
        sorted_hosts = sorted(
            stats.items(),
            key=lambda item: item[1]["tx_bytes"] + item[1]["rx_bytes"],
            reverse=True
        )
        return [
            {"ip": ip, **h_stats, "total_bytes": h_stats["tx_bytes"] + h_stats["rx_bytes"]}
            for ip, h_stats in sorted_hosts[:limit]
        ]

    def get_spatial_flows(self) -> List[Dict[str, Any]]:
        """Returns all active flows across shards that contain physical spatial vectors."""
        results = []
        for shard in self._shards:
            with shard.lock:
                for flow in shard.flows.values():
                    if flow.get("physical_vector") is not None:
                        results.append(dict(flow))
        return results

    def get_flagged_flows(self, flag_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns all active flows with spatial anomaly flags (e.g., tromboning, perimeter breach)."""
        results = []
        for shard in self._shards:
            with shard.lock:
                for flow in shard.flows.values():
                    flags = flow.get("spatial_flags", [])
                    if flags:
                        if flag_filter is None or flag_filter in flags:
                            results.append(dict(flow))
        return results

    def get_conversation_edges(self) -> List[Dict[str, Any]]:
        """
        Aggregates flows across all shards into directional node-to-node graph edges
        suitable for Cytoscape / D3 canvas visualization.
        """
        edges_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for shard in self._shards:
            with shard.lock:
                for (src_ip, dst_ip, port, proto), flow in shard.flows.items():
                    pair_key = (src_ip, dst_ip)
                    if pair_key not in edges_map:
                        edges_map[pair_key] = {
                            "source": src_ip,
                            "target": dst_ip,
                            "packets": 0,
                            "bytes": 0,
                            "ports": set(),
                            "protocols": set(),
                            "app_protocols": set()
                        }
                    e = edges_map[pair_key]
                    e["packets"] += flow["packets"]
                    e["bytes"] += flow["bytes"]
                    e["ports"].add(port)
                    e["protocols"].add(proto)
                    if flow.get("app_proto"):
                        e["app_protocols"].add(flow["app_proto"])

        result = []
        for (src, dst), e in edges_map.items():
            result.append({
                "source": src,
                "target": dst,
                "packets": e["packets"],
                "bytes": e["bytes"],
                "ports": sorted(list(e["ports"])),
                "protocols": sorted(list(e["protocols"])),
                "app_protocols": sorted(list(e["app_protocols"]))
            })
        return result

    def get_summary(self) -> Dict[str, Any]:
        """Returns summary metadata of tracked traffic flows across all shards."""
        total_flows = 0
        total_pkts = 0
        total_bytes = 0
        spatial_flows = 0
        flagged_flows = 0

        for shard in self._shards:
            with shard.lock:
                total_flows += len(shard.flows)
                for f in shard.flows.values():
                    total_pkts += f["packets"]
                    total_bytes += f["bytes"]
                    if f.get("physical_vector") is not None:
                        spatial_flows += 1
                    if f.get("spatial_flags"):
                        flagged_flows += 1

        return {
            "active_flows_count": total_flows,
            "tracked_hosts_count": len(self.host_stats),
            "total_packets": total_pkts,
            "total_bytes": total_bytes,
            "civic_cache_size": self._civic_cache.size(),
            "spatial_flows_count": spatial_flows,
            "flagged_flows_count": flagged_flows
        }


class TrafficRoleClassifier(TrafficRoleClassifierPort):
    """Classifies node functional role based on ingress/egress conversation ratios and port behavior."""

    @staticmethod
    def infer_role(ip: str, matrix: TrafficMatrixTracker) -> Dict[str, Any]:
        """
        Analyzes inbound vs outbound connections to infer if an IP is an
        Application Server, Database, Domain Controller, or Workstation.
        """
        with matrix._lock:
            stats = matrix.host_stats.get(ip, {})
            conns_in = stats.get("conns_in", 0)
            conns_out = stats.get("conns_out", 0)

            inbound_ports: Set[int] = set()
            for shard in matrix._shards:
                with shard.lock:
                    for (src, dst, port, proto) in shard.flows.keys():
                        if dst == ip:
                            inbound_ports.add(port)

        inbound_ratio = conns_in / max(1, (conns_in + conns_out))

        if 53 in inbound_ports or 389 in inbound_ports or 88 in inbound_ports:
            return {"role": "Domain Controller / DNS Server", "type": "server", "confidence": 0.95}
        elif 3306 in inbound_ports or 5432 in inbound_ports or 1433 in inbound_ports:
            return {"role": "Database Server", "type": "server", "confidence": 0.9}
        elif 80 in inbound_ports or 443 in inbound_ports or 8443 in inbound_ports:
            return {"role": "Web / Application Server", "type": "server", "confidence": 0.85}
        elif 5060 in inbound_ports or 5061 in inbound_ports:
            return {"role": "VoIP PBX / SIP Core", "type": "voip_pbx", "confidence": 0.9}
        elif 502 in inbound_ports or 44818 in inbound_ports or 102 in inbound_ports:
            return {"role": "Industrial PLC / Controller", "type": "plc", "confidence": 0.9}
        elif inbound_ratio > 0.75 and conns_in >= 5:
            return {"role": "Infrastructure Server", "type": "server", "confidence": 0.75}
        elif conns_out > 0:
            return {"role": "Client Workstation / Endpoint", "type": "workstation", "confidence": 0.7}

        return {"role": "Network Endpoint", "type": "unknown", "confidence": 0.5}
