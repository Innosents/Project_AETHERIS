import redis
import logging
from typing import List, Optional

class TelemetryLedgerAdapter:
    """
    Infrastructure Adapter for Redis telemetry streams.
    Isolates all network I/O, connection pooling, and byte-decoding logic 
    from the Bayesian mathematical domain.
    """

    def __init__(self, redis_uri: str = "redis://localhost:6379/0"):
        # Enforce strict connection pooling to prevent ephemeral port exhaustion 
        # during high-frequency hardware execution loops.
        self.pool = redis.ConnectionPool.from_url(
            redis_uri, 
            decode_responses=True, 
            max_connections=50,
            socket_timeout=2.0
        )
        self.client = redis.Redis(connection_pool=self.pool)

    def get_raw_nanosecond_flight_times(self, mac: str, sample_size: int = 50) -> List[float]:
        """
        Extracts the most recent nanosecond flight times (tau) for a given MAC address.
        Guarantees the Bayesian solver receives a pure Python List[float].
        """
        normalized_mac = str(mac).strip().lower()
        redis_key = f"aetheris:telemetry:tau_ns:{normalized_mac}"
        
        try:
            # LINDEX/LRANGE fetch targeting the tail of the list for the most recent convergence data
            raw_samples = self.client.lrange(redis_key, -sample_size, -1)
            
            if not raw_samples:
                return []

            # Cleanly decode and cast strictly to floats, discarding corrupted pipeline frames
            parsed_samples = []
            for sample in raw_samples:
                try:
                    parsed_samples.append(float(sample))
                except (ValueError, TypeError):
                    logging.warning(f"[REDIS_DECODE_FAULT] Corrupted tau frame on {redis_key}: {sample}")
                    continue
                    
            return parsed_samples

        except redis.RedisError as e:
            logging.error(f"[REDIS_IO_FAULT] Pipeline extraction failed for {normalized_mac}: {e}")
            return []

    def inject_flight_time_telemetry(self, mac: str, tau_ns: float, max_stream_length: int = 100) -> None:
        """
        Write-path adapter for the orchestrator to push live PCAP tau calculations into Redis.
        Enforces a strict O(1) LTRIM to prevent memory leaks in the telemetry ledger.
        """
        normalized_mac = str(mac).strip().lower()
        redis_key = f"aetheris:telemetry:tau_ns:{normalized_mac}"
        
        try:
            pipeline = self.client.pipeline()
            pipeline.rpush(redis_key, str(tau_ns))
            pipeline.ltrim(redis_key, -max_stream_length, -1)
            # Optional: Enforce an absolute key TTL to purge stale hardware artifacts after 24h
            pipeline.expire(redis_key, 86400) 
            pipeline.execute()
        except redis.RedisError as e:
            logging.error(f"[REDIS_IO_FAULT] Telemetry injection failed for {normalized_mac}: {e}")
            
    def flush_ledger(self) -> None:
        """Emergency teardown hook to clear ephemeral telemetry during testbed resets."""
        try:
            keys = self.client.keys("aetheris:telemetry:tau_ns:*")
            if keys:
                self.client.delete(*keys)
        except redis.RedisError as e:
            logging.error(f"[REDIS_IO_FAULT] Ledger flush failed: {e}")