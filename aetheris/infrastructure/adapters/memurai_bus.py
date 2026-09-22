import asyncio
import json
import logging
from typing import Any, Dict, Optional, Tuple
from redis.asyncio import ConnectionPool, Redis
from redis.exceptions import ConnectionError, TimeoutError

logger = logging.getLogger("aetheris.infrastructure.event_bus")


class MemuraiEventBus:
    """
    High-velocity asynchronous event bus adapter interfacing with native Memurai.
    Decouples raw packet ingestion adapters from the Aethelred inference core.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        db: int = 0,
        max_connections: int = 20,
        socket_timeout: float = 5.0,
    ):
        self.redis_url = f"redis://{host}:{port}/{db}"
        self.pool: Optional[ConnectionPool] = None
        self.client: Optional[Redis] = None
        self.max_connections = max_connections
        self.socket_timeout = socket_timeout

    async def connect(self) -> None:
        """Initializes the thread-safe asynchronous connection pool."""
        if not self.pool:
            self.pool = ConnectionPool.from_url(
                self.redis_url,
                max_connections=self.max_connections,
                decode_responses=True,
                socket_timeout=self.socket_timeout,
                socket_connect_timeout=self.socket_timeout,
            )
            self.client = Redis(connection_pool=self.pool)
            
        # Verify socket availability
        try:
            await self.client.ping()
            logger.info("Connected to Memurai event bus at %s", self.redis_url)
        except (ConnectionError, TimeoutError) as exc:
            logger.error("Failed to connect to Memurai service: %s", exc)
            raise

    async def push_telemetry(self, queue_name: str, payload: Dict[str, Any]) -> int:
        """
        Pushes serializable payload to the tail of the specified buffer (RPUSH).
        Used by raw Npcap crawlers and probers.
        """
        if not self.client:
            raise RuntimeError("Event bus is not initialized. Call connect() first.")
        
        raw_data = json.dumps(payload)
        return await self.client.rpush(queue_name, raw_data)

    async def pop_telemetry(
        self, queue_name: str, timeout: int = 0
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Blocking pop from head of queue (BLPOP) for deterministic inference consumption.
        Zero timeout blocks indefinitely until data arrives.
        """
        if not self.client:
            raise RuntimeError("Event bus is not initialized. Call connect() first.")

        result = await self.client.blpop([queue_name], timeout=timeout)
        if result is None:
            return None

        channel, raw_payload = result
        return channel, json.loads(raw_payload)

    async def publish_event(self, channel: str, message: Dict[str, Any]) -> int:
        """PubSub fan-out for global notifications and state broadcast."""
        if not self.client:
            raise RuntimeError("Event bus is not initialized. Call connect() first.")
        return await self.client.publish(channel, json.dumps(message))

    async def disconnect(self) -> None:
        """Flushes remaining handles and closes the connection pool."""
        if self.client:
            await self.client.aclose()
        if self.pool:
            await self.pool.disconnect()
        logger.info("Memurai connection pool terminated cleanly.")