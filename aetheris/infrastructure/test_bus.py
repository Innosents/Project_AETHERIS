import asyncio
from aetheris.infrastructure.adapters.memurai_bus import MemuraiEventBus

QUEUE = "aetheris:telemetry:bayesian_states"


async def main():
    bus = MemuraiEventBus()
    await bus.connect()

    # Produce synthetic packet metric
    test_packet = {
        "hardware_id": "00:1A:2B:3C:4D:5E",
        "splice_probability": 0.94,
        "spatial_jitter_ms": 3.12,
    }
    await bus.push_telemetry(QUEUE, test_packet)
    print(f"[PRODUCER] Ingested packet telemetry to {QUEUE}")

    # Consume immediately via BLPOP
    channel, consumed = await bus.pop_telemetry(QUEUE, timeout=2)
    print(f"[CONSUMER] Extracted from {channel}: {consumed}")

    await bus.disconnect()

if __name__ == "__main__":
    asyncio.run(main())