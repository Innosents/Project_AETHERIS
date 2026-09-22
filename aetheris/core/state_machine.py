"""
Project AETHERIS - Core Discovery State Machine
Thread-safe, non-reentrant state orchestrator for multi-tier discovery.
"""

import threading
from typing import Any
from loguru import logger

from aetheris.core.ports.state_machine_port import DiscoveryStateMachinePort


class DiscoveryStateMachine(DiscoveryStateMachinePort):
    def __init__(self, engine: Any) -> None:
        self.engine = engine
        self._lock = threading.Lock()
        self.is_executing = False

    def execute(self, network_cidr: str = "192.168.1.0/24") -> bool:
        if not self._lock.acquire(blocking=False):
            logger.warning(f"[StateMachine] Sweep already active for: {network_cidr}")
            return False

        try:
            self.is_executing = True
            logger.info(f"[StateMachine] Initiating coordinated infrastructure sweep: {network_cidr}")

            try:
                self.engine.run_basic_sweep(network_cidr=network_cidr)
            except Exception as e:
                logger.error(f"[StateMachine Error] Active sweeping failed: {e}")

            try:
                self.engine.graph.reconcile_topology()
                logger.success("[StateMachine] Topology graph reconciled successfully.")
            except Exception as e:
                logger.error(f"[StateMachine Error] Topology reconciliation failed: {e}")

            return True
        finally:
            self.is_executing = False
            self._lock.release()