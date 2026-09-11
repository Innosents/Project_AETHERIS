"""
GraphPath Master Application Command Line Interface & Entrypoint.
Optimized for clean signal-safe lifecycle management and zero path redundancy.
"""

import sys
import os
import time
import signal
import argparse
import threading
from loguru import logger

from graphpath.config import ConfigurationManager
from graphpath.core.discovery_engine import DiscoveryEngine
from graphpath.core.state_machine import DiscoveryStateMachine
from graphpath.ui.routes import graph
from graphpath.ui.server import start_ui_async

shutdown_event = threading.Event()

def signal_handler(signum, frame):
    logger.warning(f"[{signum}] Termination signal intercepted. Shutting down GraphPath execution engines safely...")
    shutdown_event.set()
    try:
        from graphpath.topology.graph_store import GraphStore
        GraphStore.close_all()
    except Exception:
        pass

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def parse_arguments(args=None):
    default_port = int(os.environ.get("GRAPHPATH_PORT", 8080))
    parser = argparse.ArgumentParser(
        prog="GraphPath",
        description="GraphPath: Autonomous Network Topology Discovery & Threat Modeling Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Operational Flags:
  --profile       Target specific network/OT environment profile (e.g. industrial_lab, corporate)
  --port          Specify interactive web dashboard port (default: 8080 or $GRAPHPATH_PORT)
  -h, --help      Show this help message and operational usage flags
"""
    )
    parser.add_argument(
        "--profile", "--env",
        dest="profile",
        default=None,
        help="Target environment profile or override (e.g. industrial_lab, home_lab, enterprise)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help=f"Web dashboard UI port (default: {default_port})"
    )
    return parser.parse_args(args)

def main():
    args = parse_arguments()
    port = args.port
    profile = args.profile

    logger.info("Initializing GraphPath dynamic network discovery engine...")
    config = ConfigurationManager(profile_name=profile)
    target_cidrs = getattr(config, "target_subnets", None) or ["127.0.0.1/32"]

    engine = DiscoveryEngine(graph=graph)
    state_machine = DiscoveryStateMachine(engine)

    start_ui_async(port=port)
    logger.success(f"Interactive Web Dashboard active on: http://localhost:{port}")
    logger.info(f"Execution targeting {len(target_cidrs)} network boundary tiers: {target_cidrs}")

    try:
        for cidr in target_cidrs:
            if shutdown_event.is_set():
                break
            logger.info(f"Initiating live discovery wave on boundary: {cidr}")
            graph.add_node(cidr, {
                "ip": "127.0.0.1",
                "mac": "FF:FF:FF:FF:FF:FF",
                "vendor": "Local Execution Station",
                "type": "server",
                "discovery_method": "core_system_initialization"
            })
            state_machine.execute(network_cidr=cidr)

        logger.success("Network Discovery pass completed successfully. Core engine active.")

        while not shutdown_event.is_set():
            shutdown_event.wait(timeout=1.0)

    except KeyboardInterrupt:
        pass
    finally:
        logger.info("GraphPath execution engines terminated safely.")
        try:
            from graphpath.topology.graph_store import GraphStore
            GraphStore.close_all()
        except Exception:
            pass
        sys.exit(0)

if __name__ == "__main__":
    main()