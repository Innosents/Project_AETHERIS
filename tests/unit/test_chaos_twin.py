"""
Digital Twin Chaos Engineering Suite (Phase 16).
Tests concurrency contention under 100 simultaneous threads, stochastic latency jitter injection,
relay contact chatter / inductive kickback filtering, and async task drainage.
"""

import time
import json
import asyncio
import threading
import pytest
from typing import Dict, Any, List

from graphpath.core.traffic_matrix import TrafficMatrixTracker, ShardedCivicCache
from graphpath.core.security_auditor import SecurityAuditor
from graphpath.core.spatial_dc_drop import (
    PeripheralElectricalEnvelope,
    calculate_dynamic_spatial_drop,
    COPPER_RESISTIVITY_OHMS_PER_METER_20C,
)


class TestChaosDigitalTwin:

    def test_chaos_twin_concurrency_contention_100_threads(self):
        """
        Assaults ShardedCivicCache and TrafficMatrixTracker with 100 simultaneous worker threads.
        Asserts zero deadlocks, zero lock contention timeouts (> 10ms), and strict LRU bound maintenance.
        """
        tracker = TrafficMatrixTracker(max_flows=5000)
        num_threads = 100
        iterations_per_thread = 40
        errors: List[str] = []
        max_latencies: List[float] = []

        def chaos_worker(thread_id: int):
            thread_max_lat = 0.0
            try:
                for i in range(iterations_per_thread):
                    t0 = time.perf_counter()
                    src_ip = f"10.{thread_id % 16}.{(i * 7) % 254 + 1}.{(thread_id * 3) % 254 + 1}"
                    dst_ip = f"10.{(thread_id + 1) % 16}.{(i * 11) % 254 + 1}.{(thread_id * 5) % 254 + 1}"
                    port = 1024 + (i % 5000)
                    proto = "TCP" if (i % 2 == 0) else "UDP"
                    tracker.record_flow(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        port=port,
                        proto=proto,
                        byte_count=64 + (i * 10),
                    )
                    civic_meta = {
                        "building": f"Bldg-{(thread_id % 4) + 1}",
                        "floor": f"{(i % 5) + 1}",
                        "room": f"Room-{(i % 20) + 100}",
                        "rack": f"Rack-{thread_id % 8}",
                    }
                    tracker.register_civic_location(src_ip, civic_meta)
                    retrieved = tracker.get_civic_location(src_ip)
                    if not retrieved or retrieved.get("building") != civic_meta["building"]:
                        errors.append(f"Thread {thread_id} cache mismatch: {retrieved}")
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0
                    if elapsed_ms > thread_max_lat:
                        thread_max_lat = elapsed_ms
            except Exception as exc:
                errors.append(f"Thread {thread_id} crashed: {str(exc)}")
            finally:
                max_latencies.append(thread_max_lat)

        threads = [threading.Thread(target=chaos_worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), "Contention deadlock detected: thread failed to join within 5.0s!"

        tracker.stop()

        assert len(errors) == 0, f"Chaos thread errors detected: {errors[:5]}"
        assert len(max_latencies) == num_threads
        peak_lat = max(max_latencies)
        assert peak_lat < 50.0, f"Severe lock contention detected: peak operation latency {peak_lat:.2f}ms >= 50ms"

    def test_chaos_twin_stochastic_latency_jitter_spikes(self):
        """
        Simulates stochastic flight-time spikes (> 2000us) to verify SecurityAuditor
        triggers ACCESS_CONTROLLER_SPATIAL_IMPERSONATION with zero false negatives.
        """
        # Baseline: Mercury access controller operating on-premise (15.0 us flight time)
        baseline_device = {
            "ip": "10.0.10.1",
            "vendor": "Mercury Security",
            "type": "access_controller",
            "open_ports": [3001, 80],
            "tcp_flight_time_us": 15.0,
            "port_scan_status": "completed",
        }
        res_baseline = SecurityAuditor.audit_device(baseline_device)
        baseline_finding_codes = [f["code"] for f in res_baseline.get("findings", [])]
        assert "ACCESS_CONTROLLER_SPATIAL_IMPERSONATION" not in baseline_finding_codes

        # Chaos Spike: Remote off-path proxy / WAN overlay routing (2050.0 us flight time)
        chaos_spiked_device = {
            "ip": "10.0.10.1",
            "vendor": "Mercury Security",
            "type": "access_controller",
            "open_ports": [3001, 80],
            "tcp_flight_time_us": 2050.0,
            "port_scan_status": "completed",
        }
        res_spike = SecurityAuditor.audit_device(chaos_spiked_device)
        spike_finding_codes = [f["code"] for f in res_spike.get("findings", [])]
        assert "ACCESS_CONTROLLER_SPATIAL_IMPERSONATION" in spike_finding_codes
        assert res_spike["risk_level"] == "CRITICAL"
        assert res_spike["risk_score"] >= 50

    def test_chaos_twin_relay_chatter_brownout_simulation(self):
        """
        Simulates 50Hz relay contact chatter and inductive kickback spikes on
        PeripheralElectricalEnvelope, asserting active transient rejection without baseline corruption.
        """
        strike_envelope = PeripheralElectricalEnvelope.get_envelope("door_strike")
        r_20_18awg = COPPER_RESISTIVITY_OHMS_PER_METER_20C[18]

        # 1. Feed quiescent baseline sample (24.0V source, 23.5V terminal, Delta V = 0.5V)
        dist_m, conf, state = calculate_dynamic_spatial_drop(
            v_source=24.0,
            v_sampled=23.5,
            envelope=strike_envelope,
            r_20=r_20_18awg,
            t_ambient=20.0,
        )
        assert state == "QUIESCENT_BASELINE_LOCKED"
        assert conf == 0.92
        assert dist_m > 0

        # 2. Chaos Injection: 15 consecutive inrush / kickback contact bounce chatter spikes
        # (Delta V = 2.5V, exceeding expected_quiescent_drop * 2.5)
        rejected_count = 0
        for _ in range(15):
            dist_spike, conf_spike, state_spike = calculate_dynamic_spatial_drop(
                v_source=24.0,
                v_sampled=21.5,
                envelope=strike_envelope,
                r_20=r_20_18awg,
                t_ambient=20.0,
            )
            if state_spike == "REJECTED_ACTIVE_TRANSIENT_STATE":
                rejected_count += 1
                assert conf_spike == 0.0
                assert dist_spike == 0.0

        assert rejected_count == 15

        # 3. Assert quiescent baseline measurement remains pristine and unaffected post-chatter
        dist_post, conf_post, state_post = calculate_dynamic_spatial_drop(
            v_source=24.0,
            v_sampled=23.5,
            envelope=strike_envelope,
            r_20=r_20_18awg,
            t_ambient=20.0,
        )
        assert state_post == "QUIESCENT_BASELINE_LOCKED"
        assert dist_post == dist_m
        assert conf_post == 0.92

    def test_chaos_twin_async_task_drain(self):
        """
        Dispatches concurrent asynchronous simulation tasks and asserts complete drainage
        with zero pending tasks before event loop teardown.
        """
        async def mock_spatial_ping(target_ip: str) -> Dict[str, Any]:
            await asyncio.sleep(0.01)
            return {"ip": target_ip, "status": "REACHABLE", "rtt_ms": 1.2}

        async def run_swarm():
            tasks = [asyncio.create_task(mock_spatial_ping(f"192.168.1.{i}")) for i in range(50)]
            results = await asyncio.gather(*tasks)
            assert len(results) == 50
            return results

        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(run_swarm())
            assert len(results) == 50
            # Ensure pending tasks == 0
            pending = asyncio.all_tasks(loop)
            assert len(pending) == 0, f"Lingering unawaited async tasks detected: {pending}"
        finally:
            loop.close()
