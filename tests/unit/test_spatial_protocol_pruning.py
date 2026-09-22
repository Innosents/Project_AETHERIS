"""
Project AETHERIS - Unit Test Suite for Spatial Protocol Pruning Integration (Phase II / Step 02)
Verifies:
1. AdvancedSpatialProber.evaluate_spatial_pruning_boundary state classifications.
2. AdaptiveProbeRouter.build_plan nominal copper retention (<100m).
3. AdaptiveProbeRouter.build_plan out-of-spec copper pruning (>110m) restricting RTSP and web sweeps.
4. Media conversion bypass: Trunk uplink (is_trunk=True) bypassing 100m copper bounds.
5. WAN overlay distortion bypass: net_flight_us > 2000us triggering WAN_ROUTED bypass.
6. AdaptiveDiscoveryOrchestrator.execute_adaptive_sweep end-to-end integration with spatial EvidenceVector.
"""

import unittest
from aetheris.core.adaptive_orchestrator import (
    EvidenceVector,
    HypothesisScore,
    AdaptiveProbeRouter,
    AdaptiveDiscoveryOrchestrator,
)
from aetheris.discovery.advanced_spatial_prober import AdvancedSpatialProber


class TestSpatialProtocolPruning(unittest.TestCase):
    """Validates spatial pruning integration into the adaptive probe routing matrix."""

    def test_evaluate_spatial_pruning_boundary_states(self):
        """Verifies state classification: WAN_ROUTED, TRUNK_UPLINK, OUT_OF_SPEC_COPPER, NOMINAL."""
        # 1. WAN_ROUTED (>2000us)
        eval_wan = AdvancedSpatialProber.evaluate_spatial_pruning_boundary(
            net_flight_us=2500.0, estimated_distance_m=150.0, is_trunk=False
        )
        self.assertEqual(eval_wan["spatial_state"], "WAN_ROUTED")
        self.assertTrue(eval_wan["bypass_copper_limits"])
        self.assertFalse(eval_wan["prune_high_throughput"])

        # 2. TRUNK_UPLINK (is_trunk=True)
        eval_trunk = AdvancedSpatialProber.evaluate_spatial_pruning_boundary(
            net_flight_us=45.0, estimated_distance_m=180.0, is_trunk=True
        )
        self.assertEqual(eval_trunk["spatial_state"], "TRUNK_UPLINK")
        self.assertTrue(eval_trunk["bypass_copper_limits"])
        self.assertFalse(eval_trunk["prune_high_throughput"])

        # 3. OUT_OF_SPEC_COPPER (>110m, not trunk, not WAN)
        eval_out_of_spec = AdvancedSpatialProber.evaluate_spatial_pruning_boundary(
            net_flight_us=120.0, estimated_distance_m=125.0, is_trunk=False
        )
        self.assertEqual(eval_out_of_spec["spatial_state"], "OUT_OF_SPEC_COPPER")
        self.assertFalse(eval_out_of_spec["bypass_copper_limits"])
        self.assertTrue(eval_out_of_spec["prune_high_throughput"])

        # 4. NOMINAL_LOCAL_COPPER (<=110m)
        eval_nominal = AdvancedSpatialProber.evaluate_spatial_pruning_boundary(
            net_flight_us=30.0, estimated_distance_m=45.0, is_trunk=False
        )
        self.assertEqual(eval_nominal["spatial_state"], "NOMINAL_LOCAL_COPPER")
        self.assertFalse(eval_nominal["bypass_copper_limits"])
        self.assertFalse(eval_nominal["prune_high_throughput"])

    def test_build_plan_nominal_cctv_retains_rtsp(self):
        """Verifies nominal copper link (<100m) retains RTSP and ONVIF probes."""
        hypothesis = HypothesisScore(archetype="CCTV_VIDEO", confidence=0.9)
        open_ports = [80, 554]

        queue, pruned, meta = AdaptiveProbeRouter.build_plan(
            hypothesis=hypothesis,
            open_ports=open_ports,
            net_flight_us=25.0,
            estimated_distance_m=35.0,
            is_trunk=False,
            return_meta=True,
        )

        self.assertIn("onvif", queue)
        self.assertIn("rtsp", queue)
        self.assertNotIn("rtsp", pruned)
        self.assertEqual(meta["spatial_state"], "NOMINAL_LOCAL_COPPER")
        self.assertEqual(meta["spatial_pruned_probes"], [])

    def test_build_plan_out_of_spec_copper_prunes_rtsp(self):
        """Verifies out-of-spec copper (>110m) prunes RTSP to protect physical link stability."""
        hypothesis = HypothesisScore(archetype="CCTV_VIDEO", confidence=0.9)
        open_ports = [80, 554]

        queue, pruned, meta = AdaptiveProbeRouter.build_plan(
            hypothesis=hypothesis,
            open_ports=open_ports,
            net_flight_us=150.0,
            estimated_distance_m=125.0,
            is_trunk=False,
            return_meta=True,
        )

        # RTSP must be removed from queue and added to pruned list
        self.assertNotIn("rtsp", queue)
        self.assertIn("rtsp", pruned)
        self.assertIn("rtsp", meta["spatial_pruned_probes"])
        self.assertEqual(meta["spatial_state"], "OUT_OF_SPEC_COPPER")
        self.assertTrue(meta["prune_high_throughput"])

    def test_build_plan_trunk_uplink_bypasses_copper_limits(self):
        """Verifies trunk uplink (optical fiber) bypasses 100m copper limits."""
        hypothesis = HypothesisScore(archetype="CCTV_VIDEO", confidence=0.85)
        open_ports = [80, 554]

        # 160m physical distance, but flagged as trunk uplink
        queue, pruned, meta = AdaptiveProbeRouter.build_plan(
            hypothesis=hypothesis,
            open_ports=open_ports,
            net_flight_us=80.0,
            estimated_distance_m=160.0,
            is_trunk=True,
            return_meta=True,
        )

        self.assertIn("rtsp", queue)
        self.assertNotIn("rtsp", pruned)
        self.assertEqual(meta["spatial_state"], "TRUNK_UPLINK")
        self.assertTrue(meta["bypass_copper_limits"])
        self.assertFalse(meta["prune_high_throughput"])

    def test_build_plan_wan_routed_bypasses_copper_limits(self):
        """Verifies flight times >2000us trigger WAN_ROUTED bypass without pruning valid probes."""
        hypothesis = HypothesisScore(archetype="CCTV_VIDEO", confidence=0.85)
        open_ports = [80, 554]

        # 3500us net flight time (remote site across SD-WAN)
        queue, pruned, meta = AdaptiveProbeRouter.build_plan(
            hypothesis=hypothesis,
            open_ports=open_ports,
            net_flight_us=3500.0,
            estimated_distance_m=180.0,
            is_trunk=False,
            return_meta=True,
        )

        self.assertIn("rtsp", queue)
        self.assertEqual(meta["spatial_state"], "WAN_ROUTED")
        self.assertTrue(meta["bypass_copper_limits"])
        self.assertFalse(meta["prune_high_throughput"])

    def test_execute_adaptive_sweep_integration(self):
        """End-to-end integration test with EvidenceVector feeding into AdaptiveDiscoveryOrchestrator."""
        orchestrator = AdaptiveDiscoveryOrchestrator()

        ev = EvidenceVector(
            ip="192.168.1.188",
            mac="00:1A:2B:3C:4D:5E",
            ttl=64,
            open_ports=[80, 554],
            banners={554: "RTSP/1.0 200 OK"},
            subnet_cidr="192.168.1.0/24",
            net_flight_us=140.0,
            estimated_distance_m=122.0,  # Out-of-spec copper access port
            is_trunk=False,
        )

        results = orchestrator.execute_adaptive_sweep(ev, timeout=0.1)

        self.assertEqual(results["ip"], "192.168.1.188")
        self.assertEqual(results["top_hypothesis"], "CCTV_VIDEO")
        self.assertEqual(results["spatial_state"], "OUT_OF_SPEC_COPPER")
        self.assertTrue(results["spatial_pruning"]["prune_high_throughput"])
        self.assertIn("rtsp", results["probes_pruned"])
        self.assertNotIn("rtsp", results["probes_executed"])


if __name__ == "__main__":
    unittest.main()
