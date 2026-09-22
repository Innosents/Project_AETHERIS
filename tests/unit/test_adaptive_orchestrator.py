"""
Project AETHERIS - Unit Test Suite for Adaptive Orchestrator Decoupling (Phase 28)
Verifies:
1. Pydantic v2 validation contracts on EvidenceVector (IP, MAC, TTL, port bounds).
2. Pydantic v2 validation contracts on HypothesisScore (confidence bounds, positional & keyword construction).
3. HypothesisEngine pure domain ranking and archetype scoring.
4. AdaptiveDiscoveryOrchestrator prober dispatcher dependency injection and custom prober mapping.
5. Early termination triggers and dynamic prober registration without top-level deep_prober coupling.
"""

import unittest
from pydantic import ValidationError

from aetheris.core.adaptive_orchestrator import (
    EvidenceVector,
    HypothesisScore,
    HypothesisEngine,
    AdaptiveProbeRouter,
    SubnetAdaptiveMemory,
    AdaptiveDiscoveryOrchestrator,
)


class TestAdaptiveOrchestratorPydanticValidation(unittest.TestCase):
    """Asserts strict Pydantic v2 validation rules on evidence vectors and hypothesis scores."""

    def test_evidence_vector_valid_instantiation(self):
        """Verifies valid EvidenceVector instantiations with automatic MAC normalization."""
        ev = EvidenceVector(
            ip="192.168.1.50",
            mac="aa:bb:cc:dd:ee:ff",
            ttl=64,
            open_ports=[80, 443],
            banners={80: "Apache/2.4"},
            subnet_cidr="192.168.1.0/24",
        )
        self.assertEqual(ev.ip, "192.168.1.50")
        self.assertEqual(ev.mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(ev.ttl, 64)
        self.assertEqual(ev.open_ports, [80, 443])

    def test_evidence_vector_invalid_ip_rejection(self):
        """Asserts invalid IP addresses are rejected with ValidationError."""
        with self.assertRaises(ValidationError):
            EvidenceVector(ip="invalid_ip_format")

        with self.assertRaises(ValidationError):
            EvidenceVector(ip="")

    def test_evidence_vector_ttl_bounds_rejection(self):
        """Asserts TTL outside 0-255 range triggers ValidationError."""
        with self.assertRaises(ValidationError):
            EvidenceVector(ip="10.0.0.1", ttl=256)

        with self.assertRaises(ValidationError):
            EvidenceVector(ip="10.0.0.1", ttl=-1)

    def test_evidence_vector_port_bounds_rejection(self):
        """Asserts ports outside 0-65535 range trigger ValidationError."""
        with self.assertRaises(ValidationError):
            EvidenceVector(ip="10.0.0.1", open_ports=[80, 70000])

    def test_hypothesis_score_positional_and_keyword_construction(self):
        """Verifies HypothesisScore supports both positional and keyword invocations."""
        hs_pos = HypothesisScore("WINDOWS_HOST", 0.85, ["RPC open", "SMB open"])
        self.assertEqual(hs_pos.archetype, "WINDOWS_HOST")
        self.assertEqual(hs_pos.confidence, 0.85)
        self.assertEqual(len(hs_pos.evidence_factors), 2)

        hs_kw = HypothesisScore(
            archetype="INDUSTRIAL_OT",
            confidence=0.95,
            evidence_factors=["Modbus Port 502"]
        )
        self.assertEqual(hs_kw.archetype, "INDUSTRIAL_OT")
        self.assertEqual(hs_kw.confidence, 0.95)

    def test_hypothesis_score_confidence_bounds_rejection(self):
        """Asserts confidence scores outside [0.0, 1.0] are rejected."""
        with self.assertRaises(ValidationError):
            HypothesisScore("LINUX_SERVER", 1.2)

        with self.assertRaises(ValidationError):
            HypothesisScore("LINUX_SERVER", -0.1)


class TestHypothesisEngineAndDomainServices(unittest.TestCase):
    """Validates HypothesisEngine, AdaptiveProbeRouter, and SubnetAdaptiveMemory domain behavior."""

    def test_hypothesis_engine_evaluation_ranking(self):
        """Validates archetype evaluation ranking from fused multi-signal inputs."""
        ev = EvidenceVector(
            ip="192.168.1.10",
            ttl=128,
            open_ports=[135, 445, 3389],
            banners={445: "Windows Server 2022"},
        )
        ranked = HypothesisEngine.evaluate(ev)
        self.assertIsInstance(ranked, list)
        self.assertGreater(len(ranked), 0)
        self.assertEqual(ranked[0].archetype, "WINDOWS_HOST")
        self.assertGreater(ranked[0].confidence, 0.5)

    def test_subnet_adaptive_memory_ot_density(self):
        """Verifies subnet adaptive memory tracking and OT density heuristic."""
        memory = SubnetAdaptiveMemory()
        cidr = "10.0.1.0/24"
        self.assertFalse(memory.is_ot_dense_subnet(cidr))

        memory.record_host_archetype(cidr, "INDUSTRIAL_OT")
        memory.record_host_archetype(cidr, "INDUSTRIAL_OT")
        memory.record_host_archetype(cidr, "LINUX_SERVER")

        self.assertTrue(memory.is_ot_dense_subnet(cidr))


class TestAdaptiveDiscoveryOrchestratorDecoupling(unittest.TestCase):
    """Validates dependency injection, custom dispatcher mapping, and early termination."""

    def test_default_dispatcher_initialization(self):
        """Verifies orchestrator initializes default probers lazily."""
        orchestrator = AdaptiveDiscoveryOrchestrator()
        self.assertIsInstance(orchestrator.prober_dispatcher, dict)
        self.assertIn("winrm", orchestrator.prober_dispatcher)
        self.assertIn("onvif", orchestrator.prober_dispatcher)
        self.assertIn("modbus", orchestrator.prober_dispatcher)

    def test_injectable_prober_dispatcher_mocking(self):
        """Asserts custom mock prober dispatcher isolates orchestrator from network I/O."""
        mock_called = []

        def mock_onvif(ip: str, port: int, timeout: float):
            mock_called.append(("onvif", ip, port))
            return {
                "vendor": "Axis",
                "model": "P3245-V",
                "serial_number": "ACCC8E123456",
                "firmware": "10.12.1",
            }

        custom_dispatcher = {
            "onvif": mock_onvif,
        }

        orchestrator = AdaptiveDiscoveryOrchestrator(prober_dispatcher=custom_dispatcher)
        ev = EvidenceVector(
            ip="192.168.1.120",
            open_ports=[80, 554],
            vendor_hint="axis",
        )

        results = orchestrator.execute_adaptive_sweep(ev, timeout=0.1)

        self.assertEqual(len(mock_called), 1)
        self.assertEqual(mock_called[0], ("onvif", "192.168.1.120", 80))
        self.assertEqual(results["vendor"], "Axis")
        self.assertEqual(results["model"], "P3245-V")
        self.assertEqual(results["serial_number"], "ACCC8E123456")
        self.assertTrue(results["early_terminated"])
        self.assertIn("onvif", results["deep_probes"])

    def test_register_prober_dynamic_extension(self):
        """Verifies dynamic runtime registration of new probers."""
        orchestrator = AdaptiveDiscoveryOrchestrator(prober_dispatcher={})

        def mock_winrm(ip: str, port: int, timeout: float):
            return {
                "os_version": "Microsoft Windows Server 2022 Datacenter",
                "hostname": "DC01",
                "domain": "CORP.LOCAL",
            }

        orchestrator.register_prober("winrm", mock_winrm)
        self.assertIn("winrm", orchestrator.prober_dispatcher)

        ev = EvidenceVector(
            ip="10.1.1.5",
            ttl=128,
            open_ports=[5985],
        )
        results = orchestrator.execute_adaptive_sweep(ev, timeout=0.1)

        self.assertEqual(results["os_version"], "Microsoft Windows Server 2022 Datacenter")
        self.assertEqual(results["hostname"], "DC01")
        self.assertTrue(results["early_terminated"])


if __name__ == "__main__":
    unittest.main()

