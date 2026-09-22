"""
Unit test suite for Phase 37: Hexagonal Verification of High-Density Classifier Facade.
"""
import ast
from aetheris.core.ports.classifier_engine_port import DeviceClassifierEnginePort
import aetheris.core.device_classifier_engine as engine_mod
import aetheris.core.high_density_classifier as facade_mod
from aetheris.core.high_density_classifier import (
    DEFAULT_PROFILES,
    HighDensityClassifier,
    NetworkClassifierEngine,
    TelemetryBuffer,
)


def test_high_density_classifier_facade_reexports():
    """Verify that all symbols in __all__ are identical to device_classifier_engine definitions."""
    assert facade_mod.HighDensityClassifier is engine_mod.HighDensityClassifier
    assert facade_mod.NetworkClassifierEngine is engine_mod.NetworkClassifierEngine
    assert facade_mod.TelemetryBuffer is engine_mod.TelemetryBuffer
    assert facade_mod.DEFAULT_PROFILES is engine_mod.DEFAULT_PROFILES
    assert set(facade_mod.__all__) == {
        "HighDensityClassifier",
        "NetworkClassifierEngine",
        "TelemetryBuffer",
        "DEFAULT_PROFILES",
    }


def test_high_density_classifier_protocol_conformance():
    """Assert HighDensityClassifier conforms to DeviceClassifierEnginePort protocol."""
    classifier = HighDensityClassifier()
    assert isinstance(classifier, DeviceClassifierEnginePort)
    assert isinstance(classifier, NetworkClassifierEngine)


def test_high_density_classifier_jitter_deconvolution():
    """Verify per-host baseline jitter extraction and lower-decile filtering."""
    classifier = HighDensityClassifier()
    rtt_samples = [0.012, 0.013, 0.0125, 0.014, 0.0122, 0.0128, 0.0135]
    metrics = classifier.deconvolve_rtt_jitter(rtt_samples)

    assert "min_rtt_sec" in metrics
    assert "p10_rtt_sec" in metrics
    assert "p50_rtt_sec" in metrics
    assert "p90_rtt_sec" in metrics
    assert "jitter_sec" in metrics
    assert "variance_sec2" in metrics

    assert metrics["min_rtt_sec"] > 0.0
    assert metrics["jitter_sec"] >= 0.0
    assert metrics["p90_rtt_sec"] >= metrics["p10_rtt_sec"]


def test_high_density_classifier_ast_boundaries():
    """Assert zero socket, scapy, or file I/O imports exist in high_density_classifier.py."""
    with open(facade_mod.__file__, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read())

    forbidden = {"socket", "scapy", "httpx", "requests", "urllib"}
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(alias.name == f or alias.name.startswith(f + ".") for f in forbidden):
                    violations.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if any(mod == f or mod.startswith(f + ".") for f in forbidden):
                violations.append(mod)

    assert violations == [], f"Found forbidden AST imports: {violations}"

