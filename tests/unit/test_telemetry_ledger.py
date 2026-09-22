"""
Unit Tests for TelemetryLedger and MCMC Empirical Prior Learning
Validates SQLite schema, convergence record persistence, summary aggregation,
insufficient vs learned prior thresholds (N >= 3), low-confidence filtering,
and AffineInvariantSpatialMCMC empirical prior integration.
"""

import time
import numpy as np
import pytest
from pathlib import Path
from aetheris.core.telemetry_ledger import TelemetryLedger, ConvergenceRecord
from aetheris.core.spatial_mcmc import AffineInvariantSpatialMCMC, C_VACUUM


@pytest.fixture
def temp_ledger(tmp_path):
    db_file = tmp_path / "test_spatial_ledger.db"
    return TelemetryLedger(db_path=str(db_file))


def test_ledger_initialization_and_schema(temp_ledger):
    summary = temp_ledger.get_ledger_summary()
    assert summary["total_records"] == 0
    assert summary["unique_macs"] == 0
    assert summary["avg_confidence"] == 0.0
    assert summary["avg_variance"] == 0.0


def test_record_convergence_persistence(temp_ledger):
    rec1 = ConvergenceRecord(
        timestamp=time.time(),
        mac="00:0C:29:12:34:56",
        oui="000C29",
        ip="192.168.1.10",
        archetype="LINUX_SERVER",
        min_rtt_us=1105.0,
        jitter_us=12.0,
        converged_distance_m=14.5,
        converged_kernel_us=1101.2,
        variance_m2=22.5,
        confidence_pct=82.0
    )
    rec2 = ConvergenceRecord(
        timestamp=time.time(),
        mac="00:0C:29:AB:CD:EF",
        oui="000C29",
        ip="192.168.1.11",
        archetype="LINUX_SERVER",
        min_rtt_us=1108.0,
        jitter_us=15.0,
        converged_distance_m=16.0,
        converged_kernel_us=1103.5,
        variance_m2=25.0,
        confidence_pct=80.0
    )

    temp_ledger.record_convergence(rec1)
    temp_ledger.record_convergence(rec2)

    summary = temp_ledger.get_ledger_summary()
    assert summary["total_records"] == 2
    assert summary["unique_macs"] == 2
    assert summary["avg_confidence"] == 81.0
    assert 23.0 <= summary["avg_variance"] <= 24.0


def test_empirical_kernel_prior_insufficient_samples(temp_ledger):
    # Less than 3 observations must return None
    assert temp_ledger.get_empirical_kernel_prior(oui="000C29", archetype="LINUX_SERVER") is None

    # Add 2 high-confidence records
    for i in range(2):
        temp_ledger.record_convergence(ConvergenceRecord(
            timestamp=time.time(),
            mac=f"00:0C:29:00:00:0{i}",
            oui="000C29",
            ip=f"192.168.1.{i+1}",
            archetype="LINUX_SERVER",
            min_rtt_us=1100.0,
            jitter_us=10.0,
            converged_distance_m=15.0,
            converged_kernel_us=1100.0,
            variance_m2=20.0,
            confidence_pct=85.0
        ))

    # Still under threshold (N=2 < 3)
    assert temp_ledger.get_empirical_kernel_prior(oui="000C29", archetype="LINUX_SERVER") is None


def test_empirical_kernel_prior_learned_parameters(temp_ledger):
    # Insert 4 historical observations around ~1100 µs (1.1 ms = 0.0011 s)
    kernel_delays = [1090.0, 1105.0, 1110.0, 1095.0]
    for i, tk in enumerate(kernel_delays):
        temp_ledger.record_convergence(ConvergenceRecord(
            timestamp=time.time() + i,
            mac=f"00:50:56:00:00:0{i}",
            oui="00:50:56",
            ip=f"192.168.10.{i+10}",
            archetype="LINUX_SERVER",
            min_rtt_us=tk + 5.0,
            jitter_us=8.0,
            converged_distance_m=12.0,
            converged_kernel_us=tk,
            variance_m2=15.0,
            confidence_pct=88.0
        ))

    prior = temp_ledger.get_empirical_kernel_prior(oui="00:50:56", archetype="LINUX_SERVER")
    assert prior is not None
    mu_log, sigma_log = prior

    # Expected mu_log ~ ln(1.1e-3) ~ -6.812
    expected_mu = np.log(1.1e-3)
    assert abs(mu_log - expected_mu) < 0.1
    assert 0.15 <= sigma_log <= 0.8


def test_empirical_prior_low_confidence_filtering(temp_ledger):
    # Insert 4 records, but 2 have confidence < 50%
    temp_ledger.record_convergence(ConvergenceRecord(
        timestamp=time.time(),
        mac="00:15:5D:01:01:01",
        oui="00155D",
        ip="192.168.1.1",
        archetype="WINDOWS_HOST",
        min_rtt_us=950.0,
        jitter_us=5.0,
        converged_distance_m=10.0,
        converged_kernel_us=950.0,
        variance_m2=10.0,
        confidence_pct=85.0
    ))
    temp_ledger.record_convergence(ConvergenceRecord(
        timestamp=time.time(),
        mac="00:15:5D:01:01:02",
        oui="00155D",
        ip="192.168.1.2",
        archetype="WINDOWS_HOST",
        min_rtt_us=955.0,
        jitter_us=6.0,
        converged_distance_m=12.0,
        converged_kernel_us=955.0,
        variance_m2=12.0,
        confidence_pct=80.0
    ))
    # Low confidence records that must be excluded
    for i in range(3):
        temp_ledger.record_convergence(ConvergenceRecord(
            timestamp=time.time(),
            mac=f"00:15:5D:01:01:0{i+3}",
            oui="00155D",
            ip=f"192.168.1.{i+3}",
            archetype="WINDOWS_HOST",
            min_rtt_us=5000.0,
            jitter_us=2000.0,
            converged_distance_m=80.0,
            converged_kernel_us=4800.0,
            variance_m2=500.0,
            confidence_pct=30.0  # < 50.0% filtered out
        ))

    # Only 2 valid records (confidence >= 50%), so threshold N=3 is not reached
    assert temp_ledger.get_empirical_kernel_prior(oui="00155D", archetype="WINDOWS_HOST") is None


def test_mcmc_integration_with_telemetry_ledger(temp_ledger):
    # Pre-populate ledger with 5 high-confidence records for CCTV_VIDEO (~2.2 ms = 2200 µs)
    for i in range(5):
        temp_ledger.record_convergence(ConvergenceRecord(
            timestamp=time.time() + i,
            mac=f"E0:50:8B:AA:BB:0{i}",
            oui="E0508B",
            ip=f"192.168.20.{i+10}",
            archetype="CCTV_VIDEO",
            min_rtt_us=2200.0,
            jitter_us=15.0,
            converged_distance_m=18.0,
            converged_kernel_us=2200.0,
            variance_m2=20.0,
            confidence_pct=86.0
        ))

    # Create MCMC sampler bound to this ledger
    sampler = AffineInvariantSpatialMCMC(
        nvp=0.69,
        num_walkers=20,
        steps=150,
        burn_in=40,
        ledger=temp_ledger
    )

    # Verify that log_prior uses the learned empirical prior
    theta = np.array([18.0, 2.2e-3])
    lp_empirical = sampler.log_prior(theta, archetype="CCTV_VIDEO", oui="E0508B")
    assert np.isfinite(lp_empirical)

    # Run MCMC sample with oui tag
    v_prop = 0.69 * C_VACUUM
    t_flight = (2.0 * 18.0) / v_prop
    simulated_rtts_us = [(t_flight + 2.2e-3 + n) * 1e6 for n in [10e-6, 20e-6, 30e-6, 15e-6]]

    res = sampler.sample(simulated_rtts_us, archetype="CCTV_VIDEO", oui="E0508B")
    assert 1.0 <= res.distance_m <= 40.0
    assert 2000.0 <= res.t_kernel_median_us <= 2500.0
    assert res.confidence_pct >= 60.0

