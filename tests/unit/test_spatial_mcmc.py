import numpy as np
import pytest
from graphpath.core.spatial_mcmc import AffineInvariantSpatialMCMC, MCMCResult, C_VACUUM


def test_mcmc_convergence_on_true_distance():
    nvp = 0.69
    v_prop = nvp * 299792458.0
    sampler = AffineInvariantSpatialMCMC(nvp=nvp, num_walkers=20, steps=200, burn_in=50)

    # Simulated Linux host at 15.0m with 1.1ms kernel scheduler turnaround
    true_d = 15.0
    t_flight = (2.0 * true_d) / v_prop
    t_kernel = 1.1e-3

    # Pulse burst with realistic exponential softirq jitter
    noise = np.random.exponential(scale=5e-5, size=5)
    rtt_samples_us = [(t_flight + t_kernel + n) * 1e6 for n in noise]

    res = sampler.sample(rtt_samples_us, archetype="LINUX_SERVER")

    assert 1.0 <= res.distance_m <= 35.0
    assert res.variance_m2 < 100.0
    assert res.confidence_pct >= 60.0
    assert 0.1 <= res.acceptance_fraction <= 0.8


def test_mcmc_empty_samples():
    sampler = AffineInvariantSpatialMCMC()
    res = sampler.sample([], archetype="GENERIC_HOST")
    assert isinstance(res, MCMCResult)
    assert res.distance_m == 50.0
    assert res.variance_m2 == 100.0
    assert res.confidence_pct == 0.0
    assert res.acceptance_fraction == 0.0


def test_mcmc_log_prior_boundaries():
    sampler = AffineInvariantSpatialMCMC()

    # Out of physical drop bounds (d < 0.5 or d > 100)
    assert sampler.log_prior(np.array([0.2, 1e-3]), "LINUX_SERVER") == -np.inf
    assert sampler.log_prior(np.array([105.0, 1e-3]), "LINUX_SERVER") == -np.inf

    # Non-positive kernel turnaround time (t_k <= 0)
    assert sampler.log_prior(np.array([15.0, 0.0]), "LINUX_SERVER") == -np.inf
    assert sampler.log_prior(np.array([15.0, -1e-4]), "LINUX_SERVER") == -np.inf

    # Valid parameter state returns finite log prior
    lp = sampler.log_prior(np.array([15.0, 1.1e-3]), "LINUX_SERVER")
    assert np.isfinite(lp)


def test_mcmc_log_likelihood_physical_floor_constraint():
    sampler = AffineInvariantSpatialMCMC(nvp=0.69)
    v_prop = 0.69 * C_VACUUM

    # 50m cable has physical flight time = 2 * 50 / v_prop = ~483 ns
    d = 50.0
    t_flight = (2.0 * d) / v_prop
    theta = np.array([d, 1.0e-3])

    # Sample that violates physics (observed RTT < t_flight)
    impossible_rtts = np.array([t_flight - 100e-9, t_flight + 1e-3])
    assert sampler.log_likelihood(theta, impossible_rtts) == -np.inf

    # Sample adhering to physics
    valid_rtts = np.array([t_flight + 1.0e-3, t_flight + 1.05e-3])
    ll = sampler.log_likelihood(theta, valid_rtts)
    assert np.isfinite(ll)


def test_mcmc_shifted_exponential_penalty():
    sampler = AffineInvariantSpatialMCMC(nvp=0.69)
    theta = np.array([10.0, 1.0e-3])
    t_flight = (2.0 * 10.0) / sampler.v_prop
    t_base = t_flight + 1.0e-3

    # Residual exactly zero vs positive residual (scheduling delay)
    rtts_zero_residual = np.array([t_base, t_base])
    ll_zero = sampler.log_likelihood(theta, rtts_zero_residual)

    # Positive residual represents exponential tail delay
    rtts_pos_residual = np.array([t_base + 100e-6, t_base + 200e-6])
    ll_pos = sampler.log_likelihood(theta, rtts_pos_residual)

    assert np.isfinite(ll_zero)
    assert np.isfinite(ll_pos)
    assert ll_zero > ll_pos


def test_mcmc_high_jitter_linux_scheduling_collapse():
    sampler = AffineInvariantSpatialMCMC(
        nvp=0.69,
        num_walkers=24,
        steps=250,
        burn_in=80
    )

    # Simulate 5ms-7ms scheduling spikes on a 20m drop
    true_d = 20.0
    t_flight = (2.0 * true_d) / sampler.v_prop
    severe_tk = 5.5e-3
    spikes = [0.0, 100e-6, 500e-6, 1200e-6, 1500e-6]
    simulated_rtts_us = [(t_flight + severe_tk + s) * 1e6 for s in spikes]

    res = sampler.sample(simulated_rtts_us, archetype="LINUX_SERVER")

    # Must NOT blow up to 500+ km
    assert res.distance_m <= 100.0
    assert res.distance_m >= 0.5
    # Deconvolved kernel turnaround should absorb the multi-millisecond delay
    assert res.t_kernel_median_us >= 4000.0

