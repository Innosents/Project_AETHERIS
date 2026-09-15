"""
Production Unit Test Suite for NetworkClassifierEngine
Covers all 9 algorithmic specification edge cases across:
- Kullback-Leibler Divergence (empty fallback, identical convergence, Laplace smoothing)
- Discrete-Time Markov Chains (short sequences, unseen transitions, log-likelihood)
- FFT Spectral Decomposition (insufficient samples, periodic heartbeat isolation)
- Telemetry Ingestion & Deque Memory Bounding
- Integrated Bayesian Posterior Simplex Normalization
"""

import numpy as np
import pytest
from graphpath.core.device_classifier_engine import NetworkClassifierEngine, TelemetryBuffer


@pytest.fixture
def classifier_engine():
    target_profiles = {
        "LINUX_KERNEL_SERVER": {
            "prior": 0.5,
            "size_distribution": np.array([100, 200, 500, 800, 1000, 1200, 1400, 1500]),
            "transition_matrix": {
                "SYN": {"SYN_ACK": 0.95, "RST": 0.05},
                "SYN_ACK": {"ACK": 0.98, "RST": 0.02},
                "ACK": {"DATA": 0.90, "FIN": 0.10}
            },
            "tick_frequency_hz": 100.0
        },
        "EMBEDDED_RTOS_DEVICE": {
            "prior": 0.5,
            "size_distribution": np.array([64, 64, 128, 128, 256, 256, 512, 512]),
            "transition_matrix": {
                "POLL": {"RESPONSE": 0.99, "TIMEOUT": 0.01},
                "RESPONSE": {"POLL": 0.95, "SLEEP": 0.05}
            },
            "tick_frequency_hz": 10.0
        }
    }
    return NetworkClassifierEngine(target_profiles=target_profiles, history_len=128, epsilon=1e-7)


# Edge Case 1: KL Divergence on empty sample sizes or empty target distribution
def test_edge_case_1_kl_divergence_empty_inputs(classifier_engine):
    target_dist = np.array([100, 200, 300, 400])

    assert classifier_engine.compute_kl_divergence([], target_dist) == 0.0
    assert classifier_engine.compute_kl_divergence([100, 200], None) == 0.0
    assert classifier_engine.compute_kl_divergence([100, 200], np.array([])) == 0.0


# Edge Case 2: KL Divergence identical distributions convergence (D_KL ≈ 0.0)
def test_edge_case_2_kl_divergence_identical_distributions(classifier_engine):
    # Construct samples that match target distribution bins
    sample_sizes = [100] * 50 + [300] * 50 + [700] * 50 + [1200] * 50
    hist, _ = np.histogram(sample_sizes, bins=8, range=(0, 1500), density=False)
    
    kl = classifier_engine.compute_kl_divergence(sample_sizes, hist.astype(np.float64))
    assert abs(kl) < 1e-4


# Edge Case 3: KL Divergence Laplace epsilon smoothing on disjoint bins (no NaN/Inf)
def test_edge_case_3_kl_divergence_epsilon_smoothing(classifier_engine):
    # Sample sizes in low range (0-200), target distribution strictly in high range (1300-1500)
    samples = [50, 60, 70, 80]
    target_dist = np.array([0, 0, 0, 0, 0, 0, 0, 100], dtype=np.float64)

    kl = classifier_engine.compute_kl_divergence(samples, target_dist)
    assert not np.isnan(kl)
    assert not np.isinf(kl)
    assert kl > 0.0


# Edge Case 4: DTMC Markov Likelihood below minimum sequence length
def test_edge_case_4_markov_short_sequence_threshold(classifier_engine):
    matrix = {"SYN": {"ACK": 0.9}}
    assert classifier_engine.compute_markov_likelihood([], matrix, min_seq_len=2) == 0.0
    assert classifier_engine.compute_markov_likelihood(["SYN"], matrix, min_seq_len=2) == 0.0


# Edge Case 5: DTMC Markov Likelihood unseen transitions fallback to epsilon
def test_edge_case_5_markov_unseen_transitions_no_math_domain_error(classifier_engine):
    matrix = {"SYN": {"SYN_ACK": 0.99}}
    # "SYN" -> "UNKNOWN_STATE" is not in matrix; "UNKNOWN_STATE" -> "ANOTHER" is missing
    seq = ["SYN", "UNKNOWN_STATE", "ANOTHER"]

    ll = classifier_engine.compute_markov_likelihood(seq, matrix)
    assert not np.isnan(ll)
    assert not np.isinf(ll)
    # Each transition fell back to epsilon, so normalized log-likelihood ≈ log(epsilon)
    expected_ll = np.log(classifier_engine.epsilon)
    assert abs(ll - expected_ll) < 1e-2


# Edge Case 6: DTMC Markov Likelihood known sequence matches expected log-probability
def test_edge_case_6_markov_known_sequence_evaluation(classifier_engine):
    matrix = {
        "A": {"B": 0.5},
        "B": {"C": 0.25}
    }
    seq = ["A", "B", "C"]
    # Log prob: log(0.5) + log(0.25) / 2 transitions
    expected = (np.log(0.5) + np.log(0.25)) / 2.0
    actual = classifier_engine.compute_markov_likelihood(seq, matrix)
    assert abs(actual - expected) < 1e-5


# Edge Case 7: FFT Spectral Heartbeat insufficient sample length (< 16)
def test_edge_case_7_spectral_heartbeat_under_sampled(classifier_engine):
    short_series = [0.010] * 15
    freq, power_ratio = classifier_engine.extract_spectral_heartbeat(short_series)
    assert freq == 0.0
    assert power_ratio == 0.0


# Edge Case 8: FFT Spectral Heartbeat periodic signal dominant peak isolation
def test_edge_case_8_spectral_heartbeat_periodic_peak_isolation(classifier_engine):
    # Generate synthetic periodic inter-arrival signal at 100 Hz (dt = 0.010s)
    # with small jitter
    np.random.seed(42)
    n_samples = 64
    base_dt = 0.010  # 100 Hz effective rate
    t = np.linspace(0, 1.0, n_samples)
    # Add a distinct sinusoidal modulation component
    signal = base_dt + 0.002 * np.sin(2 * np.pi * 10.0 * t) + np.random.normal(0, 0.0001, n_samples)
    iat_series = list(signal)

    freq, snr = classifier_engine.extract_spectral_heartbeat(iat_series, sampling_rate=100.0)
    assert freq > 0.0
    assert snr > 1.0


# Edge Case 9: Telemetry ingestion buffering, delta time, and deque maxlen bounds
def test_edge_case_9_telemetry_ingestion_and_buffer_clamping(classifier_engine):
    channel = ("192.168.1.10", "192.168.1.1")
    
    # 1. First event: last_ts set, iat empty
    meta1 = classifier_engine.ingest_telemetry_event(channel, timestamp=100.0, size=64, op_code="SYN")
    assert meta1["iat_count"] == 0
    assert meta1["size_count"] == 1
    assert meta1["state_count"] == 1

    # 2. Second event: dt added to iat
    meta2 = classifier_engine.ingest_telemetry_event(channel, timestamp=100.015, size=128, op_code="SYN_ACK")
    assert meta2["iat_count"] == 1
    assert abs(classifier_engine.channels[channel].iat[0] - 0.015) < 1e-5

    # 3. Buffer overflow past maxlen (128)
    for i in range(200):
        classifier_engine.ingest_telemetry_event(channel, timestamp=100.020 + i * 0.01, size=64, op_code="DATA")
    
    buf = classifier_engine.channels[channel]
    assert len(buf.iat) == 128
    assert len(buf.sizes) == 128
    assert len(buf.states) == 128


# Integration Case 10: Bayesian posterior update guarantees probability simplex (sum == 1.0)
def test_bayesian_posterior_simplex_normalization(classifier_engine):
    channel = ("10.0.0.1", "10.0.0.254")
    for i in range(20):
        classifier_engine.ingest_telemetry_event(channel, timestamp=1000.0 + i * 0.01, size=500, op_code="SYN")
        classifier_engine.ingest_telemetry_event(channel, timestamp=1000.005 + i * 0.01, size=1200, op_code="SYN_ACK")

    posteriors = classifier_engine.update_channel_posterior(channel)
    assert len(posteriors) == 2
    assert "LINUX_KERNEL_SERVER" in posteriors
    assert "EMBEDDED_RTOS_DEVICE" in posteriors
    assert abs(sum(posteriors.values()) - 1.0) < 1e-5
    for p in posteriors.values():
        assert 0.0 <= p <= 1.0

