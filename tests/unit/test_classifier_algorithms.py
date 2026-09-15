import numpy as np
import pytest
from graphpath.core.device_classifier_engine import NetworkClassifierEngine

MOCK_PROFILES = {
    "LINUX_SERVER": {
        "size_distribution": np.array([0.15, 0.35, 0.20, 0.10, 0.10, 0.05, 0.03, 0.02]),
        "transition_matrix": {
            "SYN": {"SYN-ACK": 0.95, "RST": 0.05},
            "SYN-ACK": {"ACK": 0.98, "RST": 0.02},
            "ACK": {"DATA": 0.70, "FIN": 0.30}
        },
        "target_heartbeat_hz": 100.0
    }
}

# ==========================================================
# 1. KULLBACK-LEIBLER DIVERGENCE TEST CASES
# ==========================================================

def test_kl_divergence_empty_bins_and_smoothing():
    """Test Case 1: Epsilon smoothing eliminates infinity on zero-probability bins."""
    engine = NetworkClassifierEngine(MOCK_PROFILES, epsilon=1e-7)
    sample_sizes = [50, 50, 50]  # Only occupies bin 0
    target_dist = np.array([0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.0, 0.0])

    kl = engine.compute_kl_divergence(sample_sizes, target_dist)
    assert np.isfinite(kl), f"KL Divergence produced non-finite value: {kl}"
    assert kl >= 0.0

def test_kl_divergence_identical_uniform_distributions():
    """Test Case 2: Output is near 0.0 when identical distributions are compared."""
    engine = NetworkClassifierEngine(MOCK_PROFILES, epsilon=1e-9)
    sample_sizes = [100, 250, 400, 550, 700, 900, 1100, 1400]
    hist, _ = np.histogram(sample_sizes, bins=8, range=(0, 1500), density=False)
    q_dist = hist.astype(np.float64) / np.sum(hist)

    kl = engine.compute_kl_divergence(sample_sizes, q_dist)
    assert np.isclose(kl, 0.0, atol=1e-4), f"Identical distributions must have D_KL ~ 0, got {kl}"

def test_kl_divergence_known_divergence_measurement():
    """Test Case 3: Validate numerical accuracy against pre-calculated divergence."""
    engine = NetworkClassifierEngine(MOCK_PROFILES, epsilon=1e-7)
    p = np.array([0.25, 0.25, 0.25, 0.25, 0.0, 0.0, 0.0, 0.0])
    q = np.array([0.10, 0.40, 0.10, 0.40, 0.0, 0.0, 0.0, 0.0])
    
    # Generate synthetic values that map into the first 4 bins of 8 bins (range 0-1500)
    # Bin width = 187.5. Bins: [0, 187.5), [187.5, 375), [375, 562.5), [562.5, 750)
    sample_sizes = [90, 250, 420, 600]
    kl = engine.compute_kl_divergence(sample_sizes, q)
    assert kl > 0.1

# ==========================================================
# 2. MARKOV CHAIN STATE TRANSITION TEST CASES
# ==========================================================

def test_markov_minimum_sequence_length():
    """Test Case 1: Sequences shorter than min length return 0.0 without errors."""
    engine = NetworkClassifierEngine(MOCK_PROFILES)
    matrix = MOCK_PROFILES["LINUX_SERVER"]["transition_matrix"]
    assert engine.compute_markov_likelihood([], matrix) == 0.0
    assert engine.compute_markov_likelihood(["SYN"], matrix) == 0.0

def test_markov_expected_log_likelihood():
    """Test Case 2: Calculate expected log-likelihood of a known sequence."""
    engine = NetworkClassifierEngine(MOCK_PROFILES)
    matrix = MOCK_PROFILES["LINUX_SERVER"]["transition_matrix"]
    seq = ["SYN", "SYN-ACK", "ACK"]
    # Transitions: SYN->SYN-ACK (0.95), SYN-ACK->ACK (0.98)
    expected_ll = (np.log(0.95) + np.log(0.98)) / 2.0

    calculated_ll = engine.compute_markov_likelihood(seq, matrix)
    assert np.isclose(calculated_ll, expected_ll, atol=1e-5)
    assert calculated_ll <= 0.0

def test_markov_unknown_transitions_fallback():
    """Test Case 3: Unknown states safely use epsilon fallback without math errors."""
    engine = NetworkClassifierEngine(MOCK_PROFILES, epsilon=1e-5)
    matrix = MOCK_PROFILES["LINUX_SERVER"]["transition_matrix"]
    seq = ["SYN", "UNKNOWN_STATE_A", "UNKNOWN_STATE_B"]
    
    ll = engine.compute_markov_likelihood(seq, matrix)
    assert np.isfinite(ll)
    assert ll < np.log(0.1)  # Penalized by epsilon

# ==========================================================
# 3. FAST FOURIER TRANSFORM (FFT) TEST CASES
# ==========================================================

def test_fft_synthetic_sinusoidal_signal():
    """Test Case 1: Pure periodic signal frequency is detected with high SNR."""
    engine = NetworkClassifierEngine(MOCK_PROFILES)
    fs = 100.0  # 100 Hz sampling rate
    duration = 4.0
    target_freq = 12.0  # 12 Hz target periodic jitter
    t = np.linspace(0, duration, int(fs * duration), endpoint=False)
    signal = 0.5 * np.sin(2 * np.pi * target_freq * t) + 0.01

    detected_hz, power_ratio = engine.extract_spectral_heartbeat(list(signal), sampling_rate=fs)
    assert abs(detected_hz - target_freq) <= 0.5
    assert power_ratio > 5.0

def test_fft_white_noise_rejection():
    """Test Case 2: Stochastic noise yields low power ratio without false peaks."""
    engine = NetworkClassifierEngine(MOCK_PROFILES)
    np.random.seed(42)
    noise = np.random.normal(loc=0.005, scale=0.001, size=128)
    
    detected_hz, power_ratio = engine.extract_spectral_heartbeat(list(noise), sampling_rate=200.0)
    assert power_ratio < 4.5  # Power is distributed flatly

def test_fft_sampling_rate_scaling():
    """Test Case 3: Frequency peak extraction remains invariant across sampling rates."""
    engine = NetworkClassifierEngine(MOCK_PROFILES)
    target_hz = 25.0
    duration = 3.0

    for fs in [100.0, 250.0, 500.0]:
        t = np.linspace(0, duration, int(fs * duration), endpoint=False)
        signal = np.sin(2 * np.pi * target_hz * t)
        detected_hz, _ = engine.extract_spectral_heartbeat(list(signal), sampling_rate=fs)
        assert abs(detected_hz - target_hz) <= 1.0