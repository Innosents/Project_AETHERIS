"""
Project AETHERIS - Advanced Network Classification Engine
Fuses Kullback-Leibler Divergence, Discrete-Time Markov Chains (DTMC),
and FFT spectral decomposition to isolate kernel scheduling ticks and inform
the Bayesian telemetry pipeline.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from scipy.stats import entropy
from scipy.fft import rfft, rfftfreq

from aetheris.core.ports.classifier_engine_port import (
    ClassifierEngineResult,
    DeviceClassifierEnginePort,
    DeviceObservationPayload,
    HeuristicScore,
)


@dataclass
class TelemetryBuffer:
    iat: deque = field(default_factory=lambda: deque(maxlen=128))
    sizes: deque = field(default_factory=lambda: deque(maxlen=128))
    states: deque = field(default_factory=lambda: deque(maxlen=128))
    last_ts: Optional[float] = None
    posterior: Dict[str, float] = field(default_factory=dict)


class NetworkClassifierEngine(DeviceClassifierEnginePort):
    """
    Multi-tier asynchronous inference pipeline fusing:
    - Kullback-Leibler (KL) Divergence over payload size distributions
    - Discrete-Time Markov Chains (DTMC) for protocol transition log-likelihood
    - Fast Fourier Transform (FFT) for kernel tick and IAT spectral heartbeat extraction
    - Bounded Bayesian updates to isolate kernel scheduling overhead
    """
    def __init__(self, target_profiles: Dict[str, Dict[str, Any]], history_len: int = 128, epsilon: float = 1e-7):
        self.target_profiles = target_profiles
        self.history_len = history_len
        self.epsilon = epsilon
        self.channels: Dict[Tuple[str, str], TelemetryBuffer] = defaultdict(
            lambda: TelemetryBuffer(
                iat=deque(maxlen=self.history_len),
                sizes=deque(maxlen=self.history_len),
                states=deque(maxlen=self.history_len),
                posterior={profile: 1.0 / max(1, len(target_profiles)) for profile in target_profiles}
            )
        )

    def compute_kl_divergence(self, sample_sizes: List[int], target_distribution: np.ndarray, num_bins: int = 8, bin_range: Tuple[int, int] = (0, 1500)) -> float:
        """
        Calculates KL divergence D_KL(P || Q) with Laplace epsilon smoothing.
        P: Observed empirical histogram
        Q: Baseline archetype distribution
        """
        if not sample_sizes or target_distribution is None or len(target_distribution) == 0:
            return 0.0

        hist, _ = np.histogram(sample_sizes, bins=num_bins, range=bin_range, density=False)
        p_dist = hist.astype(np.float64) + self.epsilon
        p_dist /= np.sum(p_dist)

        q_dist = target_distribution.astype(np.float64) + self.epsilon
        q_dist /= np.sum(q_dist)

        return float(entropy(p_dist, q_dist))

    def compute_markov_likelihood(self, observed_seq: List[str], transition_matrix: Dict[str, Dict[str, float]], min_seq_len: int = 2) -> float:
        """
        Calculates normalized log-likelihood for sequential protocol state transitions.
        Falls back to self.epsilon on unseen transitions to eliminate math domain errors.
        """
        if len(observed_seq) < min_seq_len:
            return 0.0

        log_prob = 0.0
        transitions = 0
        for s_curr, s_next in zip(observed_seq[:-1], observed_seq[1:]):
            prob = transition_matrix.get(s_curr, {}).get(s_next, self.epsilon)
            prob = max(self.epsilon, min(1.0, prob))
            log_prob += np.log(prob)
            transitions += 1

        return float(log_prob / max(transitions, 1))

    def extract_spectral_heartbeat(self, iat_series: List[float], sampling_rate: Optional[float] = None) -> Tuple[float, float]:
        """
        Isolates dominant periodic frequencies and peak-to-noise ratio from inter-arrival times.
        Returns: (dominant_frequency_hz, spectral_power_ratio)
        """
        if len(iat_series) < 16:
            return 0.0, 0.0

        signal = np.array(iat_series, dtype=np.float64)
        n = len(signal)
        
        # Center the signal by subtracting mean
        signal_centered = signal - np.mean(signal)
        
        # Determine effective sampling rate if not provided (mean 1/dt)
        if sampling_rate is None or sampling_rate <= 0:
            mean_dt = float(np.mean(signal))
            effective_fs = 1.0 / max(1e-6, mean_dt)
        else:
            effective_fs = sampling_rate

        fft_vals = np.abs(rfft(signal_centered))
        freqs = rfftfreq(n, d=1.0 / effective_fs)

        if len(fft_vals) <= 1:
            return 0.0, 0.0

        # Skip DC component (index 0)
        peak_idx = int(np.argmax(fft_vals[1:])) + 1
        peak_power = float(fft_vals[peak_idx])
        mean_power = float(np.mean(fft_vals[1:]))
        power_ratio = float(peak_power / max(1e-9, mean_power))

        return float(freqs[peak_idx]), power_ratio

    def ingest_telemetry_event(
        self,
        channel_key: Union[Tuple[str, str], DeviceObservationPayload],
        timestamp: Optional[float] = None,
        size: Optional[int] = None,
        op_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Synchronously buffers telemetry and updates running features for the communication channel.
        Supports direct scalar arguments or typed DeviceObservationPayload models.
        """
        if isinstance(channel_key, DeviceObservationPayload):
            ck: Tuple[str, str] = channel_key.channel_key
            ts: float = channel_key.timestamp
            sz: int = channel_key.size
            op: str = channel_key.op_code
        else:
            ck = channel_key
            ts = float(timestamp) if timestamp is not None else 0.0
            sz = int(size) if size is not None else 0
            op = str(op_code or "")

        buf = self.channels[ck]

        if buf.last_ts is not None:
            dt = max(1e-7, ts - buf.last_ts)
            buf.iat.append(dt)
        buf.last_ts = ts

        buf.sizes.append(sz)
        buf.states.append(op)

        return {
            "channel": ck,
            "iat_count": len(buf.iat),
            "size_count": len(buf.sizes),
            "state_count": len(buf.states)
        }

    def update_channel_posterior(self, channel_key: Tuple[str, str]) -> Dict[str, float]:
        """
        Fuses KL divergence, DTMC likelihood, and FFT heartbeat spectral metrics into
        a normalized Bayesian posterior distribution across target profiles.
        """
        buf = self.channels[channel_key]
        if not self.target_profiles:
            return buf.posterior

        log_posteriors: Dict[str, float] = {}

        for name, profile in self.target_profiles.items():
            prior = profile.get("prior", 1.0 / len(self.target_profiles))
            score = float(np.log(max(self.epsilon, prior)))

            # 1. KL Divergence penalty (lower divergence -> higher likelihood)
            target_sizes = profile.get("size_distribution")
            if target_sizes is not None and len(buf.sizes) > 0:
                kl = self.compute_kl_divergence(list(buf.sizes), np.array(target_sizes))
                score -= kl

            # 2. Markov Chain transition likelihood
            trans_matrix = profile.get("transition_matrix")
            if trans_matrix is not None and len(buf.states) >= 2:
                ll = self.compute_markov_likelihood(list(buf.states), trans_matrix)
                score += ll

            # 3. Spectral heartbeat resonance
            expected_freq = profile.get("tick_frequency_hz")
            if expected_freq is not None and len(buf.iat) >= 16:
                dom_freq, snr = self.extract_spectral_heartbeat(list(buf.iat))
                if snr >= 1.5:
                    freq_delta = abs(dom_freq - expected_freq)
                    if freq_delta < 5.0:
                        score += 1.0
                    else:
                        score -= min(2.0, freq_delta * 0.1)

            log_posteriors[name] = score

        # Numerical log-sum-exp normalization
        max_log = max(log_posteriors.values())
        unnormalized = {k: float(np.exp(v - max_log)) for k, v in log_posteriors.items()}
        total_mass = sum(unnormalized.values())

        if total_mass > 0:
            buf.posterior = {k: float(v / total_mass) for k, v in unnormalized.items()}

        return buf.posterior

    def classify_channel(self, channel_key: Tuple[str, str]) -> ClassifierEngineResult:
        """
        Computes channel posterior, isolates spectral heartbeat, and returns
        a typed ClassifierEngineResult model conforming to DeviceClassifierEnginePort.
        """
        posterior = self.update_channel_posterior(channel_key)
        buf = self.channels[channel_key]

        dom_freq: Optional[float] = None
        p_ratio: Optional[float] = None
        if len(buf.iat) >= 16:
            freq, ratio = self.extract_spectral_heartbeat(list(buf.iat))
            dom_freq = round(freq, 2)
            p_ratio = round(ratio, 2)

        best_archetype: Optional[str] = None
        best_confidence: float = 0.0
        if posterior:
            best_archetype = max(posterior, key=posterior.get)
            best_confidence = round(posterior[best_archetype], 4)

        return ClassifierEngineResult(
            channel=channel_key,
            posterior=posterior,
            dominant_archetype=best_archetype,
            confidence=best_confidence,
            dominant_frequency_hz=dom_freq,
            power_ratio=p_ratio,
        )


DEFAULT_PROFILES: Dict[str, Dict[str, Any]] = {
    "WINDOWS_HOST": {
        "prior": 0.30,
        "size_distribution": np.array([64, 128, 256, 512, 1024, 1200, 1400, 1500]),
        "transition_matrix": {
            "SYN": {"SYN_ACK": 0.95, "RST": 0.05},
            "SYN_ACK": {"ACK": 0.95, "RST": 0.05},
            "ACK": {"SMB": 0.80, "HTTP": 0.20}
        },
        "tick_frequency_hz": 64.0
    },
    "LINUX_SERVER": {
        "prior": 0.30,
        "size_distribution": np.array([64, 128, 256, 512, 1024, 1200, 1460, 1500]),
        "transition_matrix": {
            "SYN": {"SYN_ACK": 0.98, "RST": 0.02},
            "SYN_ACK": {"ACK": 0.98, "RST": 0.02},
            "ACK": {"SSH": 0.60, "HTTP": 0.40}
        },
        "tick_frequency_hz": 100.0
    },
    "CCTV_VIDEO": {
        "prior": 0.20,
        "size_distribution": np.array([128, 256, 512, 1024, 1400, 1460, 1500, 1500]),
        "transition_matrix": {
            "SYN": {"SYN_ACK": 0.90, "RST": 0.10},
            "SYN_ACK": {"ACK": 0.90, "RST": 0.10},
            "ACK": {"RTSP": 0.85, "HTTP": 0.15}
        },
        "tick_frequency_hz": 30.0
    },
    "GENERIC_HOST": {
        "prior": 0.20,
        "size_distribution": np.array([64, 128, 256, 512, 1024, 1200, 1400, 1500]),
        "transition_matrix": {
            "SYN": {"SYN_ACK": 0.90, "RST": 0.10},
            "SYN_ACK": {"ACK": 0.90, "RST": 0.10}
        }
    }
}


class HighDensityClassifier(NetworkClassifierEngine):
    """
    High-density telemetry classifier extracting per-host empirical baseline jitter
    via lower-decile filtering and percentile deconvolution.
    """
    def __init__(self, target_profiles: Optional[Dict[str, Dict[str, Any]]] = None, history_len: int = 128, epsilon: float = 1e-7):
        profiles = target_profiles if target_profiles is not None else DEFAULT_PROFILES
        super().__init__(target_profiles=profiles, history_len=history_len, epsilon=epsilon)

    def deconvolve_rtt_jitter(self, rtt_samples_sec: List[float], archetype: str = "GENERIC_HOST") -> Dict[str, float]:
        """
        Extracts per-host baseline jitter using lower-decile filtering and percentile deconvolution.
        Returns baseline latency, inter-percentile jitter, and empirical variance.
        """
        if not rtt_samples_sec:
            return {
                "min_rtt_sec": 0.0,
                "p10_rtt_sec": 0.0,
                "p50_rtt_sec": 0.0,
                "p90_rtt_sec": 0.0,
                "jitter_sec": 0.0,
                "variance_sec2": 0.0
            }

        arr = np.array(rtt_samples_sec, dtype=np.float64)
        p10 = float(np.percentile(arr, 10))
        p50 = float(np.percentile(arr, 50))
        p90 = float(np.percentile(arr, 90))
        jitter = max(0.0, p90 - p10)
        var = float(np.var(arr))

        return {
            "min_rtt_sec": float(np.min(arr)),
            "p10_rtt_sec": p10,
            "p50_rtt_sec": p50,
            "p90_rtt_sec": p90,
            "jitter_sec": jitter,
            "variance_sec2": var
        }


__all__ = [
    "ClassifierEngineResult",
    "DEFAULT_PROFILES",
    "DeviceClassifierEnginePort",
    "DeviceObservationPayload",
    "HeuristicScore",
    "HighDensityClassifier",
    "NetworkClassifierEngine",
    "TelemetryBuffer",
]


