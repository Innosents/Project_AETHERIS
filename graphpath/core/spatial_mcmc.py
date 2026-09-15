import numpy as np
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional

C_VACUUM = 299792458.0


@dataclass
class MCMCResult:
    distance_m: float
    variance_m2: float
    confidence_pct: float
    acceptance_fraction: float
    t_kernel_median_us: float


class AffineInvariantSpatialMCMC:
    """
    Affine-Invariant Ensemble MCMC Sampler (Goodman-Weare algorithm)
    for physical cable flight-time and kernel latency deconvolution.
    """
    def __init__(
        self,
        nvp: float = 0.69,
        num_walkers: int = 24,
        steps: int = 300,
        burn_in: int = 100,
        a_scale: float = 2.0,
        ledger: Optional[Any] = None
    ):
        self.nvp = nvp
        self.v_prop = nvp * C_VACUUM  # m/s
        self.num_walkers = max(12, (num_walkers // 2) * 2)  # Must be even
        self.steps = steps
        self.burn_in = burn_in
        self.a_scale = a_scale
        self.d_min = 0.5
        self.d_max = 100.0
        self.ledger = ledger

    def log_prior(self, theta: np.ndarray, archetype: str, oui: str = "") -> float:
        """
        Theta = [distance_m, t_kernel_s]
        Uniform prior over physical cable drop: U(0.5, 100.0)
        Empirical or Archetype Log-Normal prior over kernel turnaround latency.
        """
        d, t_k = theta[0], theta[1]
        if not (self.d_min <= d <= self.d_max) or t_k <= 0.0:
            return -np.inf

        # Query dynamic empirical prior from ledger if available (N >= 3)
        empirical_prior = None
        if self.ledger:
            try:
                empirical_prior = self.ledger.get_empirical_kernel_prior(oui=oui, archetype=archetype)
            except Exception:
                empirical_prior = None

        if empirical_prior is not None:
            mu_log, sigma_log = empirical_prior
        else:
            # Prior kernel delay expectations in seconds (calibrated archetype turnaround)
            priors = {
                "WINDOWS_HOST": (np.log(1.0e-3), 0.25),
                "LINUX_SERVER": (np.log(1.1e-3), 0.25),
                "CCTV_VIDEO":   (np.log(2.0e-3), 0.35),
                "INDUSTRIAL_OT": (np.log(3.0e-4), 0.35),
                "VOIP_TELEPHONY": (np.log(1.0e-3), 0.30),
                "NETWORK_INFRASTRUCTURE": (np.log(2.0e-4), 0.35),
                "GENERIC_HOST": (np.log(1.0e-3), 0.30)
            }
            mu_log, sigma_log = priors.get(archetype, priors["GENERIC_HOST"])

        log_pk = -np.log(t_k * sigma_log * np.sqrt(2 * np.pi)) - ((np.log(t_k) - mu_log) ** 2) / (2 * sigma_log ** 2)

        # Structured cabling prior: physical horizontal drops center at ~16m (std ~6.0m)
        mu_d = 16.0
        sigma_d = 6.0
        log_pd = -0.5 * ((d - mu_d) / sigma_d) ** 2

        return float(log_pk + log_pd)

    def log_likelihood(self, theta: np.ndarray, rtt_samples_s: np.ndarray) -> float:
        """
        Shifted Exponential-Gaussian likelihood.
        Theoretical RTT: t_flight(d) + t_kernel
        Observed RTTs cannot be smaller than true physical flight time.
        """
        d, t_k = theta[0], theta[1]
        t_flight = (2.0 * d) / self.v_prop
        t_base = t_flight + t_k

        residuals = rtt_samples_s - t_base
        
        # Hard physical constraint: transmission cannot happen faster than physical floor
        if np.any(rtt_samples_s < t_flight):
            return -np.inf

        # Heavy right-skewed penalty for scheduler delays (Exponential tails with rate lambda)
        lam = 5000.0  # 1 / 200µs decay rate
        neg_penalty = np.sum(np.where(residuals < 0, residuals ** 2 * 1e12, 0.0))
        pos_likelihood = np.sum(np.where(residuals >= 0, np.log(lam) - lam * residuals, 0.0))

        return float(pos_likelihood - neg_penalty)

    def log_posterior(self, theta: np.ndarray, rtt_samples_s: np.ndarray, archetype: str, oui: str = "") -> float:
        lp = self.log_prior(theta, archetype, oui=oui)
        if not np.isfinite(lp):
            return -np.inf
        ll = self.log_likelihood(theta, rtt_samples_s)
        if not np.isfinite(ll):
            return -np.inf
        return lp + ll

    def sample(
        self,
        rtt_samples_us: List[float],
        archetype: str = "GENERIC_HOST",
        oui: str = "",
        riser_overhead_us: float = 0.0
    ) -> MCMCResult:
        if not rtt_samples_us:
            return MCMCResult(
                distance_m=50.0,
                variance_m2=100.0,
                confidence_pct=0.0,
                acceptance_fraction=0.0,
                t_kernel_median_us=1000.0
            )

        # Sanitize oui to prevent broadcast or null prefixes from contaminating empirical priors
        if oui and (oui.upper().startswith("FFFFFF") or oui.upper().startswith("000000")):
            oui = ""

        # Deduct known infrastructure riser delay (ASIC forwarding + backbone flight time)
        effective_rtt_us = [max(0.01, r - riser_overhead_us) for r in rtt_samples_us]
        rtt_s = np.array(effective_rtt_us, dtype=np.float64) * 1e-6
        min_rtt_s = float(np.percentile(rtt_s, 5))

        # 1. Initialize walker ball around plausible states
        ndim = 2
        walkers = np.zeros((self.num_walkers, ndim))
        max_valid_d = min(self.d_max, max(self.d_min + 0.1, (float(np.min(rtt_s)) * self.v_prop / 2.0) - 0.1))
        upper_init_d = min(35.0, max_valid_d)
        lower_init_d = min(self.d_min, upper_init_d - 0.1)

        init_d = np.random.uniform(lower_init_d, upper_init_d, size=self.num_walkers)
        t_flights = (2.0 * init_d) / self.v_prop
        init_tk = np.clip(min_rtt_s - t_flights, 1e-5, None)
        walkers[:, 0] = init_d
        walkers[:, 1] = init_tk

        log_prob = np.array([self.log_posterior(w, rtt_s, archetype, oui=oui) for w in walkers])

        # Ensure all walkers have finite initial posterior probabilities
        for i in range(self.num_walkers):
            attempts = 0
            while not np.isfinite(log_prob[i]) and attempts < 100:
                d_try = np.random.uniform(lower_init_d, upper_init_d)
                t_flight_try = (2.0 * d_try) / self.v_prop
                tk_try = max(1e-5, min_rtt_s - t_flight_try)
                walkers[i] = [d_try, tk_try]
                log_prob[i] = self.log_posterior(walkers[i], rtt_s, archetype)
                attempts += 1

        chain = np.zeros((self.steps, self.num_walkers, ndim))
        accepted_moves = 0
        total_moves = 0

        half_k = self.num_walkers // 2

        # 2. Goodman-Weare Stretch Move Sampling
        for step in range(self.steps):
            # Split ensemble into complementary halves for affine invariance
            for sub_a, sub_b in [(range(0, half_k), range(half_k, self.num_walkers)),
                                 (range(half_k, self.num_walkers), range(0, half_k))]:
                for k in sub_a:
                    # Randomly pick partner j from complement sub-ensemble
                    j = np.random.choice(sub_b)
                    
                    # Sample Z from g(z) ~ 1/sqrt(z) over [1/a, a]
                    u = np.random.uniform(0.0, 1.0)
                    z = ((self.a_scale - 1.0) * u + 1.0) ** 2 / self.a_scale
                    
                    # Stretch move proposal: Y = X_j + Z * (X_k - X_j)
                    y = walkers[j] + z * (walkers[k] - walkers[j])
                    lp_y = self.log_posterior(y, rtt_s, archetype, oui=oui)
                    
                    # Metropolis-Hastings acceptance ratio: q = z^(ndim - 1) * exp(lp_y - lp_k)
                    total_moves += 1
                    if np.isfinite(lp_y):
                        log_q = (ndim - 1) * np.log(z) + lp_y - log_prob[k]
                        if np.log(np.random.uniform(0.0, 1.0)) < log_q:
                            walkers[k] = y
                            log_prob[k] = lp_y
                            accepted_moves += 1
                            
            chain[step] = walkers

        acceptance_fraction = accepted_moves / max(1, total_moves)

        # 3. Discard burn-in and flatten posterior distribution
        burn = min(self.burn_in, self.steps // 2)
        flat_chain = chain[burn:].reshape(-1, ndim)

        d_samples = flat_chain[:, 0]
        tk_samples = flat_chain[:, 1]

        median_d = float(np.median(d_samples))
        var_d = float(np.var(d_samples))
        median_tk_us = float(np.median(tk_samples) * 1e6)

        std_d = np.sqrt(max(1e-4, var_d))
        confidence = float(np.clip(100.0 / (1.0 + (std_d / 18.0) ** 1.5), 15.0, 99.0))

        return MCMCResult(
            distance_m=round(median_d, 2),
            variance_m2=round(var_d, 3),
            confidence_pct=round(confidence, 1),
            acceptance_fraction=round(acceptance_fraction, 3),
            t_kernel_median_us=round(median_tk_us, 1)
        )

