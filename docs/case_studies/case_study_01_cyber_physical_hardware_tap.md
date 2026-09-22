# Technical Case Study I: Spliced Inline Tap Detection & Cyber-Physical DC Drop Solvers

**Role & Domain:** IoT Solutions Engineering / Cyber-Physical Physical-Layer Security  
**System:** Project AETHERIS (L1/L2 Spatial Engine)  
**Primary Modules:** [`aetheris/core/spatial_dc_drop.py`](file:///e:/Project_AETHERIS/aetheris/core/spatial_dc_drop.py), [`aetheris/core/security_auditor.py`](file:///e:/Project_AETHERIS/aetheris/core/security_auditor.py), [`aetheris/discovery/advanced_spatial_prober.py`](file:///e:/Project_AETHERIS/aetheris/discovery/advanced_spatial_prober.py)

---

## 1. Executive Summary

Standard enterprise cybersecurity tools monitor Layer 3–7 traffic, assuming that Layer 1 physical infrastructure is immutable and trustworthy. In physical security and industrial automation environments, this assumption is false. Spliced physical implants—such as ESPKey Wiegand/OSDP interceptors or rogue BLE transceivers attached to access control card-reader lines—operate passively, siphoning credentials and injecting fake door unlocks without emitting IP packets or alerting network intrusion detection systems (NIDS).

Project AETHERIS solves this visibility gap by deriving physical conductor topology directly from electrical telemetry and transmission physics. By ingesting passive DC terminal voltages, linearizing copper resistivity against ambient temperature, isolating inductive inrush transients via dynamic envelope gating, and evaluating baud-rate slew divergence, AETHERIS deterministically isolates spliced hardware taps with zero reliance on credentials or invasive active probing.

---

## 2. Cyber-Physical Mechanics & Mathematical Formulations

```mermaid
graph TD
    A[Access Controller ADC Telemetry] --> B[Quiescent Baseline Ingestion]
    B --> C{Active State Filter: 2.5x Gate}
    C -->|Transient Solenoid Inrush| D[Reject Sample: REJECTED_ACTIVE_TRANSIENT_STATE]
    C -->|Quiescent Nominal Load| E[Thermal Linearization: R_T = R_20 * (1 + alpha * Delta T)]
    E --> F[Compute Loop Resistance: R_loop = Delta V / I_load]
    F --> G[Gaussian Variance Propagation: sigma_d]
    G --> H{Divergence Evaluation}
    H -->|R_parasitic > 0.85 Ohms / Baud Slew Divergence| I[CRITICAL ADVISORY: INLINE_HARDWARE_TAP_DETECTED]
    H -->|Within Spec| J[Nominal Physical Cable Distance Locked]
```

### 2.1 Thermal Linearization of Conductor Resistivity
Copper conductor resistance varies significantly across non-conditioned risers and conduits:
$$R_{\text{conductor}}(T) = R_{20} \cdot \left[1 + \alpha_{\text{copper}} \cdot (T - 20^\circ\text{C})\right]$$
where:
- $\alpha_{\text{copper}} = 0.00393/\,^\circ\text{C}$ (temperature coefficient of annealed copper).
- $R_{20}$ is the standard metric conductor resistivity at $20^\circ\text{C}$ across standard American Wire Gauge (AWG) standards:
  - $18\text{ AWG}: 0.02095\,\Omega/\text{m}$
  - $20\text{ AWG}: 0.03330\,\Omega/\text{m}$
  - $22\text{ AWG}: 0.05295\,\Omega/\text{m}$
  - $24\text{ AWG}: 0.08422\,\Omega/\text{m}$

### 2.2 Conductor Distance Deduction & Gaussian Uncertainty
One-way loop distance is calculated from the terminal voltage drop ($\Delta V = V_{\text{source}} - V_{\text{terminal}}$) under quiescent current draw ($I_{\text{quiescent}}$):
$$d_{\text{conductor}} = \frac{V_{\text{source}} - V_{\text{terminal}}}{2 \cdot I_{\text{quiescent}} \cdot R_{\text{conductor}}(T)}$$

To prevent spatial hallucinations caused by voltmeter ADC quantization noise and sensor bias, AETHERIS propagates standard measurement uncertainties ($\sigma_V = 0.05\,\text{V}$, $\sigma_I = 0.05 \cdot I$):
$$\sigma_d = d \cdot \sqrt{\left(\frac{\sigma_V}{\Delta V}\right)^2 + \left(\frac{\sigma_I}{I}\right)^2}$$

### 2.3 Transient Filtering via `PeripheralElectricalEnvelope`
Inductive access control peripherals (door strikes, magnetic locks) produce substantial inrush currents ($> 1.1\,\text{A}$) and inductive kickback spikes during activation. Applying DC drop calculations during an actuation cycle will hallucinate impossible conductor lengths. AETHERIS deploys a $2.5\times$ dynamic rejection gate:
$$\text{Reject if } \Delta V > 2.5 \cdot \left(2 \cdot I_{\text{quiescent}} \cdot R_{\text{conductor}}(T) \cdot 50\,\text{m}\right)$$
This locks the true quiescent baseline and safely ignores 50 Hz relay chatter and brownout voltage sags.

### 2.4 Spliced Parasitic Tap Detection
When an unauthorized hardware tap is spliced into an RS-485 / OSDP reader cable:
1. **DC Resistance Divergence:** The parasitic splice contact resistance and tap load produce an excess resistance:
   $$\Delta R_{\text{excess}} = \frac{\Delta V}{I_{\text{load}}} - R_{\text{loop\_expected}}$$
   If $\Delta R_{\text{excess}} > 0.85\,\Omega$, [`SecurityAuditor`](file:///e:/Project_AETHERIS/aetheris/core/security_auditor.py) triggers `INLINE_HARDWARE_TAP_DETECTED`.
2. **High-Frequency Baud-Rate Slew Divergence:** Splicing additional PCB traces and transceiver inputs introduces parasitic shunt capacitance ($C_{\text{parasitic}} \approx 80\text{--}250\,\text{pF}$), rounding RS-485 bit transitions and degrading rise time:
   $$\Delta t_{\text{rise}} \approx 2.2 \cdot R_{\text{terminal}} \cdot C_{\text{total}}$$
   A divergence ratio $> 1.45\times$ between measured baud-rate propagation and DC drop distance corroborates the presence of an inline physical interceptor.

---

## 3. End-to-End Execution Flow & Output Schema

The system ingests controller ADC samples, resolves physical distance, and exports strictly typed, sanitized JSON telemetry (`json.loads(json.dumps(res)) == res`):

```json
{
  "peripheral_id": "osdp-reader-entry-01",
  "status": "INLINE_HARDWARE_TAP_DETECTED",
  "anomaly": {
    "voltage_drop_v": 1.42,
    "current_amps": 0.11,
    "expected_distance_m": 45.0,
    "calculated_dc_distance_m": 121.84,
    "parasitic_resistance_ohms": 7.07,
    "confidence": 0.96
  },
  "audit_finding": {
    "code": "INLINE_HARDWARE_TAP_DETECTED",
    "severity": "CRITICAL",
    "risk_score_delta": 45,
    "remediation": "Physically inspect reader junction box for unauthorized splice, ESPKey, or BLE snooper."
  }
}
```

---

## 4. Key Takeaways for IoT Solutions Engineering
1. **Zero-Touch Physical Security:** Validates physical wire integrity purely through electrical telemetry without requiring on-site technicians or invasive active sweeps.
2. **Thermal & Noise Resilience:** Accounts for real-world environmental variables (ambient temperature swings, ADC noise) via rigorous Gaussian covariance math.
3. **Deterministic Defect Isolation:** Rejects inductive inrush transients from door strikes, preventing false alarms during high-traffic access cycles.
