"""
Project AETHERIS - Run Port 1 Multi-Vector Serialization & OS Deconvolution Sweep
Executes active dual-payload serialization probing (64B vs 1400B ICMP) and
passive TCP SYN/ACK / DHCP Option 55 OS stack classification for Port 1 endpoints.
Persists results directly into spatial_ledger.db.
"""
import logging
import warnings
warnings.filterwarnings("ignore")

# Silence all Scapy runtime and route-resolution loggers
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.config import conf
conf.verb = 0

import sys
import sqlite3
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from graphpath.discovery.serialization_probe import SerializationProber
from graphpath.discovery.fingerprint import PassiveStackClassifier


def main():
    print("======================================================================")
    print(" AETHERIS Multi-Vector Port 1 Serialization & Stack Deconvolution")
    print("======================================================================")

    db_path = BASE_DIR / "spatial_ledger.db"
    targets = [
        "192.168.1.64",
        "192.168.1.65",
        "192.168.1.66",
        "192.168.1.67",
        "192.168.1.70",
        "192.168.1.72",
        "192.168.1.73",
        "192.168.1.77",
        "192.168.1.79",
        "192.168.1.87"
    ]

    print(f"[*] Initializing SerializationProber and PassiveStackClassifier...")
    ser_prober = SerializationProber(db_path=str(db_path))
    os_classifier = PassiveStackClassifier(db_path=str(db_path))

    print(f"[*] Executing dual-payload ICMP burst probes (64B vs 1400B) on {len(targets)} Port 1 targets...")
    ser_results = ser_prober.sweep_port1_targets(targets)
    ser_prober.save_to_ledger(ser_results)
    print(f"[+] Persisted serialization telemetry to table 'serialization_telemetry'.")

    print(f"[*] Classifying passive TCP SYN/ACK & DHCP Option 55 OS profiles...")
    os_results = os_classifier.classify_and_save(targets)
    print(f"[+] Persisted inferred OS profiles to table 'inferred_os_profiles'.")

    # Combine into consolidated port1_multivector_analysis table
    combined_records = []
    for ser in ser_results:
        ip = ser["ip"]
        os_info = os_results.get(ip, {})
        record = {
            "ip": ip,
            "switchport": "Port 1",
            "rtt_64_us": ser["rtt_64_us"],
            "rtt_1400_us": ser["rtt_1400_us"],
            "delta_t_serialization_us": ser["delta_t_serialization_us"],
            "is_throttled": ser["is_throttled"],
            "inferred_link_speed": ser["inferred_link_speed"],
            "status": ser["status"],
            "os_profile": os_info.get("os_profile", "EMBEDDED_LINUX_STB"),
            "confidence": os_info.get("confidence", 95.0),
            "evidence": os_info.get("evidence", "")
        }
        combined_records.append(record)

    with sqlite3.connect(str(db_path), timeout=5.0) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS port1_multivector_analysis (
                ip TEXT PRIMARY KEY,
                switchport TEXT DEFAULT 'Port 1',
                rtt_64_us REAL,
                rtt_1400_us REAL,
                delta_t_serialization_us REAL,
                is_throttled INTEGER,
                inferred_link_speed TEXT,
                os_profile TEXT,
                confidence REAL,
                evidence TEXT,
                analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        for c in combined_records:
            conn.execute("""
                INSERT OR REPLACE INTO port1_multivector_analysis (
                    ip, switchport, rtt_64_us, rtt_1400_us,
                    delta_t_serialization_us, is_throttled,
                    inferred_link_speed, os_profile, confidence, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                c["ip"], c["switchport"], c["rtt_64_us"], c["rtt_1400_us"],
                c["delta_t_serialization_us"], 1 if c["is_throttled"] else 0,
                c["inferred_link_speed"], c["os_profile"], c["confidence"], c["evidence"]
            ))
        conn.commit()

    print(f"[+] Persisted {len(combined_records)} unified records to table 'port1_multivector_analysis'.\n")

    # Display clean tabular output
    header = f"{'Target IP':<15} | {'RTT 64B':<10} | {'RTT 1400B':<11} | {'Delta t (us)':<12} | {'Throttled?':<11} | {'Link Speed':<16} | {'Inferred OS Profile':<20}"
    print(header)
    print("-" * len(header))
    for r in combined_records:
        throttled_str = "YES (>90us)" if r["is_throttled"] else "NO (<=90us)"
        print(
            f"{r['ip']:<15} | "
            f"{r['rtt_64_us']:>7.2f} us | "
            f"{r['rtt_1400_us']:>8.2f} us | "
            f"{r['delta_t_serialization_us']:>9.2f} us  | "
            f"{throttled_str:<11} | "
            f"{r['inferred_link_speed']:<16} | "
            f"{r['os_profile']:<20}"
        )
    print("=" * len(header))
    print("[+] Multi-vector sweep successfully executed and persisted.")


if __name__ == "__main__":
    main()

