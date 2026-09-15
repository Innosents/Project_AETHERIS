import sqlite3
from pathlib import Path

db_path = Path(__file__).resolve().parent.parent / "spatial_ledger.db"
conn = sqlite3.connect(db_path)
cur = conn.cursor()

query = """
SELECT canonical_name, ground_truth_m, latest_estimate_m, delta_error_m, error_pct
FROM v_spatial_accuracy_history
"""

rows = cur.execute(query).fetchall()

header = f"{'DEVICE':<26} {'TRUTH (m)':<12} {'ESTIMATED (m)':<15} {'DELTA (m)':<12} {'ERROR %'}"
print("\n" + header)
print("-" * len(header))

for name, truth, est, delta, err in rows:
    t_str = f"{truth:.2f}" if truth is not None else "-"
    e_str = f"{est:.2f}" if est is not None else "-"
    d_str = f"{delta:+.3f}" if delta is not None else "-"
    err_str = f"{err:.2f}%" if err is not None else "-"
    print(f"{name:<26} {t_str:<12} {e_str:<15} {d_str:<12} {err_str}")

print(f"\nTotal registered ground truth devices tracked: {len(rows)}\n")
conn.close()