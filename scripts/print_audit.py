import json

with open("topology_audit.json", "r", encoding="utf-8") as f:
    audit = json.load(f)

print("=== GROUND TRUTH AUDIT SUMMARY ===")
for gt in audit.get("ground_truth_accuracy_audit", []):
    name = str(gt.get("canonical_name", ""))[:24].ljust(24)
    truth = f"{gt.get('ground_truth_m', 0):.2f}m"
    est = f"{gt.get('estimated_m', 0):.2f}m"
    delta = f"{gt.get('delta_m', 0):+.3f}m"
    err = f"{gt.get('error_pct', 0):.2f}%"
    print(f"  {name} | Truth: {truth:>7} | Est: {est:>7} | Delta: {delta:>7} | Err: {err:>6}")

print(f"\nTotal Converged Endpoints: {len(audit.get('converged_endpoints', []))}")
