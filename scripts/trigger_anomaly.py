import json
import time
import redis

def inject_synthetic_anomaly():
    print("[+] Connecting to local Redis ledger...")
    r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    
    anomaly_payload = {
        "event_id": "DIAG-001",
        "timestamp_ns": time.time_ns(),
        "target_ip": "10.0.20.45",
        "vlan": 20,
        "trigger": "tau_flight_variance",
        "variance_ns": 45000,
        "description": "Severe nanosecond time-of-flight variance detected on industrial VLAN. Deploy diagnostic edge-case payload to validate physical layer state."
    }
    
    # Assuming Phase 2 Redis ledger uses a standard list or sorted set for high-entropy events
    # We push it to the queue that pop_highest_entropy_event() is monitoring
    queue_key = "aetheris:telemetry:anomalies" 
    r.lpush(queue_key, json.dumps(anomaly_payload))
    
    print(f"[+] Synthetic anomaly injected into {queue_key}. Watch the Sovereign Agent terminal.")

if __name__ == "__main__":
    inject_synthetic_anomaly()