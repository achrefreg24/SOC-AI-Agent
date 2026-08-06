import requests
import json
import time

API_URL = "http://localhost:8000/qualifier-alerte?disable_ml=true"

# Fake Wazuh alerts designed specifically to test the IP boundary logic
test_ips = [
    "172.20.10.5",  # Should be INTERNAL (Inside 172.16 - 172.31)
    "172.40.5.5",   # Should be EXTERNAL (Outside the range)
    "10.50.0.1",    # Should be INTERNAL
    "127.0.0.1",    # Should be INTERNAL
    "8.8.8.8"       # Should be EXTERNAL
]

print("="*60)
print("  SIMULATING IP LOGIC WITH LLaMA 3")
print("="*60)

for ip in test_ips:
    payload = {
        "wazuh_alert": {
            "timestamp": "2026-08-05T03:00:00.000+0000", # Night time to force Critical/Suspicious
            "rule": {
                "level": 12,
                "description": "Malware detected on workstation"
            },
            "agent": {"id": "001"},
            "data": {"srcip": ip}
        },
        "threat_intelligence": {
            "opencti": {"found": False},
            "misp": {"found": False}
        }
    }
    
    print(f"\n[*] Testing IP: {ip}")
    try:
        resp = requests.post(API_URL, json=payload, timeout=120)
        if resp.status_code == 200:
            result = resp.json()
            print(f"   -> Engine Classification: {result.get('classification')}")
            print(f"   -> Engine Action: {result.get('action_type')}")
            print(f"   -> Reasoning: {result.get('reasoning')}")
        else:
            print(f"   -> [ERROR] Status {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"   -> [ERROR] Request failed: {e}")
        
    print("Cooldown 5s...")
    time.sleep(5)

print("\nSimulation Complete!")
