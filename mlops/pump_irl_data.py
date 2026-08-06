import json
import requests
import time
from pathlib import Path

# Config
DATA_FILE = Path(__file__).parent.parent / "data" / "alerts.json"
API_URL = "http://localhost:8000/qualifier-alerte?disable_ml=true"

print("=" * 60)
print("  PUMPING IRL DATA TO OLLAMA")
print("=" * 60)

if not DATA_FILE.exists():
    print(f"\n[ERROR] File not found: {DATA_FILE}")
    print("Please download a real-world Wazuh dataset (e.g. from BOTSv1)")
    print("and save it as 'alerts.json' inside the 'data/' folder.")
    exit(1)

print(f"\n[*] Reading real-world logs from {DATA_FILE}...")

try:
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            alerts = json.load(f)
        except json.JSONDecodeError:
            f.seek(0)
            alerts = [json.loads(line) for line in f if line.strip()]
except Exception as e:
    print(f"[ERROR] Failed to read JSON: {e}")
    exit(1)

# Set a safety limit so your PC doesn't get fried!
MAX_ALERTS = 50 

success_count = 0

print(f"[*] Processing a safe subset of {MAX_ALERTS} alerts...")

for i, raw_item in enumerate(alerts, 1):
    if i > MAX_ALERTS:
        print("\n[!] Safety limit reached. Stopping early to save your PC!")
        break
        
    print(f"--- Sending Alert {i}/{MAX_ALERTS} ---")
    
    # Handle Hugging Face LLM-formatted datasets (instruction/input/output)
    raw_alert = raw_item
    if isinstance(raw_item, dict) and "input" in raw_item and isinstance(raw_item["input"], str):
        try:
            # Extract the actual JSON from the Hugging Face "input" string
            # It usually starts with '{ "timestamp"'
            json_start = raw_item["input"].find('{')
            if json_start != -1:
                raw_alert = json.loads(raw_item["input"][json_start:])
        except Exception:
            pass # Fallback to original
    
    # We construct a payload that matches N8N's format
    payload = {
        "wazuh_alert": raw_alert,
        "threat_intelligence": {
            "opencti": {"found": False},
            "misp": {"found": False}
        }
    }

    try:
        start_time = time.time()
        response = requests.post(API_URL, json=payload, timeout=120)
        elapsed = round(time.time() - start_time, 1)

        if response.status_code == 200:
            result = response.json()
            classification = result.get("classification", "Unknown")
            print(f"[OK] {elapsed}s | Ollama classified as: {classification}")
            success_count += 1
        else:
            print(f"[ERROR] API returned HTTP {response.status_code}: {response.text}")

    except Exception as e:
        print(f"[ERROR] Request failed: {e}")

    # Cooldown is critical to let the GTX 1650 and Ryzen 5 cool off
    print("⏳ Cooldown 30 seconds for maximum hardware rest...\n")
    time.sleep(30)

print("=" * 60)
print(f"  FINISHED: Successfully processed {success_count}/{len(alerts)} alerts.")
print("  You can now run 'python mlops/retrain_engine1.py' to let Engine 1 learn from these!")
print("=" * 60)
