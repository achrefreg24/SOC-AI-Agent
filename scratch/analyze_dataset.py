import json
from pathlib import Path
from collections import Counter

DATA_FILE = Path(__file__).parent.parent / "data" / "alerts.json"

print("="*60)
print("  DATASET DIAGNOSTICS & ANOMALY CHECK")
print("="*60)

try:
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            raw_data = json.load(f)
        except json.JSONDecodeError:
            f.seek(0)
            raw_data = [json.loads(line) for line in f if line.strip()]
except Exception as e:
    print(f"[ERROR] Could not load file: {e}")
    exit(1)

valid_alerts = []
anomaly_count = 0

for item in raw_data:
    if isinstance(item, dict) and "input" in item and isinstance(item["input"], str):
        input_str = item["input"]
        json_start = input_str.find('{')
        if json_start != -1:
            try:
                alert = json.loads(input_str[json_start:])
                valid_alerts.append(alert)
            except json.JSONDecodeError:
                anomaly_count += 1
        else:
            anomaly_count += 1
    else:
        anomaly_count += 1

print(f"Total Rows: {len(raw_data)}")
print(f"Successfully Parsed Wazuh Alerts: {len(valid_alerts)}")
print(f"Anomalous/Unparseable Rows: {anomaly_count}")

if not valid_alerts:
    print("\n[!] No valid alerts found. The dataset format is incorrect.")
    exit(1)

print("\n--- Rule Descriptions Distribution (Top 10) ---")
descriptions = []
for alert in valid_alerts:
    desc = alert.get("rule", {}).get("description", "UNKNOWN")
    descriptions.append(desc)

counter = Counter(descriptions)
for desc, count in counter.most_common(10):
    print(f" - {count}x : {desc}")

print("\n--- Rule Levels Distribution ---")
levels = [str(alert.get("rule", {}).get("level", "UNKNOWN")) for alert in valid_alerts]
for lvl, count in Counter(levels).most_common():
    print(f" - Level {lvl}: {count} alerts")
    
print("\n--- Anomaly Check ---")
if anomaly_count > 0:
    print("[!] WARNING: Some rows could not be parsed.")
else:
    print("[OK] Dataset is perfectly clean and parseable.")
    
print("="*60)
