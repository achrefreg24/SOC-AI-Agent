import requests
import json
import time

url = "http://localhost:8000/qualifier-alerte"

# The exact JSON structure output by the N8N pipeline (Blue Team)
payload = [
  {
    "wazuh_alert": {
      "id": "86601",
      "timestamp": "2026-07-27T15:20:00.000+0000",
      "level": 3,
      "description": "Suricata: Alert - test enrichment réel",
      "src_ip": "45.120.216.232",
      "dst_ip": "100.64.0.20",
      "agent": {
        "id": "001",
        "name": "vulnerable-machine-linux",
        "ip": "100.64.0.20"
      },
      "full_raw": {
        "timestamp": "2026-07-27T15:20:00.000+0000",
        "rule": {
          "id": "86601",
          "level": 3,
          "description": "Suricata: Alert - test enrichment réel",
          "groups": ["ids", "suricata"]
        },
        "agent": {
          "id": "001",
          "name": "vulnerable-machine-linux",
          "ip": "100.64.0.20"
        },
        "data": {
          "srcip": "45.120.216.232",
          "dstip": "100.64.0.20",
          "proto": "TCP"
        },
        "full_log": "Suricata: Alert - test enrichment réel from 45.120.216.232"
      }
    },
    "threat_intelligence": {
      "misp": {
        "found": True,
        "event": {
          "id": "6271",
          "info": "Wazuh Alert [N/A] - Unknown",
          "Tag": [
            {"name": "wazuh"},
            {"name": "n8n-auto"},
            {"name": "soc-pipeline"}
          ]
        }
      },
      "opencti": {
        "found": False,
        "full_response": {
          "data": {
            "stixCyberObservables": {
              "edges": [
                {
                  "node": {
                    "observable_value": "45.120.216.232",
                    "x_opencti_score": 100,
                    "x_opencti_description": "Agressive IP known malicious on AbuseIPDB - countryCode: HK - abuseConfidenceScore: 100"
                  }
                }
              ]
            }
          }
        }
      }
    },
    "correlation_summary": {
      "total_matches": 1,
      "preliminary_verdict": "intel_found",
      "misp_attributes_count": 1,
      "opencti_indicators_count": 0
    },
    "analysis_request": {
      "task": "Analyze this security alert and determine if it's a TRUE POSITIVE or FALSE POSITIVE"
    }
  }
]

print("=" * 60)
print("  N8N PAYLOAD TEST — Real Blue Team Format")
print("=" * 60)
print(f"\n🚀 Sending N8N Payload to {url}...")
print("⏳ Waiting for Engine 2 (LLaMA 3) to analyze... (this can take 30-90 seconds)\n")

start = time.time()
try:
    response = requests.post(url, json=payload, timeout=300)
    elapsed = round(time.time() - start, 1)

    print(f"✅ Response received in {elapsed}s\n")
    result = response.json()
    
    print("=" * 60)
    print("  AI RESPONSE (sent back to N8N)")
    print("=" * 60)
    print(f"  Classification  : {result.get('classification')}")
    print(f"  Confidence      : {result.get('confidence_score')}%")
    print(f"  Attack Type     : {result.get('attack_type')}")
    print(f"  MITRE Tactic    : {result.get('mitre_tactic')}")
    print(f"  Reasoning       : {result.get('reasoning')}")
    print(f"  Recommendation  : {result.get('recommandation')}")
    action = result.get("automated_action", {})
    print(f"  Action Execute  : {action.get('execute')}")
    print(f"  Action Type     : {action.get('action_type')}")
    print(f"  Target          : {action.get('target')}")
    print("=" * 60)

except requests.exceptions.ConnectionError:
    print("❌ Connection Error: The server is probably still reloading.")
    print("   Wait 10 seconds for the server to finish restarting, then try again.")
except requests.exceptions.Timeout:
    print("❌ Timeout: The AI took too long (>5 minutes). Check Ollama is running.")
except Exception as e:
    print(f"❌ Error: {e}")
