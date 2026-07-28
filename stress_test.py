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

# 8 different attack scenarios — including Dual-Engine ML filtering and Threat Intel Bypass tests
scenarios = [
    {
        "name": "TEST 1: SQL Injection (External IP)",
        "payload": {
            "alert": {
                "id": 1001,
                "description": "Web application attack: SQL injection attempt detected in HTTP request",
                "level": 10,
                "src_ip": "45.33.32.156",
                "timestamp": "2026-07-22T22:00:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {
                    "found": True,
                    "error": None,
                    "matches": [
                        {"name": "Known SQL Injection scanner", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '45.33.32.156']"}
                    ]
                }
            },
            "correlation": {
                "total_sources_matched": 1,
                "preliminary_verdict": "known_malicious",
                "confidence": "high"
            }
        }
    },
    {
        "name": "TEST 2: External DDoS Attack",
        "payload": {
            "alert": {
                "id": 1002,
                "description": "High volume of ICMP packets detected - possible DDoS flood attack",
                "level": 12,
                "src_ip": "203.0.113.99",
                "timestamp": "2026-07-22T22:01:00Z"
            },
            "threat_intel": {
                "misp": {
                    "found": True,
                    "matches": [{"name": "DDoS botnet C2 node"}]
                },
                "opencti": {
                    "found": True,
                    "error": None,
                    "matches": [
                        {"name": "Known DDoS botnet member", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '203.0.113.99']"}
                    ]
                }
            },
            "correlation": {
                "total_sources_matched": 2,
                "preliminary_verdict": "known_malicious",
                "confidence": "high"
            }
        }
    },
    {
        "name": "TEST 3: Internal Ransomware Infection",
        "payload": {
            "alert": {
                "id": 1003,
                "description": "Mass file encryption detected - files renamed with unknown extension, possible ransomware activity",
                "level": 15,
                "src_ip": "10.0.0.45",
                "timestamp": "2026-07-22T22:02:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "error": None, "matches": []}
            },
            "correlation": {
                "total_sources_matched": 0,
                "preliminary_verdict": "suspicious",
                "confidence": "medium"
            }
        }
    },
    {
        "name": "TEST 4: Normal Employee Login (Should be Faux Positif)",
        "payload": {
            "alert": {
                "id": 1004,
                "description": "Dovecot Authentication Success.",
                "level": 2,
                "src_ip": "192.168.1.55",
                "timestamp": "2026-07-22T08:30:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "error": None, "matches": []}
            },
            "correlation": {
                "total_sources_matched": 0,
                "preliminary_verdict": "benign",
                "confidence": "high"
            }
        }
    },
    {
        "name": "TEST 5: Port Scan from Unknown IP",
        "payload": {
            "alert": {
                "id": 1005,
                "description": "Port scan detected - multiple TCP SYN requests across 1000 ports in under 10 seconds",
                "level": 7,
                "src_ip": "198.51.100.77",
                "timestamp": "2026-07-22T22:05:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "error": None, "matches": []}
            },
            "correlation": {
                "total_sources_matched": 0,
                "preliminary_verdict": "unknown",
                "confidence": "low"
            }
        }
    },
    {
        "name": "TEST 6: Repeated Attack (Checking Memory Database)",
        "payload": {
            "alert": {
                "id": 1006,
                "description": "Web application attack: SQL injection attempt detected in HTTP request AGAIN",
                "level": 10,
                "src_ip": "45.33.32.156",
                "timestamp": "2026-07-24T22:30:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": True, "error": None, "matches": [{"name": "Known SQL Injection scanner"}]}
            },
            "correlation": {
                "total_sources_matched": 1,
                "preliminary_verdict": "known_malicious",
                "confidence": "high"
            }
        }
    },
    {
        "name": "TEST 7: Instant ML Filter (Benign log)",
        "payload": {
            "alert": {
                "id": 1007,
                "description": "Dovecot Authentication Success.",
                "level": 3,
                "src_ip": "192.168.1.10",
                "timestamp": "2026-07-25T09:00:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {"found": False, "error": None, "matches": []}
            },
            "correlation": {
                "total_sources_matched": 0,
                "preliminary_verdict": "benign",
                "confidence": "high"
            }
        }
    },
    {
        "name": "TEST 8: Threat Intel Bypass (Low level, but malicious IP)",
        "payload": {
            "alert": {
                "id": 1008,
                "description": "Connection closed by authentication failure",
                "level": 3,
                "src_ip": "85.20.10.5",
                "timestamp": "2026-07-25T23:00:00Z"
            },
            "threat_intel": {
                "misp": {"found": False, "matches": []},
                "opencti": {
                    "found": True,
                    "error": None,
                    "matches": [
                        {"name": "Known Brute Forcer", "pattern_type": "stix", "pattern": "[ipv4-addr:value = '85.20.10.5']"}
                    ]
                }
            },
            "correlation": {
                "total_sources_matched": 1,
                "preliminary_verdict": "known_malicious",
                "confidence": "high"
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
