"""
soc_agent.py
------------
Central AI SOC agent module: classifies a Wazuh alert AND generates a
response recommendation, via Ollama/LLaMA3. Designed to be imported by
both a CLI script and the FastAPI API.
"""

import argparse
import json
import requests
from app.agent.rag_module import get_rag_context_vector
import pandas as pd

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3"
VALID_LABELS = ["Critical", "Suspicious", "Informational", "False Positive"]

RECOMMENDATIONS_BY_CLASS = {
    # Default recommendation if the LLM fails to provide actionable text.
    "Critical": "Isolate the affected machine, immediately escalate to a senior "
                "analyst, and preserve logs for forensic investigation.",
    "Suspicious": "Investigate manually within the next few hours: verify the "
                  "legitimacy of the source, correlate with other recent alerts.",
    "Informational": "No action required. Archive for traceability.",
    "False Positive": "No action required. Consider tuning the rule if "
                      "this pattern repeats frequently (noise reduction).",
}


def build_system_prompt() -> str:
    lines = [
        "You are a Senior Threat Hunter. For each Wazuh security alert, you must:",
        "1. Classify it into EXACTLY one of these 4 categories: Critical, Suspicious, Informational, False Positive",
        "2. Identify the attack type (attack_type) explicitly (e.g., 'SSH Brute Force', 'SQL Injection', 'Trojan', or 'None' if False Positive).",
        "3. Provide a short, actionable recommendation for the SOC analyst.",
        "4. Provide an 'automated_action' ONLY if the alert is Critical.",
        "",
        "MANDATORY SECURITY RULES FOR AUTOMATED ACTION (STRICT COMPLIANCE REQUIRED):",
        "RULE 1 - INTERNAL IP: If src_ip starts with '192.168.', '10.', or '172.16.' -> the IP is INTERNAL. 'firewall-drop' is FORBIDDEN. 'wazuh-isolate-endpoint' is MANDATORY.",
        "RULE 2 - EXTERNAL IP: If src_ip does NOT start with '192.168.', '10.', or '172.16.' -> the IP is EXTERNAL. 'firewall-drop' is MANDATORY. 'wazuh-isolate-endpoint' is FORBIDDEN.",
        "RULE 3 - NO IP: If src_ip is null or missing -> use 'action_type': null and 'execute': false.",
        "RULE 4 - TIME: Always analyze the 'timestamp'. Normal business hours: 08:00 - 18:00. Activity outside these hours is more suspicious.",
        "THESE RULES ARE ABSOLUTE. They apply to ALL Critical alerts, even if OpenCTI has no match.",
        "",
        "GUARDRAILS (STRICT PROHIBITIONS FOR THE AI):",
        "- NO HALLUCINATIONS: NEVER invent IP addresses, ports, or MITRE tactics that are not explicitly in the alert.",
        "- NO ASSUMPTIONS: If an IP or port is 'N/A' or missing, NEVER guess what it is. Treat it as unknown.",
        "- BE CONCISE: Do not write long philosophical paragraphs in your 'reasoning'. Be direct, analytical, and limit yourself to 3 or 4 sentences maximum.",
        "",
        "MANDATORY CLASSIFICATION - ALWAYS 'Critical' for these attack types (NO EXCEPTIONS):",
        "- SQL Injection (keywords: SQL injection, SQLi, UNION SELECT, etc.) --> ALWAYS Critical",
        "- Ransomware (keywords: file encryption, ransomware, .locked, .encrypted, unknown extension) --> ALWAYS Critical",
        "- Malware / Trojan (keywords: malware detected, trojan, virus) --> ALWAYS Critical",
        "- High volume SSH Brute Force (>100 attempts) --> ALWAYS Critical",
        "- DDoS confirmed by Threat Intel (OpenCTI or MISP found=true) --> ALWAYS Critical",
        "- IP known as malicious by Threat Intel (found=true) --> ALWAYS Critical",
        "- Repeated attack: if [HISTORICAL CONTEXT] indicates >2 attacks from the same IP --> ALWAYS Critical",
        "",
        "CLASSIFICATION 'Suspicious' ONLY if the attack is NOT confirmed (e.g., isolated port scan without Threat Intel).",
        "",
        "Definitions:",
        "- Critical: confirmed attack OR attack type in the list above. Automated action is MANDATORY.",
        "- Suspicious: anomalous activity not yet confirmed. NO automated action.",
        "- Informational: normal tracking event, no risk.",
        "- False Positive: legitimate traffic. MANDATORY recommendation: 'No action required.'",
        "",
        "Strict JSON format expected (DO NOT ADD ANY TEXT OUTSIDE THE JSON):",
        '{',
        '  "analysis_context": "<List the facts received: alert details, IP history, Threat Intel, and RAG context>",',
        '  "reasoning": "<Write your step-by-step reasoning based on the context above>",',
        '  "confidence_score": <1 to 100>,',
        '  "classification": "<one of the 4 categories>",',
        '  "attack_type": "<Exact type of the attack>",',
        '  "mitre_tactic": "<MITRE ATT&CK ID, e.g., T1110>",',
        '  "recommandation": "<one sentence>",',
        '  "automated_action": {',
        '    "execute": <true or false>,',
        '    "action_type": "<wazuh-isolate-endpoint, firewall-drop, or null>",',
        '    "target": "<Source IP or null>"',
        '  }',
        '}',
        "",
        "Here are perfect examples (learn from them):",
        "",
        "Wazuh Alert: {\"alert\": {\"id\": 1, \"description\": \"SSH Brute Force from unknown source\", \"level\": 12, \"src_ip\": \"203.0.113.50\", \"timestamp\": \"2026-07-24T03:00:00Z\"}}",
        "Expected Response:",
        "{",
        "  \"analysis_context\": \"The alert mentions an SSH Brute Force. The source IP is 203.0.113.50. The event time is 03:00Z.\",",
        "  \"reasoning\": \"The attack occurred outside normal business hours (03:00), which confirms its malicious nature. The IP 203.0.113.50 is external (no 192.168/10/172 prefix). According to the rules, I apply firewall-drop.\",",
        "  \"confidence_score\": 95,",
        "  \"classification\": \"Critical\",",
        "  \"attack_type\": \"SSH Brute Force\",",
        "  \"mitre_tactic\": \"T1110 - Brute Force\",",
        "  \"recommandation\": \"Block the IP at the firewall level.\",",
        "  \"automated_action\": {\"execute\": true, \"action_type\": \"firewall-drop\", \"target\": \"203.0.113.50\"}",
        "}",
        "",
        "Wazuh Alert: {\"alert\": {\"id\": 2, \"description\": \"Malware detected on workstation\", \"level\": 12, \"src_ip\": \"192.168.1.100\", \"timestamp\": \"2026-07-24T14:00:00Z\"}}",
        "Expected Response:",
        "{",
        "  \"analysis_context\": \"The alert indicates malware presence on the machine. The source IP is 192.168.1.100. The time is 14:00Z.\",",
        "  \"reasoning\": \"Even during business hours, malware detection is critical. The source IP 192.168.1.100 is an internal IP. According to the security rule, firewall-drop is forbidden. I apply wazuh-isolate-endpoint to isolate the host without disrupting the network.\",",
        "  \"confidence_score\": 90,",
        "  \"classification\": \"Critical\",",
        "  \"attack_type\": \"Malware\",",
        "  \"mitre_tactic\": \"T1204 - User Execution\",",
        "  \"recommandation\": \"Isolate the machine from the internal network.\",",
        "  \"automated_action\": {\"execute\": true, \"action_type\": \"wazuh-isolate-endpoint\", \"target\": \"192.168.1.100\"}",
        "}",
        "",
        "Wazuh Alert: {\"alert\": {\"id\": 3, \"description\": \"Dovecot Authentication Success.\", \"level\": 2, \"src_ip\": \"192.168.1.55\", \"timestamp\": \"2026-07-24T09:00:00Z\"}}",
        "Expected Response:",
        "{",
        "  \"analysis_context\": \"The alert mentions a successful Dovecot authentication. Alert level 2 (very low). Internal IP. Business hours (09:00).\",",
        "  \"reasoning\": \"A successful Dovecot authentication at 09:00 from an internal IP is a perfectly normal event. There are no threat indicators. I classify it as a False Positive.\",",
        "  \"confidence_score\": 95,",
        "  \"classification\": \"False Positive\",",
        "  \"attack_type\": \"None\",",
        "  \"mitre_tactic\": \"N/A\",",
        "  \"recommandation\": \"No action required. Legitimate event.\",",
        "  \"automated_action\": {\"execute\": false, \"action_type\": null, \"target\": null}",
        "}",
        "",
    ]
    return "\n".join(lines)


def qualify_alert(alert_data: dict, system_prompt: str, history: dict = None) -> dict:
    """
    Sends the formatted alert to the local Ollama API (LLaMA 3) to get a SOC decision.
    """
    import requests
    import json
    
    # Inject historical context if available
    if history and history.get("times_seen", 0) > 0:
        times = history["times_seen"]
        last_action = history.get("last_action_executed", "None")
        hist_text = f"\n\n[HISTORICAL CONTEXT] The source IP of this alert has already attacked {times} times in the last 24h! The last executed countermeasure was: {last_action}. If this is a persistent attack, be aggressive in your response."
        system_prompt += hist_text
        
    # Retrieve RAG Playbook Context
    desc = (
        alert_data.get("wazuh_alert", {}).get("description", "") or
        alert_data.get("wazuh_alert", {}).get("full_raw", {}).get("rule", {}).get("description", "") or
        alert_data.get("wazuh_alert", {}).get("full_raw", {}).get("full_log", "") or
        alert_data.get("alert", {}).get("rule_desc", "") or
        alert_data.get("alert", {}).get("description", "") or
        alert_data.get("description", "") or
        ""
    )
    rag_context = get_rag_context_vector(desc)
    if rag_context:
        system_prompt += rag_context

    url = "http://localhost:11434/api/chat"

    user_message = f"Wazuh Alert: {json.dumps(alert_data, ensure_ascii=False)}"

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "options": {
            "temperature": 0,
            "num_ctx": 8192
        },
        "format": "json",
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=300)
        r.raise_for_status()
        raw_answer = r.json()["message"]["content"].strip()
        print(f"\n[DEBUG] OLLAMA RAW ANSWER:\n{raw_answer}\n")
        parsed = json.loads(raw_answer)
        analysis_context = parsed.get("analysis_context", "Context not provided").strip()
        reasoning = parsed.get("reasoning", "No reasoning provided").strip()
        try:
            confidence_score = int(parsed.get("confidence_score", 0))
        except ValueError:
            confidence_score = 0
            
        classification = parsed.get("classification", "").strip()
        attack_type = parsed.get("attack_type", "Unknown").strip()
        mitre_tactic = parsed.get("mitre_tactic", "Unknown").strip()
        recommandation = parsed.get("recommandation", "").strip()
        action = parsed.get("automated_action", {"execute": False, "action_type": None, "target": None})
        
        # PYTHON SAFETY OVERRIDE
        if action.get("execute") and confidence_score < 85:
            action["execute"] = False
            action["action_type"] = None
            recommandation += " [ACTION CANCELED: AI confidence too low (< 85%), manual verification required]"
        
        # Guardrail: if LLM outputs an invalid/empty class
        if classification not in VALID_LABELS:
            classification = "Suspicious"
            attack_type = attack_type or "Unknown"
            recommandation = recommandation or "Uncertain classification - manual verification required."
            action = {"execute": False, "action_type": None, "target": None}
        if not recommandation or recommandation.startswith("ERROR"):
            recommandation = RECOMMENDATIONS_BY_CLASS.get(classification, "Manual verification required.")
        
        return {
            "analysis_context": analysis_context,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
            "classification": classification,
            "attack_type": attack_type,
            "mitre_tactic": mitre_tactic,
            "recommandation": recommandation,
            "automated_action": action
        }
    except Exception as e:
        action = {"execute": False, "action_type": None, "target": None}
        return {
            "analysis_context": "Error",
            "reasoning": f"Error during processing: {e}",
            "confidence_score": 0,
            "classification": "Suspicious",
            "attack_type": "Error",
            "mitre_tactic": "Unknown",
            "recommandation": "Manual verification required due to processing error.",
            "automated_action": action
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert_json", required=True, help="JSON string representing the alert")
    parser.add_argument("--dataset", default="dataset_clean.csv", help="Pour construire les exemples few-shot")
    parser.add_argument("--n_examples", type=int, default=4)
    args = parser.parse_args()

    try:
        alert_data = json.loads(args.alert_json)
    except:
        import ast
        alert_data = ast.literal_eval(args.alert_json)

    system_prompt = build_system_prompt()

    result = qualify_alert(
        alert_data=alert_data,
        system_prompt=system_prompt,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
