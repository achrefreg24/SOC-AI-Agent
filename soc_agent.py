"""
soc_agent.py
------------
Module central de l'agent IA SOC : classifie une alerte Wazuh ET genere une
recommandation de reponse, via Ollama/LLaMA3. Concu pour etre importe a la
fois par un script CLI et par l'API FastAPI (etape suivante du projet).

Usage en script :
    python soc_agent.py --description "..." --rule_level 10 --rule_groups "ids"

Usage en import :
    from soc_agent import qualify_alert
    result = qualify_alert(description="...", rule_level=10, ...)
    # -> {"classification": "Critique", "recommandation": "..."}
"""

import argparse
import json
import requests
import pandas as pd
from rag_module import get_rag_context

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3"
VALID_LABELS = ["Critique", "Suspect", "Informatif", "Faux positif"]

RECOMMENDATIONS_BY_CLASS = {
    # Recommandation par defaut si le LLM ne fournit pas de texte exploitable ;
    # sert aussi de garde-fou/fallback pour rester coherent avec le cahier des charges.
    "Critique": "Isoler la machine concernee, escalader immediatement a l'analyste "
                "senior, conserver les logs pour investigation forensique.",
    "Suspect": "Investiguer manuellement dans les prochaines heures : verifier la "
               "legitimite de la source, correler avec d'autres alertes recentes.",
    "Informatif": "Aucune action requise. Archiver pour tracabilite.",
    "Faux positif": "Aucune action requise. Envisager un ajustement de regle si "
                     "ce pattern se repete frequemment (reduction du bruit).",
}


def build_system_prompt() -> str:
    lines = [
        "Tu es un Senior Threat Hunter. Pour chaque alerte de securite Wazuh, tu dois :",
        "1. La classifier dans EXACTEMENT une de ces 4 categories : Critique, Suspect, Informatif, Faux positif",
        "2. Identifier le type d'attaque (attack_type) de maniere explicite (ex: 'SSH Brute Force', 'SQL Injection', 'Trojan', ou 'Aucune' si Faux positif).",
        "3. Donner une recommandation d'action courte pour l'analyste SOC",
        "4. Fournir une 'automated_action' (une action automatique) si et seulement si l'alerte est Critique.",
        "",
        "REGLES DE SECURITE OBLIGATOIRES POUR L'ACTION AUTOMATIQUE (STRICTEMENT RESPECTER) :",
        "REGLE 1 - IP INTERNE : Si src_ip commence par '192.168.', '10.', ou '172.16.' -> l'IP est INTERNE. INTERDIT d'utiliser 'firewall-drop'. OBLIGATOIRE d'utiliser 'wazuh-isolate-endpoint'.",
        "REGLE 2 - IP EXTERNE : Si src_ip NE commence PAS par '192.168.', '10.', ou '172.16.' -> l'IP est EXTERNE. OBLIGATOIRE d'utiliser 'firewall-drop'. INTERDIT d'utiliser 'wazuh-isolate-endpoint'.",
        "REGLE 3 - PAS D'IP : Si src_ip est null ou absent -> utilise 'action_type': null et 'execute': false.",
        "REGLE 4 - TEMPS : Analyse toujours le 'timestamp'. Heures de bureau normales : 08h00 - 18h00. Une activite hors de ces heures est plus suspecte.",
        "CES REGLES SONT ABSOLUES. Elles s'appliquent a TOUTES les alertes Critique, meme si OpenCTI n'a pas de correspondance.",
        "",
        "GUARDRAILS (INTERDICTIONS ABSOLUES POUR L'IA) :",
        "- PAS D'HALLUCINATIONS : N'invente JAMAIS d'adresses IP, de ports ou de tactiques MITRE qui ne sont pas explicitement dans l'alerte.",
        "- PAS DE SUPPOSITIONS : Si une IP ou un port est 'N/A' ou manquant, ne devine JAMAIS ce que c'est. Traite-le comme inconnu.",
        "- SOIS CONCIS : N'ecris pas de longs paragraphes philosophiques dans ton 'reasoning'. Sois direct, analytique et limite-toi a 3 ou 4 phrases maximum.",
        "",
        "CLASSIFICATION OBLIGATOIRE - TOUJOURS 'Critique' pour ces types d'attaques (AUCUNE EXCEPTION) :",
        "- SQL Injection (mots-cles: SQL injection, SQLi, UNION SELECT, etc.) --> TOUJOURS Critique",
        "- Ransomware (mots-cles: file encryption, ransomware, .locked, .encrypted, unknown extension) --> TOUJOURS Critique",
        "- Malware / Trojan (mots-cles: malware detected, trojan, virus) --> TOUJOURS Critique",
        "- SSH Brute Force a volume eleve (>100 tentatives) --> TOUJOURS Critique",
        "- DDoS confirme par Threat Intel (OpenCTI ou MISP found=true) --> TOUJOURS Critique",
        "- IP connue comme malveillante par Threat Intel (found=true) --> TOUJOURS Critique",
        "- Attaque repetee : si [CONTEXTE HISTORIQUE] indique >2 attaques de la meme IP --> TOUJOURS Critique",
        "",
        "CLASSIFICATION 'Suspect' uniquement si l'attaque n'est PAS confirmee (ex: port scan seul, tentative isolee sans Threat Intel).",
        "",
        "Definitions :",
        "- Critique : attaque confirmee OU type d'attaque dans la liste ci-dessus. Action automatique OBLIGATOIRE.",
        "- Suspect : activite anormale pas encore confirmee. PAS d'action automatique.",
        "- Informatif : evenement normal de suivi, sans risque.",
        "- Faux positif : trafic legitime. Recommandation OBLIGATOIRE : 'Aucune action requise.'",
        "",
        "Format JSON strict attendu (N'AJOUTE AUCUN TEXTE AUTOUR DU JSON) :",
        '{',
        '  "analysis_context": "<Liste les faits recus : details de l\'alerte, historique IP, Threat Intel, et contexte RAG>",',
        '  "reasoning": "<Ecris ta reflexion etape par etape basee sur le contexte ci-dessus>",',
        '  "confidence_score": <1 a 100>,',
        '  "classification": "<une des 4 categories>",',
        '  "attack_type": "<Type exact de l\'attaque>",',
        '  "mitre_tactic": "<ID MITRE ATT&CK, ex: T1110>",',
        '  "recommandation": "<une phrase>",',
        '  "automated_action": {',
        '    "execute": <true ou false>,',
        '    "action_type": "<wazuh-isolate-endpoint, firewall-drop, ou null>",',
        '    "target": "<IP source ou null>"',
        '  }',
        '}',
        "",
        "Voici des exemples parfaits (apprends d'eux) :",
        "",
        "Alerte Wazuh: {\"alert\": {\"id\": 1, \"description\": \"SSH Brute Force from unknown source\", \"level\": 12, \"src_ip\": \"203.0.113.50\", \"timestamp\": \"2026-07-24T03:00:00Z\"}}",
        "Reponse attendue :",
        "{",
        "  \"analysis_context\": \"L'alerte mentionne un SSH Brute Force. L'IP source est 203.0.113.50. L'heure de l'evenement est 03h00Z.\",",
        "  \"reasoning\": \"L'attaque se produit en dehors des heures de travail normales (03h00), ce qui confirme le caractere malveillant. L'IP 203.0.113.50 est externe (pas de prefixe 192.168/10/172). Conformement aux regles, j'applique firewall-drop.\",",
        "  \"confidence_score\": 95,",
        "  \"classification\": \"Critique\",",
        "  \"attack_type\": \"SSH Brute Force\",",
        "  \"mitre_tactic\": \"T1110 - Brute Force\",",
        "  \"recommandation\": \"Bloquer l'IP au niveau du pare-feu.\",",
        "  \"automated_action\": {\"execute\": true, \"action_type\": \"firewall-drop\", \"target\": \"203.0.113.50\"}",
        "}",
        "",
        "Alerte Wazuh: {\"alert\": {\"id\": 2, \"description\": \"Malware detected on workstation\", \"level\": 12, \"src_ip\": \"192.168.1.100\", \"timestamp\": \"2026-07-24T14:00:00Z\"}}",
        "Reponse attendue :",
        "{",
        "  \"analysis_context\": \"L'alerte indique la presence d'un malware sur la machine. L'IP source est 192.168.1.100. L'heure est 14h00Z.\",",
        "  \"reasoning\": \"Meme pendant les heures de bureau, une detection de malware est critique. L'IP source 192.168.1.100 est une IP interne. Conformement a la regle de securite, l'action firewall-drop est interdite. J'applique wazuh-isolate-endpoint pour isoler le poste sans perturber le reseau.\",",
        "  \"confidence_score\": 90,",
        "  \"classification\": \"Critique\",",
        "  \"attack_type\": \"Malware\",",
        "  \"mitre_tactic\": \"T1204 - User Execution\",",
        "  \"recommandation\": \"Isoler la machine du reseau interne.\",",
        "  \"automated_action\": {\"execute\": true, \"action_type\": \"wazuh-isolate-endpoint\", \"target\": \"192.168.1.100\"}",
        "}",
        "",
        "Alerte Wazuh: {\"alert\": {\"id\": 3, \"description\": \"Dovecot Authentication Success.\", \"level\": 2, \"src_ip\": \"192.168.1.55\", \"timestamp\": \"2026-07-24T09:00:00Z\"}}",
        "Reponse attendue :",
        "{",
        "  \"analysis_context\": \"L'alerte mentionne une authentication Dovecot reussie. Niveau d'alerte 2 (tres bas). IP interne. Heure de bureau (09h00).\",",
        "  \"reasoning\": \"Une authentication Dovecot reussie a 09h00 depuis une IP interne est un evenement parfaitement normal. Il n'y a aucun indicateur de menace. Je classe comme Faux positif.\",",
        "  \"confidence_score\": 95,",
        "  \"classification\": \"Faux positif\",",
        "  \"attack_type\": \"Aucune\",",
        "  \"mitre_tactic\": \"N/A\",",
        "  \"recommandation\": \"Aucune action requise. Evenement legitime.\",",
        "  \"automated_action\": {\"execute\": false, \"action_type\": null, \"target\": null}",
        "}",
        "",
    ]
    return "\n".join(lines)


def qualify_alert(alert_data: dict, system_prompt: str, history: dict = None) -> dict:
    """
    Envoie l'alerte formatee a l'API locale Ollama (LLaMA 3) pour obtenir une decision SOC.
    """
    import requests
    import json
    
    # Inject historical context if available
    if history and history.get("times_seen", 0) > 0:
        times = history["times_seen"]
        last_action = history.get("last_action_executed", "None")
        hist_text = f"\n\n[CONTEXTE HISTORIQUE] L'IP source de cette alerte a deja attaque {times} fois dans les dernieres 24h ! La derniere contre-mesure executee etait : {last_action}. S'il s'agit d'une attaque persistante, sois agressif dans ta reponse."
        system_prompt += hist_text
        
    # Retrieve RAG Playbook Context (cherche la description dans tous les formats possibles)
    desc = (
        alert_data.get("wazuh_alert", {}).get("description", "") or
        alert_data.get("wazuh_alert", {}).get("full_raw", {}).get("rule", {}).get("description", "") or
        alert_data.get("wazuh_alert", {}).get("full_raw", {}).get("full_log", "") or
        alert_data.get("alert", {}).get("rule_desc", "") or
        alert_data.get("alert", {}).get("description", "") or
        alert_data.get("description", "") or
        ""
    )
    rag_context = get_rag_context(desc)
    if rag_context:
        system_prompt += rag_context

    url = "http://localhost:11434/api/chat"

    user_message = f"Alerte Wazuh: {json.dumps(alert_data, ensure_ascii=False)}"

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "options": {"temperature": 0},
        "format": "json",
    }

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=300)
        r.raise_for_status()
        raw_answer = r.json()["message"]["content"].strip()
        parsed = json.loads(raw_answer)
        analysis_context = parsed.get("analysis_context", "Contexte non fourni").strip()
        reasoning = parsed.get("reasoning", "Aucune reflexion fournie").strip()
        try:
            confidence_score = int(parsed.get("confidence_score", 0))
        except ValueError:
            confidence_score = 0
            
        classification = parsed.get("classification", "").strip()
        attack_type = parsed.get("attack_type", "Inconnu").strip()
        mitre_tactic = parsed.get("mitre_tactic", "Inconnu").strip()
        recommandation = parsed.get("recommandation", "").strip()
        action = parsed.get("automated_action", {"execute": False, "action_type": None, "target": None})
        
        # PYTHON SAFETY OVERRIDE
        if action.get("execute") and confidence_score < 85:
            action["execute"] = False
            action["action_type"] = None
            recommandation += " [ACTION ANNULEE : Confiance de l'IA trop basse (< 85%), verification humaine requise]"
        
        # Garde-fou : si le LLM sort une classe invalide/vide
        if classification not in VALID_LABELS:
            classification = "Suspect"
            attack_type = attack_type or "Inconnu"
            recommandation = recommandation or "Classification incertaine - verification manuelle requise."
            action = {"execute": False, "action_type": None, "target": None}
        if not recommandation or recommandation.startswith("ERREUR"):
            recommandation = RECOMMENDATIONS_BY_CLASS.get(classification, "Verification manuelle requise.")
        
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
            "analysis_context": "Erreur",
            "reasoning": f"Erreur lors du traitement: {e}",
            "confidence_score": 0,
            "classification": "Suspect",
            "attack_type": "Erreur",
            "mitre_tactic": "Inconnu",
            "recommandation": "Verification manuelle requise suite a une erreur de traitement.",
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
