"""
api.py
------
API FastAPI qui expose l'architecture unifiée "Dual-Engine" SOC AI.
Engine 1: RandomForest (filtrage supersonique des faux positifs)
Engine 2: LLaMA 3 + SQLite (analyse approfondie et mémorisation contextuelle)
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import pandas as pd
from pathlib import Path
import pickle
from datetime import datetime
import time
import json

import soc_agent
import database
from soc_agent import qualify_alert, build_system_prompt
from scipy.sparse import hstack, csr_matrix

# Initialisation de la base de donnees memoire
database.init_db()

app = FastAPI(
    title="Agent IA SOC - API de qualification d'alertes",
    description="Architecture Dual-Engine unifiee (ML NLP + LLM).",
    version="3.0",
)

# --- Chargement des exemples et des modeles au demarrage ---
DATASET_PATH = Path(r"dataset_ready_for_ai.csv")
_system_prompt_cache = None

print("📂 Chargement du modele Machine Learning NLP (Engine 1)...")
try:
    rf_model = pickle.load(open("models/model_nlp_v4.pkl", "rb"))
    rf_tfidf = pickle.load(open("models/tfidf_vectorizer_v4.pkl", "rb"))
    rf_le    = pickle.load(open("models/label_encoder_v4.pkl", "rb"))
    print("✅ Engine 1 (Random Forest NLP v4) charge !")
except Exception as e:
    print(f"⚠️ Modele NLP v4 introuvable, tentative avec l'ancien modele: {e}")
    rf_tfidf = None
    try:
        rf_model = pickle.load(open("models/model_4_classes_v3.pkl", "rb"))
        rf_le    = pickle.load(open("models/label_encoder_4_classes_v3.pkl", "rb"))
        print("✅ Engine 1 (RandomForest v3 legacy) charge !")
    except Exception as e2:
        print(f"⚠️ Erreur de chargement du modele ML : {e2}")
        rf_model = None
        rf_le    = None


def get_system_prompt() -> str:
    global _system_prompt_cache
    if _system_prompt_cache is None:
        _system_prompt_cache = build_system_prompt()
    return _system_prompt_cache


# --- Schemas de requete/reponse ---
class BlueTeamAlert(BaseModel):
    rule_id: Optional[str] = None
    rule_desc: str
    level: int
    agent: Optional[str] = None
    agent_ip: Optional[str] = None
    srcip: Optional[str] = None
    dstip: Optional[str] = None
    proto: Optional[str] = None
    timestamp: str
    full_log: Optional[str] = None

class BlueTeamThreatContext(BaseModel):
    actors: List[str] = []
    malwares: List[str] = []
    ttps: List[str] = []

class BlueTeamSignals(BaseModel):
    is_known_ioc: bool = False
    is_malicious: bool = False
    is_private_srcip: bool = False
    has_threat_actor: bool = False
    has_mitre_ttp: bool = False

class BlueTeamEnrichment(BaseModel):
    known_in_opencti: bool = False
    iocs: List[Any] = []
    misp: Optional[Dict[str, Any]] = None
    threat_context: Optional[BlueTeamThreatContext] = None
    signals: Optional[BlueTeamSignals] = None

class AlertRequest(BaseModel):
    alert: BlueTeamAlert
    enrichment: Optional[BlueTeamEnrichment] = None
    blue_team_context: Optional[str] = None


class AutomatedAction(BaseModel):
    execute: bool
    action_type: Optional[str] = None
    target: Optional[str] = None

class AlertResponse(BaseModel):
    analysis_context: str
    reasoning: str
    confidence_score: int
    classification: str
    attack_type: str
    mitre_tactic: str
    recommandation: str
    automated_action: AutomatedAction


# --- Endpoints ---
@app.get("/")
def root():
    return {
        "message": "Agent IA SOC - API Dual-Engine active",
        "endpoints": {
            "POST /qualifier-alerte": "Classifie une alerte Wazuh",
            "GET /health": "Verifie la sante des moteurs",
        },
    }

@app.get("/health")
def health():
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        r.raise_for_status()
        ollama_ok = True
    except Exception:
        ollama_ok = False

    return {
        "api": "ok",
        "engine1_ml": "ok" if rf_model else "indisponible",
        "engine2_llm": "ok" if ollama_ok else "indisponible",
        "dataset": "ok" if DATASET_PATH.exists() else "introuvable",
    }


@app.post("/qualifier-alerte", response_model=AlertResponse)
def qualifier_alerte(alert_data: AlertRequest, disable_ml: bool = False):
    t0 = time.time()
    system_prompt = get_system_prompt()
    # Support model_dump (Pydantic v2) or dict (Pydantic v1)
    payload = alert_data.model_dump() if hasattr(alert_data, "model_dump") else alert_data.dict()
    
    # 1. Verification Threat Intel (BYPASS RULE)
    threat_found = False
    if payload.get("enrichment"):
        enrichment = payload["enrichment"]
        signals = enrichment.get("signals", {})
        if enrichment.get("known_in_opencti") or signals.get("is_malicious") or signals.get("is_known_ioc"):
            threat_found = True
        if enrichment.get("misp") and enrichment["misp"].get("matched"):
            threat_found = True

    # 2. Engine 1 : ML Filter (RandomForest)
    # Skip if ML is disabled via query param (for testing/demos)
    if not threat_found and not disable_ml and rf_model is not None and rf_le is not None:
        try:
            # Extraction des vraies features depuis le timestamp (ex: "2026-07-19T01:00:00Z")
            dt = datetime.fromisoformat(alert_data.alert.timestamp.replace("Z", "+00:00"))
            hour = dt.hour
            day_of_week = dt.weekday()
            month = dt.month
            is_weekend = 1 if day_of_week >= 5 else 0
            
            # Extraction de la vraie frequence d'attaque depuis SQLite
            ip_str = alert_data.alert.srcip or ""
            alerts_per_minute = database.get_alerts_last_minute(ip_str)
            
            numeric_features = pd.DataFrame([{
                "rule_level": alert_data.alert.level,
                "hour": hour,
                "day_of_week": day_of_week,
                "month": month,
                "is_weekend": is_weekend,
                "alerts_per_minute": alerts_per_minute,
            }])

            # If NLP model is available, add TF-IDF text features
            if rf_tfidf is not None:
                text_features = rf_tfidf.transform([alert_data.alert.rule_desc])
                X = hstack([csr_matrix(numeric_features.values), text_features])
            else:
                # Fallback: old model needs src_ip_encoded and dst_ip_encoded
                numeric_features["src_ip_encoded"] = 0
                numeric_features["dst_ip_encoded"] = 0
                X = numeric_features
            
            rf_pred   = rf_model.predict(X)
            rf_classe = rf_le.inverse_transform(rf_pred)[0]
            rf_proba  = max(rf_model.predict_proba(X)[0]) * 100
            
            # FILTRE SUPERSONIQUE : Si le ML est certain que c'est benin
            if rf_classe in ["Faux positif", "Informatif"] and rf_proba >= 90.0:
                elapsed = time.time() - t0
                result = {
                    "analysis_context": "L'alerte a ete evaluee par le moteur Machine Learning (Engine 1) base sur le texte, l'heure et la frequence d'attaque.",
                    "reasoning": f"[ENGINE 1] Filtre ML instantane (Confiance: {rf_proba:.1f}%, Temps: {elapsed:.3f}s). L'alerte correspond au profil classique de bruit de fond (Faux positif connu).",
                    "confidence_score": int(rf_proba),
                    "classification": rf_classe,
                    "attack_type": "Aucun",
                    "mitre_tactic": "N/A",
                    "recommandation": "Aucune action requise. Ignore par le pre-filtre IA.",
                    "automated_action": {"execute": False, "action_type": None, "target": None}
                }
                
                # Save decision
                database.save_alert(
                    src_ip=alert_data.alert.srcip,
                    description=alert_data.alert.rule_desc,
                    classification=result["classification"],
                    attack_type=result["attack_type"],
                    action_executed=None
                )
                return result
                
        except Exception as e:
            print(f"⚠️ Erreur Engine 1 : {e}")

    # 3. Engine 2 : LLaMA 3 + Memory (Escalade)
    # Fetch historical context for this IP
    history = database.get_ip_history(alert_data.alert.srcip)
    
    # Injection du flag bypass si besoin
    if threat_found:
        system_prompt += "\n\n[INFO] THREAT INTEL A FLAGGE CETTE ALERTE ! Le pre-filtre ML a ete bypasse. Sois agressif dans ton jugement."

    # Injection du contexte manuel de la Blue Team
    if payload.get("blue_team_context"):
        bt_context = payload["blue_team_context"]
        system_prompt += f"\n\n[CONTEXTE BLUE TEAM] {bt_context}\nPrends OBLIGATOIREMENT en compte cette consigne de la Blue Team dans ton analyse et ta decision finale."

    # Injection native de l'Enrichissement complet (Threat Intel massif)
    if payload.get("enrichment"):
        system_prompt += f"\n\n[ENRICHISSEMENT THREAT INTEL (JSON)]\n{json.dumps(payload['enrichment'], indent=2)}\nUtilise toutes ces donnees (Threat Actors, Malwares, TTPs) pour affiner ton analyse."

    result = soc_agent.qualify_alert(payload, system_prompt, history)
    
    # Save the decision into memory
    database.save_alert(
        src_ip=alert_data.alert.srcip,
        description=alert_data.alert.rule_desc,
        classification=result.get("classification", "Erreur"),
        attack_type=result.get("attack_type", "Inconnu"),
        action_executed=result.get("automated_action", {}).get("action_type")
    )
    
    return result
