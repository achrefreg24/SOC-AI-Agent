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

from app.agent import soc_agent
from app import database
from app.agent.soc_agent import qualify_alert, build_system_prompt
from scipy.sparse import hstack, csr_matrix
import redis
from sentence_transformers import SentenceTransformer

# Initialisation de la base de donnees SQL
database.init_db()

# Initialisation Redis (Fail-safe)
try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    print("✅ Connecte a Redis (Velocity Tracking).")
except redis.ConnectionError:
    print("⚠️ Redis introuvable sur localhost:6379. Le tracking de velocite sera limite.")
    redis_client = None

def get_redis_alerts_per_minute(src_ip: str) -> int:
    """O(1) sliding window velocity tracking via Redis."""
    if not redis_client or not src_ip:
        return database.get_alerts_last_minute(src_ip)
    
    key = f"rate:{src_ip}"
    current_time = int(time.time())
    window_start = current_time - 60
    
    try:
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start) # Remove old entries
        pipe.zadd(key, {str(current_time): current_time}) # Add new entry
        pipe.zcard(key) # Count entries in window
        pipe.expire(key, 60) # Auto-cleanup
        results = pipe.execute()
        return results[2]
    except Exception as e:
        print(f"⚠️ Erreur Redis: {e}")
        return database.get_alerts_last_minute(src_ip)


app = FastAPI(
    title="Agent IA SOC - API de qualification d'alertes",
    description="Architecture Dual-Engine unifiee (ML NLP + LLM).",
    version="3.0",
)

# --- Chargement des exemples et des modeles au demarrage ---
DATASET_PATH = Path(r"dataset_ready_for_ai.csv")
_system_prompt_cache = None

# Engine 1 toggle — can be flipped at runtime via API without restarting uvicorn
ENGINE1_ENABLED = True

print("📂 Chargement du modele Machine Learning NLP (Engine 1)...")
BASE_DIR = Path(__file__).parent.parent
try:
    rf_model = pickle.load(open(BASE_DIR / "data/models/model_nlp_v4.pkl", "rb"))
    rf_encoder = SentenceTransformer("all-MiniLM-L6-v2")
    rf_le    = pickle.load(open(BASE_DIR / "data/models/label_encoder_v4.pkl", "rb"))
    print("✅ Engine 1 (Random Forest NLP v4 + Embeddings) charge !")
except Exception as e:
    print(f"⚠️ Modele NLP v4 introuvable : {e}")
    rf_model = None
    rf_encoder = None
    rf_le    = None


def get_system_prompt() -> str:
    global _system_prompt_cache
    if _system_prompt_cache is None:
        _system_prompt_cache = build_system_prompt()
    return _system_prompt_cache


# ── Engine 1 Toggle Endpoints ─────────────────────────────────────────────────
@app.get("/engine1/status", tags=["Engine Control"])
def engine1_status():
    """Check whether Engine 1 (Random Forest ML) is currently active."""
    return {
        "engine1_enabled": ENGINE1_ENABLED,
        "message": "Engine 1 is ACTIVE — fast ML pre-filter running." if ENGINE1_ENABLED
                   else "Engine 1 is DISABLED — all alerts go directly to Ollama (Engine 2)."
    }


@app.post("/engine1/enable", tags=["Engine Control"])
def engine1_enable():
    """Enable Engine 1 (Random Forest ML pre-filter). Takes effect immediately, no restart needed."""
    global ENGINE1_ENABLED
    ENGINE1_ENABLED = True
    print("✅ Engine 1 ENABLED via API.")
    return {"engine1_enabled": True, "message": "Engine 1 is now ACTIVE."}


@app.post("/engine1/disable", tags=["Engine Control"])
def engine1_disable():
    """Disable Engine 1 — all alerts bypass ML and go straight to Ollama (Engine 2)."""
    global ENGINE1_ENABLED
    ENGINE1_ENABLED = False
    print("⚠️  Engine 1 DISABLED via API. All alerts routed to Engine 2 (Ollama).")
    return {"engine1_enabled": False, "message": "Engine 1 is now DISABLED. Engine 2 (Ollama) handles everything."}



# --- Schema de reponse uniquement (pas de schema de requete - on accepte TOUT) ---
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


def extract_field(data: dict, candidates: list, default=None):
    """
    Cherche un champ dans un dictionnaire JSON imbriqué.
    Essaie chaque chemin dans 'candidates' et retourne la premiere valeur trouvee.
    Exemples de chemins: "wazuh_alert.description", "alert.rule_desc", "description"
    """
    for path in candidates:
        keys = path.split(".")
        val = data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                val = None
                break
        if val is not None:
            return val
    return default


# --- Endpoints ---
@app.get("/")
def root():
    return {
        "message": "Agent IA SOC - API Dual-Engine active",
        "endpoints": {
            "POST /qualifier-alerte": "Classifie une alerte Wazuh (accepte tout format JSON)",
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


from fastapi import Request

@app.post("/qualifier-alerte", response_model=AlertResponse)
async def qualifier_alerte(request: Request, disable_ml: bool = False):
    """
    Accepte N'IMPORTE QUEL format JSON.
    Extrait intelligemment les champs necessaires pour Engine 1.
    Envoie la TOTALITE du JSON brut a Engine 2 (Ollama / LLaMA 3).
    """
    t0 = time.time()
    system_prompt = get_system_prompt()

    # Lire le body JSON brut (aucun schema impose)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Le body doit etre du JSON valide.")

    # FIX 1: Si le Blue Team envoie un tableau [{}], on prend le premier element
    if isinstance(payload, list):
        if len(payload) == 0:
            raise HTTPException(status_code=400, detail="Le tableau JSON est vide.")
        payload = payload[0]

    # --- Extraction intelligente des champs cles ---
    description = extract_field(payload, [
        "wazuh_alert.description",
        "wazuh_alert.full_raw.rule.description",
        "alert.rule_desc",
        "alert.description",
        "description",
    ], default="")

    src_ip = extract_field(payload, [
        "wazuh_alert.src_ip",
        "wazuh_alert.full_raw.data.srcip",
        "alert.srcip",
        "alert.src_ip",
        "src_ip",
    ], default=None)

    timestamp_str = extract_field(payload, [
        "wazuh_alert.timestamp",
        "wazuh_alert.full_raw.timestamp",
        "alert.timestamp",
        "timestamp",
    ], default="")

    level = extract_field(payload, [
        "wazuh_alert.level",
        "wazuh_alert.full_raw.rule.level",
        "alert.level",
        "level",
    ], default=5)
    try:
        level = int(level)
    except (ValueError, TypeError):
        level = 5

    # --- Detection Threat Intel (BYPASS RULE) ---
    threat_found = False

    # FIX 2: Format Blue Team reel - cles sous "threat_intelligence"
    threat_intel_block = payload.get("threat_intelligence", {})
    if isinstance(threat_intel_block, dict):
        ti_misp = threat_intel_block.get("misp", {})
        if isinstance(ti_misp, dict) and (ti_misp.get("found") or ti_misp.get("matched")):
            threat_found = True
        ti_opencti = threat_intel_block.get("opencti", {})
        if isinstance(ti_opencti, dict):
            if ti_opencti.get("found"):
                threat_found = True
            # FIX 3: OpenCTI dit found=false mais a des edges avec score eleve
            edges = []
            try:
                edges = ti_opencti.get("full_response", {}).get("data", {}).get("stixCyberObservables", {}).get("edges", [])
            except Exception:
                pass
            for edge in edges:
                score = edge.get("node", {}).get("x_opencti_score", 0)
                if score and int(score) >= 70:
                    threat_found = True
                    break

    # Format avec correlation_summary
    correlation = payload.get("correlation_summary", {})
    if isinstance(correlation, dict):
        if correlation.get("preliminary_verdict") == "intel_found":
            threat_found = True

    # Format ancien (opencti / misp top-level)
    opencti = payload.get("opencti", {})
    if isinstance(opencti, dict) and opencti.get("found"):
        threat_found = True

    misp = payload.get("misp", {})
    if isinstance(misp, dict):
        if misp.get("matched") or misp.get("found"):
            threat_found = True

    # Format ancien (enrichment block)
    enrichment = payload.get("enrichment", {})
    if isinstance(enrichment, dict):
        if enrichment.get("known_in_opencti"):
            threat_found = True
        signals = enrichment.get("signals", {})
        if isinstance(signals, dict) and (signals.get("is_malicious") or signals.get("is_known_ioc")):
            threat_found = True

    # Format ancien (threat_intel block)
    threat_intel = payload.get("threat_intel", {})
    if isinstance(threat_intel, dict):
        ti_opencti2 = threat_intel.get("opencti", {})
        if isinstance(ti_opencti2, dict) and ti_opencti2.get("found"):
            threat_found = True
        ti_misp2 = threat_intel.get("misp", {})
        if isinstance(ti_misp2, dict) and ti_misp2.get("found"):
            threat_found = True

    # Format ancien (enrichment block)
    enrichment = payload.get("enrichment", {})
    if isinstance(enrichment, dict):
        if enrichment.get("known_in_opencti"):
            threat_found = True
        signals = enrichment.get("signals", {})
        if isinstance(signals, dict) and (signals.get("is_malicious") or signals.get("is_known_ioc")):
            threat_found = True
        misp_enr = enrichment.get("misp", {})
        if isinstance(misp_enr, dict) and misp_enr.get("matched"):
            threat_found = True

    # Format ancien (threat_intel block)
    threat_intel = payload.get("threat_intel", {})
    if isinstance(threat_intel, dict):
        ti_opencti = threat_intel.get("opencti", {})
        if isinstance(ti_opencti, dict) and ti_opencti.get("found"):
            threat_found = True
        ti_misp = threat_intel.get("misp", {})
        if isinstance(ti_misp, dict) and ti_misp.get("found"):
            threat_found = True

    # --- Engine 1 : ML Filter (RandomForest) ---
    if not threat_found and not disable_ml and ENGINE1_ENABLED and rf_model is not None and rf_le is not None:
        try:
            ts_clean = timestamp_str.replace("Z", "+00:00")
            if ts_clean.endswith("+0000"):
                ts_clean = ts_clean[:-5] + "+00:00"
            dt = datetime.fromisoformat(ts_clean)
            hour = dt.hour
            day_of_week = dt.weekday()
            month = dt.month
            is_weekend = 1 if day_of_week >= 5 else 0

            ip_str = src_ip or ""
            alerts_per_minute = get_redis_alerts_per_minute(ip_str)

            numeric_features = pd.DataFrame([{
                "rule_level": level,
                "hour": hour,
                "day_of_week": day_of_week,
                "month": month,
                "is_weekend": is_weekend,
                "alerts_per_minute": alerts_per_minute,
            }])

            if rf_encoder is not None:
                text_features = rf_encoder.encode([description])
                X = hstack([csr_matrix(numeric_features.values), csr_matrix(text_features)])
            else:
                numeric_features["src_ip_encoded"] = 0
                numeric_features["dst_ip_encoded"] = 0
                X = numeric_features

            rf_pred   = rf_model.predict(X)
            rf_classe = rf_le.inverse_transform(rf_pred)[0]
            rf_proba  = max(rf_model.predict_proba(X)[0]) * 100

            # SUPERSONIC FILTER: If ML is highly confident the alert is benign, short-circuit
            if rf_classe in ["Faux positif", "Informatif", "False Positive", "Informational"] and rf_proba >= 90.0:
                elapsed = time.time() - t0
                result = {
                    "analysis_context": f"Alert evaluated by Engine 1 (ML pre-filter) based on text, time, and attack frequency. Classification: {rf_classe} with {rf_proba:.1f}% confidence.",
                    "reasoning": f"[ENGINE 1] Instant ML filter (Confidence: {rf_proba:.1f}%, Time: {elapsed:.3f}s). Alert matches a classic background noise profile. Bypassing Engine 2 (Ollama) to save compute.",
                    "confidence_score": int(rf_proba),
                    "classification": rf_classe,
                    "attack_type": "None",
                    "mitre_tactic": "N/A",
                    "recommandation": "No action required. Filtered out by the ML pre-filter.",
                    "automated_action": {"execute": False, "action_type": None, "target": None}
                }

                database.save_alert(
                    src_ip=src_ip,
                    description=description,
                    classification=result["classification"],
                    attack_type=result["attack_type"],
                    action_executed=None,
                    rule_level=level,
                    ai_confidence=rf_proba,
                    mitre_tactic="N/A",
                    engine_used="Engine1"
                )
                return result

        except Exception as e:
            print(f"⚠️ Engine 1 error: {e}")
    elif ENGINE1_ENABLED is False:
        print("[INFO] Engine 1 is DISABLED — skipping ML filter, routing directly to Ollama.")

    # --- Engine 2 : LLaMA 3 + Memory (Escalade) ---
    history = database.get_ip_history(src_ip)

    if threat_found:
        system_prompt += "\n\n[INFO] THREAT INTEL A FLAGGE CETTE ALERTE ! Le pre-filtre ML a ete bypasse. Sois agressif dans ton jugement."

    # Injection du contexte Blue Team (si present)
    bt_context = payload.get("blue_team_context") or extract_field(payload, ["analysis_request.task"], default=None)
    if bt_context:
        system_prompt += f"\n\n[CONTEXTE BLUE TEAM] {bt_context}\nPrends OBLIGATOIREMENT en compte cette consigne de la Blue Team dans ton analyse et ta decision finale."

    # INJECTION TOTALE : Tout le JSON brut est envoye a Ollama
    system_prompt += f"\n\n[DONNEES COMPLETES DE L'ALERTE (JSON BRUT)]\n{json.dumps(payload, indent=2, default=str)}\nAnalyse TOUTES ces donnees sans exception. Utilise chaque champ pertinent pour ton raisonnement."

    result = soc_agent.qualify_alert(payload, system_prompt, history)

    # Save the decision into memory
    database.save_alert(
        src_ip=src_ip,
        description=description,
        classification=result.get("classification", "Erreur"),
        attack_type=result.get("attack_type", "Inconnu"),
        action_executed=result.get("automated_action", {}).get("action_type"),
        rule_level=level,
        ai_confidence=result.get("confidence_score", 0.0),
        mitre_tactic=result.get("mitre_tactic", "N/A"),
        engine_used="Engine2"
    )

    return result

