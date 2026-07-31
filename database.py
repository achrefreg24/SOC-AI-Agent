import sqlite3
import datetime
import os
import pandas as pd

DB_PATH = "soc_memory.db"

def init_db():
    """Initialise la base de donnees et cree la table si elle n'existe pas."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            description TEXT,
            ai_classification TEXT,
            ai_attack_type TEXT,
            action_executed TEXT
        )
    ''')
    
    # Add new columns for analytics and knowledge distillation (ignoring errors if they already exist)
    new_columns = [
        ("rule_level", "INTEGER"),
        ("ai_confidence", "REAL"),
        ("mitre_tactic", "TEXT"),
        ("engine_used", "TEXT")
    ]
    
    for col_name, col_type in new_columns:
        try:
            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass # Column already exists
            
    conn.commit()
    conn.close()

def save_alert(src_ip: str, description: str, classification: str, attack_type: str, action_executed: str,
               rule_level: int = None, ai_confidence: float = None, mitre_tactic: str = None, engine_used: str = "Engine2"):
    """Sauvegarde une alerte traitee par l'IA dans la base de donnees."""
    if src_ip in [None, "None", "nan", "N/A", ""]:
        src_ip = "UNKNOWN"
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, description, ai_classification, ai_attack_type, action_executed,
                            rule_level, ai_confidence, mitre_tactic, engine_used)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (now, src_ip, description, classification, attack_type, str(action_executed),
          rule_level, ai_confidence, mitre_tactic, engine_used))
    
    conn.commit()
    conn.close()

def get_ip_history(src_ip: str) -> dict:
    """Renvoie l'historique d'une IP (nombre de fois vue, classifications precedentes)."""
    if src_ip in [None, "None", "nan", "N/A", "", "UNKNOWN"]:
        return {"times_seen": 0, "previous_classifications": []}

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # On recupere les alertes de cette IP dans les dernieres 24h
    cursor.execute('''
        SELECT ai_classification, ai_attack_type, action_executed, timestamp 
        FROM alerts 
        WHERE src_ip = ? AND timestamp >= datetime('now', '-1 day')
        ORDER BY timestamp DESC
    ''', (src_ip,))
    
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return {"times_seen": 0, "previous_classifications": []}
        
    history = {
        "times_seen": len(rows),
        "previous_classifications": [row[0] for row in rows],
        "last_attack_type": rows[0][1],
        "last_action_executed": rows[0][2]
    }
    return history

def get_alerts_last_minute(src_ip: str) -> int:
    """Retourne le nombre d'alertes generees par cette IP dans la derniere minute."""
    if src_ip in [None, "None", "nan", "N/A", "", "UNKNOWN"]:
        return 0

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT COUNT(*)
        FROM alerts 
        WHERE src_ip = ? AND timestamp >= datetime('now', '-1 minute')
    ''', (src_ip,))
    
    count = cursor.fetchone()[0]
    conn.close()
    
    return count

def get_all_alerts_df():
    """Return all alerts as a Pandas DataFrame (for analytics dashboard)."""
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM alerts ORDER BY timestamp DESC"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df
