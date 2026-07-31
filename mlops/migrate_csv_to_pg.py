import pandas as pd
from sqlalchemy import create_engine
import datetime

# ── Config ────────────────────────────────────────────────────────────────────
CSV_PATH = "dataset_ready_for_ai.csv"
DB_URL = "postgresql+psycopg2://soc_user:soc_secret@localhost:5432/soc_db"

print("=" * 60)
print("  MLOps: Migrating CSV dataset to PostgreSQL")
print("=" * 60)

try:
    print(f"[*] Loading {CSV_PATH}...")
    df = pd.read_csv(CSV_PATH)
    
    # We only need specific columns for the database
    # The old CSV has: 'description', 'label', 'attack_type', 'rule_level'
    
    print("[*] Formatting columns for PostgreSQL...")
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Create a new DataFrame matching the PostgreSQL 'alerts' table schema
    pg_df = pd.DataFrame({
        "timestamp": [now] * len(df),
        "src_ip": ["192.168.1.1"] * len(df), # Dummy IP for historical data
        "description": df["description"],
        "rule_level": df.get("rule_level", 5),
        "ai_classification": df["label"],
        "ai_attack_type": df.get("attack_type", "Unknown"),
        "ai_confidence": [95.0] * len(df), # High confidence since it's ground truth
        "mitre_tactic": ["N/A"] * len(df),
        "action_executed": ["Migrated_from_CSV"] * len(df),
        "engine_used": ["Engine2"] * len(df) # Treat as high-quality LLM decisions
    })
    
    print(f"[*] Connecting to PostgreSQL at {DB_URL}...")
    engine = create_engine(DB_URL)
    
    print("[*] Injecting rows into 'alerts' table...")
    pg_df.to_sql("alerts", engine, if_exists="append", index=False)
    
    print(f"✅ Successfully migrated {len(pg_df)} rows to PostgreSQL!")
    print("You can now safely delete dataset_ready_for_ai.csv")

except FileNotFoundError:
    print(f"⚠️ {CSV_PATH} not found. Maybe it was already deleted?")
except Exception as e:
    print(f"❌ Error during migration: {e}")
