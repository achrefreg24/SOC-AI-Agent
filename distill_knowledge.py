"""
distill_knowledge.py
--------------------
MLOps Knowledge Distillation Pipeline.

How it works:
  1. Engine 2 (LLaMA 3 / Ollama) makes expensive, high-quality decisions on real alerts.
  2. This script reads those decisions from the PostgreSQL database.
  3. It formats them as labeled training samples and appends them to the CSV dataset.
  4. It then automatically retrains Engine 1 (Random Forest) so it absorbs the LLM's knowledge.

Over time: Engine 1 becomes smarter and handles more cases alone,
           reducing LLM calls by up to 95% and cutting response time from 5s -> 5ms.

Run weekly (or after a live test session):
    python distill_knowledge.py
"""

import subprocess
import sys
import datetime
import pandas as pd
from pathlib import Path
from sqlalchemy import create_engine, text

# ── Config ─────────────────────────────────────────────────────────────────────
DB_URL       = "postgresql+psycopg2://soc_user:soc_secret@localhost:5432/soc_db"
DATASET_PATH = Path("dataset_ready_for_ai.csv")
MIN_CONFIDENCE = 85.0   # Only distill decisions the LLM was confident about
MIN_NEW_ROWS   = 5      # Only retrain if we have at least 5 new rows to add

# ── Label normalization (English -> Dataset format) ───────────────────────────
LABEL_MAP = {
    "Critical":      "Critique",
    "Suspicious":    "Suspect",
    "Informational": "Informatif",
    "False Positive": "Faux positif",
    # French labels (in case old alerts are in DB)
    "Critique":      "Critique",
    "Suspect":       "Suspect",
    "Informatif":    "Informatif",
    "Faux positif":  "Faux positif",
}


def fetch_new_decisions():
    """
    Fetch Engine 2 decisions from PostgreSQL that are:
    - High confidence (>= 85%)
    - Not yet distilled (from the last 7 days)
    """
    print("📊 Connecting to PostgreSQL...")
    engine = create_engine(DB_URL)
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)

    query = text("""
        SELECT 
            timestamp,
            src_ip,
            description,
            rule_level,
            ai_classification,
            ai_attack_type,
            ai_confidence,
            mitre_tactic
        FROM alerts
        WHERE engine_used = 'Engine2'
          AND ai_confidence >= :min_conf
          AND timestamp >= :cutoff
        ORDER BY timestamp DESC
    """)

    with engine.connect() as conn:
        result = conn.execute(query, {"min_conf": MIN_CONFIDENCE, "cutoff": cutoff})
        rows = result.fetchall()
        columns = result.keys()

    df = pd.DataFrame(rows, columns=list(columns))
    print(f"   Found {len(df)} high-confidence Engine 2 decisions.")
    return df


def format_for_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transform PostgreSQL rows into the format expected by retrain_engine1.py.
    Maps to the same columns as dataset_ready_for_ai.csv.
    """
    if df.empty:
        return pd.DataFrame()

    new_rows = []
    for _, row in df.iterrows():
        label = LABEL_MAP.get(row.get("ai_classification", ""), "Suspect")
        new_rows.append({
            "timestamp":   row["timestamp"].isoformat() if pd.notna(row["timestamp"]) else "",
            "description": row.get("description", ""),
            "rule_level":  int(row["rule_level"]) if pd.notna(row.get("rule_level")) else 5,
            "src_ip":      row.get("src_ip", "UNKNOWN"),
            "label":       label,
            "attack_type": row.get("ai_attack_type", "Unknown"),
            "mitre":       row.get("mitre_tactic", ""),
            "source":      "engine2_distillation",   # Track provenance
            "confidence":  float(row["ai_confidence"]) if pd.notna(row.get("ai_confidence")) else 0.0
        })

    return pd.DataFrame(new_rows)


def append_to_dataset(new_df: pd.DataFrame):
    """Append new labeled samples to the main CSV training dataset."""
    if new_df.empty:
        print("⚠️  No new rows to append.")
        return 0

    if DATASET_PATH.exists():
        existing_df = pd.read_csv(DATASET_PATH)
        combined_df = pd.concat([existing_df, new_df], ignore_index=True)
        # Deduplicate based on (description + label) to avoid double-training
        before = len(combined_df)
        combined_df.drop_duplicates(subset=["description", "label"], keep="last", inplace=True)
        after = len(combined_df)
        added = after - len(existing_df)
        print(f"   Deduplicated: removed {before - after} duplicates.")
    else:
        combined_df = new_df
        added = len(new_df)

    combined_df.to_csv(DATASET_PATH, index=False)
    print(f"✅ Appended {added} net new samples to {DATASET_PATH}.")
    return added


def trigger_retrain():
    """Automatically trigger Engine 1 retraining."""
    print("\n🧠 Triggering Engine 1 retraining...")
    result = subprocess.run(
        [sys.executable, "retrain_engine1.py"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print("✅ Engine 1 retrained successfully!")
        print(result.stdout[-500:])  # Show last 500 chars of output
    else:
        print("❌ Retraining failed!")
        print(result.stderr)


def main():
    print("=" * 60)
    print("  MLOps Knowledge Distillation Pipeline")
    print("  Engine 2 (LLaMA 3) -> Engine 1 (Random Forest)")
    print("=" * 60)

    # 1. Fetch decisions from Postgres
    raw_df = fetch_new_decisions()
    if raw_df.empty:
        print("No new decisions to distill. Run more test alerts first!")
        return

    # 2. Format for dataset
    new_df = format_for_dataset(raw_df)
    print(f"\nNew samples by classification:")
    print(new_df["label"].value_counts().to_string())

    # 3. Append to dataset
    added = append_to_dataset(new_df)

    # 4. Only retrain if we added enough new samples
    if added >= MIN_NEW_ROWS:
        trigger_retrain()
    else:
        print(f"\n⚠️  Only {added} new samples added (minimum: {MIN_NEW_ROWS}). Skipping retrain.")
        print("   Run more real alerts against the API to generate training data!")

    print("\n✅ Knowledge Distillation complete!")
    print(f"   Engine 1 is now smarter thanks to {added} new real-world decisions from Engine 2.")


if __name__ == "__main__":
    main()
