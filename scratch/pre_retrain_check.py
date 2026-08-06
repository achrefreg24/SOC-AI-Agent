import sys
sys.path.append('.')
from app.database import engine as pg_engine
import pandas as pd

with pg_engine.connect() as conn:
    df = pd.read_sql(
        "SELECT ai_classification as label, COUNT(*) as count FROM alerts WHERE ai_classification IS NOT NULL GROUP BY ai_classification",
        conn
    )
    total = pd.read_sql(
        "SELECT COUNT(*) as total FROM alerts WHERE ai_classification IS NOT NULL",
        conn
    )
    src_ip_check = pd.read_sql(
        "SELECT COUNT(*) as unknown_ips FROM alerts WHERE src_ip = 'UNKNOWN' OR src_ip IS NULL",
        conn
    )
    print("--- DB Label Distribution ---")
    print(df.to_string(index=False))
    print(f"\nTotal Classified: {total.iloc[0]['total']}")
    print(f"Alerts with UNKNOWN src_ip: {src_ip_check.iloc[0]['unknown_ips']}")
    
    # Check if stratify will work (need at least 2 samples per class)
    print("\n--- Stratify Safety Check ---")
    for _, row in df.iterrows():
        count = row['count']
        label = row['label']
        safe = "OK" if count >= 2 else "WARNING - TOO FEW SAMPLES"
        print(f"  {label}: {count} samples -> {safe}")
