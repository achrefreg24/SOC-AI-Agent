import sys
sys.path.append('c:\\Users\\achre\\Downloads\\Stage 3eme passe 4eme TT\\combined work ai soc')
from app.database import engine
import pandas as pd

try:
    with engine.connect() as conn:
        df = pd.read_sql("SELECT id, src_ip, ai_classification, ai_attack_type, action_executed FROM alerts ORDER BY id DESC LIMIT 5", conn)
        print("--- LATEST 5 ALERTS ---")
        print(df.to_string())
        
        df_count = pd.read_sql("SELECT COUNT(*) as count FROM alerts WHERE ai_classification IS NOT NULL", conn)
        print(f"\nTotal AI Classified Alerts: {df_count.iloc[0]['count']}")
except Exception as e:
    print(f"Error querying postgres: {e}")
