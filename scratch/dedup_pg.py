import sys
sys.path.append('c:\\Users\\achre\\Downloads\\Stage 3eme passe 4eme TT\\combined work ai soc')
from app.database import engine, Alert
from sqlalchemy.orm import Session
from sqlalchemy import func

try:
    with Session(engine) as session:
        # Find all alerts
        alerts = session.query(Alert).all()
        
        seen = set()
        duplicates_to_delete = []
        
        for alert in alerts:
            # Create a unique signature for each alert
            # We use description and timestamp (if available) to identify duplicates
            sig = (alert.timestamp, alert.description, alert.src_ip)
            
            if sig in seen:
                duplicates_to_delete.append(alert)
            else:
                seen.add(sig)
                
        if duplicates_to_delete:
            print(f"[*] Found {len(duplicates_to_delete)} duplicate alerts. Deleting...")
            for dup in duplicates_to_delete:
                session.delete(dup)
            session.commit()
            print("[+] Duplicates successfully deleted!")
        else:
            print("[*] No duplicates found in the database. It is perfectly clean!")
            
        final_count = session.query(Alert).count()
        print(f"[*] Total alerts remaining in database: {final_count}")

except Exception as e:
    print(f"[ERROR] Failed to deduplicate: {e}")
