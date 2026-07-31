"""
database.py
-----------
Enterprise PostgreSQL database module for the SOC AI Agent.
Replaces the SQLite-based backend with a production-ready
PostgreSQL backend using SQLAlchemy.

Connection: postgresql://soc_user:soc_secret@localhost:5432/soc_db
(Requires PostgreSQL to be running on localhost:5432)
"""

import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text,
    DateTime, Index, text
)
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.pool import QueuePool
import pandas as pd

# ── Connection Config ─────────────────────────────────────────────────────────
DB_URL = "postgresql+psycopg2://soc_user:soc_secret@localhost:5432/soc_db"

engine = create_engine(
    DB_URL,
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # Reconnect automatically if connection drops
    echo=False
)

# ── Schema Definition ─────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass

class Alert(Base):
    __tablename__ = "alerts"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    timestamp        = Column(DateTime(timezone=True), nullable=False, index=True)
    src_ip           = Column(String(64), nullable=False, index=True)
    description      = Column(Text, nullable=True)
    rule_level       = Column(Integer, nullable=True)
    ai_classification = Column(String(32), nullable=True)
    ai_attack_type   = Column(String(128), nullable=True)
    ai_confidence    = Column(Float, nullable=True)
    mitre_tactic     = Column(String(128), nullable=True)
    action_executed  = Column(Text, nullable=True)
    engine_used      = Column(String(16), nullable=True)

    # Composite index for fast IP + time lookups (the hot query path)
    __table_args__ = (
        Index("ix_alerts_src_ip_timestamp", "src_ip", "timestamp"),
    )

def init_db():
    """Create all tables if they do not exist. Safe to call on every startup."""
    try:
        Base.metadata.create_all(engine)
        print("✅ PostgreSQL schema ready.")
    except Exception as e:
        print(f"⚠️ Could not connect to PostgreSQL. Is it running? Error: {e}")

def save_alert(
    src_ip: str,
    description: str,
    classification: str,
    attack_type: str,
    action_executed: str,
    rule_level: int = None,
    ai_confidence: float = None,
    mitre_tactic: str = None,
    engine_used: str = "Engine2"
):
    """Persist a processed alert to PostgreSQL."""
    if src_ip in [None, "None", "nan", "N/A", ""]:
        src_ip = "UNKNOWN"

    alert = Alert(
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        src_ip=src_ip,
        description=description,
        rule_level=rule_level,
        ai_classification=classification,
        ai_attack_type=attack_type,
        ai_confidence=ai_confidence,
        mitre_tactic=mitre_tactic,
        action_executed=str(action_executed),
        engine_used=engine_used
    )
    try:
        with Session(engine) as session:
            session.add(alert)
            session.commit()
    except Exception as e:
        print(f"⚠️ Error saving to Postgres: {e}")

def get_ip_history(src_ip: str) -> dict:
    """Return the 24-hour history of a source IP address from Postgres."""
    if src_ip in [None, "None", "nan", "N/A", "", "UNKNOWN"]:
        return {"times_seen": 0, "previous_classifications": []}

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)

    try:
        with Session(engine) as session:
            rows = (
                session.query(
                    Alert.ai_classification,
                    Alert.ai_attack_type,
                    Alert.action_executed,
                    Alert.timestamp
                )
                .filter(Alert.src_ip == src_ip, Alert.timestamp >= cutoff)
                .order_by(Alert.timestamp.desc())
                .all()
            )

        if not rows:
            return {"times_seen": 0, "previous_classifications": []}

        return {
            "times_seen": len(rows),
            "previous_classifications": [r[0] for r in rows],
            "last_attack_type": rows[0][1],
            "last_action_executed": rows[0][2]
        }
    except Exception as e:
        print(f"⚠️ Error reading from Postgres: {e}")
        return {"times_seen": 0, "previous_classifications": []}

def get_alerts_last_minute(src_ip: str) -> int:
    """Return the number of alerts from this IP in the last 60 seconds (Fallback if Redis fails)."""
    if src_ip in [None, "None", "nan", "N/A", "", "UNKNOWN"]:
        return 0

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)

    try:
        with Session(engine) as session:
            count = (
                session.query(Alert)
                .filter(Alert.src_ip == src_ip, Alert.timestamp >= cutoff)
                .count()
            )
        return count
    except Exception:
        return 0

def get_all_alerts_df():
    """Return all alerts as a Pandas DataFrame (for analytics dashboard)."""
    try:
        with Session(engine) as session:
            rows = session.query(Alert).order_by(Alert.timestamp.desc()).all()

        if not rows:
            return pd.DataFrame()

        data = []
        for r in rows:
            data.append({
                "id": r.id,
                "timestamp": r.timestamp,
                "src_ip": r.src_ip,
                "description": r.description,
                "rule_level": r.rule_level,
                "ai_classification": r.ai_classification,
                "ai_attack_type": r.ai_attack_type,
                "ai_confidence": r.ai_confidence,
                "mitre_tactic": r.mitre_tactic,
                "action_executed": r.action_executed,
                "engine_used": r.engine_used
            })
        return pd.DataFrame(data)
    except Exception as e:
        print(f"⚠️ Error reading from Postgres: {e}")
        return pd.DataFrame()
