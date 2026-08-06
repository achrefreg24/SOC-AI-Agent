"""
retrain_engine1.py
------------------
Trains a new, smarter Engine 1 model that understands BOTH:
  - Temporal features (hour, day_of_week, rule_level, etc.)
  - NLP text features (TF-IDF on the Wazuh description)

This produces two new model files:
  - models/model_nlp_v4.pkl         (the NLP-aware XGBoost Classifier)
  - models/label_encoder_v4.pkl     (the label encoder)

Run this ONCE from the 'combined work ai soc' folder:
    python retrain_engine1.py
"""

import pandas as pd
import pickle
import numpy as np
from pathlib import Path
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_sample_weight
from scipy.sparse import hstack, csr_matrix
from sentence_transformers import SentenceTransformer
from sqlalchemy import create_engine

# ── Config ────────────────────────────────────────────────────────────────────
DB_URL = "postgresql+psycopg2://soc_user:soc_secret@localhost:5432/soc_db"
MODELS_DIR    = Path(__file__).parent.parent / "data" / "models"
MODELS_DIR.mkdir(exist_ok=True)

print("=" * 60)
print("  ENGINE 1 RETRAINING — ENTERPRISE XGBOOST + EMBEDDINGS")
print("=" * 60)

# ── 1. Load & Clean ───────────────────────────────────────────────────────────
print("\n[*] Loading dataset from PostgreSQL...")
engine = create_engine(DB_URL)
# Pull only alerts that have been classified by the AI
query = "SELECT timestamp, description, rule_level, ai_classification as label FROM alerts WHERE ai_classification IS NOT NULL"
df = pd.read_sql(query, engine)
df = df.dropna(subset=["label", "description"])
print(f"   {len(df)} rows loaded (before rare-label filter).")

# Drop labels with fewer than 5 samples to prevent stratify crash
value_counts = df['label'].value_counts()
rare_labels = value_counts[value_counts < 5].index.tolist()
if rare_labels:
    print(f"   [!] Dropping rare labels (< 5 samples): {rare_labels}")
    df = df[~df['label'].isin(rare_labels)]

print(f"   {len(df)} rows after rare-label filter.")
print(f"   Label distribution:\n{df['label'].value_counts()}\n")

# ── 2. Feature Engineering ────────────────────────────────────────────────────
print("[*] Engineering features...")

# Temporal features (same as before — fast, lightweight)
dt_series = pd.to_datetime(df["timestamp"], format="mixed", utc=True)
df["hour"]        = dt_series.dt.hour
df["day_of_week"] = dt_series.dt.dayofweek
df["month"]       = dt_series.dt.month
df["is_weekend"]  = (df["day_of_week"] >= 5).astype(int)
df["alerts_per_minute"] = df.get("alerts_per_minute", 0)  # default 0 if missing

# Encode labels
le = LabelEncoder()
y = le.fit_transform(df["label"])

# Numeric feature matrix
NUMERIC_FEATURES = ["rule_level", "hour", "day_of_week", "month", "is_weekend", "alerts_per_minute"]
# Fill missing numeric cols with 0
for col in NUMERIC_FEATURES:
    if col not in df.columns:
        df[col] = 0

X_numeric = df[NUMERIC_FEATURES].fillna(0).values

# NLP features: Dense Semantic Embeddings via MiniLM
print("    Building Dense Semantic Embeddings on alert descriptions...")
encoder = SentenceTransformer("all-MiniLM-L6-v2")
X_text = encoder.encode(df["description"].fillna("").tolist(), show_progress_bar=True)
print(f"   Embeddings shape: {X_text.shape}")

# Combine numeric + NLP into one feature matrix
X_combined = hstack([csr_matrix(X_numeric), csr_matrix(X_text)])
print(f"   Combined feature matrix shape: {X_combined.shape}")

# ── 3. Train/Test Split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_combined, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n   Training set: {X_train.shape[0]} samples")
print(f"   Test set:     {X_test.shape[0]} samples")

# ── 4. Train the Model ────────────────────────────────────────────────────────
print("[*] Training Enterprise XGBoost Classifier...")
# Compute sample weights to handle class imbalance
sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    objective='multi:softprob',
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train, sample_weight=sample_weights)
print("   Training complete!")

# ── 5. Evaluate ───────────────────────────────────────────────────────────────
print("\n[*] Evaluating on test set...")
y_pred = model.predict(X_test)
y_pred_labels = le.inverse_transform(y_pred)
y_test_labels = le.inverse_transform(y_test)
print(classification_report(y_test_labels, y_pred_labels, target_names=le.classes_))

print("Confusion Matrix:")
print(confusion_matrix(y_test_labels, y_pred_labels))

train_acc = model.score(X_train, y_train)
test_acc  = model.score(X_test, y_test)
print("\n[OK] Train Accuracy: {:.2f}%".format(train_acc * 100))
print("[OK] Test  Accuracy: {:.2f}%".format(test_acc  * 100))

# ── 6. Save Models ────────────────────────────────────────────────────────────
print("\n[*] Saving models...")
with open(MODELS_DIR / "model_nlp_v4.pkl", "wb") as f:
    pickle.dump(model, f)
with open(MODELS_DIR / "label_encoder_v4.pkl", "wb") as f:
    pickle.dump(le, f)

print("   Saved: models/model_nlp_v4.pkl (XGBoost)")
print("   Saved: models/label_encoder_v4.pkl")

print("\n[DONE] Restart your API to use the new Enterprise XGBoost + Embeddings Engine 1.")
