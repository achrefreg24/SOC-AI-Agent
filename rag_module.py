import json
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

PLAYBOOK_PATH = Path("soc_playbooks.json")

def load_playbooks():
    if not PLAYBOOK_PATH.exists():
        return []
    with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

playbooks = load_playbooks()
corpus = []
for pb in playbooks:
    # We embed the triggers + the name to match against the alert description
    corpus.append(pb["name"] + " " + " ".join(pb["triggers"]))

if corpus:
    vectorizer = TfidfVectorizer(stop_words='english')
    tfidf_matrix = vectorizer.fit_transform(corpus)
else:
    vectorizer = None
    tfidf_matrix = None

def get_rag_context(alert_description: str) -> str:
    """
    Given an alert description, finds the most relevant SOC playbook
    and returns its procedure. Returns empty string if no good match.
    """
    if vectorizer is None or tfidf_matrix is None or not playbooks:
        return ""
        
    query_vec = vectorizer.transform([alert_description])
    similarities = cosine_similarity(query_vec, tfidf_matrix).flatten()
    
    best_idx = np.argmax(similarities)
    best_score = similarities[best_idx]
    
    # Threshold for relevance (0.25 = professional enterprise threshold, avoids false matches)
    if best_score > 0.25:
        pb = playbooks[best_idx]
        context = (
            f"\n\n[CONTEXTE RAG] - PROCEDURE STANDARD DU SOC\n"
            f"L'alerte correspond au playbook: {pb['name']} ({pb['mitre_tactic']}).\n"
            f"Procédure recommandée à inclure dans ton analyse: {pb['procedure']}"
        )
        return context
    
    return ""

if __name__ == "__main__":
    # Test
    desc = "Mass file encryption detected - files renamed with unknown extension"
    print(get_rag_context(desc))
