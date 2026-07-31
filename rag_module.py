"""
rag_vector.py
-------------
Semantic Vector Database RAG module using ChromaDB + sentence-transformers.
Replaces the keyword-based TF-IDF rag_module.py with true semantic search.

The model used: sentence-transformers/all-MiniLM-L6-v2
- Tiny (22MB), runs locally, no GPU needed, no internet after first download.
- Understands semantic meaning: "database union select error" matches "SQL Injection".

Usage:
    from rag_vector import get_rag_context_vector
    context = get_rag_context_vector("SSH brute force from unknown source")
"""

import json
import chromadb
from pathlib import Path
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

PLAYBOOK_PATH = Path("soc_playbooks.json")
CHROMA_DIR    = Path("chroma_db")  # Where ChromaDB stores its vectors locally

# ── Embedding Model ───────────────────────────────────────────────────────────
# Downloads once (~22MB) on first run, then cached locally forever.
print("🔄 Loading semantic embedding model (MiniLM)...")
embedding_fn = SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# ── ChromaDB Client (persistent, local) ──────────────────────────────────────
chroma_client = chromadb.PersistentClient(path=str(CHROMA_DIR))

collection = chroma_client.get_or_create_collection(
    name="soc_playbooks",
    embedding_function=embedding_fn,
    metadata={"hnsw:space": "cosine"}  # Cosine similarity for text
)


def _index_playbooks():
    """Load playbooks from JSON and index them into ChromaDB."""
    if not PLAYBOOK_PATH.exists():
        print("⚠️  soc_playbooks.json not found. RAG disabled.")
        return

    with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
        playbooks = json.load(f)

    # Only add if collection is empty (avoid re-indexing on every restart)
    if collection.count() == 0:
        print(f"📚 Indexing {len(playbooks)} playbooks into ChromaDB...")
        docs, ids, metadatas = [], [], []
        for pb in playbooks:
            # Rich document: combine name + triggers + procedure for best matching
            doc = (
                pb["name"] + ". " +
                "Triggers: " + ", ".join(pb.get("triggers", [])) + ". " +
                "Procedure: " + pb.get("procedure", "")
            )
            docs.append(doc)
            ids.append(pb["id"])
            metadatas.append({
                "name": pb["name"],
                "mitre_tactic": pb.get("mitre_tactic", ""),
                "procedure": pb.get("procedure", "")
            })

        collection.add(documents=docs, ids=ids, metadatas=metadatas)
        print(f"✅ ChromaDB indexed {len(docs)} playbooks successfully.")
    else:
        print(f"✅ ChromaDB loaded ({collection.count()} playbooks already indexed).")


def get_rag_context_vector(alert_description: str, threshold: float = 0.45) -> str:
    """
    Semantic vector search: finds the most relevant SOC playbook.
    Uses cosine similarity on dense embeddings — understands meaning, not just keywords.

    Args:
        alert_description: The alert text to search against.
        threshold: Minimum cosine similarity to include a result (0.45 = good match).

    Returns:
        A formatted string with the playbook context to inject into the LLM prompt.
        Returns empty string if no relevant playbook found.
    """
    if not alert_description or collection.count() == 0:
        return ""

    results = collection.query(
        query_texts=[alert_description],
        n_results=1,
        include=["metadatas", "distances"]
    )

    if not results or not results["distances"][0]:
        return ""

    distance = results["distances"][0][0]  # ChromaDB returns cosine DISTANCE (0=identical, 2=opposite)
    similarity = 1 - distance              # Convert to similarity score

    if similarity >= threshold:
        meta = results["metadatas"][0][0]
        context = (
            f"\n\n[RAG PLAYBOOK CONTEXT] - STANDARD SOC PROCEDURE\n"
            f"The alert semantically matches the playbook: {meta['name']} ({meta['mitre_tactic']}).\n"
            f"Similarity confidence: {similarity:.0%}\n"
            f"Recommended procedure to include in your analysis: {meta['procedure']}"
        )
        return context

    return ""


def add_playbook(playbook: dict):
    """
    Dynamically add a new playbook to the vector database at runtime.
    No restart required — the new playbook is immediately searchable.
    """
    doc = (
        playbook["name"] + ". " +
        "Triggers: " + ", ".join(playbook.get("triggers", [])) + ". " +
        "Procedure: " + playbook.get("procedure", "")
    )
    collection.add(
        documents=[doc],
        ids=[playbook["id"]],
        metadatas=[{
            "name": playbook["name"],
            "mitre_tactic": playbook.get("mitre_tactic", ""),
            "procedure": playbook.get("procedure", "")
        }]
    )
    print(f"✅ Added new playbook '{playbook['name']}' to ChromaDB.")


# Index playbooks on module import
_index_playbooks()


if __name__ == "__main__":
    print("\n--- Testing Semantic RAG ---")
    tests = [
        "SSH multiple authentication failures from external IP",
        "Ransomware detected: files renamed with .locked extension",
        "Database union select syntax error in WAF logs",
        "Dovecot authentication success from internal machine",
        "Unusual large outbound DNS traffic detected",
    ]
    for t in tests:
        result = get_rag_context_vector(t)
        print(f"\nQuery: '{t}'")
        print(f"Result: {result[:150] + '...' if result else 'No match (below threshold)'}")
