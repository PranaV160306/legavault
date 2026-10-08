"""Semantic search over statutes and precedents.
USE_LANGCHAIN=1: LangChain + FAISS (or Pinecone when PINECONE_API_KEY is set) with MiniLM sentence embeddings.
Default: TF-IDF vectors, which need no downloads."""
import json, os
KB = json.load(open(os.path.join(os.path.dirname(__file__), "kb.json"), encoding="utf-8"))
_r = None

def _embeddings():
    try: from langchain_huggingface import HuggingFaceEmbeddings
    except ImportError: from langchain_community.embeddings import HuggingFaceEmbeddings
    return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2", encode_kwargs={"normalize_embeddings": True})

class Retriever:
    def __init__(self):
        self.texts = [f"{k['title']}. {k['citation']}. {k['text']}" for k in KB]
        self.mode, self.scale = "TF-IDF vectors", 3.0
        if os.environ.get("USE_LANGCHAIN", "").lower() in {"1", "true", "yes"}:
            try:
                from langchain_core.documents import Document
                docs = [Document(page_content=t, metadata={"i": i}) for i, t in enumerate(self.texts)]
                if os.environ.get("PINECONE_API_KEY"):   # index must exist: dimension 384, cosine metric
                    from langchain_pinecone import PineconeVectorStore
                    self.store = PineconeVectorStore.from_documents(docs, _embeddings(), index_name=os.environ.get("PINECONE_INDEX", "legavault"))
                    self.mode = "LangChain + Pinecone"
                else:
                    from langchain_community.vectorstores import FAISS
                    self.store, self.mode = FAISS.from_documents(docs, _embeddings()), "LangChain + FAISS"
                self.scale = 1.5
                return
            except Exception as e:
                self.mode = f"TF-IDF vectors (optional vector setup unavailable: {type(e).__name__})"
        from sklearn.feature_extraction.text import TfidfVectorizer
        self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
        self.mat = self.vec.fit_transform(self.texts)

    def search(self, q, k=4):
        if not q.strip(): return []
        if hasattr(self, "store"):
            hits = self.store.similarity_search_with_score(q, k=k)
            pairs = [(d.metadata["i"], s if "Pinecone" in self.mode else max(0.0, 1 - s / 2)) for d, s in hits]   # FAISS returns squared L2; convert to cosine
        else:
            sims = (self.mat @ self.vec.transform([q]).T).toarray().ravel()
            pairs = [(j, sims[j]) for j in sims.argsort()[::-1][:k]]
        return [dict(KB[int(i)], score=round(float(s), 3)) for i, s in pairs if s > 0.02]

def get():
    global _r
    _r = _r or Retriever()
    return _r
