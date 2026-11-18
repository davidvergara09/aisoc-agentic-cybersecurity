import json
import os
import re
import math
from typing import List, Dict, Any, Tuple
import numpy as np
try:
    from src.config import DATA_DIR, RAG_TOP_K, SIMILARITY_THRESHOLD
except (ImportError, ModuleNotFoundError):
    from config import DATA_DIR, RAG_TOP_K, SIMILARITY_THRESHOLD

class DocumentChunk:
    def __init__(self, doc_id: str, title: str, category: str, content: str, metadata: Dict[str, Any]):
        self.doc_id = doc_id
        self.title = title
        self.category = category
        self.content = content
        self.metadata = metadata

class HybridRAGEngine:
    """
    Motor RAG Vectorial Híbrido especializado en ciberseguridad para LLMs y Agentes.
    Implementa indexación semántica y búsqueda por similitud coseno con TF-IDF y pesos terminológicos.
    """
    def __init__(self, data_dir: str = DATA_DIR):
        self.data_dir = data_dir
        self.documents: List[DocumentChunk] = []
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.doc_vectors: List[np.ndarray] = []
        self.is_indexed = False
        self._load_and_index()

    def _tokenize(self, text: str) -> List[str]:
        cleaned = re.sub(r'[^a-zA-Z0-9_\-\s]', ' ', text.lower())
        tokens = [t.strip() for t in cleaned.split() if len(t.strip()) > 2]
        return tokens

    def _load_and_index(self):
        chunks: List[DocumentChunk] = []

        # 1. Cargar OWASP Top 10 for LLMs
        owasp_path = os.path.join(self.data_dir, "owasp_llm_top10.json")
        if os.path.exists(owasp_path):
            with open(owasp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    content = (
                        f"{item['id']} {item['name']}: {item['description']} "
                        f"Vectores de ataque: {' '.join(item.get('attack_vectors', []))}. "
                        f"Mitigaciones: {' '.join(item.get('mitigations', []))}."
                    )
                    chunks.append(DocumentChunk(
                        doc_id=item['id'],
                        title=f"{item['id']}: {item['name']}",
                        category=item['category'],
                        content=content,
                        metadata={
                            "severity": item.get('severity', 'UNKNOWN'),
                            "mitigations": item.get('mitigations', []),
                            "source": "OWASP Top 10 for LLMs 2025"
                        }
                    ))

        # 2. Cargar MITRE ATLAS Threats
        mitre_path = os.path.join(self.data_dir, "mitre_atlas_threats.json")
        if os.path.exists(mitre_path):
            with open(mitre_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    content = (
                        f"MITRE ATLAS {item['id']} {item['technique']} (Táctica: {item['tactic']}). "
                        f"Descripción: {item['description']} "
                        f"Detección: {item.get('detection', '')} "
                        f"Controles: {' '.join(item.get('controls', []))}."
                    )
                    chunks.append(DocumentChunk(
                        doc_id=item['id'],
                        title=f"{item['id']}: {item['technique']}",
                        category=f"MITRE ATLAS - {item['tactic']}",
                        content=content,
                        metadata={
                            "severity": "HIGH",
                            "controls": item.get('controls', []),
                            "source": "MITRE ATLAS"
                        }
                    ))

        # 3. Cargar MCP Security Guidelines
        mcp_path = os.path.join(self.data_dir, "mcp_security_guidelines.json")
        if os.path.exists(mcp_path):
            with open(mcp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data:
                    content = f"Guía MCP {item['rule_code']}: {item['principle']}. {item['description']}"
                    chunks.append(DocumentChunk(
                        doc_id=item['rule_code'],
                        title=f"{item['rule_code']}: {item['principle']}",
                        category="Model Context Protocol Security",
                        content=content,
                        metadata={
                            "severity": item.get('severity', 'HIGH'),
                            "source": "MCP Security Best Practices"
                        }
                    ))

        self.documents = chunks
        self._build_vector_index()

    def _build_vector_index(self):
        if not self.documents:
            return

        doc_tokens = [self._tokenize(doc.content) for doc in self.documents]
        df: Dict[str, int] = {}
        for tokens in doc_tokens:
            for token in set(tokens):
                df[token] = df.get(token, 0) + 1

        total_docs = len(self.documents)
        self.vocab = {term: idx for idx, term in enumerate(df.keys())}
        self.idf = {term: math.log((total_docs + 1) / (count + 1)) + 1.0 for term, count in df.items()}

        vectors = []
        for tokens in doc_tokens:
            vec = np.zeros(len(self.vocab), dtype=np.float32)
            tf: Dict[str, int] = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1
            for t, count in tf.items():
                if t in self.vocab:
                    idx = self.vocab[t]
                    vec[idx] = (count / len(tokens)) * self.idf[t]
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
            vectors.append(vec)

        self.doc_vectors = vectors
        self.is_indexed = True

    def query(self, query_text: str, top_k: int = RAG_TOP_K) -> List[Tuple[DocumentChunk, float]]:
        """
        Realiza búsqueda semántica en la base de conocimiento vectorial de ciberseguridad.
        """
        if not self.is_indexed or not self.documents:
            return []

        q_tokens = self._tokenize(query_text)
        if not q_tokens:
            return []

        q_vec = np.zeros(len(self.vocab), dtype=np.float32)
        tf: Dict[str, int] = {}
        for t in q_tokens:
            tf[t] = tf.get(t, 0) + 1
        for t, count in tf.items():
            if t in self.vocab:
                idx = self.vocab[t]
                q_vec[idx] = (count / len(q_tokens)) * self.idf[t]

        norm = np.linalg.norm(q_vec)
        if norm > 0:
            q_vec = q_vec / norm

        scores = [float(np.dot(q_vec, d_vec)) for d_vec in self.doc_vectors]
        ranked_indices = np.argsort(scores)[::-1]

        results = []
        for idx in ranked_indices[:top_k]:
            score = scores[idx]
            if score >= SIMILARITY_THRESHOLD or len(results) == 0:
                results.append((self.documents[idx], score))

        return results

    def format_context_for_prompt(self, query_text: str, top_k: int = RAG_TOP_K) -> str:
        """
        Retorna el contexto recuperado formateado para inyección segura en el prompt de los agentes.
        """
        results = self.query(query_text, top_k=top_k)
        if not results:
            return "No se encontraron referencias específicas en la base de conocimiento de seguridad."

        formatted = ["### CONOCIMIENTO DE CIBERSEGURIDAD RECUPERADO (RAG):"]
        for idx, (doc, score) in enumerate(results, 1):
            formatted.append(
                f"[{idx}] {doc.title} (Relevancia: {score:.2f}) [Severidad: {doc.metadata.get('severity', 'N/A')}]\n"
                f"    Fuente: {doc.metadata.get('source', 'Manual')}\n"
                f"    Detalles: {doc.content}\n"
            )
        return "\n".join(formatted)

if __name__ == "__main__":
    rag = HybridRAGEngine()
    print(f"Total documentos indexados: {len(rag.documents)}")
    test_query = "inyección indirecta de prompts en documentos y jailbreak de agentes"
    matches = rag.query(test_query)
    for doc, score in matches:
        print(f"-> {doc.title} (Score: {score:.3f})")
