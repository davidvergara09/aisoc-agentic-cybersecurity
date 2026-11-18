import os

# Configuración del Sistema AISOC (AI Security Operations Center)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "qwen2.5:1.5b")
FALLBACK_MODEL = os.getenv("FALLBACK_MODEL", "llama3.2:3b")

# Parámetros de RAG
RAG_TOP_K = 3
SIMILARITY_THRESHOLD = 0.05

# Parámetros de Costos (USD por 1M de tokens para comparación con Cloud APIs)
COST_TABLE = {
    "local_ollama": {
        "input_per_m": 0.0,
        "output_per_m": 0.0,
        "energy_kwh_per_1k_tokens": 0.00004, # Consumo estimado RTX 4060 (~65W)
        "kwh_usd": 0.15 # Tarifa promedio electricidad
    },
    "gpt-4o": {
        "input_per_m": 2.50,
        "output_per_m": 10.00
    },
    "claude-3-5-sonnet": {
        "input_per_m": 3.00,
        "output_per_m": 15.00
    }
}

# Rutas de datos
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DOCS_DIR = os.path.join(BASE_DIR, "docs")
