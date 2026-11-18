# Reto Final IA: Arquitectura Agéntica de Ciberseguridad (AISOC)

Plataforma agéntica para la auditoría, análisis de amenazas en el uso corporativo de Inteligencia Artificial, detección de ataques contra agentes (OWASP LLM 2025 / MITRE ATLAS), integración de herramientas con **Model Context Protocol (MCP)** y evaluación comparativa de rendimiento y costos con modelos locales en GPU.

---

## 📋 Requerimientos del Reto Cumplidos al 100%

| Requerimiento | Implementación en este Proyecto | Archivo Clave |
| :--- | :--- | :--- |
| **1. Arquitectura Agéntica de Ciberseguridad** | Análisis integral de Gobernanza de IA, Vectores de ataque a agentes y Rendimiento con diagramas Mermaid. | `docs/arquitectura_agentica_ciberseguridad.md` |
| **2. Prototipo con RAG, Herramientas y MCP** | RAG vectorial sobre OWASP LLM 2025 + MITRE ATLAS; Herramientas heurísticas; Servidor JSON-RPC Model Context Protocol (MCP). | `src/rag_engine.py`, `src/tools.py`, `src/mcp_service.py` |
| **3. Comparativa: Agente Único vs. Multiagente** | Implementación de Agente Monolítico vs. Sistema AISOC (4 especialistas) con evaluación en 5 escenarios. | `src/single_agent.py`, `src/agents.py`, `src/benchmark.py` |
| **4. Calidad, Rendimiento y Costo (Modelos Locales)** | Benchmark cuantitativo: precisión, latencia, throughput y ahorro del 99.8% de costos en GPU local (NVIDIA RTX 4060). | `src/evaluator.py`, `docs/benchmark_results.json` |
| **5. Interfaz Interactiva de Presentación** | Dashboard web completo en Streamlit con demo en vivo, comparativas y calculadora de costos. | `app.py` |

---

## 🚀 Inicio Rápido (Ejecución en 1 Clic)

### 1. Iniciar el Dashboard Interactivo de Demostración
Desde la raíz del proyecto, ejecute:
```powershell
python -m streamlit run app.py
```
La aplicación se abrirá automáticamente en su navegador en `http://localhost:8501`.

### 2. Ejecutar el Benchmark Técnico en Consola
```powershell
python src/benchmark.py
```

---

## 🏛️ Estructura del Proyecto

```
RetoFinalIA/
├── app.py                      # Interfaz gráfica Streamlit interactiva para la defensa técnica
├── README.md                   # Documentación principal del repositorio
├── data/                       # Base de conocimiento estructurada para el motor RAG
│   ├── owasp_llm_top10.json        # Taxonomía completa OWASP LLM Applications 2025
│   ├── mitre_atlas_threats.json    # Técnicas adversariales MITRE ATLAS (AML.T0051, AML.T0054...)
│   └── mcp_security_guidelines.json# Políticas de seguridad para servidores y herramientas MCP
├── docs/                       # Documentación técnica y reportes
│   ├── arquitectura_agentica_ciberseguridad.md # Documento técnico de arquitectura con diagramas Mermaid
│   ├── benchmark_results.json                  # Resultados empíricos de la comparativa
│   └── guia_presentacion_profesor.md           # Guion paso a paso para la exposición ante el profesor
└── src/                        # Código fuente modular del sistema agéntico
    ├── config.py               # Configuración de URLs, modelos y tabla de costos de inferencia
    ├── llm_client.py           # Cliente con soporte para Ollama en GPU local y motor de fallback
    ├── rag_engine.py           # Motor RAG vectorial híbrido con búsqueda semántica y similitud coseno
    ├── tools.py                # Herramientas de ciberseguridad (Detección de injection, DLP, permisos)
    ├── mcp_service.py          # Servidor y cliente Model Context Protocol (MCP JSON-RPC 2.0)
    ├── agents.py               # Sistema multiagente AISOC (Supervisor, ThreatIntel, RedTeam, MCP, BlueTeam)
    ├── single_agent.py         # Agente único monolítico para análisis comparativo A/B
    ├── evaluator.py            # Motor de scoring de calidad, latencia y costos (GPU vs Cloud APIs)
    └── benchmark.py            # Suite de pruebas automatizadas sobre 5 escenarios corporativos
```

---

## 🤖 Roles del Sistema Multiagente (AISOC)

1. **Supervisor & Triage Agent:** Descompone el evento de seguridad y orquesta a los especialistas.
2. **Threat Intelligence Agent (RAG):** Consulta la base vectorial para identificar vulnerabilidades OWASP y tácticas MITRE.
3. **Red Team Agent (Adversarial):** Evalúa el vector de ataque y ejecuta escáneres heurísticos de inyección y jailbreak.
4. **MCP Inspector Agent:** Audita los esquemas JSON-RPC de las herramientas invocadas y valida Human-in-the-Loop.
5. **Blue Team Agent:** Sintetiza los hallazgos y formula los guardrails defensivos emitiendo el veredicto `BLOCK` o `ALLOW`.

---

## 💡 Ventajas Clave del Modelo Local (GPU RTX 4060)

- **Costo Marginal Cero:** \$0.00 por token frente a \$2.50-\$10.00/1M en GPT-4o.
- **Soberanía y Privacidad de Datos:** Ningún dato sensible corporativo sale de la red local (Zero Data Egress).
- **Latencia Controlada:** Inferencia a 65-85 tokens/segundo con baja latencia sin dependencia de colas de red externas.
