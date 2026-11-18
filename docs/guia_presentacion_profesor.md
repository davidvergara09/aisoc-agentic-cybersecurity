# Guion de Presentación y Defensa Técnica ante el Profesor (5 a 10 Minutos)

**Proyecto:** AISOC — Centro de Operaciones Agénticas de Ciberseguridad  
**Entorno:** Windows + GPU NVIDIA RTX 4060 Laptop (8GB) + Python 3.14  
**Comando de Ejecución:** `python -m streamlit run app.py`

---

## 1. Estructura de la Exposición (Minute by Minute)

### Minuto 0:00 - 1:30 | Introducción y Planteamiento del Problema
> *"Profesor, hoy la ciberseguridad corporativa enfrenta un cambio de paradigma radical debido a la adopción de la Inteligencia Artificial y los Sistemas Agénticos. Los SIEM tradicionales basados en firmas no pueden detectar ataques semánticos como la inyección indirecta de prompts en documentos de negocio, ni supervisar si un agente autónomo tiene permisos excesivos para ejecutar comandos en el sistema.*  
> *Para resolver esto, diseñamos **AISOC**: una arquitectura multiagente especializada que evalúa tres dimensiones críticas: Gobernanza del uso de la IA, Defensa contra ataques agénticos (basados en OWASP LLM 2025 y MITRE ATLAS), y Optimización de Rendimiento y Costo utilizando modelos locales con aceleración GPU."*

### Minuto 1:30 - 3:30 | Arquitectura Agéntica y Componentes Clave (Pestañas 2 y 5)
* **Mostrar en la UI la Pestaña 2 ("Arquitectura Agéntica"):**
  - **Supervisor & Triage Agent:** Recibe el evento, desacopla la tarea y coordina a los especialistas.
  - **Threat Intelligence Agent con RAG:** Búsqueda vectorial semántica (similitud coseno) sobre la base de conocimiento estructurada de **OWASP Top 10 for LLMs 2025** y **MITRE ATLAS**. Cita en tiempo real tácticas como `AML.T0051` (Indirect Prompt Injection).
  - **Red Team Agent:** Utiliza herramientas heurísticas (`detect_prompt_injection`) para detectar jailbreaks, bypass de rol (DAN mode) y delimitadores falsificados.
  - **MCP Inspector Agent:** Implementa el estándar abierto **Model Context Protocol (MCP)** de la industria. Valida esquemas JSON-RPC de herramientas y previene **Excessive Agency (OWASP LLM06)** obligando a implementar Human-in-the-Loop antes de ejecutar acciones de riesgo (shell/escritura).
  - **Blue Team Agent:** Sintetiza los hallazgos de los 3 agentes anteriores y genera el plan de mitigación defensiva con dictamen vinculante (`BLOCK` o `ALLOW`).

### Minuto 3:30 - 6:00 | Demostración en Vivo (Pestaña 1)
* **Demostración Caso 1: Jailbreak Directo / DAN Mode**
  - Seleccionar en el dropdown: *"Ataque 1: Jailbreak Directo / DAN (OWASP LLM01)"*.
  - Hacer clic en **"🚀 Ejecutar Análisis Multiagente (AISOC)"**.
  - **Destacar:** Cómo cada especialista emite su diagnóstico en secuencia; Red Team detecta el jailbreak, RAG recupera controles OWASP, y Blue Team emite el veredicto **🚨 BLOCK**.
* **Demostración Caso 2: Vulnerabilidad en Herramienta MCP (Tool Poisoning / Excessive Agency)**
  - Seleccionar en el dropdown: *"Ataque 3: Excessive Agency en Herramienta MCP"*.
  - Marcar *"Herramienta Peligrosa (Shell sin HITL)"*.
  - Ejecutar el análisis: Mostrar cómo el **MCP Inspector Agent** detecta que la función `system_exec_shell` no tiene confirmación humana y bloquea la operación preventivamente.
* **Demostración Caso 3: Control Benigno**
  - Seleccionar *"Caso 4: Consulta Benigna de Seguridad"*.
  - Ejecutar: Mostrar cómo el sistema distingue tráfico legítimo y emite dictamen **✅ ALLOW**.

### Minuto 6:00 - 7:30 | Comparativa: Agente Único vs. Sistema Multiagente (Pestaña 3)
* **Mostrar en la UI la Pestaña 3:**
  - Explicar por qué un **Agente Único (Monolítico)** no es adecuado para ciberseguridad:
    1. **Contaminación de Contexto:** Mezcla en un solo prompt la detección de ataques, las consultas RAG y la formulación de defensas.
    2. **Fragilidad ante Jailbreaks:** Si el atacante vulnera el prompt del agente único, compromete toda la suite de herramientas.
    3. **En el Sistema Multiagente:** Existe separación estricta de privilegios (*Defense in Depth*). El Red Team evalúa sin acceso a herramientas destructivas, y el Blue Team aplica guardrails antes de que cualquier acción toque el entorno.

### Minuto 7:30 - 9:00 | Evaluación de Calidad, Rendimiento y Costos (Pestaña 4)
* **Mostrar en la UI la Pestaña 4:**
  - **Calidad:** 100% de precisión en la batería de 5 escenarios críticos; mitigaciones respaldadas por citations OWASP/MITRE (cero alucinaciones).
  - **Rendimiento:** Latencia de inferencia optimizada con GPU local NVIDIA GeForce RTX 4060 (8GB VRAM).
  - **Costo Operacional:** Mover el deslizador a **50,000 consultas/mes**:
    - OpenAI GPT-4o: **\$330.00 USD/mes**
    - Claude 3.5 Sonnet: **\$468.00 USD/mes**
    - **AISOC Local en GPU:** **\$0.36 USD/mes** (consumo eléctrico de ~65W de la RTX 4060).
    - **Ahorro:** **> 99.8% de reducción de costo** + **100% de privacidad** (Zero Data Egress: ningún dato confidencial de la organización sale a APIs de terceros).

---

## 2. Preguntas Típicas que Puede Hacer el Profesor y Respuestas Clave

**P: ¿Por qué usaron Model Context Protocol (MCP) en lugar de funciones tradicionales?**  
*R: "MCP es el nuevo estándar abierto de la industria promovido por Anthropic para la interoperabilidad segura de agentes con herramientas. Nos permite estandarizar la validación de esquemas JSON-RPC, restringir accesos mediante listas blancas, registrar trazas forenses inmutables y forzar puntos de control Human-in-the-Loop en herramientas de alto riesgo."*

**P: ¿Qué ventaja tiene el RAG vectorial sobre darle las reglas completas en el System Prompt?**  
*R: "El System Prompt tiene una ventana de contexto limitada y saturarlo con todas las taxonomías de OWASP y MITRE genera fatiga semántica y mayor costo de tokens. El RAG vectorial recupera dinámicamente solo los vectores semánticamente relevantes para el incidente actual, reduciendo tokens y evitando alucinaciones."*

**P: ¿Por qué preferir modelos locales sobre APIs de nube?**  
*R: "En ciberseguridad corporativa, enviar logs, fragmentos de código y trazas de incidentes a una API de terceros viola normativas de privacidad (GDPR, PCI-DSS) y expone secretos industriales. Ejecutar localmente en la GPU RTX 4060 garantiza soberanía de datos, costo marginal cero y elimina la dependencia de conexión a internet o cuotas de API externas."*
