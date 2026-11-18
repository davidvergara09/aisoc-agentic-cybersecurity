import re
import base64
from typing import Dict, Any, List

class SecurityTools:
    """
    Conjunto de herramientas de seguridad para el Centro de Operaciones Agénticas (AISOC).
    Estas herramientas son invocables tanto por agentes individuales como por servidores MCP.
    """

    @staticmethod
    def detect_prompt_injection(text: str) -> Dict[str, Any]:
        """
        Analiza el texto de entrada en busca de patrones de Prompt Injection directos,
        jailbreaks, evasiones lingüísticas e instrucciones conflictivas.
        """
        threats_found = []
        score = 0.0

        # 1. Patrones de Override / Evasión de Reglas
        override_patterns = [
            (r"(?i)(ignore|disregard|forget|omit)\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts|guidelines)", 0.85, "Override Directo de Instrucciones Previas"),
            (r"(?i)(act as|pretend to be|roleplay as|you are now)\s+(dan|an unrestricted ai|developer mode|chaosgpt|evil|unfiltered)", 0.90, "Jailbreak por Personificación (Roleplay DAN/Unrestricted)"),
            (r"(?i)(system prompt|system instruction|reveal your prompt|show me your base instructions)", 0.70, "Intento de Extracción de System Prompt (Prompt Leakage)"),
            (r"(?i)(output|print|dump|send)\s+(all\s+)?(passwords|credentials|api[_\s]?keys|env vars|secrets)", 0.95, "Intento de Exfiltración de Credenciales"),
            (r"(?i)(format c:|rm\s+-rf|powershell|cmd\.exe|/bin/sh|subprocess|eval\(|exec\()", 0.90, "Inyección de Comandos de Sistema Operativo"),
            (r"(?i)(ignore guardrails|bypass safety|modo sin restricciones)", 0.80, "Solicitud Explícita de Evasión de Guardrails")
        ]

        for pattern, weight, label in override_patterns:
            if re.search(pattern, text):
                threats_found.append(label)
                score = max(score, weight)

        # 2. Detección de Payloads Ofuscados (Base64)
        b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        for b64 in b64_matches:
            try:
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                for pattern, weight, label in override_patterns:
                    if re.search(pattern, decoded):
                        threats_found.append(f"Payload Base64 Ofuscado detectado: '{label}'")
                        score = max(score, weight + 0.05)
            except Exception:
                pass

        # 3. Delimitadores maliciosos simulados
        if re.search(r"(?i)(<\s*system\s*>|<\s*admin\s*>|\[system_instruction\]|```system)", text):
            threats_found.append("Falsificación de delimitadores de contexto de sistema (Context Spoofing)")
            score = max(score, 0.75)

        is_malicious = score >= 0.65
        risk_level = "CRITICAL" if score >= 0.85 else ("HIGH" if score >= 0.65 else ("MEDIUM" if score >= 0.40 else "LOW"))

        return {
            "tool_name": "detect_prompt_injection",
            "is_malicious": is_malicious,
            "risk_score": round(score, 2),
            "risk_level": risk_level,
            "threats_detected": threats_found,
            "recommended_action": "BLOCK" if is_malicious else "ALLOW"
        }

    @staticmethod
    def audit_tool_permissions(tool_definition: Dict[str, Any]) -> Dict[str, Any]:
        """
        Audita una herramienta (o herramienta expuesta vía MCP) para identificar exceso de privilegios,
        ausencia de validación de esquemas y falta de Human-in-the-Loop.
        """
        name = tool_definition.get("name", "unnamed_tool")
        description = tool_definition.get("description", "").lower()
        schema = tool_definition.get("inputSchema") or tool_definition.get("parameters") or {}
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        
        risks = []
        severity = "LOW"

        # Palabras de alto riesgo en nombre, descripción o esquema
        critical_keywords = ["shell", "bash", "cmd", "exec", "eval", "delete", "drop table", "format", "write_file", "sudo", "system", "command", "mantenimiento"]
        for kw in critical_keywords:
            if kw in name.lower() or kw in description:
                risks.append(f"Herramienta con capacidad de ejecución/destrucción: palabra clave '{kw}' detectada en definición.")
                severity = "CRITICAL"

        # Verificación estricta de parámetros en inputSchema (MCP) y parameters (OpenAI)
        for prop_name, prop_val in properties.items():
            p_name_lower = prop_name.lower()
            p_desc = prop_val.get("description", "").lower() if isinstance(prop_val, dict) else ""
            
            # Detectar si el nombre del parámetro contiene capacidades de comando o shell
            if any(k in p_name_lower for k in ["command", "cmd", "script", "query", "code", "bash", "shell", "exec"]):
                risks.append(f"Vulnerabilidad OWASP-LLM03 (Tool Poisoning): Parámetro de ejecución oculta '{prop_name}' detectado en esquema.")
                severity = "CRITICAL"
            elif any(k in p_desc for k in ["bash", "shell", "exec", "cmd", "powershell", "comando"]):
                risks.append(f"Parámetro con descripción de ejecución arbitraria: '{prop_name}' ({p_desc}).")
                severity = "CRITICAL"

        # Verificación de Human-in-the-Loop (HITL) para herramientas críticas
        requires_approval = tool_definition.get("requires_approval", False) or tool_definition.get("requires_human_approval", False)
        if severity == "CRITICAL" and not requires_approval:
            risks.append("Vulnerabilidad OWASP-LLM06 (Excessive Agency): Herramienta crítica carece de Human-in-the-Loop (HITL) obligatorio.")

        return {
            "tool_name": "audit_tool_permissions",
            "target_tool": name,
            "severity": severity,
            "excessive_agency_detected": severity == "CRITICAL",
            "risks_identified": risks,
            "compliant_with_mcp_sec": len(risks) == 0,
            "remediation": "Añadir control Human-in-the-Loop y restringir esquema de parámetros a enums cerrados." if risks else "Configuración segura."
        }

    @staticmethod
    def scan_log_entry(log_str: str) -> Dict[str, Any]:
        """
        Inspecciona entradas de log en busca de fugas de credenciales (DLP), tokens JWT,
        llaves de API y PII (OWASP-LLM02).
        """
        leaks = []
        
        # Regex de secretos comunes
        patterns = [
            (r"(?i)(sk-[a-zA-Z0-9]{20,})", "OpenAI API Key expuesta"),
            (r"(?i)(ghp_[a-zA-Z0-9]{30,})", "GitHub Personal Access Token expuesto"),
            (r"(?i)(AKIA[0-9A-Z]{16})", "AWS Access Key ID expuesta"),
            (r"(?i)(password\s*[:=]\s*['\"][^'\"]+['\"])", "Contraseña en texto claro detectada"),
            (r"Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+", "Token JWT Bearer expuesto en logs")
        ]

        for pat, desc in patterns:
            if re.search(pat, log_str):
                leaks.append(desc)

        return {
            "tool_name": "scan_log_entry",
            "secrets_detected": len(leaks) > 0,
            "leaks_list": leaks,
            "dlp_violation": len(leaks) > 0,
            "risk_level": "CRITICAL" if leaks else "LOW"
        }

    @staticmethod
    def verify_rag_chunk_integrity(chunk_text: str) -> Dict[str, Any]:
        """
        Inspecciona un fragmento devuelto por RAG para prevenir Inyección Indirecta de Prompts (MITRE AML.T0051).
        """
        threat = SecurityTools.detect_prompt_injection(chunk_text)
        is_poisoned = threat["is_malicious"]
        return {
            "tool_name": "verify_rag_chunk_integrity",
            "is_poisoned": is_poisoned,
            "risk_level": threat["risk_level"],
            "poison_indicators": threat["threats_detected"],
            "safe_for_agent_consumption": not is_poisoned
        }
