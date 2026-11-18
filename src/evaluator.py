import time
from typing import Dict, Any, List
try:
    from src.config import COST_TABLE
except (ImportError, ModuleNotFoundError):
    from config import COST_TABLE

class SolutionEvaluator:
    """
    Evaluador cuantitativo y cualitativo de soluciones de ciberseguridad con LLMs.
    Calcula métricas de calidad de respuesta, rendimiento temporal y costo operacional.
    """

    @staticmethod
    def calculate_costs(total_tokens: int, prompt_tokens: int = None, completion_tokens: int = None) -> Dict[str, float]:
        """
        Calcula el costo comparativo entre inferencia local (GPU RTX 4060) y APIs comerciales.
        """
        if prompt_tokens is None:
            prompt_tokens = int(total_tokens * 0.6)
        if completion_tokens is None:
            completion_tokens = int(total_tokens * 0.4)

        # 1. Costo Local (Consumo Eléctrico de GPU Laptop RTX 4060 ~65W)
        cfg_local = COST_TABLE["local_ollama"]
        kwh = (total_tokens / 1000.0) * cfg_local["energy_kwh_per_1k_tokens"]
        local_cost = kwh * cfg_local["kwh_usd"]

        # 2. Costo GPT-4o
        cfg_gpt4o = COST_TABLE["gpt-4o"]
        gpt4o_cost = (prompt_tokens / 1_000_000.0 * cfg_gpt4o["input_per_m"]) + (completion_tokens / 1_000_000.0 * cfg_gpt4o["output_per_m"])

        # 3. Costo Claude 3.5 Sonnet
        cfg_claude = COST_TABLE["claude-3-5-sonnet"]
        claude_cost = (prompt_tokens / 1_000_000.0 * cfg_claude["input_per_m"]) + (completion_tokens / 1_000_000.0 * cfg_claude["output_per_m"])

        savings_vs_gpt4o = max(0.0, (gpt4o_cost - local_cost) / max(gpt4o_cost, 0.000001) * 100.0)

        return {
            "local_hardware_cost_usd": round(local_cost, 6),
            "gpt4o_equivalent_cost_usd": round(gpt4o_cost, 6),
            "claude_sonnet_equivalent_cost_usd": round(claude_cost, 6),
            "percentage_savings": round(savings_vs_gpt4o, 2)
        }

    @staticmethod
    def evaluate_quality(response_text: str, ground_truth_is_threat: bool, detected_is_threat: bool) -> Dict[str, Any]:
        """
        Evalúa la calidad de la respuesta técnica generada por el agente o sistema.
        """
        text_lower = response_text.lower()

        # Detección correcta (Accuracy binaria)
        correct_detection = (ground_truth_is_threat == detected_is_threat)

        # Dimensiones de completitud técnica (0 a 100)
        has_owasp_ref = any(k in text_lower for k in ["owasp", "llm01", "llm02", "llm03", "llm06", "mitre", "aml."])
        has_vector_detail = any(k in text_lower for k in ["jailbreak", "injection", "exfiltración", "agencia", "schema", "permiso", "token"])
        has_mitigation = any(k in text_lower for k in ["guardrail", "sanitiz", "bloque", "human-in-the-loop", "hitl", "aisl", "delimitad"])
        has_structured_output = any(k in response_text for k in ["•", "**", "1.", "2.", "Dictamen", "Severidad"])

        score_components = [
            40 if correct_detection else 0,
            20 if has_owasp_ref else 0,
            15 if has_vector_detail else 0,
            15 if has_mitigation else 0,
            10 if has_structured_output else 0
        ]
        quality_score = sum(score_components)

        # Estimación de alucinación (baja si cita taxonomías y controles reales)
        hallucination_risk = "LOW" if (has_owasp_ref and has_mitigation) else ("MEDIUM" if has_vector_detail else "HIGH")

        return {
            "correct_detection": correct_detection,
            "quality_score_100": quality_score,
            "has_taxonomy_citation": has_owasp_ref,
            "has_actionable_mitigation": has_mitigation,
            "hallucination_risk": hallucination_risk
        }
