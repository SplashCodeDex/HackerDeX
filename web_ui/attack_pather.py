import os
from typing import List, Dict
from vuln_store import VulnStore

class AttackPather:
    """
    Uses LLM to analyze correlated findings and predict multi-step attack chains.
    """

    def __init__(self, gemini_client, store: VulnStore):
        self.client = gemini_client
        self.store = store
        self.model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

    def analyze_attack_paths(self) -> str:
        """
        Generates a strategic attack path analysis based on the current VulnStore state.
        """
        # Gather context
        targets = self.store.get_all_targets_summary()

        # Build prompt context
        context = "Detected Targets:\n"
        for t in targets[:5]: # Top 5 risky targets
            context += f"- {t['target']} (Risk: {t.get('risk_score', 0)}, Priority: {t.get('priority_level', 'low')})\n"

        prompt = f"""
        You are a Red Team Lead.

        OPERATIONAL CONTEXT:
        {context}

        TASK:
        Analyze the provided target landscape.
        Identify the most likely multi-step attack chain that leads to high-value compromise.
        Connect the dots between OSINT, Network, and Web findings if possible.

        OUTPUT FORMAT:
        Provide a concise, step-by-step narrative of the attack path.
        """

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Error analyzing attack paths: {str(e)}"
