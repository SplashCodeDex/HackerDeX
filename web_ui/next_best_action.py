from typing import Dict, Any
from vuln_store import VulnStore

class NextBestActionEngine:
    """
    Analyzes the current state of a target and suggests the most effective next tool to run.
    """

    def __init__(self, gemini_client, store: VulnStore):
        self.client = gemini_client
        self.store = store
        self.model = "gemini-2.0-flash-exp"

    def suggest_next_action(self, target_str: str) -> Dict[str, Any]:
        """
        Returns a suggestion for the next tool to run.
        Format: {"tool": "nikto", "reason": "...", "command": "..."}
        """
        profile = self.store.get_target_profile(target_str)
        if not profile:
            return {"tool": "nmap", "reason": "Target not found. Start with basic recon.", "command": f"nmap -sV {target_str}"}

        # Summarize profile for LLM
        summary = f"Target: {profile.get('main_target')}\n"
        summary += f"Open Ports: {[p['port'] for p in profile.get('ports', [])]}\n"
        summary += f"Known Vulns: {[v['title'] for v in profile.get('vulnerabilities', [])]}\n"
        
        prompt = f"""
        You are an autonomous penetration testing agent.
        
        CURRENT INTELLIGENCE:
        {summary}
        
        AVAILABLE TOOLS:
        - nmap (Network Recon)
        - nikto (Web Scanner)
        - sqlmap (SQL Injection)
        - commix (Command Injection)
        - hydra (Brute Force)
        - theHarvester (OSINT)
        
        TASK:
        Decide the single most effective NEXT STEP to advance the engagement.
        
        OUTPUT FORMAT (Strict JSON):
        {{
            "tool": "<tool_name>",
            "reason": "<short explanation>",
            "command": "<full command line>"
        }}
        """
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            # Parse simple JSON (robustness would require json.loads with error handling)
            text = response.text.replace("```json", "").replace("```", "").strip()
            import json
            return json.loads(text)
        except Exception as e:
            return {"tool": "error", "reason": str(e), "command": ""}