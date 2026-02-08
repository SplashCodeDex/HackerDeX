import os
import json
import logging
from typing import List, Dict, Any
from tool_registry import registry

class MissionPlanner:
    """
    Decomposes high-level Red Team objectives into tactical phases and tool-specific tasks.
    """

    def __init__(self, gemini_client):
        self.client = gemini_client
        self.model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

    def decompose_goal(self, goal: str, target: str) -> Dict[str, Any]:
        """
        Queries Gemini to create a high-level mission plan.
        """
        toolbox = registry.get_toolbox_summary()

        prompt = f"""
        You are a Strategic Red Team Planner.

        OBJECTIVE: {goal}
        TARGET: {target}

        TOOLBOX (55+ Tools Available):
        {toolbox}

        TASK:
        Decompose this objective into a structured mission plan consisting of tactical phases.
        Each phase should have a clear goal and a list of candidate tools to use.

        OUTPUT FORMAT (Strict JSON):
        {{
            "mission_name": "<short_name>",
            "phases": [
                {{
                    "name": "Phase Name (e.g. Reconnaissance)",
                    "goal": "What to achieve in this phase",
                    "tasks": ["tool1", "tool2"],
                    "parallel": true/false
                }},
                ...
            ]
        }}
        """

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            text = response.text.strip()
            # Clean markdown if present
            if text.startswith('```json'):
                text = text[7:]
            if text.endswith('```'):
                text = text[:-3]

            return json.loads(text)
        except Exception as e:
            logging.error(f"Mission Decomposer Error: {e}")
            return {
                "mission_name": "Emergency Fallback",
                "phases": [
                    {"name": "Initial Recon", "goal": "Map target", "tasks": ["nmap"], "parallel": false}
                ]
            }
