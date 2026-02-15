import os
import json
import logging
from typing import Dict, Any, List
from mission_manager import MissionManager

class FeedbackLoopController:
    """
    The closed-loop execution controller.
    Analyzes tool output in real-time to update the mission state and decide if new attack paths should be added.
    """

    def __init__(self, gemini_client, mission_mgr: MissionManager):
        self.client = gemini_client
        self.mission_mgr = mission_mgr
        self.model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

    def process_tool_output(self, tool_name: str, output: str, target: str):
        """
        Analyzes output and updates the mission.
        """
        # 1. Inform Mission Manager task is done
        self.mission_mgr.mark_task_complete(tool_name, "success")

        # 2. Use Gemini to reason about the findings and potentially update the plan
        prompt = f"""
        You are an Autonomous Red Team Orchestrator.

        TOOL: {tool_name}
        TARGET: {target}
        OUTPUT (Snippet):
        {output[:2000]}

        TASK:
        Analyze this output for strategic intelligence.
        Should we add new tasks to the mission based on what was found?
        (e.g., if a new IP was found, add recon for it).

        OUTPUT FORMAT (Strict JSON):
        {{
            "intelligence": "<summary_of_findings>",
            "new_tasks": ["tool1", "tool2"],
            "reasoning": "<why_these_tasks>"
        }}
        """

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt
            )
            text = response.text.strip()
            # Clean markdown
            if text.startswith('```json'):
                text = text[7:]
            if text.endswith('```'):
                text = text[:-3]

            update = json.loads(text)

            # 3. Dynamic Re-Planning: Inject new tasks if identified
            if update.get("new_tasks"):
                # Heuristic: Add new tasks to a 'Discovery Expansion' phase
                self._inject_new_tasks(update["new_tasks"], update["intelligence"])

            return update
        except Exception as e:
            logging.error(f"Feedback Loop Error: {e}")
            return {"intelligence": "Error analyzing output", "new_tasks": []}

    def _inject_new_tasks(self, tasks: List[str], rationale: str):
        """
        Injects newly discovered tasks into the current mission.
        Enforces intellectual exhaustion.
        """
        if not self.mission_mgr.current_mission:
            return

        new_phase = {
            "name": "Dynamic Expansion",
            "goal": rationale,
            "tasks": tasks,
            "parallel": True
        }
        self.mission_mgr.active_phases.append(new_phase)
        logging.info(f"Feedback Loop: Injected {len(tasks)} new tasks for discovery expansion.")
