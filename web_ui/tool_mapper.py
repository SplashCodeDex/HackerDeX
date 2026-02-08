import os
import json
import logging
from typing import Dict, Any
from tool_registry import registry

class ToolCapabilityMapper:
    """
    Translates tactical goals into precise tool commands for the 55+ tool catalog.
    Uses Gemini to synthesize command line arguments based on target context and intent.
    """

    def __init__(self, gemini_client):
        self.client = gemini_client
        self.model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

    def get_command(self, tool_name: str, goal: str, target: str) -> Dict[str, Any]:
        """
        Returns a specific command line for the given tool to achieve the goal.
        """
        tool = registry.get_tool(tool_name)
        if not tool:
            return {"command": "", "error": f"Tool '{tool_name}' not found in registry."}

        # Provide tool metadata to LLM
        tool_info = f"Title: {tool.TITLE}\nDescription: {tool.DESCRIPTION}\n"
        if hasattr(tool, 'RUN_COMMANDS') and tool.RUN_COMMANDS:
            tool_info += f"Typical Run Commands: {tool.RUN_COMMANDS}\n"

        prompt = f"""
        You are a Red Team Operator.

        TOOL: {tool_name}
        TOOL METADATA:
        {tool_info}

        TACTICAL GOAL: {goal}
        TARGET: {target}

        TASK:
        Generate the most effective and precise command line for this tool to achieve the goal.
        Ensure you use appropriate flags for the target type and goal.

        OUTPUT FORMAT (Strict JSON):
        {{
            "command": "<full_shell_command>",
            "rationale": "<brief_explanation_of_flags_used>",
            "category": "<recon|exploit|post-exploit|etc>"
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

            return json.loads(text)
        except Exception as e:
            logging.error(f"Tool Mapper Error for {tool_name}: {e}")
            # Basic fallback
            return {
                "command": f"{tool_name} {target}",
                "rationale": "Fallback to basic command due to error.",
                "category": "recon"
            }
