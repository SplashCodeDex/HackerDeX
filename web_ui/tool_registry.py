import os
import shutil
import logging
from typing import List, Dict
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hackingtool_definitions import ALL_TOOLS as all_tools
from core import HackingTool

class ToolRegistry:
    """
    Manages the arsenal of 55+ tools.
    Handles discovery and provides summaries for AI.
    """
    def __init__(self):
        self.tools_map: Dict[str, HackingTool] = {}
        self.categories_map: Dict[str, List[HackingTool]] = {}
        self._discover_tools()

    def _discover_tools(self):
        """Introspects hackingtool to build a catalog."""
        try:
            for category in all_tools:
                cat_title = getattr(category, 'TITLE', 'Uncategorized')
                if not hasattr(category, 'TOOLS'):
                    continue

                self.categories_map[cat_title] = []

                for tool in category.TOOLS:
                    # Map simplified name (e.g. 'nmap') to tool object
                    safe_name = tool.TITLE.lower().replace(' ', '_')
                    self.tools_map[safe_name] = tool
                    self.tools_map[tool.TITLE] = tool

                    # Extract alias from parentheses
                    if '(' in tool.TITLE and ')' in tool.TITLE:
                        alias = tool.TITLE.split('(')[1].split(')')[0].strip().lower()
                        self.tools_map[alias] = tool

                    self.categories_map[cat_title].append(tool)

            logging.info(f"ToolRegistry: Loaded {len(self.tools_map)} tool entries.")
        except Exception as e:
            logging.error(f"ToolRegistry Discovery Failed: {e}")

    def get_tool(self, name: str) -> HackingTool:
        return self.tools_map.get(name.lower().replace(' ', '_'))

    def get_toolbox_summary(self) -> str:
        summary = ""
        for cat, tools in self.categories_map.items():
            names = [t.TITLE for t in tools]
            summary += f"- {cat}: {', '.join(names)}\n"
        return summary

# Global instance
registry = ToolRegistry()