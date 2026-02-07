import sys
import os
import threading
from threading import Lock

# Add parent directory to path to import hackingtool modules
# This is required because hackingtool modules are one level up
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core modules
from io import StringIO
old_stdout = sys.stdout
sys.stdout = StringIO()
try:
    from hackingtool_definitions import ALL_TOOLS as all_tools
    from core import ToolExecutor
finally:
    sys.stdout = old_stdout

from vuln_store import VulnStore
from session_store import get_session_store
from listener_manager import get_listener_manager

# Initialize shared managers
store = VulnStore()
session_store = get_session_store()
listener_mgr = get_listener_manager()
executor = ToolExecutor()

# Job tracking storage
jobs = {}
jobs_lock = Lock()

# Gemini Configuration
from gemini_config import get_gemini_client, GEMINI_MODEL, SAFETY_SETTINGS, GEMINI_API_KEY
    if GEMINI_API_KEY:
        try:
            return genai.Client(api_key=GEMINI_API_KEY)
        except Exception:
            return None
    return None

def load_all_tools():
    """Introspects the all_tools list from hackingtool.py"""
    catalog = {}
    for category in all_tools:
        cat_name = getattr(category, 'TITLE', 'Unknown Category')
        tools_list = []
        if hasattr(category, 'TOOLS'):
            for tool in category.TOOLS:
                if hasattr(tool, 'TITLE'):
                     tools_list.append(tool.TITLE)
        if tools_list:
            catalog[cat_name] = tools_list
    return catalog
