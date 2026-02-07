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
    from hackingtool import all_tools
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
from google import genai
from google.genai.types import HarmCategory, HarmBlockThreshold

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
GEMINI_MODEL = 'gemini-2.5-pro'

# Agent Safety Configuration: Unrestricted for Offensive Operations
SAFETY_SETTINGS = {
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

def get_gemini_client():
    """Get configured Gemini client with unrestricted safety settings."""
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
