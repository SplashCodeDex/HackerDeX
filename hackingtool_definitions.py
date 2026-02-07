from typing import List, Tuple
from core import HackingToolsCollection
from tools.anonsurf import AnonSurfTools
from tools.ddos import DDOSTools
from tools.exploit_frameworks import ExploitFrameworkTools
from tools.forensic_tools import ForensicTools
from tools.information_gathering_tools import InformationGatheringTools
from tools.other_tools import OtherTools
from tools.payload_creator import PayloadCreatorTools
from tools.phising_attack import PhishingAttackTools
from tools.post_exploitation import PostExploitationTools
from tools.remote_administration import RemoteAdministrationTools
from tools.reverse_engineering import ReverseEngineeringTools
from tools.sql_tools import SqlInjectionTools
from tools.steganography import SteganographyTools
from tools.tool_manager import ToolManager
from tools.webattack import WebAttackTools
from tools.wireless_attack_tools import WirelessAttackTools
from tools.wordlist_generator import WordlistGeneratorTools
from tools.xss_attack import XSSAttackTools
from tools.intelligence_engine import IntelligenceEngineTools

TOOL_DEFINITIONS: List[Tuple[str, str]] = [
    ("Anonymously Hiding Tools", "🛡️"),
    ("Information gathering tools", "🔍"),
    ("Wordlist Generator", "📚"),
    ("Wireless attack tools", "📶"),
    ("SQL Injection Tools", "🧩"),
    ("Phishing attack tools", "🎣"),
    ("Web Attack tools", "🌐"),
    ("Post exploitation tools", "🔧"),
    ("Forensic tools", "🕵️"),
    ("Payload creation tools", "📦"),
    ("Exploit framework", "🧰"),
    ("Reverse engineering tools", "🔁"),
    ("DDOS Attack Tools", "⚡"),
    ("Remote Administrator Tools (RAT)", "🖥️"),
    ("XSS Attack Tools", "💥"),
    ("Steganograhy tools", "🖼️"),
    ("Other tools", "✨"),
    ("Robust Intelligence Engine", "🧠"),
    ("Update or Uninstall | Hackingtool", "♻️"),
]

ALL_TOOLS: List[HackingToolsCollection] = [
    AnonSurfTools(),
    InformationGatheringTools(),
    WordlistGeneratorTools(),
    WirelessAttackTools(),
    SqlInjectionTools(),
    PhishingAttackTools(),
    WebAttackTools(),
    PostExploitationTools(),
    ForensicTools(),
    PayloadCreatorTools(),
    ExploitFrameworkTools(),
    ReverseEngineeringTools(),
    DDOSTools(),
    RemoteAdministrationTools(),
    XSSAttackTools(),
    SteganographyTools(),
    OtherTools(),
    IntelligenceEngineTools(),
    ToolManager()
]
