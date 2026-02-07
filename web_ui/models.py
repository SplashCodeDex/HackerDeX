from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime

class PortModel(BaseModel):
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    last_seen: Optional[str] = None

class VulnerabilityModel(BaseModel):
    title: str
    severity: str
    details: str = ""
    affected_url: Optional[str] = None
    source_tool: str = ""
    source_layer: str = "network"
    privilege_level: str = "none"
    strategic_advantage: str = ""
    confidence: float = 1.0
    discovered_at: Optional[str] = None
    verified: bool = False
    verification_script: Optional[str] = None

class TechnologyModel(BaseModel):
    name: str
    version: str = ""
    category: Optional[str] = None

class ScanResultModel(BaseModel):
    target: str
    tool_name: str
    ports: List[PortModel] = []
    vulns: List[VulnerabilityModel] = []
    urls: List[str] = []
    technologies: List[TechnologyModel] = []
    os_info: Dict[str, str] = {}
    dns_info: Dict[str, List[str]] = {}
    osint_info: Dict[str, List[str]] = {}
    sessions: List[Dict] = []
