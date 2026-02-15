from parsers.nmap_parser import NmapParser
from parsers.sqlmap_parser import SqlmapParser
from parsers.nikto_parser import NiktoParser
from parsers.metasploit_parser import MetasploitParser
from parsers.theharvester_parser import TheHarvesterParser
from parsers.amass_parser import AmassParser
from parsers.ffuf_parser import FFUFParser
from parsers.semgrep_parser import SemgrepParser
from parsers.naabu_parser import NaabuParser
from parsers.httpx_parser import HttpxParser
from parsers.gobuster_parser import GobusterParser
from parsers.hydra_parser import HydraParser
from parsers.nuclei_parser import NucleiParser
from parsers.wpscan_parser import WPScanParser
from parsers.burp_parser import BurpSuiteParser
from parsers.generic_parser import GenericParser
from models import ScanResultModel, PortModel, VulnerabilityModel, TechnologyModel

class ParserRegistry:
    def __init__(self):
        self.parsers = []
        self._register_defaults()
        self.fallback = GenericParser()

    def _register_defaults(self):
        self.register_parser(NmapParser())
        self.register_parser(SqlmapParser())
        self.register_parser(NiktoParser())
        self.register_parser(MetasploitParser())
        self.register_parser(AmassParser())
        self.register_parser(FFUFParser())
        self.register_parser(SemgrepParser())
        self.register_parser(NaabuParser())
        self.register_parser(HttpxParser())
        self.register_parser(GobusterParser())
        self.register_parser(HydraParser())
        self.register_parser(NucleiParser())
        self.register_parser(WPScanParser())
        self.register_parser(BurpSuiteParser())
        self.register_parser(TheHarvesterParser())

    def register_parser(self, parser):
        """Add a new parser to the registry."""
        self.parsers.append(parser)

    def get_parser(self, tool_name: str):
        """Find a suitable parser for the given tool."""
        for parser in self.parsers:
            if parser.can_parse(tool_name):
                return parser
        return self.fallback

    def parse_output(self, raw_output: str, tool_name: str, target: str) -> ScanResultModel:
        """Parse tool output and return a standardized ScanResultModel."""
        parser = self.get_parser(tool_name)

        # Primary parsing
        results_dict = parser.parse(raw_output, tool_name, target)

        # Ensure all required keys exist in the dict returned by parsers
        for key in ["ports", "vulns", "urls", "technologies", "os_info"]:
            if key not in results_dict:
                results_dict[key] = [] if key != "os_info" else {}

        # Merge with generic if it wasn't the primary parser
        if not isinstance(parser, GenericParser):
            generic_dict = self.fallback.parse(raw_output, tool_name, target)
            results_dict["urls"] = list(set(results_dict.get("urls", []) + generic_dict.get("urls", [])))
            results_dict["vulns"] += generic_dict.get("vulns", [])

        # Map to Pydantic models for consistency and validation
        techs = []
        for t in results_dict.get("technologies", []):
            if 'type' in t and 'category' not in t:
                t['category'] = t.pop('type')
            try:
                techs.append(TechnologyModel(**t))
            except Exception:
                continue

        return ScanResultModel(
            target=target,
            tool_name=tool_name,
            ports=[PortModel(**p) for p in results_dict.get("ports", [])],
            vulns=[VulnerabilityModel(**v) for v in results_dict.get("vulns", [])],
            urls=results_dict.get("urls", []),
            technologies=techs,
            os_info=results_dict.get("os_info", {}),
            sessions=results_dict.get("sessions", []),
            dns_info=results_dict.get("dns_info", {}),
            osint_info=results_dict.get("osint_info", {})
        )

# Global registry instance
registry = ParserRegistry()
