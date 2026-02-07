from .nmap_parser import NmapParser
from .sqlmap_parser import SqlmapParser
from .nikto_parser import NiktoParser
from .generic_parser import GenericParser

class ParserRegistry:
    def __init__(self):
        self.parsers = [
            NmapParser(),
            SqlmapParser(),
            NiktoParser(),
        ]
        self.fallback = GenericParser()

    def get_parser(self, tool_name: str):
        for parser in self.parsers:
            if parser.can_parse(tool_name):
                return parser
        return self.fallback

    def parse_output(self, raw_output: str, tool_name: str, target: str):
        parser = self.get_parser(tool_name)

        # Primary parsing
        results = parser.parse(raw_output, tool_name, target)

        # Always run generic parser as well to catch extras, if it's not the primary
        if not isinstance(parser, GenericParser):
            generic_results = self.fallback.parse(raw_output, tool_name, target)
            # Merge (simple dedup for URLs)
            results["urls"] = list(set(results["urls"] + generic_results["urls"]))
            results["vulns"] += generic_results["vulns"]

        return results

# Global registry instance
registry = ParserRegistry()
