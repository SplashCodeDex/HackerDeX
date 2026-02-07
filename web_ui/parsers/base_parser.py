from abc import ABC, abstractmethod

class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, tool_name: str) -> bool:
        """Return True if this parser can handle the given tool."""
        pass

    @abstractmethod
    def parse(self, raw_output: str, tool_name: str, target: str) -> dict:
        """
        Parse raw output and return a structured dictionary of findings.
        Returns format: {
            "ports": [{"port": 80, "protocol": "tcp", "service": "http", "version": "..."}],
            "vulns": [{"title": "...", "severity": "high", "details": "...", "url": "..."}],
            "urls": ["http://...", ...],
            "technologies": [{"name": "...", "version": "..."}],
            "os_info": {"name": "...", "version": "..."}
        }
        """
        pass
