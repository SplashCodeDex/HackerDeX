# Session Parsers - Auto-detect session creation from tool output
# Each parser analyzes tool output and returns Session objects when detected

import re
from typing import Optional, List
from session_store import Session, SessionType, SessionStatus, get_session_store


class BaseSessionParser:
    """Base class for session detection parsers."""

    TOOL_NAME = "unknown"

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        """
        Parse tool output and return detected sessions.
        Override in subclasses or return empty list.
        """
        # Default implementation: return empty list (no sessions detected)
        return []


class SQLMapParser(BaseSessionParser):
    """
    Parser for SQLMap output.
    Detects: os-shell, sql-shell, file-read capabilities
    """

    TOOL_NAME = "sqlmap"

    # Patterns for SQLMap session detection
    PATTERNS = {
        'os_shell': re.compile(r'os-shell>', re.IGNORECASE),
        'sql_shell': re.compile(r'sql-shell>', re.IGNORECASE),
        'dbms_info': re.compile(r'\[INFO\] the back-end DBMS is (\w+)', re.IGNORECASE),
        'os_info': re.compile(r'\[INFO\] the back-end DBMS operating system is (\w+)', re.IGNORECASE),
        'file_read': re.compile(r'\[INFO\] retrieved: (.+)', re.IGNORECASE),
        'injectable': re.compile(r'Parameter: (.+) \((.+)\)'),
    }

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        sessions = []

        # Detect os-shell (command execution on DB server)
        if self.PATTERNS['os_shell'].search(output):
            session = Session(
                session_type=SessionType.DB_SHELL,
                status=SessionStatus.ACTIVE,
                target_ip=target_ip,
                source_tool=self.TOOL_NAME,
                shell_prompt="os-shell>",
                vuln_id=vuln_id,
                capabilities=["command_exec", "file_read", "file_write"],
                raw_output=output[-2000:],  # Last 2KB for debugging
            )

            # Extract OS info if available
            os_match = self.PATTERNS['os_info'].search(output)
            if os_match:
                session.target_os = os_match.group(1)

            # Extract DBMS info
            dbms_match = self.PATTERNS['dbms_info'].search(output)
            if dbms_match:
                session.metadata['dbms'] = dbms_match.group(1)

            sessions.append(session)

        # Detect sql-shell (SQL query access only)
        elif self.PATTERNS['sql_shell'].search(output):
            session = Session(
                session_type=SessionType.DB_SHELL,
                status=SessionStatus.ACTIVE,
                target_ip=target_ip,
                source_tool=self.TOOL_NAME,
                shell_prompt="sql-shell>",
                vuln_id=vuln_id,
                capabilities=["db_query"],
                raw_output=output[-2000:],
            )
            sessions.append(session)

        return sessions


class HydraParser(BaseSessionParser):
    """
    Parser for Hydra/THC-Hydra output.
    Detects: SSH, FTP, RDP, SMB, HTTP credentials
    """

    TOOL_NAME = "hydra"

    # Hydra success pattern: [22][ssh] host: 192.168.1.1 login: admin password: secret
    CREDENTIAL_PATTERN = re.compile(
        r'\[(\d+)\]\[(\w+)\]\s+host:\s+([^\s]+)\s+login:\s+([^\s]+)\s+password:\s+(.+)',
        re.IGNORECASE
    )

    # Map protocol names to SessionTypes and default ports
    PROTOCOL_MAP = {
        'ssh': (SessionType.SSH, 22),
        'ftp': (SessionType.CREDENTIAL, 21),
        'rdp': (SessionType.RDP, 3389),
        'smb': (SessionType.CREDENTIAL, 445),
        'http-get': (SessionType.CREDENTIAL, 80),
        'http-post': (SessionType.CREDENTIAL, 80),
        'https-get': (SessionType.CREDENTIAL, 443),
        'mysql': (SessionType.DB_SHELL, 3306),
        'postgres': (SessionType.DB_SHELL, 5432),
        'mssql': (SessionType.DB_SHELL, 1433),
        'telnet': (SessionType.CREDENTIAL, 23),
        'vnc': (SessionType.CREDENTIAL, 5900),
    }

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        sessions = []

        for match in self.CREDENTIAL_PATTERN.finditer(output):
            port = int(match.group(1))
            protocol = match.group(2).lower()
            host = match.group(3)
            username = match.group(4)
            password = match.group(5).strip()

            # Determine session type based on protocol
            session_type, default_port = self.PROTOCOL_MAP.get(protocol, (SessionType.CREDENTIAL, port))

            session = Session(
                session_type=session_type,
                status=SessionStatus.PENDING,  # Needs to be converted to active session
                target_ip=host,
                target_port=port or default_port,
                protocol=protocol,
                username=username,
                password=password,
                source_tool=self.TOOL_NAME,
                vuln_id=vuln_id,
                capabilities=["credential"],
                raw_output=match.group(0),
            )
            sessions.append(session)

        return sessions


class FastsshParser(BaseSessionParser):
    """
    Parser for Fastssh output (SSH brute-force tool).
    Similar to Hydra but different output format.
    """

    TOOL_NAME = "fastssh"

    # Pattern: [+] FOUND: admin:password123@192.168.1.100
    CREDENTIAL_PATTERN = re.compile(
        r'\[\+\]\s*FOUND[:\s]+([^:]+):([^@]+)@([^\s]+)',
        re.IGNORECASE
    )

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        sessions = []

        for match in self.CREDENTIAL_PATTERN.finditer(output):
            username = match.group(1).strip()
            password = match.group(2).strip()
            host = match.group(3).strip()

            session = Session(
                session_type=SessionType.SSH,
                status=SessionStatus.PENDING,
                target_ip=host,
                target_port=22,
                protocol="ssh",
                username=username,
                password=password,
                source_tool=self.TOOL_NAME,
                vuln_id=vuln_id,
                capabilities=["credential"],
                raw_output=match.group(0),
            )
            sessions.append(session)

        return sessions


class PhishingCredentialParser(BaseSessionParser):
    """
    Generic parser for phishing tool credential captures.
    Works with: Setoolkit, SocialFish, ShellPhish, HiddenEye
    """

    TOOL_NAME = "phishing"

    # Common patterns for credential capture in phishing tools
    PATTERNS = [
        # Username/password in logs
        re.compile(r'(?:username|user|email|login)[:\s]+([^\s,]+)[,\s]+(?:password|pass|pwd)[:\s]+([^\s,]+)', re.IGNORECASE),
        # JSON format
        re.compile(r'"(?:username|email)"[:\s]*"([^"]+)"[,\s]+"password"[:\s]*"([^"]+)"', re.IGNORECASE),
        # Key=value format
        re.compile(r'(?:email|user)=([^&\s]+)&(?:pass|password)=([^&\s]+)', re.IGNORECASE),
    ]

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        sessions = []
        seen = set()  # Avoid duplicates

        for pattern in self.PATTERNS:
            for match in pattern.finditer(output):
                username = match.group(1).strip()
                password = match.group(2).strip()

                # Skip duplicates
                key = f"{username}:{password}"
                if key in seen:
                    continue
                seen.add(key)

                session = Session(
                    session_type=SessionType.CREDENTIAL,
                    status=SessionStatus.PENDING,
                    target_ip=target_ip or "unknown",
                    protocol="https",
                    username=username,
                    password=password,
                    source_tool=self.TOOL_NAME,
                    vuln_id=vuln_id,
                    capabilities=["credential", "social_engineering"],
                    raw_output=match.group(0),
                )
                sessions.append(session)

        return sessions


class Evilginx2Parser(BaseSessionParser):
    """
    Parser for Evilginx2 output (phishing with session cookie capture).
    """

    TOOL_NAME = "evilginx2"

    # Pattern for phished session
    SESSION_PATTERN = re.compile(
        r'\[\*\]\s*(?:Phished|Captured)\s+session\s+from\s+([^\s]+)',
        re.IGNORECASE
    )

    # Cookie capture pattern
    COOKIE_PATTERN = re.compile(
        r'cookies?[:\s]+(\[.+\]|{.+})',
        re.IGNORECASE | re.DOTALL
    )

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        sessions = []

        session_matches = self.SESSION_PATTERN.finditer(output)
        for match in session_matches:
            victim_ip = match.group(1)

            # Try to extract cookies
            cookie = None
            cookie_match = self.COOKIE_PATTERN.search(output)
            if cookie_match:
                cookie = cookie_match.group(1)

            session = Session(
                session_type=SessionType.SESSION_COOKIE,
                status=SessionStatus.ACTIVE,
                target_ip=victim_ip,
                cookie=cookie,
                source_tool=self.TOOL_NAME,
                vuln_id=vuln_id,
                protocol="https",
                capabilities=["session_hijack", "cookie"],
                raw_output=output[-2000:],
            )
            sessions.append(session)

        return sessions


class NetcatReverseShellParser(BaseSessionParser):
    """
    Parser for detecting reverse shell connections via Netcat/nc.
    """

    TOOL_NAME = "netcat"

    # Patterns indicating shell connection
    SHELL_INDICATORS = [
        re.compile(r'Connection\s+(?:from|received)', re.IGNORECASE),
        re.compile(r'connect to.*from', re.IGNORECASE),
        re.compile(r'\$\s*$'),  # Shell prompt
        re.compile(r'#\s*$'),   # Root shell prompt
        re.compile(r'bash-[\d.]+[$#]'),  # Bash prompt
        re.compile(r'sh-[\d.]+[$#]'),    # sh prompt
    ]

    # Extract connection info
    CONNECTION_PATTERN = re.compile(
        r'(?:Connection|connect).*?(\d+\.\d+\.\d+\.\d+)',
        re.IGNORECASE
    )

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        sessions = []

        # Check for shell indicators
        shell_detected = any(p.search(output) for p in self.SHELL_INDICATORS)

        if shell_detected:
            # Try to extract connecting IP
            conn_match = self.CONNECTION_PATTERN.search(output)
            connected_ip = conn_match.group(1) if conn_match else target_ip

            # Determine if root based on prompt
            is_root = '#' in output[-50:] or 'root@' in output.lower()

            session = Session(
                session_type=SessionType.REVERSE_SHELL,
                status=SessionStatus.ACTIVE,
                target_ip=connected_ip,
                source_tool=self.TOOL_NAME,
                vuln_id=vuln_id,
                target_os="Linux" if any(x in output.lower() for x in ['bash', 'sh', 'linux']) else None,
                capabilities=["command_exec", "file_upload" if is_root else "command_exec"],
                metadata={'is_root': is_root},
                raw_output=output[-2000:],
            )
            sessions.append(session)

        return sessions


class MeterpreterParser(BaseSessionParser):
    """
    Parser for Metasploit Meterpreter session output.
    """

    TOOL_NAME = "metasploit"

    # Meterpreter session opened pattern
    SESSION_PATTERN = re.compile(
        r'Meterpreter session (\d+) opened \(([^)]+)\)',
        re.IGNORECASE
    )

    # Session info pattern: 192.168.1.100:4444 -> 192.168.1.50:49812
    CONNECTION_PATTERN = re.compile(
        r'(\d+\.\d+\.\d+\.\d+):(\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)'
    )

    def parse(self, output: str, target_ip: str = "", vuln_id: str = "") -> List[Session]:
        sessions = []

        for match in self.SESSION_PATTERN.finditer(output):
            session_num = match.group(1)
            connection_info = match.group(2)

            # Parse connection info
            listener_ip = listener_port = victim_ip = None
            conn_match = self.CONNECTION_PATTERN.search(connection_info)
            if conn_match:
                listener_ip = conn_match.group(1)
                listener_port = int(conn_match.group(2))
                victim_ip = conn_match.group(3)

            session = Session(
                session_type=SessionType.METERPRETER,
                status=SessionStatus.ACTIVE,
                target_ip=victim_ip or target_ip,
                source_tool=self.TOOL_NAME,
                listener_ip=listener_ip,
                listener_port=listener_port,
                vuln_id=vuln_id,
                capabilities=[
                    "command_exec", "file_upload", "file_download",
                    "screenshot", "keylog", "pivot", "hashdump"
                ],
                metadata={'msf_session_id': session_num},
                raw_output=output[-2000:],
            )
            sessions.append(session)

        return sessions


# ==================== PARSER REGISTRY ====================

class SessionParserRegistry:
    """
    Registry for all session parsers.
    Auto-detects session creation by running output through all parsers.
    """

    PARSERS = [
        SQLMapParser(),
        HydraParser(),
        FastsshParser(),
        PhishingCredentialParser(),
        Evilginx2Parser(),
        NetcatReverseShellParser(),
        MeterpreterParser(),
    ]

    @classmethod
    def parse_output(cls, tool_name: str, output: str,
                     target_ip: str = "", vuln_id: str = "") -> List[Session]:
        """
        Run output through appropriate parser(s) and return detected sessions.
        If tool_name matches a parser, use that parser. Otherwise, try all.
        """
        sessions = []

        # Find matching parser
        tool_name_lower = tool_name.lower()
        matched_parsers = [p for p in cls.PARSERS if p.TOOL_NAME in tool_name_lower]

        # If no specific match, try all parsers
        parsers_to_use = matched_parsers if matched_parsers else cls.PARSERS

        for parser in parsers_to_use:
            try:
                detected = parser.parse(output, target_ip, vuln_id)
                sessions.extend(detected)
            except Exception as e:
                print(f"[SessionParser] {parser.TOOL_NAME} error: {e}")

        return sessions

    @classmethod
    def auto_detect_and_store(cls, tool_name: str, output: str,
                               target_ip: str = "", vuln_id: str = "") -> List[str]:
        """
        Parse output, auto-detect sessions, and store them.
        Returns list of created session IDs.
        """
        sessions = cls.parse_output(tool_name, output, target_ip, vuln_id)
        store = get_session_store()

        created_ids = []
        for session in sessions:
            sid = store.add_session(session)
            created_ids.append(sid)
            print(f"[+] Session detected: {session.session_type.value} from {tool_name} -> {sid}")

        return created_ids


# ==================== CLI TESTING ====================
if __name__ == "__main__":
    # Test SQLMap parser
    sqlmap_output = """
[INFO] the back-end DBMS is MySQL
[INFO] the back-end DBMS operating system is Linux
[INFO] testing direct connection to the target URL
os-shell> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
os-shell>
"""

    sessions = SessionParserRegistry.auto_detect_and_store("sqlmap", sqlmap_output, "192.168.1.100")
    print(f"[*] SQLMap test: {len(sessions)} sessions detected")

    # Test Hydra parser
    hydra_output = """
Hydra v9.0 (c) 2019 by van Hauser/THC
[22][ssh] host: 192.168.1.50 login: admin password: secret123
[22][ssh] host: 192.168.1.51 login: root password: toor
"""

    sessions = SessionParserRegistry.auto_detect_and_store("hydra", hydra_output)
    print(f"[*] Hydra test: {len(sessions)} sessions detected")

    # Show store summary
    from session_store import get_session_store
    store = get_session_store()
    print(f"\n[*] Store summary: {store.get_summary()}")
