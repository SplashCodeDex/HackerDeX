# Session Store - Universal Session Management for HackerDeX C2 Core
# Handles sessions from all 55+ tools: SQLMap, Hydra, Metasploit, Phishing, RATs, etc.

import json
import os
import uuid
import threading
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


class SessionType(Enum):
    """Universal session types across all tools."""
    REVERSE_SHELL = "reverse_shell"     # Target connects back to attacker
    BIND_SHELL = "bind_shell"           # Attacker connects to open port on target
    DB_SHELL = "db_shell"               # SQL command execution (e.g., SQLMap os-shell)
    WEB_SHELL = "web_shell"             # HTTP-based command execution
    METERPRETER = "meterpreter"         # Metasploit agent
    SSH = "ssh"                         # SSH credential-based access
    RDP = "rdp"                         # RDP credential-based access
    CREDENTIAL = "credential"           # Captured username/password (not yet an active session)
    SESSION_COOKIE = "session_cookie"   # Captured auth cookie (e.g., from Evilginx2)
    MITM_SESSION = "mitm_session"       # Active ARP spoof / network interception
    ROGUE_AP = "rogue_ap"               # Active fake access point
    PERSISTENCE = "persistence"         # Installed backdoor / cron job
    CUSTOM = "custom"                   # Other/custom session types


class SessionStatus(Enum):
    """Session lifecycle states."""
    ACTIVE = "active"           # Live, interactive
    DORMANT = "dormant"         # Implant installed, not currently connected
    DEAD = "dead"               # Connection lost / target rebooted
    PENDING = "pending"         # Credential captured, not yet converted to active session


@dataclass
class Session:
    """Universal session container for all tool types."""

    # Core Identity
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    session_type: SessionType = SessionType.REVERSE_SHELL
    status: SessionStatus = SessionStatus.PENDING

    # Target Information
    target_ip: str = ""
    target_port: int = 0
    target_hostname: Optional[str] = None
    target_os: Optional[str] = None  # "Linux", "Windows", "macOS"

    # Access Information
    protocol: str = "tcp"               # tcp, http, ssh, rdp, dns, icmp
    username: Optional[str] = None      # For credential/ssh/rdp sessions
    password: Optional[str] = None      # For credential sessions
    cookie: Optional[str] = None        # For session_cookie sessions
    shell_prompt: Optional[str] = None  # e.g., "os-shell>" for SQLMap

    # Origin / Context
    source_tool: str = ""               # e.g., "sqlmap", "hydra", "setoolkit"
    vuln_id: Optional[str] = None       # Link to VulnStore entry that led to this session

    # Capabilities
    capabilities: List[str] = field(default_factory=list)
    # Examples: ["command_exec", "file_upload", "file_download", "screenshot", "pivot", "keylog"]

    # Listener Information (for reverse shells)
    listener_ip: Optional[str] = None   # Attacker's listener IP
    listener_port: Optional[int] = None

    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())

    # Raw Data (for debugging/advanced use)
    raw_output: Optional[str] = None    # The tool output that triggered session creation
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert session to JSON-serializable dictionary."""
        data = asdict(self)
        data['session_type'] = self.session_type.value
        data['status'] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> 'Session':
        """Reconstruct session from dictionary."""
        data['session_type'] = SessionType(data.get('session_type', 'reverse_shell'))
        data['status'] = SessionStatus(data.get('status', 'pending'))
        return cls(**data)

    def touch(self):
        """Update last_activity timestamp."""
        self.last_activity = datetime.now().isoformat()

    def upgrade_to_active(self):
        """Upgrade a pending credential to an active session."""
        self.status = SessionStatus.ACTIVE
        self.touch()

    def mark_dead(self):
        """Mark session as dead (connection lost)."""
        self.status = SessionStatus.DEAD
        self.touch()


class SessionStore:
    """
    Singleton session store for managing all active/pending sessions.
    Thread-safe with JSON persistence.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._sessions: Dict[str, Session] = {}
        self._listeners: Dict[int, dict] = {}  # port -> listener info
        self._store_path = os.path.join(os.path.dirname(__file__), 'session_data.json')
        self._load()
        self._initialized = True

    def _load(self):
        """Load sessions from persistent storage."""
        if os.path.exists(self._store_path):
            try:
                with open(self._store_path, 'r') as f:
                    data = json.load(f)
                for sid, sdata in data.get('sessions', {}).items():
                    self._sessions[sid] = Session.from_dict(sdata)
                self._listeners = data.get('listeners', {})
            except Exception as e:
                print(f"[SessionStore] Failed to load: {e}")

    def _save(self):
        """Persist sessions to JSON file."""
        with self._lock:
            data = {
                'sessions': {sid: s.to_dict() for sid, s in self._sessions.items()},
                'listeners': self._listeners
            }
            with open(self._store_path, 'w') as f:
                json.dump(data, f, indent=2)

    # ==================== SESSION MANAGEMENT ====================

    def add_session(self, session: Session) -> str:
        """Add a new session to the store."""
        with self._lock:
            self._sessions[session.session_id] = session
        self._save()
        return session.session_id

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        return self._sessions.get(session_id)

    def list_sessions(self,
                      status: Optional[SessionStatus] = None,
                      session_type: Optional[SessionType] = None,
                      target_ip: Optional[str] = None) -> List[Session]:
        """List sessions with optional filters."""
        results = list(self._sessions.values())

        if status:
            results = [s for s in results if s.status == status]
        if session_type:
            results = [s for s in results if s.session_type == session_type]
        if target_ip:
            results = [s for s in results if s.target_ip == target_ip]

        return sorted(results, key=lambda s: s.created_at, reverse=True)

    def update_session(self, session_id: str, **updates) -> bool:
        """Update session attributes."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        with self._lock:
            for key, value in updates.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            session.touch()

        self._save()
        return True

    def remove_session(self, session_id: str) -> bool:
        """Remove a session from the store."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                self._save()
                return True
        return False

    def clear_dead_sessions(self):
        """Remove all dead sessions."""
        with self._lock:
            dead = [sid for sid, s in self._sessions.items() if s.status == SessionStatus.DEAD]
            for sid in dead:
                del self._sessions[sid]
        self._save()

    # ==================== LISTENER MANAGEMENT ====================

    def register_listener(self, port: int, listener_type: str = "tcp",
                          callback_ip: str = "0.0.0.0") -> bool:
        """Register a listener port."""
        with self._lock:
            if port in self._listeners:
                return False
            self._listeners[port] = {
                'type': listener_type,
                'callback_ip': callback_ip,
                'started_at': datetime.now().isoformat(),
                'status': 'running'
            }
        self._save()
        return True

    def unregister_listener(self, port: int) -> bool:
        """Unregister a listener port."""
        with self._lock:
            if port in self._listeners:
                del self._listeners[port]
                self._save()
                return True
        return False

    def list_listeners(self) -> Dict[int, dict]:
        """List all registered listeners."""
        return dict(self._listeners)

    # ==================== QUICK SESSION FACTORIES ====================

    @staticmethod
    def create_credential_session(target_ip: str, username: str, password: str,
                                   source_tool: str, protocol: str = "ssh",
                                   target_port: int = 22) -> Session:
        """Factory for credential-based sessions (Hydra, Fastssh, Phishing)."""
        return Session(
            session_type=SessionType.CREDENTIAL,
            status=SessionStatus.PENDING,
            target_ip=target_ip,
            target_port=target_port,
            protocol=protocol,
            username=username,
            password=password,
            source_tool=source_tool,
            capabilities=["credential"]
        )

    @staticmethod
    def create_shell_session(target_ip: str, session_type: SessionType,
                             source_tool: str, listener_port: int,
                             target_os: Optional[str] = None) -> Session:
        """Factory for shell-based sessions (SQLMap, Netcat, Meterpreter)."""
        caps = ["command_exec"]
        if session_type == SessionType.METERPRETER:
            caps.extend(["file_upload", "file_download", "screenshot", "pivot", "keylog"])
        elif session_type == SessionType.DB_SHELL:
            caps.extend(["db_query", "file_read"])

        return Session(
            session_type=session_type,
            status=SessionStatus.ACTIVE,
            target_ip=target_ip,
            source_tool=source_tool,
            listener_port=listener_port,
            target_os=target_os,
            capabilities=caps
        )

    @staticmethod
    def create_cookie_session(target_ip: str, cookie: str, source_tool: str,
                              target_hostname: Optional[str] = None) -> Session:
        """Factory for session cookie capture (Evilginx2)."""
        return Session(
            session_type=SessionType.SESSION_COOKIE,
            status=SessionStatus.ACTIVE,
            target_ip=target_ip,
            target_hostname=target_hostname,
            cookie=cookie,
            source_tool=source_tool,
            protocol="https",
            capabilities=["session_hijack"]
        )

    # ==================== SUMMARY / STATS ====================

    def get_summary(self) -> dict:
        """Get session store summary for UI/reports."""
        sessions = list(self._sessions.values())
        return {
            'total_sessions': len(sessions),
            'active': len([s for s in sessions if s.status == SessionStatus.ACTIVE]),
            'pending': len([s for s in sessions if s.status == SessionStatus.PENDING]),
            'dormant': len([s for s in sessions if s.status == SessionStatus.DORMANT]),
            'dead': len([s for s in sessions if s.status == SessionStatus.DEAD]),
            'by_type': {t.value: len([s for s in sessions if s.session_type == t])
                        for t in SessionType if any(s.session_type == t for s in sessions)},
            'listeners': len(self._listeners)
        }


# Singleton accessor
def get_session_store() -> SessionStore:
    """Get the global SessionStore instance."""
    return SessionStore()


# ==================== CLI TESTING ====================
if __name__ == "__main__":
    store = get_session_store()

    # Test: Add a credential session
    cred_session = SessionStore.create_credential_session(
        target_ip="192.168.1.100",
        username="admin",
        password="password123",
        source_tool="hydra"
    )
    sid = store.add_session(cred_session)
    print(f"[+] Created credential session: {sid}")

    # Test: Add a shell session
    shell_session = SessionStore.create_shell_session(
        target_ip="192.168.1.100",
        session_type=SessionType.DB_SHELL,
        source_tool="sqlmap",
        listener_port=4444,
        target_os="Linux"
    )
    sid2 = store.add_session(shell_session)
    print(f"[+] Created shell session: {sid2}")

    # Test: List and summary
    print(f"\n[*] Summary: {store.get_summary()}")
    print(f"[*] Active sessions: {[s.session_id for s in store.list_sessions(status=SessionStatus.ACTIVE)]}")
