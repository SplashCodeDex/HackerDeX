# Listener Manager - Multi-protocol listener hub for HackerDeX C2 Core
# Manages TCP, HTTP, and DNS listeners for catching reverse shells

import socket
import threading
import select
import time
from typing import Dict, Callable, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from session_store import (
    Session, SessionType, SessionStatus,
    get_session_store, SessionStore
)


@dataclass
class ListenerConfig:
    """Configuration for a listener."""
    port: int
    protocol: str = "tcp"           # tcp, http, dns
    bind_ip: str = "0.0.0.0"
    handler: Optional[str] = None   # "raw", "http", "meterpreter"
    auto_session: bool = True       # Auto-create session on connection
    timeout: int = 300              # Connection timeout in seconds


@dataclass
class ActiveConnection:
    """Represents an active connection to a listener."""
    conn_id: str
    client_socket: socket.socket
    client_ip: str
    client_port: int
    listener_port: int
    connected_at: datetime = field(default_factory=datetime.now)
    session_id: Optional[str] = None
    buffer: bytes = b""


class TCPListener:
    """
    Raw TCP listener for catching reverse shells.
    Supports multiple simultaneous connections.
    """

    def __init__(self, config: ListenerConfig, on_connection: Callable = None):
        self.config = config
        self.on_connection = on_connection
        self.server_socket: Optional[socket.socket] = None
        self.connections: Dict[str, ActiveConnection] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self) -> bool:
        """Start the listener."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.bind_ip, self.config.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)  # For clean shutdown

            self.running = True
            self._thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._thread.start()

            print(f"[+] TCP Listener started on {self.config.bind_ip}:{self.config.port}")
            return True
        except Exception as e:
            print(f"[-] Failed to start listener on port {self.config.port}: {e}")
            return False

    def stop(self):
        """Stop the listener and close all connections."""
        self.running = False

        with self._lock:
            for conn in self.connections.values():
                try:
                    conn.client_socket.close()
                except:
                    pass
            self.connections.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        print(f"[-] TCP Listener on port {self.config.port} stopped")

    def _accept_loop(self):
        """Main accept loop for incoming connections."""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_ip, client_port = addr

                conn_id = f"{client_ip}:{client_port}:{int(time.time())}"
                connection = ActiveConnection(
                    conn_id=conn_id,
                    client_socket=client_socket,
                    client_ip=client_ip,
                    client_port=client_port,
                    listener_port=self.config.port
                )

                with self._lock:
                    self.connections[conn_id] = connection

                print(f"[+] Connection received from {client_ip}:{client_port} on port {self.config.port}")

                # Auto-create session if enabled
                if self.config.auto_session:
                    session = Session(
                        session_type=SessionType.REVERSE_SHELL,
                        status=SessionStatus.ACTIVE,
                        target_ip=client_ip,
                        target_port=client_port,
                        listener_port=self.config.port,
                        source_tool="listener",
                        capabilities=["command_exec"],
                    )
                    store = get_session_store()
                    sid = store.add_session(session)
                    connection.session_id = sid
                    print(f"[+] Session created: {sid}")

                # Notify callback if set
                if self.on_connection:
                    self.on_connection(connection)

                # Start handler thread for this connection
                handler_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(conn_id,),
                    daemon=True
                )
                handler_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[-] Accept error: {e}")

    def _handle_connection(self, conn_id: str):
        """Handle a single connection."""
        connection = self.connections.get(conn_id)
        if not connection:
            return

        connection.client_socket.settimeout(self.config.timeout)

        try:
            while self.running:
                ready = select.select([connection.client_socket], [], [], 1.0)
                if ready[0]:
                    data = connection.client_socket.recv(4096)
                    if not data:
                        break
                    connection.buffer += data

                    # Update session last_activity
                    if connection.session_id:
                        store = get_session_store()
                        store.update_session(connection.session_id,
                                           last_activity=datetime.now().isoformat())
        except socket.timeout:
            print(f"[-] Connection {conn_id} timed out")
        except Exception as e:
            print(f"[-] Connection error {conn_id}: {e}")
        finally:
            self._cleanup_connection(conn_id)

    def _cleanup_connection(self, conn_id: str):
        """Clean up a closed connection."""
        with self._lock:
            connection = self.connections.pop(conn_id, None)

        if connection:
            try:
                connection.client_socket.close()
            except:
                pass

            # Mark session as dead
            if connection.session_id:
                store = get_session_store()
                store.update_session(connection.session_id, status=SessionStatus.DEAD)

            print(f"[-] Connection {conn_id} closed")

    def send_command(self, conn_id: str, command: str) -> bool:
        """Send a command to a specific connection."""
        connection = self.connections.get(conn_id)
        if not connection:
            return False

        try:
            connection.client_socket.sendall((command + "\n").encode())
            return True
        except Exception as e:
            print(f"[-] Send error: {e}")
            return False

    def get_output(self, conn_id: str, clear: bool = True) -> str:
        """Get buffered output from a connection."""
        connection = self.connections.get(conn_id)
        if not connection:
            return ""

        output = connection.buffer.decode('utf-8', errors='ignore')
        if clear:
            connection.buffer = b""
        return output


class ListenerManager:
    """
    Manages multiple listeners across protocols.
    Singleton pattern for global access.
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
        if getattr(self, '_initialized', False):
            return

        self.listeners: Dict[int, TCPListener] = {}
        self._initialized = True

    def start_listener(self, port: int, protocol: str = "tcp",
                       bind_ip: str = "0.0.0.0",
                       on_connection: Callable = None) -> bool:
        """Start a new listener on the specified port."""
        if port in self.listeners:
            print(f"[-] Listener already running on port {port}")
            return False

        config = ListenerConfig(
            port=port,
            protocol=protocol,
            bind_ip=bind_ip
        )

        if protocol == "tcp":
            listener = TCPListener(config, on_connection)
            if listener.start():
                self.listeners[port] = listener

                # Register in session store
                store = get_session_store()
                store.register_listener(port, protocol, bind_ip)
                return True
        else:
            print(f"[-] Protocol '{protocol}' not yet implemented")

        return False

    def stop_listener(self, port: int) -> bool:
        """Stop a listener on the specified port."""
        listener = self.listeners.pop(port, None)
        if listener:
            listener.stop()

            store = get_session_store()
            store.unregister_listener(port)
            return True
        return False

    def stop_all(self):
        """Stop all active listeners."""
        for port in list(self.listeners.keys()):
            self.stop_listener(port)

    def list_listeners(self) -> List[dict]:
        """List all active listeners."""
        result = []
        for port, listener in self.listeners.items():
            result.append({
                'port': port,
                'protocol': listener.config.protocol,
                'bind_ip': listener.config.bind_ip,
                'connections': len(listener.connections)
            })
        return result

    def get_connections(self, port: int) -> List[dict]:
        """Get active connections for a listener."""
        listener = self.listeners.get(port)
        if not listener:
            return []

        return [
            {
                'conn_id': c.conn_id,
                'client_ip': c.client_ip,
                'client_port': c.client_port,
                'session_id': c.session_id,
                'connected_at': c.connected_at.isoformat()
            }
            for c in listener.connections.values()
        ]

    def send_to_session(self, session_id: str, command: str) -> bool:
        """Send a command to a session by session ID."""
        for listener in self.listeners.values():
            for conn in listener.connections.values():
                if conn.session_id == session_id:
                    return listener.send_command(conn.conn_id, command)
        return False

    def get_session_output(self, session_id: str, clear: bool = True) -> str:
        """Get output from a session by session ID."""
        for listener in self.listeners.values():
            for conn in listener.connections.values():
                if conn.session_id == session_id:
                    return listener.get_output(conn.conn_id, clear)
        return ""


def get_listener_manager() -> ListenerManager:
    """Get the global ListenerManager instance."""
    return ListenerManager()


# ==================== CLI TESTING ====================
if __name__ == "__main__":
    import sys

    manager = get_listener_manager()

    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 4444

    print(f"[*] Starting listener on port {port}...")

    def on_connect(conn):
        print(f"[CALLBACK] New connection: {conn.client_ip}")

    if manager.start_listener(port, on_connection=on_connect):
        print(f"[*] Listener active. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
                # Print any received data
                for p, listener in manager.listeners.items():
                    for conn_id, conn in list(listener.connections.items()):
                        output = listener.get_output(conn_id, clear=True)
                        if output:
                            print(f"[{conn.client_ip}] {output}")
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            manager.stop_all()
