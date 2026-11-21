"""Shared fixtures for the test suite (no third-party dependencies)."""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from sentinel.audit import AuditLog
from sentinel.collectors import CommandResult, LocalFacts
from sentinel.scope import Scope, ScopeGuard


def scope_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": "sentinel.scope/1",
        "engagement_id": "TEST-ENGAGEMENT",
        "client": "test",
        "operator": "tester",
        "authorization": {
            "authorized": True,
            "reference": "TEST-AUTH-1",
            "approved_by": "test suite",
        },
        "valid_from": "2020-01-01T00:00:00Z",
        "expires_at": "2999-01-01T00:00:00Z",
        "targets": [{"kind": "host", "value": "127.0.0.1", "ports": [18080], "max_tier": 2}],
        "max_requests": 100,
        "rate_per_second": 1000,
        "burst": 100,
    }
    base.update(overrides)
    return base


def write_scope(directory: str, data: dict[str, Any], name: str = "scope.json") -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def make_guard(directory: str, **overrides: Any) -> tuple[Scope, AuditLog, ScopeGuard]:
    scope = Scope.from_dict(scope_dict(**overrides))
    audit = AuditLog(os.path.join(directory, "audit.jsonl"), scope.engagement_id, scope.operator)
    return scope, audit, ScopeGuard(scope, audit)


# ------------------------------------------------------------------- servers
class WeakHandler(BaseHTTPRequestHandler):
    """Deliberately weak HTTP server: version disclosure, no headers, bad cookie."""

    server_version = "Apache/2.4.49 (Debian)"
    sys_version = ""

    def _respond(self, body: bool) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        payload = b"<html><body>ok</body></html>"
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if body:
            self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        self._respond(True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._respond(False)

    def log_message(self, *args: Any) -> None:  # silence test output
        pass


class HardenedHandler(WeakHandler):
    server_version = "nginx"
    sys_version = ""

    def _respond(self, body: bool) -> None:
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Set-Cookie", "sessionid=0123456789abcdef0123456789abcdef; Secure; HttpOnly; SameSite=Lax")
        self.send_header("Content-Length", "0")
        self.end_headers()


class _ServerHandle:
    def __init__(self, server: ThreadingHTTPServer, thread: threading.Thread, tls: bool) -> None:
        self.server = server
        self.thread = thread
        self.port = server.server_address[1]
        self.tls = tls

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def start_http_server(handler: type[BaseHTTPRequestHandler] = WeakHandler,
                      certfile: str | None = None, keyfile: str | None = None) -> _ServerHandle:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    tls = False
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        tls = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    return _ServerHandle(server, thread, tls)


def make_self_signed_cert(directory: str) -> tuple[str, str] | None:
    """Generate a throwaway certificate with the system openssl, if available."""
    cert = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
             "-days", "2", "-nodes", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return cert, key


class BannerServer:
    """Fake SSH server: sends a greeting and closes. No protocol implementation."""

    def __init__(self, banner: bytes = b"SSH-2.0-OpenSSH_8.2p1 Debian-4\r\n") -> None:
        import socket

        self.banner = banner
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (OSError, ssl.SSLError):
                continue
            try:
                conn.sendall(self.banner)
            except OSError:
                pass
            finally:
                conn.close()

    def stop(self) -> None:
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


def closed_port() -> int:
    """Return a TCP port that is very likely closed (bind then release)."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# --------------------------------------------------------------------- facts
def make_facts(**overrides: Any) -> LocalFacts:
    facts = LocalFacts(host="test-host")
    facts.identity = {"user": "analyst", "euid": 1000, "group_ids": [1000], "id_output": "uid=1000(analyst)"}
    facts.os = {"PRETTY_NAME": "Debian GNU/Linux 12 (bookworm)", "kernel_release": "6.1.0"}
    facts.files = {
        "os_release": "",
        "passwd": "root:x:0:0:root:/root:/bin/bash\nanalyst:x:1000:1000::/home/analyst:/bin/bash\n",
        "sshd_config": None,
        "login_defs": None,
        "pam_common_password": None,
        "pwquality": None,
        "sudoers": None,
    }
    facts.permissions = {}
    facts.accounts = [
        {"name": "root", "uid": 0, "gid": 0, "shell": "/bin/bash", "is_system": False, "is_root": True,
         "login_shell": True},
        {"name": "analyst", "uid": 1000, "gid": 1000, "shell": "/bin/bash", "is_system": False,
         "is_root": False, "login_shell": True},
    ]
    facts.sudo = CommandResult(argv=["sudo", "-n", "-l"], ok=False, exit_code=1, stdout="", stderr="")
    facts.suid = {"available": True, "paths": [], "scanned_roots": ["/usr/bin"]}
    facts.capabilities = {"available": True, "entries": []}
    facts.cron = []
    facts.path_dirs = []
    facts.systemd_units = []
    for key, value in overrides.items():
        setattr(facts, key, value)
    return facts


def sudo_result(text: str) -> CommandResult:
    return CommandResult(argv=["sudo", "-n", "-l"], ok=True, exit_code=0, stdout=text, stderr="")


SSHD_WEAK = """\
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
PermitEmptyPasswords yes
PasswordAuthentication yes
X11Forwarding yes
MaxAuthTries 6
"""

SSHD_HARD = """\
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
X11Forwarding no
MaxAuthTries 3
AllowGroups ssh-operators
LogLevel VERBOSE
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256
"""


def tempdir() -> str:
    return tempfile.mkdtemp(prefix="sentinel-test-")
