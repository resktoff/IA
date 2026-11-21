"""Active discovery and service fingerprinting (Tier 2 / VALIDATE).

Everything here is *bounded and polite*:

* TCP **connect** only — no SYN/half-open scans, no raw sockets, so the scan
  cannot bypass a host firewall's logging and cannot be repurposed as a
  stealth scanner.
* One connection per port, one request per service, no retries.
* Banner reading is passive (whatever the service sends first).  For HTTP we
  send a single ``HEAD``/``GET`` with the ``body`` not read by default, and a
  User-Agent that identifies the engagement.
* Every connection goes through :class:`sentinel.scope.ScopeGuard`, so the port
  must be in the scope allowlist and the rate limiter applies.

Not implemented on purpose: TLS version *downgrade* probing (requires lowering
the OpenSSL security level process-wide), UDP scanning, OS fingerprinting,
service-specific authentication attempts.  See docs/LIMITATIONS.md.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import ssl
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from .errors import ScopeViolation
from .model import Asset, Evidence, Service, Tier
from .scope import ScopeGuard

DEFAULT_TIMEOUT = 2.5
MAX_RESPONSE_HEADER_BYTES = 16_384
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 8888, 3000, 5000, 9000}
TLS_PORTS = {443, 8443, 9443, 4443, 993, 995, 465, 636}

USER_AGENT = "sentinel-agent/0.1 (authorized security assessment; non-destructive)"


# ------------------------------------------------------------------ utilities
def decode_certificate(der: bytes) -> dict[str, Any]:
    """Decode a DER cert without third-party deps, best effort.

    Uses the CPython helper ``_ssl._test_decode_cert`` on a temporary PEM file.
    It is a private API, so failure is handled and reported as ``decoded=False``
    instead of aborting the probe.
    """
    info: dict[str, Any] = {
        "sha256": hashlib.sha256(der).hexdigest(),
        "size_bytes": len(der),
        "decoded": False,
    }
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        try:
            decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            os.unlink(path)
        info["decoded"] = True
        info["subject"] = _flatten_name(decoded.get("subject", []))
        info["issuer"] = _flatten_name(decoded.get("issuer", []))
        info["not_before"] = decoded.get("notBefore")
        info["not_after"] = decoded.get("notAfter")
        info["subject_alt_names"] = [v for k, v in decoded.get("subjectAltName", []) if k == "DNS"][:20]
        info["self_signed"] = bool(info["subject"]) and info["subject"] == info["issuer"]
        info["san_count"] = len(decoded.get("subjectAltName", []))
    except Exception as exc:  # noqa: BLE001 - decoding must never fail the probe
        info["decode_error"] = f"{type(exc).__name__}: {exc}"
    return info


def _flatten_name(name: list) -> str:
    parts: list[str] = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


@dataclass
class ConnectionResult:
    ok: bool
    banner: str | None = None
    error: str | None = None
    duration_ms: int = 0


def _connect(guard: ScopeGuard, host: str, port: int, timeout: float, action: str):
    guard.check(action, host, port, Tier.VALIDATE)
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _read_some(sock, limit: int = 1024) -> bytes:
    try:
        return sock.recv(limit)
    except (socket.timeout, TimeoutError, OSError):
        return b""


def tls_handshake(guard: ScopeGuard, host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                  server_hostname: str | None = None) -> dict[str, Any]:
    """Complete a TLS handshake and record the negotiated parameters.

    Certificate verification is disabled on purpose: the goal is to *observe*
    the certificate the service presents, including invalid ones, not to make a
    trust decision.  This is recorded in the evidence so the report can say so.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    import time

    started = time.monotonic()
    sock = None
    tls_sock = None
    try:
        sock = _connect(guard, host, port, timeout, "tcp_connect:tls")
        tls_sock = context.wrap_socket(sock, server_hostname=server_hostname or host)
        der = tls_sock.getpeercert(binary_form=True)
        cipher = tls_sock.cipher()
        data = {
            "host": host,
            "port": port,
            "protocol": tls_sock.version(),
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "cipher_protocol": cipher[1] if cipher else None,
            "certificate": decode_certificate(der) if der else None,
            "verification": "disabled (observation only)",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        return {"ok": True, **data}
    except (ssl.SSLError, OSError, ScopeViolation) as exc:
        if isinstance(exc, ScopeViolation):
            raise
        return {"ok": False, "host": host, "port": port, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        for s in (tls_sock, sock):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass


def probe_http(
    guard: ScopeGuard,
    host: str,
    port: int,
    path: str = "/",
    method: str = "GET",
    max_body: int = 0,
    tls: bool | None = None,
    action: str = "http_probe",
    timeout: float = DEFAULT_TIMEOUT,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """One HTTP request.  Reads at most ``max_body`` bytes of the response body."""
    use_tls = (port in TLS_PORTS) if tls is None else tls
    context = None
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    sock = None
    wrapped = None
    try:
        sock = _connect(guard, host, port, timeout, f"{action}:connect")
        if context is not None:
            wrapped = context.wrap_socket(sock, server_hostname=host)
            sock = wrapped

        request_lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}" + ("" if port in (80, 443) else f":{port}"),
            f"User-Agent: {USER_AGENT}",
            "Accept: */*",
            "Connection: close",
        ]
        for key, value in (extra_headers or {}).items():
            request_lines.append(f"{key}: {value}")
        request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii", "replace")
        sock.sendall(request)

        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < MAX_RESPONSE_HEADER_BYTES:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if len(raw) > MAX_RESPONSE_HEADER_BYTES:
                break

        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", "replace").split("\r\n")
        status_line = lines[0] if lines else ""
        match = re.match(r"HTTP/(\d\.\d)\s+(\d{3})\s*(.*)", status_line)
        headers: dict[str, str] = {}
        set_cookies: list[str] = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key, value = key.strip(), value.strip()
            if key.lower() == "set-cookie":
                set_cookies.append(value)
            headers[key] = value

        body = rest[:max_body] if max_body else b""
        return {
            "ok": bool(match),
            "host": host,
            "port": port,
            "tls": use_tls,
            "path": path,
            "method": method,
            "status": int(match.group(2)) if match else None,
            "reason": match.group(3) if match else None,
            "http_version": match.group(1) if match else None,
            "headers": headers,
            "set_cookies": set_cookies,
            "body_bytes_read": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
            "body_sample": body.decode("utf-8", "replace")[:512] if body else None,
        }
    except ScopeViolation:
        raise
    except (socket.timeout, TimeoutError) as exc:
        return {"ok": False, "host": host, "port": port, "error": f"timeout: {exc}", "headers": {}}
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "host": host, "port": port, "error": f"{type(exc).__name__}: {exc}", "headers": {}}
    finally:
        for s in (wrapped, sock):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass


BANNER_PATTERNS = (
    (re.compile(r"^SSH-\d\.\d-(?P<product>\S+)", re.I), "ssh"),
    (re.compile(r"^(?P<proto>220)[ \-].*?(?P<product>vsFTPd|ProFTPD|Pure-FTPd|FileZilla)[ /]?(?P<version>[\d.]+)?", re.I), "ftp"),
)


def parse_banner(banner: str | None) -> dict[str, Any]:
    """Extract product/version from a greeting or HTTP Server header."""
    if not banner:
        return {}
    text = banner.strip()

    ssh = re.match(r"^SSH-(?P<proto>\d\.\d)-(?P<software>\S+?)(?:\s+(?P<comment>.*))?$", text, re.I)
    if ssh:
        software = ssh.group("software")
        match = re.match(r"^(?P<product>[A-Za-z][A-Za-z0-9_\-]*?)[_-]?(?P<version>[\d][\w.\-]*)?$", software)
        product = (match.group("product") if match and match.group("product") else software).lower().replace("-", "_")
        return {
            "protocol": "ssh",
            "banner": text,
            "product": _normalise_product(product),
            "version": match.group("version") if match else None,
            "raw_software": software,
            "comment": (ssh.group("comment") or "")[:200],
        }

    server = re.search(r"(?P<product>Apache|nginx|Microsoft-IIS|lighttpd|Caddy|OpenResty|Jetty|Tomcat)[/ ]?(?P<version>[\d.]+)?", text, re.I)
    if server:
        product = server.group("product").lower()
        mapping = {"apache": "apache_httpd", "microsoft-iis": "iis", "openresty": "openresty"}
        return {
            "protocol": "http",
            "banner": text,
            "product": mapping.get(product, product),
            "version": server.group("version"),
        }

    ftp = re.search(r"(?i)(vsftpd|proftpd|pure-ftpd|filezilla)[ /]?([\d.]+)?", text)
    if ftp:
        return {"protocol": "ftp", "banner": text, "product": ftp.group(1).lower().replace("-", ""),
                "version": ftp.group(2)}

    return {"banner": text}


def _normalise_product(product: str) -> str:
    product = product.lower()
    if product.startswith("openssh"):
        return "openssh"
    if product.startswith("dropbear"):
        return "dropbear"
    return product


def fingerprint_service(guard: ScopeGuard, host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Service:
    """Identify what listens on ``host:port`` with one connection (plus TLS if applicable)."""
    service = Service(host=host, port=port)
    tls_info: dict[str, Any] | None = None

    if port in TLS_PORTS:
        tls_info = tls_handshake(guard, host, port, timeout=timeout)
        if tls_info.get("ok"):
            service.tls = tls_info
            service.evidence.append(Evidence(
                kind="tls_handshake",
                asset=host,
                summary=f"Handshake TLS en {host}:{port}: {tls_info.get('protocol')} / {tls_info.get('cipher')}",
                data={k: v for k, v in tls_info.items() if k != "duration_ms"},
                source="discovery.tls_handshake",
            ))
            http = probe_http(guard, host, port, path="/", method="HEAD", tls=True,
                              action="http_probe:https")
        else:
            service.evidence.append(Evidence(
                kind="tls_handshake", asset=host,
                summary=f"Handshake TLS fallido en {host}:{port}",
                data=tls_info, source="discovery.tls_handshake",
            ))
            return service
    else:
        http = None

    if http is None:
        # Try passive banner first, then a single HTTP request.
        sock = None
        try:
            sock = _connect(guard, host, port, timeout, "tcp_connect:banner")
            sock.settimeout(min(1.5, timeout))
            greeting = _read_some(sock)
            if greeting:
                service.banner = greeting.decode("latin-1", "replace").strip()[:400]
        except (OSError, ScopeViolation) as exc:
            if isinstance(exc, ScopeViolation):
                raise
            service.state = "filtered"
            service.evidence.append(Evidence(
                kind="tcp_connect", asset=host,
                summary=f"Sin conexión a {host}:{port}",
                data={"port": port, "error": f"{type(exc).__name__}: {exc}"},
                source="discovery.fingerprint_service",
            ))
            return service
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        if port in HTTP_PORTS or not service.banner:
            http = probe_http(guard, host, port, path="/", method="HEAD", tls=False,
                              action="http_probe:http")

    if http is not None:
        service.http = http
        if http.get("ok"):
            server = http.get("headers", {}).get("Server")
            service.banner = service.banner or (f"HTTP {http.get('status')}" + (f" {server}" if server else ""))
            fingerprint = parse_banner(server or "")
            service.product = fingerprint.get("product")
            service.version = fingerprint.get("version")
            service.evidence.append(Evidence(
                kind="http_response",
                asset=host,
                summary=f"Respuesta HTTP {http.get('status')} en {host}:{port}",
                data={k: http[k] for k in ("status", "http_version", "headers", "set_cookies",
                                           "body_bytes_read", "body_sha256") if k in http},
                source="discovery.probe_http",
            ))
        elif http.get("error"):
            service.evidence.append(Evidence(
                kind="http_probe", asset=host,
                summary=f"Sin respuesta HTTP en {host}:{port}",
                data={"port": port, "error": http.get("error")},
                source="discovery.probe_http",
            ))

    if service.banner and not service.product:
        fingerprint = parse_banner(service.banner)
        service.product = fingerprint.get("product")
        service.version = fingerprint.get("version")
        if fingerprint:
            service.evidence.append(Evidence(
                kind="service_banner", asset=host,
                summary=f"Banner de servicio en {host}:{port}: {service.banner[:120]}",
                data=fingerprint, source="discovery.parse_banner",
            ))
    return service


def scan_host(guard: ScopeGuard, host: str, ports: list[int], max_workers: int = 4,
              timeout: float = DEFAULT_TIMEOUT) -> Asset:
    asset = Asset(host=host)
    open_ports: list[Service] = []
    closed: list[int] = []

    def work(port: int):
        return fingerprint_service(guard, host, port, timeout=timeout)

    workers = max(1, min(max_workers, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(work, p): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            service = future.result()
            if service.state == "open":
                open_ports.append(service)
            else:
                closed.append(port)

    asset.services = sorted(open_ports, key=lambda s: s.port)
    asset.evidence.append(Evidence(
        kind="port_scan",
        asset=host,
        summary=f"Escaneo TCP connect: {len(open_ports)} abierto(s) de {len(ports)} puerto(s) autorizados",
        data={
            "ports_requested": sorted(ports),
            "open": [s.port for s in open_ports],
            "closed_or_filtered": sorted(closed),
            "scan_type": "TCP connect (no SYN, no raw sockets)",
            "requests_sent": len(ports) + len(open_ports),
        },
        source="discovery.scan_host",
    ))
    return asset
