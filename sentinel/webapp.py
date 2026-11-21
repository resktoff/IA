"""Same-origin web interface for the existing Sentinel engine.

The web layer only orchestrates existing ScopeGuard, discovery, checks and
reporting modules. It does not add attack primitives or bypass authorization.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from itertools import islice
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from . import __version__
from .audit import AuditLog, verify_chain
from .checks import exposure, web
from .discovery import DEFAULT_TIMEOUT, scan_host
from .engine import MAX_HOSTS_PER_TARGET, coverage_table
from .errors import SentinelError, ScopeError
from .model import Assessment, utcnow
from .report import write_reports
from .scope import Scope, ScopeGuard

STATIC_DIR = Path(__file__).resolve().parent / "web"
DEFAULT_DATA_DIR = Path.cwd() / "evidence" / "web"
MAX_BODY_BYTES = 1_000_000
MAX_SCAN_PAIRS = 512


@dataclass
class Operation:
    id: str
    kind: str
    status: str = "queued"
    message: str = "En cola"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "message": self.message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result": self.result,
            "error": self.error,
            "cancellable": self.kind == "scan" and self.status in {"queued", "running"},
        }


@dataclass
class ScanContext:
    id: str
    scope: Scope
    assessment: Assessment
    data_dir: Path
    audit_path: str | None = None
    state: str = "completed"
    analysis_done: bool = False
    report_paths: dict[str, str] = field(default_factory=dict)


class SentinelWeb:
    """Application state + real backend actions, independently testable."""

    def __init__(self, data_dir: str | os.PathLike[str] = DEFAULT_DATA_DIR, timeout: float = DEFAULT_TIMEOUT):
        self.data_dir = Path(data_dir).resolve()
        self.timeout = min(max(float(timeout), 0.1), 5.0)
        self._lock = threading.RLock()
        self.operations: dict[str, Operation] = {}
        self.scans: dict[str, ScanContext] = {}
        self.activity: list[dict[str, Any]] = []
        self._active_scan: str | None = None

    def _log(self, message: str, level: str = "info", operation_id: str | None = None) -> None:
        entry = {"at": utcnow(), "level": level, "message": message, "operation_id": operation_id}
        with self._lock:
            self.activity.append(entry)
            self.activity = self.activity[-200:]

    def _set_operation(self, op: Operation, *, status: str | None = None,
                       message: str | None = None, result: dict[str, Any] | None = None,
                       error: str | None = None) -> None:
        with self._lock:
            if status is not None:
                op.status = status
            if message is not None:
                op.message = message
            if result is not None:
                op.result = result
            if error is not None:
                op.error = error
            op.updated_at = time.time()

    def start_scan(self, scope_document: dict[str, Any]) -> Operation:
        # Parse through the core parser before queueing any network action.
        scope = Scope.from_dict(scope_document, source_path="web-upload")
        targets = [t for t in scope.targets if t.kind in {"host", "cidr"} and t.max_tier >= 2]
        if not targets:
            raise ScopeError("el alcance debe declarar un target host/cidr con autorización Tier 2 para ESCANEAR")
        pairs: list[tuple[str, list[int]]] = []
        total_pairs = 0
        # Bound expansion before materialising targets; large CIDRs or port ranges
        # are rejected without allocating their cartesian product.
        for target in targets:
            ports_count = len(target.ports)
            if target.kind == "host":
                hosts = [target.value]
            else:
                network = ipaddress.ip_network(target.value, strict=False)
                hosts = [str(ip) for ip in islice(network.hosts(), MAX_HOSTS_PER_TARGET)]
            target_pairs = len(hosts) * ports_count
            if total_pairs + target_pairs > MAX_SCAN_PAIRS:
                raise ScopeError(f"límite de interfaz: más de {MAX_SCAN_PAIRS} pares host/puerto autorizados")
            ports = list(target.ports)
            pairs.extend((host, ports) for host in hosts)
            total_pairs += target_pairs
        if total_pairs == 0:
            raise ScopeError("el alcance no contiene pares host/puerto para escanear")
        with self._lock:
            if self._active_scan:
                current = self.operations.get(self._active_scan)
                if current and current.status in {"queued", "running"}:
                    raise ScopeError("ya hay un escaneo en curso; espere o cancélelo antes de iniciar otro")
            op = Operation(uuid.uuid4().hex[:12], "scan")
            self.operations[op.id] = op
            self._active_scan = op.id
        self._log(f"ESCANEAR solicitado; alcance validado ({scope.engagement_id}, {total_pairs} pares host/puerto)",
                  operation_id=op.id)
        threading.Thread(target=self._run_scan, args=(op, scope, scope_document, pairs),
                         daemon=True, name=f"sentinel-scan-{op.id}").start()
        return op

    def _run_scan(self, op: Operation, scope: Scope, document: dict[str, Any],
                  pairs: list[tuple[str, list[int]]]) -> None:
        audit = None
        try:
            run_id = uuid.uuid4().hex[:12]
            run_dir = self.data_dir / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            scope_path = run_dir / "scope.json"
            scope_path.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
            # Reload the exact, persisted authorization document through the core parser.
            scope = Scope.from_file(str(scope_path))
            # Keep evidence self-contained without disclosing the server's absolute filesystem path.
            scope.source_path = f"web-upload/{run_id}/scope.json"
            safe_engagement = re.sub(r"[^A-Za-z0-9_.-]+", "_", scope.engagement_id)[:80].strip(".") or "engagement"
            audit_path = str(run_dir / f"audit-{safe_engagement}-{run_id}.jsonl")
            audit = AuditLog(audit_path, scope.engagement_id, scope.operator, run_id=run_id)
            audit.record("run_start", "info", detail={"source": "sentinel-web", "mode": "network"})
            guard = ScopeGuard(scope, audit)
            assessment = Assessment(
                engagement_id=scope.engagement_id,
                operator=scope.operator,
                target_mode="network",
                scope_summary=scope.summary(),
                run_id=run_id,
                audit_path=os.path.basename(audit_path),
            )
            self._set_operation(op, status="running", message="Reconocimiento TCP autorizado en curso")
            self._log("Conexiones TCP connect limitadas al alcance; sin payloads ni autenticación",
                      operation_id=op.id)
            completed = 0
            total = sum(len(ports) for _, ports in pairs)
            host_assets: dict[str, Any] = {}
            for host, ports in pairs:
                for port in ports:
                    if op.cancel_event.is_set():
                        assessment.skipped.append({"check": "scan", "reason": "cancelación solicitada por el operador"})
                        break
                    self._set_operation(op, message=f"Escaneando {host}:{port} ({completed + 1}/{total})")
                    asset = scan_host(guard, host, [port], max_workers=1, timeout=self.timeout)
                    if host not in host_assets:
                        host_assets[host] = asset
                    else:
                        existing = host_assets[host]
                        existing.services.extend(asset.services)
                        existing.evidence.extend(asset.evidence)
                    completed += 1
                    service = asset.services[0] if asset.services else None
                    if service:
                        self._log(f"Servicio observado: {host}:{port} abierto"
                                  + (f" · {service.product} {service.version or ''}" if service.product else ""),
                                  operation_id=op.id)
                    else:
                        self._log(f"{host}:{port}: sin servicio TCP observable", "warning", op.id)
                if op.cancel_event.is_set():
                    break
            assessment.assets.extend(host_assets.values())
            was_cancelled = op.cancel_event.is_set()
            audit.record("guard_stats", "info", detail=guard.stats.to_dict())
            audit.record("run_finish", "info", detail={
                "assets": len(assessment.assets), "ports_completed": completed,
                "cancelled": was_cancelled,
            })
            assessment.finished_at = utcnow()
            assessment.audit_chain = verify_chain(audit_path)
            context = ScanContext(run_id, scope, assessment, run_dir, audit_path=audit_path,
                                  state="cancelled" if was_cancelled else "completed")
            with self._lock:
                self.scans[run_id] = context
            summary = self._scan_result(context, completed, total)
            status = "cancelled" if was_cancelled else "completed"
            self._set_operation(op, status=status,
                                message="Escaneo cancelado; resultados parciales disponibles" if was_cancelled
                                else "Reconocimiento completado", result=summary)
            self._log(f"ESCANEAR {status}: {len(assessment.assets)} activos, "
                      f"{sum(len(a.services) for a in assessment.assets)} servicios abiertos; auditoría "
                      f"{'íntegra' if assessment.audit_chain.get('ok') else 'con error'}",
                      "warning" if was_cancelled else "success", op.id)
        except Exception as exc:
            if audit is not None:
                try:
                    audit.record("run_error", "denied" if isinstance(exc, SentinelError) else "error",
                                 detail={"error": f"{type(exc).__name__}: {exc}"})
                except Exception:
                    pass
            self._set_operation(op, status="error", message="El reconocimiento falló",
                                error=f"{type(exc).__name__}: {exc}")
            self._log(f"ESCANEAR error: {type(exc).__name__}: {exc}", "error", op.id)
        finally:
            with self._lock:
                if self._active_scan == op.id:
                    self._active_scan = None

    @staticmethod
    def _scan_result(context: ScanContext, completed: int, total: int) -> dict[str, Any]:
        a = context.assessment
        return {
            "scan_id": context.id,
            "engagement_id": a.engagement_id,
            "target_mode": a.target_mode,
            "ports_completed": completed,
            "ports_total": total,
            "assets": [asset.to_dict() for asset in a.assets],
            "open_services": sum(len(asset.services) for asset in a.assets),
            "audit_chain": a.audit_chain,
            "audit_path": a.audit_path,
            "state": context.state,
        }

    def cancel_scan(self, operation_id: str) -> Operation:
        with self._lock:
            op = self.operations.get(operation_id)
            if not op or op.kind != "scan":
                raise ScopeError("operación de escaneo desconocida")
            if op.status not in {"queued", "running"}:
                raise ScopeError("el escaneo ya terminó y no se puede cancelar")
            op.cancel_event.set()
            op.updated_at = time.time()
        self._log("Cancelación solicitada; se detendrá al terminar la conexión TCP actual (timeout acotado)",
                  "warning", op.id)
        return op

    @staticmethod
    def _audit_file(context: ScanContext) -> str:
        path = context.audit_path or context.assessment.audit_path
        if not path:
            raise ScopeError("no hay ruta de auditoría asociada al reconocimiento")
        return path

    def analyze(self, scan_id: str) -> dict[str, Any]:
        with self._lock:
            context = self.scans.get(scan_id)
        if not context:
            raise ScopeError("no existe ese reconocimiento en esta sesión del servidor")
        if context.analysis_done:
            raise ScopeError("este reconocimiento ya fue analizado")
        chain = verify_chain(self._audit_file(context))
        if not chain.get("ok"):
            raise ScopeError(f"cadena de auditoría inválida; se rechaza el análisis: {chain.get('reason')}")
        audit = AuditLog(self._audit_file(context), context.scope.engagement_id,
                         context.scope.operator, run_id=context.id)
        audit.record("analysis_start", "allowed", detail={"source": "sentinel-web", "network_requests": 0})
        findings = []
        advisories = exposure.load_advisories()
        for asset in context.assessment.assets:
            for service in asset.services:
                findings.extend(exposure.analyze_service(service, advisories))
                findings.extend(web.analyze_service_web(service))
        context.assessment.add_findings(findings)
        context.assessment.coverage = coverage_table("network")
        for coverage in context.assessment.coverage:
            if coverage.id in {"CAP-4", "CAP-5"}:
                coverage.exercised_in_run = False
                coverage.detail += " Esta fase de interfaz no ejecutó análisis local de privilegios/autenticación."
        context.assessment.skipped.append({
            "check": "authentication-attacks",
            "reason": "no se enviaron credenciales; ataques de autenticación bloqueados por ADR-005",
        })
        audit.record("analysis_finish", "info", detail={"findings": len(context.assessment.findings)})
        context.assessment.audit_chain = verify_chain(self._audit_file(context))
        context.analysis_done = True
        result = {
            "scan_id": context.id,
            "findings": [finding.to_dict() for finding in context.assessment.sorted_findings()],
            "severity_counts": context.assessment.counts_by_severity(),
            "asset_count": len(context.assessment.assets),
            "service_count": sum(len(asset.services) for asset in context.assessment.assets),
            "audit_chain": context.assessment.audit_chain,
        }
        self._log(f"ANALIZAR completado: {len(findings)} hallazgos reales a partir de "
                  f"{result['service_count']} servicios observados; 0 conexiones adicionales",
                  "success", scan_id)
        return result

    def create_report(self, scan_id: str) -> dict[str, Any]:
        with self._lock:
            context = self.scans.get(scan_id)
        if not context:
            raise ScopeError("no existe ese reconocimiento en esta sesión del servidor")
        if not context.analysis_done:
            raise ScopeError("primero debe completarse ANALIZAR")
        if context.report_paths:
            raise ScopeError("el informe de este análisis ya fue generado")
        chain = verify_chain(self._audit_file(context))
        if not chain.get("ok"):
            raise ScopeError(f"cadena de auditoría inválida; se rechaza el informe: {chain.get('reason')}")
        audit = AuditLog(self._audit_file(context), context.scope.engagement_id,
                         context.scope.operator, run_id=context.id)
        audit.record("report_generate", "allowed", detail={"formats": ["markdown", "html", "json"]})
        context.assessment.audit_chain = verify_chain(self._audit_file(context))
        safe_engagement = re.sub(r"[^A-Za-z0-9_.-]+", "_", context.scope.engagement_id)[:80].strip(".") or "engagement"
        paths = write_reports(context.assessment, str(context.data_dir),
                              basename=f"report-{safe_engagement}-{context.id}")
        context.report_paths = paths
        result = {
            "scan_id": context.id,
            "report_paths": {kind: os.path.basename(path) for kind, path in paths.items()},
            "audit_path": os.path.basename(self._audit_file(context)),
            "audit_chain": context.assessment.audit_chain,
            "findings": len(context.assessment.findings),
        }
        self._log(f"INFORME generado desde Assessment real: {len(context.assessment.findings)} hallazgos; "
                  "Markdown, HTML y JSON", "success", scan_id)
        return result

    def report_html(self, scan_id: str) -> str:
        context = self._get_context(scan_id)
        if not context.report_paths or "html" not in context.report_paths:
            raise ScopeError("informe aún no generado")
        return Path(context.report_paths["html"]).read_text(encoding="utf-8")

    def download_report(self, scan_id: str, kind: str) -> tuple[str, bytes, str]:
        context = self._get_context(scan_id)
        if kind not in context.report_paths:
            raise ScopeError("formato de informe inexistente")
        path = Path(context.report_paths[kind])
        content_type = {"markdown": "text/markdown; charset=utf-8", "html": "text/html; charset=utf-8",
                        "json": "application/json; charset=utf-8"}[kind]
        return path.name, path.read_bytes(), content_type

    def _get_context(self, scan_id: str) -> ScanContext:
        with self._lock:
            context = self.scans.get(scan_id)
        if not context:
            raise ScopeError("reconocimiento desconocido")
        return context

    def operation(self, operation_id: str) -> dict[str, Any] | None:
        with self._lock:
            op = self.operations.get(operation_id)
            return op.public() if op else None

    def state(self) -> dict[str, Any]:
        with self._lock:
            operations = [op.public() for op in self.operations.values()]
            scans = [{"scan_id": c.id, "state": c.state, "analysis_done": c.analysis_done,
                      "report_ready": bool(c.report_paths), "engagement_id": c.scope.engagement_id}
                     for c in self.scans.values()]
            activity = list(reversed(self.activity[-80:]))
        return {"version": __version__, "operations": operations, "scans": scans, "activity": activity}


class WebHandler(BaseHTTPRequestHandler):
    server_version = "SentinelWeb/1"
    sys_version = ""

    @property
    def app(self) -> SentinelWeb:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        # Avoid writing authorization data or report content to standard logs.
        return

    def _headers(self, content_type: str, length: int, *, disposition: str | None = None) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
        if disposition:
            self.send_header("Content-Disposition", disposition)

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _body_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ScopeError("Content-Length inválido") from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ScopeError(f"cuerpo JSON requerido; máximo {MAX_BODY_BYTES} bytes")
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ScopeError("Content-Type debe ser application/json")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ScopeError("el cuerpo no contiene JSON válido") from exc
        if not isinstance(value, dict):
            raise ScopeError("se esperaba un objeto JSON")
        return value

    def _check_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True  # CLI and same-origin clients may omit Origin.
        parsed = urlparse(origin)
        host = self.headers.get("Host", "")
        return parsed.netloc.lower() == host.lower() and parsed.scheme in {"http", "https"}

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self._json(200, {"ok": True, "service": "sentinel-web", "version": __version__})
            return
        if path == "/api/state":
            self._json(200, self.app.state())
            return
        if path.startswith("/api/operations/"):
            op_id = unquote(path.rsplit("/", 1)[-1])
            value = self.app.operation(op_id)
            self._json(200 if value else 404, value or {"error": "operación inexistente"})
            return
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "reports"] and parts[3] == "view":
            try:
                body = self.app.report_html(parts[2]).encode("utf-8")
                self.send_response(200)
                self._headers("text/html; charset=utf-8", len(body))
                self.end_headers()
                self.wfile.write(body)
            except SentinelError as exc:
                self._json(404, {"error": str(exc)})
            return
        if len(parts) == 4 and parts[:2] == ["api", "reports"] and parts[3] in {"markdown", "html", "json"}:
            try:
                filename, body, content_type = self.app.download_report(parts[2], parts[3])
                self.send_response(200)
                self._headers(content_type, len(body), disposition=f'attachment; filename="{filename}"')
                self.end_headers()
                self.wfile.write(body)
            except SentinelError as exc:
                self._json(404, {"error": str(exc)})
            return
        static_files = {
            "/app.css": (STATIC_DIR / "app.css", "text/css; charset=utf-8"),
            "/app.js": (STATIC_DIR / "app.js", "text/javascript; charset=utf-8"),
            "/scope-help": (STATIC_DIR / "scope-help.html", "text/html; charset=utf-8"),
        }
        if path in {"/", "/index.html"}:
            body = (STATIC_DIR / "index.html").read_bytes()
            self.send_response(200)
            self._headers("text/html; charset=utf-8", len(body))
            self.end_headers()
            self.wfile.write(body)
            return
        if path in static_files:
            file_path, content_type = static_files[path]
            body = file_path.read_bytes()
            self.send_response(200)
            self._headers(content_type, len(body))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json(404, {"error": "ruta inexistente"})

    def do_POST(self) -> None:
        if not self._check_origin():
            self._json(403, {"error": "origen no permitido"})
            return
        path = urlparse(self.path).path
        try:
            body = self._body_json() if path in {"/api/scan", "/api/analyze", "/api/report"} else {}
            if path == "/api/scan":
                op = self.app.start_scan(body.get("scope"))
                self._json(202, op.public())
            elif path == "/api/analyze":
                self._json(200, self.app.analyze(str(body.get("scan_id", ""))))
            elif path == "/api/report":
                self._json(200, self.app.create_report(str(body.get("scan_id", ""))))
            elif path.startswith("/api/cancel/"):
                op = self.app.cancel_scan(unquote(path.rsplit("/", 1)[-1]))
                self._json(202, op.public())
            else:
                self._json(404, {"error": "ruta inexistente"})
        except SentinelError as exc:
            self.app._log(f"Solicitud rechazada: {exc}", "warning")
            self._json(400, {"error": str(exc)})
        except (TypeError, ValueError, AttributeError) as exc:
            self._json(400, {"error": f"solicitud inválida: {exc}"})
        except Exception as exc:
            self.app._log(f"Error interno: {type(exc).__name__}: {exc}", "error")
            self._json(500, {"error": "error interno; consulte el registro del servidor"})

    def do_OPTIONS(self) -> None:
        self.send_response(405)
        self.send_header("Allow", "GET, POST")
        self.end_headers()


def create_server(host: str = "0.0.0.0", port: int = 8765,
                  app: SentinelWeb | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), WebHandler)
    server.daemon_threads = True
    server.app = app or SentinelWeb()  # type: ignore[attr-defined]
    return server


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Interfaz web local de Sentinel")
    parser.add_argument("--host", default="0.0.0.0", help="interfaz de escucha (default 0.0.0.0 para preview)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR))
    args = parser.parse_args()
    server = create_server(args.host, args.port, SentinelWeb(args.data_dir))
    print(f"Sentinel Web {__version__} escuchando en http://{args.host}:{args.port}")
    print(f"Artefactos de ejecuciones web: {Path(args.data_dir).resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nApagando Sentinel Web...")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
