"""`self-check`: demonstrates the controls and the pipeline in one run.

Each check prints PASS/FAIL with the evidence that supports it.  This is the
"técnicamente verificable" part of the deliverable: it does not describe
controls, it exercises them — including the ones that *refuse*.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable

from . import auth
from .audit import AuditLog, verify_chain
from .errors import CapabilityBlocked, SentinelError, ScopeViolation
from .model import Tier
from .scope import Scope, ScopeGuard


@dataclass
class CheckResult:
    id: str
    name: str
    passed: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


def _valid_scope_dict(**overrides: Any) -> dict[str, Any]:
    base = {
        "schema": "sentinel.scope/1",
        "engagement_id": "SELFCHECK",
        "client": "internal",
        "operator": "selfcheck",
        "authorization": {
            "authorized": True,
            "reference": "SELFCHECK-AUTH-001",
            "approved_by": "owner of the host",
        },
        "valid_from": "2020-01-01T00:00:00Z",
        "expires_at": "2999-01-01T00:00:00Z",
        "targets": [{"kind": "local_host", "value": "self", "ports": [65000], "max_tier": 2}],
        "max_requests": 5,
        "rate_per_second": 50,
    }
    base.update(overrides)
    return base


def run_control_checks() -> list[CheckResult]:
    results: list[CheckResult] = []
    tmp = tempfile.mkdtemp(prefix="sentinel-selfcheck-")

    # 1. authorization gate
    try:
        Scope.from_dict(_valid_scope_dict(authorization={"authorized": False, "reference": "x", "approved_by": "y"}))
        results.append(CheckResult("CTL-1", "Alcance sin autorización explícita rechazado", False,
                                   "se aceptó un alcance con authorized=false"))
    except SentinelError as exc:
        results.append(CheckResult("CTL-1", "Alcance sin autorización explícita rechazado", True, str(exc)))
    try:
        Scope.from_dict(_valid_scope_dict(authorization={"authorized": True, "reference": "", "approved_by": ""}))
        results.append(CheckResult("CTL-1b", "Autorización sin referencia rechazada", False, "se aceptó sin referencia"))
    except SentinelError as exc:
        results.append(CheckResult("CTL-1b", "Autorización sin referencia rechazada", True, str(exc)))

    # 2. metadata / public address rules
    for label, value, extra in (
        ("169.254.169.254 (metadata cloud)", "169.254.169.254", {}),
        ("8.8.8.8 (público sin opt-in)", "8.8.8.8", {}),
        ("224.0.0.1 (multicast)", "224.0.0.1", {}),
    ):
        try:
            Scope.from_dict(_valid_scope_dict(targets=[{"kind": "host", "value": value, "ports": [80]}]))
            results.append(CheckResult(f"CTL-2:{value}", f"Target {label} rechazado", False, "fue aceptado"))
        except SentinelError as exc:
            results.append(CheckResult(f"CTL-2:{value}", f"Target {label} rechazado", True, str(exc)))

    # 3. tier 3 blocked even when the scope asks for it
    requested = _valid_scope_dict(targets=[{"kind": "local_host", "value": "self", "ports": [65000], "max_tier": 3}])
    scope = Scope.from_dict(requested)
    audit_path = os.path.join(tmp, "audit.jsonl")
    audit = AuditLog(audit_path, scope.engagement_id, "selfcheck")
    guard = ScopeGuard(scope, audit)
    results.append(CheckResult(
        "CTL-3a", "El alcance no puede habilitar Tier 3 (se degrada a 2)",
        scope.max_tier == 2, f"max_tier efectivo = {scope.max_tier}", {"requested": 3, "effective": scope.max_tier},
    ))
    try:
        guard.check("exploit", "127.0.0.1", 65000, Tier.EXPLOIT)
        results.append(CheckResult("CTL-3b", "Tier 3 rechazado aunque se intente", False, "no lanzó excepción"))
    except CapabilityBlocked as exc:
        results.append(CheckResult("CTL-3b", "Tier 3 rechazado aunque se intente", True, str(exc)))

    # 4. port not in allowlist
    try:
        guard.check("tcp_connect", "127.0.0.1", 22, Tier.VALIDATE)
        results.append(CheckResult("CTL-4", "Puerto fuera de allowlist rechazado", False, "fue aceptado"))
    except ScopeViolation as exc:
        results.append(CheckResult("CTL-4", "Puerto fuera de allowlist rechazado", True, str(exc)))

    # 4b. port allowlist with a host target in scope
    host_scope = Scope.from_dict(_valid_scope_dict(
        targets=[{"kind": "host", "value": "127.0.0.1", "ports": [65000], "max_tier": 2}]
    ))
    host_guard = ScopeGuard(host_scope, AuditLog(os.path.join(tmp, "audit-port.jsonl"), "SELFCHECK", "selfcheck"))
    try:
        host_guard.check("tcp_connect", "127.0.0.1", 22, Tier.VALIDATE)
        results.append(CheckResult("CTL-4b", "Puerto no declarado rechazado en un host autorizado", False,
                                   "fue aceptado"))
    except ScopeViolation as exc:
        results.append(CheckResult("CTL-4b", "Puerto no declarado rechazado en un host autorizado", True, str(exc)))

    # 5. host outside scope
    try:
        guard.check("tcp_connect", "192.0.2.10", 65000, Tier.VALIDATE)
        results.append(CheckResult("CTL-5", "Host fuera de alcance rechazado", False, "fue aceptado"))
    except ScopeViolation as exc:
        results.append(CheckResult("CTL-5", "Host fuera de alcance rechazado", True, str(exc)))

    # 6. kill switch
    stop = os.path.join(tmp, "STOP")
    kill_scope = Scope.from_dict(_valid_scope_dict(killswitch_path=stop))
    kill_audit = AuditLog(os.path.join(tmp, "audit-kill.jsonl"), "SELFCHECK", "selfcheck")
    kill_guard = ScopeGuard(kill_scope, kill_audit)
    open(stop, "w").close()
    try:
        kill_guard.check_local("collect:identity")
        results.append(CheckResult("CTL-6", "Kill switch detiene la ejecución", False, "acción permitida"))
    except Exception as exc:  # BudgetExceeded
        results.append(CheckResult("CTL-6", "Kill switch detiene la ejecución", True, str(exc)))

    # 7. credential attacks blocked
    for name, fn in (("credential_attack_guard", auth.credential_attack_guard),
                     ("password_spray", auth.password_spray),
                     ("default_credential_test", auth.default_credential_test)):
        try:
            fn()
            results.append(CheckResult(f"CTL-7:{name}", f"{name} bloqueado", False, "no lanzó excepción"))
        except CapabilityBlocked as exc:
            results.append(CheckResult(f"CTL-7:{name}", f"{name} bloqueado", True, str(exc)[:160]))

    # 8. audit chain tamper detection
    tamper_path = os.path.join(tmp, "audit-tamper.jsonl")
    t_audit = AuditLog(tamper_path, "SELFCHECK", "selfcheck")
    for i in range(3):
        t_audit.record(f"action_{i}", "info", target="local")
    before = verify_chain(tamper_path)
    lines = open(tamper_path, encoding="utf-8").read().splitlines()
    rec = json.loads(lines[1])
    rec["outcome"] = "tampered"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    with open(tamper_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    after = verify_chain(tamper_path)
    results.append(CheckResult(
        "CTL-8", "La cadena de auditoría detecta manipulación",
        bool(before.get("ok")) and not after.get("ok"),
        f"antes: {before.get('records')} registros OK · después: {after.get('reason')}",
        {"before": before, "after": after},
    ))

    # 9. expiry
    expired = _valid_scope_dict()
    expired["valid_from"] = "2020-01-01T00:00:00Z"
    expired["expires_at"] = "2020-06-01T00:00:00Z"
    try:
        Scope.from_dict(expired)
        results.append(CheckResult("CTL-9", "Engagement vencido rechazado", False, "fue aceptado"))
    except SentinelError as exc:
        results.append(CheckResult("CTL-9", "Engagement vencido rechazado", True, str(exc)))

    # 10. no secrets / no shadow read
    from .collectors import READABLE_FILES
    results.append(CheckResult(
        "CTL-10", "El colector no abre /etc/shadow",
        "/etc/shadow" not in READABLE_FILES.values(),
        f"archivos declarados: {sorted(READABLE_FILES.values())}",
    ))
    return results


def run_pipeline_checks() -> list[CheckResult]:
    """Runs the real local assessment against this host and verifies the artefacts."""
    from .engine import assess_local, coverage_table
    from .report import write_reports

    tmp = tempfile.mkdtemp(prefix="sentinel-pipeline-")
    scope_path = os.path.join(tmp, "scope.json")
    scope_dict = _valid_scope_dict(engagement_id="SELFCHECK-PIPELINE")
    scope_dict["targets"] = [{"kind": "local_host", "value": "self", "ports": [65000], "max_tier": 2}]
    with open(scope_path, "w", encoding="utf-8") as fh:
        json.dump(scope_dict, fh)

    out_dir = os.path.join(tmp, "evidence")
    result = assess_local(scope_path, out_dir)
    paths = write_reports(result.assessment, out_dir)
    a = result.assessment

    checks = [
        CheckResult("RUN-1", "La evaluación local produce al menos un hallazgo",
                    len(a.findings) > 0, f"{len(a.findings)} hallazgos"),
        CheckResult("RUN-2", "El informe se genera en md/html/json",
                    all(os.path.getsize(p) > 500 for p in paths.values()),
                    ", ".join(f"{k}={os.path.getsize(v)}B" for k, v in paths.items())),
        CheckResult("RUN-3", "La cadena de auditoría del run verifica",
                    bool((a.audit_chain or {}).get("ok")),
                    f"{(a.audit_chain or {}).get('records')} registros"),
        CheckResult("RUN-4", "Ningún hallazgo se marca como validado sin evidencia",
                    all(f.validation_state.value in {"observed", "inferred", "not_validated"} for f in a.findings),
                    "estados: " + ", ".join(sorted({f.validation_state.value for f in a.findings}))),
        CheckResult("RUN-5", "La matriz de capacidades está adjunta y no exagera",
                    any(c.status == "blocked" and not c.exercised_in_run for c in a.coverage)
                    and all(c.status in {"implemented", "partial", "blocked"} for c in a.coverage),
                    "estados: " + ", ".join(f"{c.id}={c.status}" for c in a.coverage)),
        CheckResult("RUN-6", "Toda evidencia tiene digest SHA-256",
                    all(len(ev.to_dict()["evidence_sha256"]) == 64 for f in a.findings for ev in f.evidence),
                    f"{sum(len(f.evidence) for f in a.findings)} bloques de evidencia"),
    ]

    # each CAP claimed as implemented must map to an importable module
    import importlib

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for cap in coverage_table("local"):
        refs = [r.strip() for r in cap.code_ref.split(",") if r.strip()]
        missing = []
        checked = []
        for ref in refs:
            if ref.endswith(".py"):
                module = ref.replace("/", ".").removesuffix(".py")
                try:
                    importlib.import_module(module)
                    checked.append(ref)
                except Exception as exc:  # noqa: BLE001
                    missing.append(f"{ref} ({type(exc).__name__})")
            elif ref.endswith(".json"):
                if os.path.exists(os.path.join(root, ref)):
                    checked.append(ref)
                else:
                    missing.append(f"{ref} (archivo ausente)")
        checks.append(CheckResult(
            f"CODE-{cap.id}",
            f"{cap.id} apunta a código/datos existentes",
            not missing,
            "; ".join(missing) if missing else f"verificado: {', '.join(checked)}",
        ))
    return checks


def render(results: list[CheckResult]) -> str:
    lines = ["# Self-check de controles y pipeline", ""]
    passed = sum(1 for r in results if r.passed)
    lines.append(f"**{passed}/{len(results)} comprobaciones OK**")
    lines.append("")
    lines.append("| ID | Comprobación | Resultado | Detalle |")
    lines.append("|---|---|---|---|")
    for r in results:
        lines.append(f"| {r.id} | {r.name} | {'PASS' if r.passed else 'FAIL'} | {r.detail.replace('|', '/')} |")
    return "\n".join(lines)
