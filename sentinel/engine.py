"""Orchestration: scope -> audit -> collection -> checks -> report."""

from __future__ import annotations

import ipaddress
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from . import auth, privesc
from .audit import AuditLog, verify_chain
from .checks import exposure, ssh, web
from .collectors import collect_local_facts
from .discovery import DEFAULT_TIMEOUT, scan_host
from .errors import ScopeError, ScopeViolation
from .model import (
    Asset,
    Assessment,
    CapabilityCoverage,
    Evidence,
    Finding,
    Severity,
    Tier,
    utcnow,
)
from .scope import Scope, ScopeGuard


@dataclass
class RunResult:
    assessment: Assessment
    scope: Scope
    evidence_dir: str
    audit_path: str
    out_dir: str
    report_paths: dict[str, str] = field(default_factory=dict)


def coverage_table(mode: str) -> list[CapabilityCoverage]:
    """Static, truthful capability matrix attached to every report.

    ``exercised_in_run`` is the field that prevents architecture from being
    read as implementation: it is set from what actually executed in *this* run.
    """
    network = mode == "network"
    return [
        CapabilityCoverage(
            id="CAP-1",
            name="Identificación de activos y servicios expuestos",
            status="implemented",
            exercised_in_run=True,
            detail=("Escaneo TCP connect con allowlist de puertos y fingerprint de servicio (banner, HTTP, TLS)"
                    if network else
                    "Inventario local: identidad, SO, cuentas, servicios systemd con unidades legibles y "
                    "puertos no evaluados (el modo local no abre conexiones)"),
            code_ref="sentinel/discovery.py, sentinel/collectors.py",
            test_ref="tests/test_discovery.py, tests/test_collectors.py",
        ),
        CapabilityCoverage(
            id="CAP-2",
            name="Detección de vulnerabilidades y clasificación por criticidad",
            status="implemented",
            exercised_in_run=True,
            detail=("Correlación versión->aviso contra un subconjunto curado y cálculo CVSS v3.1 base propio. "
                    "Es inferencia por versión, no validACIÓN de explotabilidad."),
            code_ref="sentinel/checks/exposure.py, sentinel/cvss.py, sentinel/data/advisories.json",
            test_ref="tests/test_cvss.py, tests/test_versions.py",
        ),
        CapabilityCoverage(
            id="CAP-3",
            name="Evaluación de configuraciones y vectores de ataque",
            status="implemented",
            exercised_in_run=True,
            detail="Reglas deterministas sobre sshd_config, cabeceras HTTP, TLS, PAM/pwquality y permisos de archivos",
            code_ref="sentinel/checks/ssh.py, sentinel/checks/web.py, sentinel/auth.py",
            test_ref="tests/test_ssh_checks.py, tests/test_web_checks.py, tests/test_auth.py",
        ),
        CapabilityCoverage(
            id="CAP-4",
            name="Análisis de posibilidades de escalamiento de privilegios",
            status="partial",
            exercised_in_run=True,
            detail=("Enumeración y clasificación de sudo/SUID/capabilities/cron/systemd/PATH con hipótesis y "
                    "prerrequisitos. No se ejecuta ningún binario ni comando privilegiado: no hay validación "
                    "ni explotación (ADR-006)."),
            code_ref="sentinel/privesc.py",
            test_ref="tests/test_privesc.py",
        ),
        CapabilityCoverage(
            id="CAP-5",
            name="Resistencia de mecanismos de autenticación y protección",
            status="partial",
            exercised_in_run=True,
            detail=("Análisis de política (longitud, hash, caducidad, pwquality, permisos de shadow/sudoers) "
                    "y de cookies/atributos. Sin envío de credenciales ni pruebas de bloqueo (ADR-005)."),
            code_ref="sentinel/auth.py",
            test_ref="tests/test_auth.py",
        ),
        CapabilityCoverage(
            id="CAP-6",
            name="Informes técnicos con evidencias, impacto y recomendaciones",
            status="implemented",
            exercised_in_run=True,
            detail="Markdown + HTML autocontenido + JSON, con digest SHA-256 por evidencia y cadena de auditoría verificada",
            code_ref="sentinel/report.py",
            test_ref="tests/test_report.py",
        ),
        CapabilityCoverage(
            id="CAP-7",
            name="Explotación efectiva y post-explotación",
            status="blocked",
            exercised_in_run=False,
            detail=("No implementado por diseño (ADR-002). Controles: `Tier.EXPLOIT` rechazado en scope.py y `credential_attack_guard` en auth.py. Sin payloads, sin entrega de exploits, sin persistencia."),
            code_ref="sentinel/scope.py, sentinel/auth.py",
            test_ref="tests/test_controls.py",
        ),
    ]


def _prepare(scope_path: str, out_dir: str, run_id: str | None = None) -> tuple[Scope, AuditLog, ScopeGuard, str]:
    scope = Scope.from_file(scope_path)
    run_id = run_id or uuid.uuid4().hex[:12]
    os.makedirs(out_dir, exist_ok=True)
    audit_path = os.path.join(out_dir, f"audit-{scope.engagement_id}-{run_id}.jsonl")
    audit = AuditLog(audit_path, scope.engagement_id, scope.operator, run_id=run_id)
    audit.record("run_start", "info", detail={"scope_file": scope_path, "mode": scope.max_tier})
    guard = ScopeGuard(scope, audit)
    return scope, audit, guard, audit_path


def _finish(assessment: Assessment, audit: AuditLog, audit_path: str) -> Assessment:
    assessment.finished_at = utcnow()
    audit.record("run_finish", "info", detail={
        "findings": len(assessment.findings),
        "assets": len(assessment.assets),
        "guard_stats": {},
    })
    assessment.audit_path = audit_path
    assessment.audit_chain = verify_chain(audit_path)
    return assessment


# ------------------------------------------------------------------- local
def assess_local(scope_path: str, out_dir: str, run_id: str | None = None) -> RunResult:
    scope, audit, guard, audit_path = _prepare(scope_path, out_dir, run_id)
    assessment = Assessment(
        engagement_id=scope.engagement_id,
        operator=scope.operator,
        target_mode="local_host",
        scope_summary=scope.summary(),
        run_id=audit.run_id,
    )

    facts = collect_local_facts(guard)
    asset = Asset(host=facts.host, role="local_host", os=facts.os)
    asset.evidence.extend(facts.evidence)
    assessment.assets.append(asset)

    findings: list[Finding] = []
    skipped: list[dict[str, Any]] = []

    # --- SSH configuration -------------------------------------------------
    guard.check_local("check:sshd_config")
    ssh_findings = ssh.analyze_sshd(facts)
    findings.extend(ssh_findings)
    if not ssh_findings:
        skipped.append({
            "check": "SSH-*",
            "reason": "no se encontró /etc/ssh/sshd_config legible; la evaluación de hardening SSH no se ejecutó",
        })

    # --- authentication policy --------------------------------------------
    guard.check_local("check:authentication_policy")
    findings.extend(auth.analyze_password_policy(facts))
    findings.extend(auth.analyze_account_database(facts))

    # --- privilege escalation analysis ------------------------------------
    priv_findings, priv_skipped, posture = privesc.analyze_all(guard, facts)
    findings.extend(priv_findings)
    skipped.extend(priv_skipped)
    asset.evidence.append(Evidence(
        kind="privilege_posture",
        asset=facts.host,
        summary="Postura de privilegios (sin explotación)",
        data=posture,
        source="engine.assess_local",
    ))

    # --- file permission baseline -----------------------------------------
    findings.extend(_permission_checks(facts))

    assessment.add_findings(findings)
    assessment.skipped.extend(skipped)
    assessment.coverage = coverage_table("local")
    # CAP-1 in local mode does not scan the network.
    for cap in assessment.coverage:
        if cap.id == "CAP-1":
            cap.detail = ("Inventario local (identidad, SO, cuentas, configuración, permisos). "
                          "El descubrimiento de red (Tier 2) no se ejecutó en este modo.")
    assessment.skipped.append({
        "check": "CAP-1.network",
        "reason": "modo local: no se abrieron conexiones TCP (el objetivo elegido es el propio host)",
    })

    assessment = _finish(assessment, audit, audit_path)
    audit.record("guard_stats", "info", detail=guard.stats.to_dict())

    return RunResult(
        assessment=assessment,
        scope=scope,
        evidence_dir=out_dir,
        audit_path=audit_path,
        out_dir=out_dir,
    )


def _permission_checks(facts) -> list[Finding]:
    findings: list[Finding] = []
    sshd = (facts.permissions or {}).get("sshd_config") or {}
    if sshd.get("present") and sshd.get("world_writable"):
        findings.append(Finding(
            asset=facts.host,
            check_id="CFG-SSHD-WRITABLE",
            title="sshd_config es escribible por cualquier usuario",
            category="configuration",
            severity=Severity.CRITICAL,
            impact=("Cualquier usuario local puede modificar la configuración del servidor SSH (por ejemplo "
                    "habilitar PermitRootLogin o PermitEmptyPasswords) y obtener control administrativo."),
            remediation="`chmod 644 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config`.",
            evidence=[Evidence(kind="file_permissions", asset=facts.host,
                               summary="permisos de sshd_config", data=sshd, source="engine")],
            tags=["configuration", "permissions"],
        ))
    return findings


# ----------------------------------------------------------------- network
MAX_HOSTS_PER_TARGET = 256


def _expand_targets(scope: Scope) -> list[tuple[str, list[int]]]:
    out: list[tuple[str, list[int]]] = []
    for target in scope.targets:
        if target.kind == "local_host":
            continue
        ports = list(target.ports)
        if target.kind == "host":
            out.append((target.value, ports))
        else:
            net = ipaddress.ip_network(target.value, strict=False)
            hosts = list(net.hosts())[:MAX_HOSTS_PER_TARGET]
            for ip in hosts:
                out.append((str(ip), ports))
    return out


def assess_network(scope_path: str, out_dir: str, run_id: str | None = None,
                   progress: Callable[[str], None] | None = None,
                   timeout: float = DEFAULT_TIMEOUT) -> RunResult:
    scope, audit, guard, audit_path = _prepare(scope_path, out_dir, run_id)
    assessment = Assessment(
        engagement_id=scope.engagement_id,
        operator=scope.operator,
        target_mode="network",
        scope_summary=scope.summary(),
        run_id=audit.run_id,
    )
    advisories = exposure.load_advisories()
    findings: list[Finding] = []
    skipped: list[dict[str, Any]] = []

    for host, ports in _expand_targets(scope):
        if progress:
            progress(f"scan {host} ({len(ports)} puertos)")
        try:
            asset = scan_host(guard, host, ports, max_workers=4, timeout=timeout)
        except ScopeViolation as exc:
            skipped.append({"check": f"scan:{host}", "reason": str(exc)})
            continue
        assessment.assets.append(asset)
        for service in asset.services:
            findings.extend(exposure.analyze_service(service, advisories))
            findings.extend(web.analyze_service_web(service))
        skipped.append({
            "check": f"auth-probe:{host}",
            "reason": "no se enviaron credenciales ni se probaron vectores de autenticación (ADR-005)",
        })

    assessment.add_findings(findings)
    assessment.skipped.extend(skipped)
    assessment.coverage = coverage_table("network")
    assessment = _finish(assessment, audit, audit_path)
    audit.record("guard_stats", "info", detail=guard.stats.to_dict())
    return RunResult(assessment=assessment, scope=scope, evidence_dir=out_dir, audit_path=audit_path, out_dir=out_dir)


def run(scope_path: str, mode: str, out_dir: str, run_id: str | None = None) -> RunResult:
    if mode == "local":
        return assess_local(scope_path, out_dir, run_id)
    if mode == "network":
        return assess_network(scope_path, out_dir, run_id)
    raise ScopeError(f"unknown mode: {mode}")
