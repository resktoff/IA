"""Report generation: Markdown, self-contained HTML and JSON.

Rules the renderer follows:

* A finding's ``confidence`` and ``validation_state`` are always printed next to
  the severity, so an inferred CVE match cannot be mistaken for a proven
  vulnerability.
* Estimé CVSS vectors are marked ``(estimado)``; published advisory vectors are
  marked ``(publicado)``.
* Each evidence block prints its SHA-256 digest, which makes the report
  verifiable against the JSON artefact.
* Every report contains the capability table, including the capabilities that
  were **not** implemented.
"""

from __future__ import annotations

import html
import json
import os
from typing import Any

from .model import Assessment, Finding, Severity
from .redact import redact_obj

SEVERITY_ORDER = ("critical", "high", "medium", "low", "none")
SEVERITY_LABEL = {
    "critical": "CRÍTICO",
    "high": "ALTO",
    "medium": "MEDIO",
    "low": "BAJO",
    "none": "INFO",
}
CONFIDENCE_LABEL = {
    "confirmed": "confirmado",
    "inferred": "inferido",
    "hypothesis": "hipótesis",
}
VALIDATION_LABEL = {
    "observed": "observado",
    "inferred": "inferido",
    "not_validated": "no validado",
    "blocked_by_policy": "bloqueado por política",
}

NOT_IMPLEMENTED = [
    ("Explotación de vulnerabilidades", "ADR-002",
     "Entrega de payloads, weaponización de PoCs, bypass de mitigaciones y post-explotación. Convierte el "
     "entregable en una herramienta de intrusión reutilizable y no es necesario para el objetivo de "
     "evaluación."),
    ("Ataques de credenciales", "ADR-005",
     "Fuerza bruta, password spraying, prueba de credenciales por defecto y prueba de bloqueo por fallos "
     "deliberados. Cambia el estado del servidor y puede dejar cuentas reales bloqueadas."),
    ("Validación activa de escalamiento de privilegios", "ADR-006",
     "Ejecución de binarios SUID vulnerables, comandos sudo o unidades systemd creadas por el agente. "
     "Se entrega la hipótesis con prerrequisitos y se delega la validación al operador en laboratorio."),
    ("Detección de versiones TLS heredadas por downgrade", "ADR-009",
     "Probar TLS 1.0/1.1 requiere bajar el nivel de seguridad de OpenSSL en todo el proceso. Se reporta "
     "solo la versión negociada observada."),
    ("Enumeración de usuarios remota y fingerprinting de SO", "ADR-010",
     "Aumenta el ruido y la intrusividad sin mejorar la decisión de remediación; se prioriza la "
     "evidencia de configuración."),
]

DECISIONS = [
    ("ADR-001", "Default deny con allowlist de alcance y autorización explícita",
     "Toda acción requiere engagement válido, referencia de autorización y host/puerto declarados."),
    ("ADR-002", "Tier 3 (explotación) bloqueado en código, no en documentación",
     "`Tier.EXPLOIT` se rechaza aunque el archivo de alcance lo pida; el alcance se degrada al cargar."),
    ("ADR-003", "Un solo tipo de escaneo: TCP connect",
     "Sin sockets crudos ni SYN scan: el escaneo queda registrado por el objetivo y no sirve como scanner stealth."),
    ("ADR-004", "Rangos públicos y metadatos cloud bloqueados sin doble opt-in",
     "169.254.0.0/16, multicast, reservados y direcciones globales quedan fuera salvo flag explícito por target y por scope."),
    ("ADR-005", "Sin ataques de credenciales",
     "La superficie existe y lanza `CapabilityBlocked`; el análisis se limita a política y atributos observados."),
    ("ADR-006", "Privilegios: hipótesis, no exploits",
     "Se publica clase de técnica y prerrequisitos; no se incluyen secuencias de comandos ni payloads."),
    ("ADR-007", "CVSS v3.1 solo base",
     "Sin métricas temporales ni ambientales: no se dispone de madurez de exploit ni de criticidad del activo."),
    ("ADR-008", "Vectores CVSS de configuración marcados como estimados",
     "Los hallazgos sin CVE llevan vector elegido por el agente y se rotulan `(estimado)`."),
    ("ADR-009", "Sin downgrade de TLS",
     "No se baja el security level de OpenSSL; se reporta la versión negociada y se documenta el límite."),
    ("ADR-010", "Sin enumeración remota de usuarios ni fingerprint de SO",
     "Coste/beneficio desfavorable y mayor intrusividad."),
    ("ADR-011", "Auditoría encadenada por hash y kill switch por archivo",
     "Cada acción y cada rechazo se registran antes de ejecutarse; `touch STOP` detiene la ejecución."),
    ("ADR-012", "Sin secretos en el informe",
     "No se leen /etc/shadow ni cuerpos de respuesta por defecto; el renderer redacta claves sensibles."),
]


# ------------------------------------------------------------------ helpers
def _counts(a: Assessment) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in a.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _fmt_score(f: Finding) -> str:
    if f.cvss_score is None:
        return "—"
    origin = "publicado" if f.check_id.startswith("ADV-") else "estimado"
    return f"{f.cvss_score:.1f} ({origin})"


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _evidence_json(ev: dict[str, Any], limit: int = 1400) -> str:
    data = json.dumps(redact_obj(ev.get("data", {})), indent=2, ensure_ascii=False, default=str)
    if len(data) > limit:
        data = data[:limit] + "\n… (truncado; ver el JSON adjunto)"
    return data


def _mk_table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(_md_escape(c) for c in row) + " |")
    return "\n".join(out)


# ---------------------------------------------------------------- markdown
def build_markdown(a: Assessment) -> str:
    counts = _counts(a)
    lines: list[str] = []
    add = lines.append

    add(f"# Informe técnico — Evaluación de seguridad\n")
    add(f"| Campo | Valor |")
    add(f"|---|---|")
    add(f"| Engagement | `{a.engagement_id}` |")
    add(f"| Cliente | {a.scope_summary.get('client', '—')} |")
    add(f"| Operador | {a.operator} |")
    add(f"| Run ID | `{a.run_id}` |")
    add(f"| Modo | `{a.target_mode}` |")
    add(f"| Inicio / fin | {a.started_at} → {a.finished_at} |")
    add(f"| Autorización | {a.scope_summary.get('authorization_ref')} (aprobada por "
        f"{a.scope_summary.get('approved_by')}) |")
    add(f"| Clasificación del documento | Confidencial — partes autorizadas |")
    add("")

    add("## 1. Resumen ejecutivo")
    add("")
    add(f"Se identificaron **{len(a.findings)} hallazgos** sobre **{len(a.assets)} activos**: "
        + ", ".join(f"{counts[s]} {SEVERITY_LABEL[s].lower()}" for s in SEVERITY_ORDER if counts[s]) + ".")
    add("")
    if a.findings:
        top = a.sorted_findings()[:5]
        add(_mk_table(
            ["ID", "Severidad", "Hallazgo", "Activo", "Confianza"],
            [[f.id, SEVERITY_LABEL[f.severity.value], f.title, f"{f.asset}:{f.port}" if f.port else f.asset,
              CONFIDENCE_LABEL[f.confidence.value]] for f in top],
        ))
        add("")
    add("**Qué se hizo en esta ejecución**")
    add("")
    for cap in a.coverage:
        if cap.exercised_in_run:
            add(f"- {cap.name} — {cap.status}: {cap.detail}")
    add("")
    add("**Qué no se hizo (y por qué)**")
    add("")
    add("- No se envió ningún exploit ni payload y no se intentó post-explotación (ADR-002).")
    add("- No se enviaron credenciales ni se provocaron bloqueos de cuenta (ADR-005).")
    add("- No se ejecutaron binarios SUID, comandos sudo ni unidades systemd para validar hipótesis (ADR-006).")
    add("- Las coincidencias CVE por versión son **inferencias**, no pruebas de explotabilidad.")
    add("")

    add("## 2. Autorización, alcance y controles")
    add("")
    s = a.scope_summary
    add(_mk_table(["Campo", "Valor"], [
        ["Referencia de autorización", s.get("authorization_ref", "—")],
        ["Aprobada por", s.get("approved_by", "—")],
        ["Vigencia", f"{s.get('valid_from')} → {s.get('expires_at')}"],
        ["Tier máximo permitido", str(s.get("max_tier"))],
        ["Presupuesto de peticiones", str(s.get("max_requests"))],
        ["Tasa máxima", f"{s.get('rate_per_second')} req/s"],
        ["Kill switch", s.get("killswitch_path") or "(no configurado)"],
        ["Archivo de alcance", s.get("scope_file") or "—"],
    ]))
    add("")
    add("**Objetivos declarados**")
    add("")
    add(_mk_table(["Tipo", "Objetivo", "Puertos", "Tier máx."],
                  [[t["kind"], t["value"], t["ports"], str(t["max_tier"])] for t in s.get("targets", [])]))
    add("")
    add("Controles activos durante la ejecución (implementados en código, no solo documentados):")
    add("")
    add("| Control | Implementación |")
    add("|---|---|")
    add("| Allowlist default-deny de hosts y puertos | `sentinel/scope.py::ScopeGuard.check` |")
    add("| Autorización explícita obligatoria | `Scope.from_dict` rechaza alcances sin `authorized=true` |")
    add("| Tier 3 (explotación) inalcanzable | `Tier.EXPLOIT` rechazado antes de cualquier I/O |")
    add("| Presupuesto y rate limit | token bucket + contador duro por engagement |")
    add("| Kill switch | archivo de parada comprobado en cada acción |")
    add("| Auditoría encadenada | `sentinel/audit.py`, SHA-256 por registro |")
    add("| Redacción de secretos | `sentinel/redact.py` en el renderer |")
    add("")

    add("## 3. Metodología y límites")
    add("")
    add(_mk_table(["Tier", "Nombre", "Qué incluye", "Estado en el agente"], [
        ["1", "DETECT", "Lectura de configuración y hechos locales, correlación offline", "implementado"],
        ["2", "VALIDATE", "TCP connect, banner, una petición HTTP, handshake TLS", "implementado"],
        ["3", "EXPLOIT", "Entrega de exploits, credenciales, post-explotación", "**bloqueado**"],
    ]))
    add("")
    add("Escala de confianza usada en todos los hallazgos:")
    add("")
    add("- **confirmado**: el estado se observó directamente (cabecera ausente, directiva presente, permiso de archivo).")
    add("- **inferido**: derivado de un banner o de una versión; puede ser falso si el servicio miente o el "
        "paquete está parcheado sin cambiar la versión.")
    add("- **hipótesis**: ruta plausible de escalamiento o de ataque; requiere validación manual.")
    add("")

    add("## 4. Cobertura de capacidades")
    add("")
    add(_mk_table(["ID", "Capacidad", "Estado", "Ejercitada en esta corrida", "Detalle"],
                  [[c.id, c.name, c.status, "sí" if c.exercised_in_run else "**no**", c.detail]
                   for c in a.coverage]))
    add("")
    add("Estados: `implemented` (código funcional con tests), `partial` (análisis sin validación activa por "
        "diseño), `blocked` (no implementado, con control explícito que lo impide).")
    add("")

    add("## 5. Hallazgos")
    add("")
    if not a.findings:
        add("No se registraron hallazgos con la evidencia recolectada.")
        add("")
    else:
        add("### 5.1 Tabla resumen")
        add("")
        add(_mk_table(["ID", "Sev.", "CVSS", "Confianza", "Validación", "Hallazgo", "Activo"],
                      [[f.id, SEVERITY_LABEL[f.severity.value], _fmt_score(f),
                        CONFIDENCE_LABEL[f.confidence.value], VALIDATION_LABEL[f.validation_state.value],
                        f.title, f"{f.asset}:{f.port}" if f.port else f.asset]
                       for f in a.sorted_findings()]))
        add("")
        add("### 5.2 Detalle")
        add("")
        for f in a.sorted_findings():
            add(f"#### {f.id} — {f.title}")
            add("")
            meta = [
                ["Severidad", f"{SEVERITY_LABEL[f.severity.value]} ({f.severity.value})"],
                ["CVSS v3.1 base", _fmt_score(f)],
                ["Vector", f"`{f.cvss_vector}`" if f.cvss_vector else "—"],
                ["Categoría", f.category],
                ["Activo", f"{f.asset}" + (f":{f.port}" if f.port else "")],
                ["Confianza", CONFIDENCE_LABEL[f.confidence.value]],
                ["Estado de validación", VALIDATION_LABEL[f.validation_state.value]],
                ["Check", f"`{f.check_id}`"],
            ]
            if f.manual_validation_required:
                meta.append(["Validación manual requerida", "sí"])
            if f.prerequisites:
                meta.append(["Prerrequisitos", "; ".join(f.prerequisites)])
            add(_mk_table(["Campo", "Valor"], meta))
            add("")
            add(f"**Impacto.** {f.impact}")
            add("")
            add(f"**Recomendación.** {f.remediation}")
            add("")
            if f.notes:
                add(f"> {f.notes}")
                add("")
            if f.evidence:
                add("**Evidencia**")
                add("")
                for ev in f.evidence:
                    d = ev.to_dict()
                    add(f"- `{d['kind']}` — {d['summary']}")
                    add(f"  - fuente: `{d['source']}` · sha256: `{d['evidence_sha256'][:32]}…` · "
                        f"recolectado: {d['collected_at']}")
                    add("")
                    add("```json")
                    add(_evidence_json(d))
                    add("```")
                    add("")
            if f.references:
                add("**Referencias**")
                add("")
                for ref in f.references:
                    add(f"- {ref}")
                add("")

    add("## 6. Capacidades no implementadas")
    add("")
    add(_mk_table(["Capacidad", "ADR", "Motivo"],
                  [[name, adr, reason] for name, adr, reason in NOT_IMPLEMENTED]))
    add("")

    add("## 7. Registro de decisiones de seguridad")
    add("")
    add(_mk_table(["ADR", "Decisión", "Consecuencia"], [[i, d, c] for i, d, c in DECISIONS]))
    add("")
    add("El detalle completo, con alternativas descartadas y trazabilidad al código, está en "
        "`docs/DECISIONS.md`.")
    add("")

    add("## 8. Anexos")
    add("")
    chain = a.audit_chain or {}
    add("### A. Cadena de auditoría")
    add("")
    add(_mk_table(["Campo", "Valor"], [
        ["Archivo", a.audit_path or "—"],
        ["Integridad", "OK" if chain.get("ok") else f"FALLIDA — {chain.get('reason')}"],
        ["Registros", str(chain.get("records"))],
        ["Hash de cabeza", f"`{chain.get('head')}`" if chain.get("head") else "—"],
    ]))
    add("")
    add("Cualquier modificación, borrado o reordenamiento de registros invalida la verificación "
        "(`python -m sentinel.cli verify-audit <archivo>`).")
    add("")
    add("### B. Comprobaciones no ejecutadas")
    add("")
    if a.skipped:
        add(_mk_table(["Check", "Motivo"], [[s.get("check", "?"), s.get("reason", "")] for s in a.skipped]))
    else:
        add("Ninguna.")
    add("")
    add("### C. Reproducibilidad")
    add("")
    add("```bash")
    add(f"python -m sentinel.cli assess --scope <scope.json> --mode {a.target_mode} --out evidence")
    add(f"python -m sentinel.cli verify-audit {a.audit_path or '<audit.jsonl>'}")
    add("python -m unittest discover -s tests -v")
    add("```")
    add("")
    add("### D. Limitaciones aplicables")
    add("")
    add("- La correlación CVE usa un subconjunto curado offline de avisos; no sustituye a un feed con "
        "backports de la distribución.")
    add("- El escaneo de puertos cubre exclusivamente los puertos declarados en el alcance.")
    add("- Los hallazgos de configuración evalúan el archivo tal como está en disco; no se consultó la "
        "configuración efectiva via `sshd -T`.")
    add("- No se evaluó comportamiento en runtime (WAF, rate limiting real, lógica de negocio).")
    add("")
    add("---")
    add("")
    add("_Informe generado por `sentinel` a partir de evidencia recolectada en la ejecución indicada. Las "
        "capacidades marcadas como `partial` o `blocked` no fueron ejecutadas y no deben interpretarse como "
        "validadas. Este documento no certifica la ausencia de vulnerabilidades._")
    return "\n".join(lines)


# -------------------------------------------------------------------- HTML
HTML_CSS = """
:root { color-scheme: light; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin: 0; padding: 32px; background: #f6f7f9; color: #16181d; line-height: 1.55; }
main { max-width: 1040px; margin: 0 auto; background: #fff; padding: 40px 48px;
       box-shadow: 0 1px 3px rgba(0,0,0,.12); border-radius: 8px; }
h1 { font-size: 28px; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 { font-size: 20px; margin-top: 40px; border-bottom: 1px solid #e6e8ec; padding-bottom: 6px; }
h3 { font-size: 16px; margin-top: 28px; }
h4 { font-size: 15px; margin: 24px 0 8px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0 20px; font-size: 13.5px; }
th, td { border: 1px solid #e6e8ec; padding: 7px 10px; text-align: left; vertical-align: top; }
th { background: #f2f4f7; font-weight: 600; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
pre { background: #f6f7f9; padding: 12px 14px; border-radius: 6px; overflow-x: auto;
      border: 1px solid #e6e8ec; max-height: 420px; }
.sev { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11.5px;
       font-weight: 700; letter-spacing: .03em; text-transform: uppercase; }
.sev-critical { background: #fde2e1; color: #8a1c1c; }
.sev-high { background: #ffe8d5; color: #8a4b12; }
.sev-medium { background: #fff4cc; color: #6b5300; }
.sev-low { background: #e3f0ff; color: #1c4a8a; }
.sev-none { background: #eceff3; color: #47505c; }
.meta { color: #5b6472; font-size: 13px; }
.note { background: #fff8e6; border-left: 3px solid #d9a300; padding: 10px 14px; margin: 14px 0; font-size: 13.5px; }
.ok { color: #146c2e; font-weight: 600; }
.bad { color: #8a1c1c; font-weight: 600; }
.blocked { background: #f2f4f7; border-left: 3px solid #47505c; padding: 10px 14px; margin: 12px 0; }
.pill { display: inline-block; border: 1px solid #d5d9e0; border-radius: 999px; padding: 0 8px;
        font-size: 11.5px; color: #47505c; }
footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid #e6e8ec; color: #5b6472; font-size: 12.5px; }
@media print { body { background: #fff; padding: 0; } main { box-shadow: none; padding: 0; } }
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _sev_badge(sev: str) -> str:
    return f'<span class="sev sev-{_e(sev)}">{_e(SEVERITY_LABEL.get(sev, sev))}</span>'


def _html_table(header: list[str], rows: list[list[str]], escape: bool = True) -> str:
    cells = "".join(f"<th>{_e(h)}</th>" for h in header)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{_e(c) if escape else c}</td>" for c in row) + "</tr>"
    return f"<table><thead><tr>{cells}</tr></thead><tbody>{body}</tbody></table>"


def build_html(a: Assessment) -> str:
    counts = _counts(a)
    s = a.scope_summary
    parts: list[str] = []
    add = parts.append

    add("<!doctype html><html lang='es'><head><meta charset='utf-8'>")
    add(f"<title>Informe de evaluación — {_e(a.engagement_id)}</title>")
    add(f"<style>{HTML_CSS}</style></head><body><main>")
    add("<h1>Informe técnico de evaluación de seguridad</h1>")
    add(f"<p class='meta'>Engagement <code>{_e(a.engagement_id)}</code> · {_e(s.get('client', ''))} · "
        f"operador {_e(a.operator)} · run <code>{_e(a.run_id)}</code> · modo <code>{_e(a.target_mode)}</code> · "
        f"{_e(a.started_at)} → {_e(a.finished_at)}</p>")
    add(f"<p class='meta'>Autorización: {_e(s.get('authorization_ref'))} (aprobada por "
        f"{_e(s.get('approved_by'))}) · vigencia {_e(s.get('valid_from'))} → {_e(s.get('expires_at'))}</p>")

    add("<h2>1. Resumen ejecutivo</h2>")
    add(f"<p><strong>{len(a.findings)} hallazgos</strong> sobre {len(a.assets)} activos: "
        + ", ".join(f"{counts[k]} {SEVERITY_LABEL[k].lower()}" for k in SEVERITY_ORDER if counts[k]) + ".</p>")
    add("<div class='note'><strong>Alcance de la evidencia.</strong> Solo los hallazgos con confianza "
        "«confirmado» se basan en estado observado. Las coincidencias CVE por versión son inferencias y las "
        "rutas de escalamiento son hipótesis sin validar. No se envió ningún exploit ni credencial.</div>")
    rows = []
    for f in a.sorted_findings()[:8]:
        rows.append([f.id, _sev_badge(f.severity.value), _fmt_score(f),
                     CONFIDENCE_LABEL[f.confidence.value], f.title, f"{f.asset}:{f.port}" if f.port else f.asset])
    if rows:
        add("<table><thead><tr><th>ID</th><th>Severidad</th><th>CVSS</th><th>Confianza</th>"
            "<th>Hallazgo</th><th>Activo</th></tr><tbody>")
        for r in rows:
            add("<tr>" + "".join(f"<td>{c if i == 1 else _e(c)}</td>" for i, c in enumerate(r)) + "</tr>")
        add("</tbody></table>")

    add("<h2>2. Autorización, alcance y controles</h2>")
    add(_html_table(["Campo", "Valor"], [
        ["Referencia de autorización", s.get("authorization_ref", "—")],
        ["Aprobada por", s.get("approved_by", "—")],
        ["Vigencia", f"{s.get('valid_from')} → {s.get('expires_at')}"],
        ["Tier máximo", s.get("max_tier")],
        ["Presupuesto de peticiones", s.get("max_requests")],
        ["Tasa máxima", f"{s.get('rate_per_second')} req/s"],
        ["Kill switch", s.get("killswitch_path") or "(no configurado)"],
    ]))
    add(_html_table(["Tipo", "Objetivo", "Puertos", "Tier máx."],
                    [[t["kind"], t["value"], t["ports"], t["max_tier"]] for t in s.get("targets", [])]))
    add("<p class='meta'>Controles implementados: allowlist default-deny, autorización explícita, "
        "Tier 3 inalcanzable, rate limit + presupuesto, kill switch, auditoría encadenada, redacción de "
        "secretos.</p>")

    add("<h2>3. Cobertura de capacidades</h2>")
    add("<table><thead><tr><th>ID</th><th>Capacidad</th><th>Estado</th><th>Ejercitada</th>"
        "<th>Detalle</th></tr></thead><tbody>")
    for c in a.coverage:
        cls = "ok" if c.status == "implemented" else ("bad" if c.status == "blocked" else "meta")
        add(f"<tr><td>{_e(c.id)}</td><td>{_e(c.name)}</td><td class='{cls}'>{_e(c.status)}</td>"
            f"<td>{'sí' if c.exercised_in_run else '<strong>no</strong>'}</td><td>{_e(c.detail)}</td></tr>")
    add("</tbody></table>")

    add("<h2>4. Hallazgos</h2>")
    if not a.findings:
        add("<p>No se registraron hallazgos con la evidencia recolectada.</p>")
    for f in a.sorted_findings():
        add(f"<h3>{_e(f.id)} — {_e(f.title)}</h3>")
        add(f"<p>{_sev_badge(f.severity.value)} <span class='pill'>CVSS {_e(_fmt_score(f))}</span> "
            f"<span class='pill'>confianza: {_e(CONFIDENCE_LABEL[f.confidence.value])}</span> "
            f"<span class='pill'>validación: {_e(VALIDATION_LABEL[f.validation_state.value])}</span></p>")
        add(_html_table(["Campo", "Valor"], [
            ["Activo", f"{f.asset}" + (f":{f.port}" if f.port else "")],
            ["Categoría", f.category],
            ["Vector CVSS", f.cvss_vector or "—"],
            ["Check", f.check_id],
            ["Prerrequisitos", "; ".join(f.prerequisites) or "—"],
            ["Validación manual", "sí" if f.manual_validation_required else "no"],
        ]))
        add(f"<p><strong>Impacto.</strong> {_e(f.impact)}</p>")
        add(f"<p><strong>Recomendación.</strong> {_e(f.remediation)}</p>")
        if f.notes:
            add(f"<div class='note'>{_e(f.notes)}</div>")
        for ev in f.evidence:
            d = ev.to_dict()
            add(f"<h4>Evidencia · <code>{_e(d['kind'])}</code></h4>")
            add(f"<p class='meta'>{_e(d['summary'])} · fuente <code>{_e(d['source'])}</code> · "
                f"sha256 <code>{_e(d['evidence_sha256'][:40])}…</code></p>")
            add(f"<pre>{_e(_evidence_json(d))}</pre>")
        if f.references:
            add("<p class='meta'>Referencias: " + " · ".join(_e(r) for r in f.references) + "</p>")

    add("<h2>5. Capacidades no implementadas</h2>")
    for name, adr, reason in NOT_IMPLEMENTED:
        add(f"<div class='blocked'><strong>{_e(name)}</strong> <span class='pill'>{_e(adr)}</span><br>"
            f"<span class='meta'>{_e(reason)}</span></div>")

    add("<h2>6. Registro de decisiones de seguridad</h2>")
    add(_html_table(["ADR", "Decisión", "Consecuencia"], [[i, d, c] for i, d, c in DECISIONS]))

    chain = a.audit_chain or {}
    add("<h2>7. Auditoría y anexos</h2>")
    add(f"<p>Cadena de auditoría: "
        + (f"<span class='ok'>íntegra</span> ({chain.get('records')} registros, cabeza "
           f"<code>{_e((chain.get('head') or '')[:24])}…</code>)" if chain.get("ok")
           else f"<span class='bad'>FALLIDA</span> — {_e(chain.get('reason'))}")
        + f" · archivo <code>{_e(a.audit_path or '—')}</code></p>")
    if a.skipped:
        add("<h4>Comprobaciones no ejecutadas</h4>")
        add(_html_table(["Check", "Motivo"], [[x.get("check", "?"), x.get("reason", "")] for x in a.skipped]))

    add("<footer>Generado por <code>sentinel</code>. Las capacidades <code>partial</code> y "
        "<code>blocked</code> no se ejecutaron. Este informe no certifica la ausencia de "
        "vulnerabilidades.</footer>")
    add("</main></body></html>")
    return "\n".join(parts)


# -------------------------------------------------------------------- write
def build_json(a: Assessment) -> dict[str, Any]:
    payload = a.to_dict()
    payload["report"] = {
        "generator": "sentinel",
        "not_implemented": [{"capability": n, "adr": i, "reason": r} for n, i, r in NOT_IMPLEMENTED],
        "decisions": [{"id": i, "decision": d, "consequence": c} for i, d, c in DECISIONS],
    }
    return redact_obj(payload)


def write_reports(a: Assessment, out_dir: str, basename: str | None = None) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    base = basename or f"report-{a.engagement_id}-{a.run_id}"
    paths = {
        "markdown": os.path.join(out_dir, f"{base}.md"),
        "html": os.path.join(out_dir, f"{base}.html"),
        "json": os.path.join(out_dir, f"{base}.json"),
    }
    with open(paths["markdown"], "w", encoding="utf-8") as fh:
        fh.write(build_markdown(a))
    with open(paths["html"], "w", encoding="utf-8") as fh:
        fh.write(build_html(a))
    with open(paths["json"], "w", encoding="utf-8") as fh:
        json.dump(build_json(a), fh, indent=2, ensure_ascii=False, default=str)
    return paths
