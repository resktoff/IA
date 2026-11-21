"""Privilege-escalation *analysis* from read-only facts (Tier 1, DETECT).

The agent enumerates the inputs that a privilege-escalation path needs — sudo
rules, SUID binaries, file capabilities, writable cron jobs, writable PATH
entries, writable systemd units — and ranks them as **hypotheses**.  It never
executes the binary, never runs the sudo command and never writes a payload.

Each hypothesis carries:
* ``confidence`` (``hypothesis`` unless the state itself proves the path),
* ``prerequisites`` (what must also be true for the path to work),
* ``manual_validation_required = True``,
* a technique *class* and a reference, never a command sequence (ADR-006).

That boundary is the difference between "there is a plausible escalation
path here, verify it in a lab" and a working exploit.
"""

from __future__ import annotations

import os
import re
from typing import Any

from .model import Confidence, Finding, Severity, Tier, ValidationState
from .scope import ScopeGuard

# Binary -> technique class.  Classes only: no flags, no one-liners.
GTFOBINS_CLASSES = {
    "bash": "shell directa con privilegios del propietario",
    "sh": "shell directa con privilegios del propietario",
    "dash": "shell directa con privilegios del propietario",
    "env": "ejecución de un comando arbitrario",
    "find": "ejecución de comandos (-exec)",
    "vim": "shell escape desde el editor",
    "vi": "shell escape desde el editor",
    "nano": "shell escape vía editor/fichero de configuración",
    "less": "shell escape desde el paginador",
    "more": "shell escape desde el paginador",
    "man": "shell escape desde el paginador",
    "awk": "ejecución de comandos desde el lenguaje",
    "gawk": "ejecución de comandos desde el lenguaje",
    "python": "ejecución de código interpretado",
    "python3": "ejecución de código interpretado",
    "perl": "ejecución de código interpretado",
    "ruby": "ejecución de código interpretado",
    "node": "ejecución de código interpretado",
    "php": "ejecución de código interpretado",
    "lua": "ejecución de código interpretado",
    "tar": "ejecución de comandos vía checkpoint",
    "zip": "ejecución de comandos vía opción de compresión",
    "git": "ejecución vía hooks/pager",
    "gdb": "ejecución de comandos desde el depurador",
    "systemctl": "ejecución vía unidad creada por el atacante",
    "docker": "acceso al filesystem del host vía contenedor",
    "podman": "acceso al filesystem del host vía contenedor",
    "cp": "escritura arbitraria como root",
    "tee": "escritura arbitraria como root",
    "dd": "escritura arbitraria como root",
    "chmod": "cambio de permisos arbitrario",
    "chown": "cambio de propietario arbitrario",
    "mount": "montaje de filesystem controlado",
    "ssh": "ejecución vía opciones de proxy",
    "rsync": "escritura arbitraria vía -e",
    "nmap": "modo interactivo con ejecución",
    "apt": "ejecución vía hook de APT",
    "apt-get": "ejecución vía hook de APT",
}

EXPECTED_SUID_BASENAMES = {
    "chfn", "chsh", "gpasswd", "mount", "newgrp", "passwd", "su", "umount", "sudo", "pkexec",
    "fusermount", "fusermount3", "mount.nfs", "expiry", "sg", "at", "wall", "write", "chage",
    "unix_chkpwd", "pam_extrausers_chkpwd", "dbus-daemon-launch-helper", "postdrop", "postqueue",
    "newuidmap", "newgidmap", "snap-confine", "chrome-sandbox", "Xorg", "ssh-keysign",
}

RISKY_CAPABILITIES = {
    "cap_setuid": (Severity.HIGH, "permite cambiar de UID a cualquier valor"),
    "cap_setgid": (Severity.HIGH, "permite cambiar de GID a cualquier valor"),
    "cap_dac_read_search": (Severity.HIGH, "permite leer cualquier archivo (bypass de permisos)"),
    "cap_dac_override": (Severity.HIGH, "permite escribir/leer ignorando permisos"),
    "cap_sys_admin": (Severity.CRITICAL, "equivalente práctico a root (montajes, namespaces, ptrace)"),
    "cap_sys_ptrace": (Severity.HIGH, "permite inyectar en procesos de otros usuarios"),
    "cap_sys_module": (Severity.CRITICAL, "carga de módulos del kernel"),
    "cap_chown": (Severity.MEDIUM, "permite cambiar el propietario de archivos"),
    "cap_fowner": (Severity.MEDIUM, "permite cambiar permisos de archivos ajenos"),
    "cap_net_admin": (Severity.MEDIUM, "permite reconfigurar red e interceptar tráfico"),
}

INTERPRETER_PREFIXES = ("python", "perl", "ruby", "node", "php", "lua", "sh", "bash", "dash", "env", "tclsh", "expect")


def _is_interpreter(basename: str) -> bool:
    base = basename.lower()
    return any(base == prefix or base.startswith(prefix) for prefix in INTERPRETER_PREFIXES)

SENSITIVE_WRITABLE_ROOTS = ("/home", "/tmp", "/var/tmp", "/opt", "/srv", "/root")


def _finding(asset: str, check_id: str, key: str, **fields: Any) -> Finding:
    return Finding(asset=asset, check_id=check_id, fingerprint_seed=f"{asset}|{check_id}|{key}", **fields)


# --------------------------------------------------------------------- sudo
SUDO_RULE_RE = re.compile(r"^\((?P<runas>[^)]*)\)\s+(?P<rest>.+)$")


def parse_sudo_listing(text: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith(("matching defaults", "user ", "defaults", "runas")):
            continue
        if line.startswith("("):
            match = SUDO_RULE_RE.match(line)
            if not match:
                continue
            rest = match.group("rest").strip()
            nopasswd = False
            if rest.upper().startswith("NOPASSWD:"):
                nopasswd = True
                rest = rest.split(":", 1)[1].strip()
            commands = [c.strip() for c in rest.split(",") if c.strip()]
            for command in commands:
                rules.append({
                    "runas": match.group("runas").strip(),
                    "command": command,
                    "nopasswd": nopasswd,
                    "all": command.upper() in {"ALL", "(ALL) ALL"} or command == "ALL",
                })
    return rules


def analyze_sudo(facts) -> tuple[list[Finding], list[dict[str, Any]]]:
    asset = facts.host
    findings: list[Finding] = []
    skipped: list[dict[str, Any]] = []
    sudo = facts.sudo
    if sudo is None:
        return findings, [{"check": "PRIV-SUDO", "reason": "no se ejecutó sudo -n -l"}]
    if not sudo.ok:
        skipped.append({
            "check": "PRIV-SUDO",
            "reason": "`sudo -n -l` no devolvió la política (requiere contraseña o el usuario no está en sudoers)",
            "stderr": (sudo.stderr or "").strip()[:200],
            "exit_code": sudo.exit_code,
        })
        return findings, skipped

    rules = parse_sudo_listing(sudo.stdout)
    identity = facts.identity.get("user", "?")

    # Full-sudo rules are aggregated into one finding: reporting "(ALL) ALL"
    # four times (as Debian's default sudoers fragments do) would inflate the
    # count without adding information.
    all_rules = [r for r in rules if r["all"]]
    if all_rules:
        nopasswd = any(r["nopasswd"] for r in all_rules)
        runas = sorted({r["runas"] for r in all_rules})
        findings.append(_finding(
            asset, "PRIV-SUDO-ALL", "all|" + "|".join(runas),
            title=(f"La cuenta '{identity}' puede ejecutar cualquier comando como {', '.join(runas)}"
                   + (" sin contraseña" if nopasswd else "")),
            category="privilege_escalation",
            severity=Severity.CRITICAL if nopasswd else Severity.HIGH,
            impact=("No existe una frontera de privilegios que escalar para esta cuenta: ya es "
                    "administrativa. El riesgo relevante es que una credencial de esta cuenta "
                    "comprometida otorga control total"
                    + (", y NOPASSWD la hace utilizable sin segundo factor ni interacción" if nopasswd else "")
                    + "."),
            remediation=("Sustituir las reglas `ALL` por comandos concretos, eliminar NOPASSWD, habilitar "
                         "MFA en sudo (pam_google_authenticator) y registrar la sesión (`log_output`) en un "
                         "destino remoto."),
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "sudo_policy", {
                "identity": identity,
                "rules": all_rules,
                "normalised": [f"({r['runas']}) " + ("NOPASSWD: " if r["nopasswd"] else "") + r["command"]
                               for r in all_rules],
                "raw_listing": sudo.stdout.strip()[:2000],
            })],
            references=["https://www.sudo.ws/docs/man/sudoers.man/"],
            tags=["privesc", "sudo"],
            notes=("Hecho observado, no vulnerabilidad: describe el nivel de privilegio de la cuenta con la "
                   "que corre la evaluación. Es la línea base contra la que se miden las demás hipótesis."),
        ))
        rules = [r for r in rules if not r["all"]]

    for rule in rules:
        command = rule["command"]
        binary = os.path.basename(command.split()[0]) if command else ""
        all_commands = False

        if binary in GTFOBINS_CLASSES:
            findings.append(_finding(
                asset, "PRIV-SUDO-GTFOBIN", f"{rule['runas']}|{command}|{rule['nopasswd']}",
                title=f"Regla sudo sobre binario con escape de shell: {command}",
                category="privilege_escalation",
                severity=Severity.HIGH,
                impact=(f"El binario `{binary}` permite {GTFOBINS_CLASSES[binary]}; con esta regla, la "
                        f"cuenta '{identity}' obtendría una shell como {rule['runas']}."),
                remediation=(f"Eliminar la regla directa sobre `{binary}`; si se necesita esa función, "
                             "envolverla en un script con argumentos fijos y propiedad root (sudoers "
                             "permite fijar argumentos: `/ruta/script ""`)."),
                confidence=Confidence.HYPOTHESIS,
                validation_state=ValidationState.NOT_VALIDATED,
                tier_required=Tier.DETECT,
                prerequisites=[
                    f"la cuenta '{identity}' es la que ejecuta la evaluación o puede obtenerla",
                    f"la regla sudo sobre `{binary}` sigue vigente",
                    "la política de SELinux/AppArmor no restringe la ejecución",
                ],
                manual_validation_required=True,
                evidence=[_ev(asset, "sudo_policy", {"rule": rule, "technique_class": GTFOBINS_CLASSES[binary]})],
                references=["https://gtfobins.github.io/"],
                tags=["privesc", "sudo", "hypothesis"],
                notes="Clase de técnica, no secuencia de comandos (ADR-006). Validar manualmente en laboratorio.",
            ))
            continue

        if "*" in command or "?" in command:
            findings.append(_finding(
                asset, "PRIV-SUDO-WILDCARD", f"{rule['runas']}|{command}",
                title=f"Regla sudo con comodines: {command}",
                category="privilege_escalation",
                severity=Severity.MEDIUM,
                impact="Los comodines en sudoers permiten inyectar argumentos o rutas no previstas por el autor "
                       "de la política.",
                remediation="Fijar rutas y argumentos exactos; evitar `*` en la parte de comandos de sudoers.",
                confidence=Confidence.HYPOTHESIS,
                validation_state=ValidationState.NOT_VALIDATED,
                manual_validation_required=True,
                evidence=[_ev(asset, "sudo_policy", {"rule": rule})],
                tags=["privesc", "sudo"],
            ))

        path = command.split()[0]
        if path.startswith("/"):
            info = _path_writable(path)
            if info.get("writable_by_current_user"):
                findings.append(_finding(
                    asset, "PRIV-SUDO-WRITABLE-BINARY", path,
                    title=f"Binario referenciado por sudo es escribible: {path}",
                    category="privilege_escalation",
                    severity=Severity.CRITICAL,
                    impact="Cualquiera con permiso de escritura puede reemplazar el binario y obtener ejecución "
                           "con el usuario de la regla sudo.",
                    remediation="Corregir permisos del binario y del directorio contenedor (root:root, 0755).",
                    confidence=Confidence.CONFIRMED,
                    validation_state=ValidationState.OBSERVED,
                    evidence=[_ev(asset, "file_permissions", info)],
                    tags=["privesc", "sudo", "permissions"],
                ))
    return findings, skipped


# ---------------------------------------------------------------------- SUID
def analyze_suid(facts) -> list[Finding]:
    asset = facts.host
    findings: list[Finding] = []
    suid = facts.suid or {}
    if not suid.get("available"):
        return findings
    unexpected, sensitive = [], []
    for path in suid.get("paths", []):
        base = os.path.basename(path)
        if base in EXPECTED_SUID_BASENAMES:
            continue
        unexpected.append(path)
        if any(path.startswith(root + "/") or path == root for root in SENSITIVE_WRITABLE_ROOTS):
            sensitive.append(path)

    if unexpected:
        findings.append(_finding(
            asset, "PRIV-SUID-UNEXPECTED", "suid",
            title=f"{len(unexpected)} binario(s) SUID fuera de la línea base esperada",
            category="privilege_escalation",
            severity=Severity.HIGH if sensitive else Severity.MEDIUM,
            impact=("Un binario SUID ejecuta con los privilegios de su propietario. Si permite ejecutar "
                    "comandos, leer archivos arbitrarios o cargar bibliotecas, constituye una vía de "
                    "escalamiento para cualquier usuario local."),
            remediation=("Inventariar y justificar cada SUID; retirar el bit (`chmod u-s`) cuando no sea "
                         "imprescindible y preferir capabilities acotadas."),
            confidence=Confidence.HYPOTHESIS,
            validation_state=ValidationState.NOT_VALIDATED,
            manual_validation_required=True,
            prerequisites=["acceso local como usuario no privilegiado", "el binario no está restringido por AppArmor/SELinux"],
            evidence=[_ev(asset, "suid_inventory", {"unexpected": unexpected, "sensitive_paths": sensitive,
                                                    "scanned_roots": suid.get("scanned_roots", [])})],
            references=["https://gtfobins.github.io/#+suid"],
            tags=["privesc", "suid", "hypothesis"],
            notes="Inventario y clasificación; no se ejecutó ningún binario SUID.",
        ))
    return findings


# -------------------------------------------------------------- capabilities
CAP_RE = re.compile(r"^(?P<path>\S+)\s+(?P<caps>\S+)$")


def parse_capabilities(entries: list[str]) -> list[dict[str, Any]]:
    parsed = []
    for entry in entries:
        match = CAP_RE.match(entry.strip())
        if not match:
            continue
        caps = [c for c in match.group("caps").split("+")[0].split(",") if c]
        parsed.append({"path": match.group("path"), "raw": entry.strip(), "capabilities": caps})
    return parsed


def analyze_capabilities(facts) -> list[Finding]:
    asset = facts.host
    findings: list[Finding] = []
    cap_data = facts.capabilities or {}
    if not cap_data.get("available"):
        return findings

    for item in parse_capabilities(cap_data.get("entries", [])):
        risky = [(c, *RISKY_CAPABILITIES[c]) for c in item["capabilities"] if c in RISKY_CAPABILITIES]
        if not risky:
            continue
        base = os.path.basename(item["path"])
        worst = max((r[1] for r in risky), key=lambda s: s.rank)
        if _is_interpreter(base):
            worst = Severity.CRITICAL
        findings.append(_finding(
            asset, "PRIV-CAP-RISKY", item["path"],
            title=f"Capability peligrosa en {item['path']}: {', '.join(r[0] for r in risky)}",
            category="privilege_escalation",
            severity=worst,
            impact="; ".join(f"{c}: {desc}" for c, _sev, desc in risky),
            remediation=("Reemplazar el binario por uno con la mínima capability necesaria, o retirar "
                         "`cap_setuid`/`cap_dac_override`/`cap_sys_admin`; usar `ambient`/`bounding` "
                         "sets y monitorear con `getcap -r /`."),
            confidence=Confidence.HYPOTHESIS,
            validation_state=ValidationState.NOT_VALIDATED,
            manual_validation_required=True,
            prerequisites=["acceso local como usuario no privilegiado",
                           "el binario permite ejecutar código o escribir archivos arbitrarios"],
            evidence=[_ev(asset, "file_capabilities", item)],
            references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"],
            tags=["privesc", "capabilities", "hypothesis"],
        ))
    return findings


# --------------------------------------------------------- cron / systemd / PATH
def analyze_writable_jobs(facts) -> list[Finding]:
    asset = facts.host
    findings: list[Finding] = []
    for entry in facts.cron or []:
        if not entry.get("present") or entry.get("is_symlink"):
            continue
        is_dir = entry.get("mode", "").startswith("d")
        if entry.get("world_writable") or (entry.get("mode_octal") in ("0o777", "0o666")):
            findings.append(_finding(
                asset, "PRIV-CRON-WRITABLE", entry["path"],
                title=f"{'Directorio' if is_dir else 'Archivo'} de cron escribible por cualquier usuario: {entry['path']}",
                category="privilege_escalation",
                severity=Severity.CRITICAL if is_dir else Severity.HIGH,
                impact=("Los trabajos de cron se ejecutan como root. Poder reemplazar el directorio o el "
                        "script permite ejecución arbitraria como root en el próximo ciclo."),
                remediation="`chmod 755` el directorio, `chmod 644` los scripts, propietario root:root, y "
                            "verificar con `find /etc/cron* -perm -o+w`.",
                confidence=Confidence.HYPOTHESIS,
                validation_state=ValidationState.NOT_VALIDATED,
                manual_validation_required=True,
                prerequisites=["acceso local como usuario no privilegiado", "existe una tarea programada en ese path"],
                evidence=[_ev(asset, "cron_permissions", entry)],
                tags=["privesc", "cron", "permissions"],
            ))

    for entry in facts.systemd_units or []:
        if (entry.get("present") and entry.get("world_writable") and not entry.get("is_symlink")
                and not entry.get("mode", "").startswith("d")):
            findings.append(_finding(
                asset, "PRIV-SYSTEMD-WRITABLE", entry["path"],
                title=f"Unidad systemd escribible por cualquier usuario: {entry['path']}",
                category="privilege_escalation",
                severity=Severity.CRITICAL,
                impact="Permite definir un servicio que se ejecuta como root (ExecStart) y obtener ejecución "
                       "arbitraria tras `daemon-reload`/reinicio.",
                remediation="Asegurar root:root 0644 en unidades, y que /etc/systemd/system sea 0755 root:root.",
                confidence=Confidence.HYPOTHESIS,
                validation_state=ValidationState.NOT_VALIDATED,
                manual_validation_required=True,
                evidence=[_ev(asset, "systemd_permissions", entry)],
                tags=["privesc", "systemd", "permissions"],
            ))

    for entry in facts.path_dirs or []:
        if entry.get("writable_by_current_user"):
            findings.append(_finding(
                asset, "PRIV-PATH-WRITABLE", entry["path"],
                title=f"Directorio del PATH escribible por el usuario: {entry['path']}",
                category="privilege_escalation",
                severity=Severity.MEDIUM,
                impact=("Si un script privilegiado invoca un binario por nombre sin ruta absoluta, se puede "
                        "interceptar colocando un ejecutable en este directorio."),
                remediation="Retirar directorios escribibles del PATH de root y de los servicios; usar rutas "
                            "absolutas en scripts privilegiados.",
                confidence=Confidence.HYPOTHESIS,
                validation_state=ValidationState.NOT_VALIDATED,
                manual_validation_required=True,
                prerequisites=["un proceso privilegiado resuelve comandos a través del PATH"],
                evidence=[_ev(asset, "path_permissions", entry)],
                tags=["privesc", "path", "hypothesis"],
            ))
    return findings


def analyze_all(guard: ScopeGuard, facts) -> tuple[list[Finding], list[dict[str, Any]], dict[str, Any]]:
    """Run every local privilege analyser.  Nothing is executed."""
    from .errors import ScopeViolation

    guard.check_local("analyze:privilege_escalation")
    findings: list[Finding] = []
    skipped: list[dict[str, Any]] = []

    for analyser in (analyze_sudo,):
        try:
            f, s = analyser(facts)
            findings.extend(f)
            skipped.extend(s)
        except ScopeViolation:
            raise
        except Exception as exc:  # analysers must never abort the run
            skipped.append({"check": analyser.__name__, "reason": f"error interno: {exc}"})

    for analyser in (analyze_suid, analyze_capabilities, analyze_writable_jobs):
        try:
            findings.extend(analyser(facts))
        except ScopeViolation:
            raise
        except Exception as exc:
            skipped.append({"check": analyser.__name__, "reason": f"error interno: {exc}"})

    identity = facts.identity or {}
    sudo = facts.sudo
    posture = {
        "identity": identity.get("user"),
        "uid": identity.get("euid"),
        "sudo_available": bool(sudo and sudo.ok),
        "sudo_rule_count": len(parse_sudo_listing(sudo.stdout)) if (sudo and sudo.ok) else 0,
        "suid_count": len((facts.suid or {}).get("paths", [])),
        "capability_entries": len((facts.capabilities or {}).get("entries", [])),
        "hypotheses": sum(1 for f in findings if f.confidence is Confidence.HYPOTHESIS),
        "observed": sum(1 for f in findings if f.confidence is Confidence.CONFIRMED),
        "exploitation_attempted": False,
    }
    return findings, skipped, posture


def _path_writable(path: str) -> dict[str, Any]:
    try:
        st = os.stat(path)
    except OSError as exc:
        return {"path": path, "present": False, "error": str(exc)}
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    gids = set(os.getgroups()) | {os.getegid()} if hasattr(os, "getegid") else set()
    import stat as statmod

    writable = bool(
        st.st_mode & statmod.S_IWOTH
        or (st.st_uid == euid and st.st_mode & statmod.S_IWUSR)
        or (st.st_gid in gids and st.st_mode & statmod.S_IWGRP)
    )
    dir_info = _path_writable(os.path.dirname(path)) if os.path.dirname(path) else {}
    return {
        "path": path,
        "present": True,
        "mode_octal": oct(st.st_mode & 0o777),
        "writable_by_current_user": writable,
        "parent_dir_writable": bool(dir_info.get("writable_by_current_user")),
    }


def _ev(asset: str, kind: str, data: dict[str, Any]):
    from .model import Evidence

    return Evidence(kind=kind, asset=asset, summary=f"evidencia {kind}", data=data, source="privesc")
