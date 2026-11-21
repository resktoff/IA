"""SSH server hardening checks (Tier 1, static config analysis).

Semantics matter here: OpenSSH applies **the first obtained value** for a
keyword, and a keyword that is absent falls back to the compiled default.  The
checks below therefore report, for every weakness, either the directive that
produced it (file + line) or the default that applies because the directive is
absent.  Guessing "absent means secure" is the most common false negative in
this kind of assessment, so absence is treated explicitly.
"""

from __future__ import annotations

from typing import Any

from ..collectors import LocalFacts, first_directive, sshd_effective_config
from ..model import Confidence, Finding, Severity, ValidationState
from .common import CONFIRMED, OBSERVED, evidence, estimated, with_vector

CHECK_PREFIX = "SSH"

# OpenSSH defaults (sshd_config(5), Debian bookworm / OpenSSH 9.2).
DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "permitemptypasswords": "no",
    "passwordauthentication": "yes",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "allowagentforwarding": "yes",
    "loglevel": "INFO",
    "protocol": "2",
    "hostbasedauthentication": "no",
    "ignorerhosts": "yes",
}

WEAK_CIPHERS = ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "blowfish-cbc", "cast128-cbc")
WEAK_MACS = ("hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com", "hmac-ripemd160")
WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")


def _value(facts: LocalFacts, directives: list[dict[str, Any]], key: str) -> tuple[str, dict[str, Any] | None, bool]:
    directive = first_directive(directives, key)
    if directive is not None:
        return directive["value"].strip().lower(), directive, False
    return DEFAULTS.get(key.lower(), ""), None, True


def _note_source(directive: dict[str, Any] | None, key: str, used_default: bool) -> tuple[str, str]:
    if used_default or directive is None:
        return f"`{key}` no está definido; se aplica el valor por defecto de OpenSSH ({DEFAULTS.get(key.lower(), 'n/d')})", ""
    return (
        f"`{key} {directive['value']}` en {directive['file']}:{directive['line']}",
        f"{directive['file']}:{directive['line']}",
    )


def analyze_sshd(facts: LocalFacts) -> list[Finding]:
    directives = sshd_effective_config(facts)
    if not directives:
        return []
    asset = facts.host
    findings: list[Finding] = []

    def add(check_id: str, key: str, title: str, severity: Severity, impact: str, remediation: str,
            *, vector: str | None = None, confidence: Confidence = CONFIRMED, tags: list[str] | None = None,
            detail: dict[str, Any] | None = None, evidence_line: str = "") -> None:
        value, directive, used_default = _value(facts, directives, key)
        source_note, location = _note_source(directive, key, used_default)
        data = {
            "directive": key,
            "effective_value": value,
            "from_default": used_default,
            "source": location or "compiled default",
            "config_file_present": True,
            **(detail or {}),
        }
        fields: dict[str, Any] = {
            "title": title,
            "category": "ssh_hardening",
            "severity": severity,
            "impact": impact,
            "remediation": remediation,
            "confidence": confidence,
            "validation_state": OBSERVED,  # the config state itself was observed
            "references": ["https://www.ssh.com/academy/ssh/sshd_config", "https://cisecurity.org/controls"],
            "notes": source_note + (f" {evidence_line}" if evidence_line else ""),
            "tags": ["configuration", "ssh"] + (tags or []),
            "evidence": [evidence("config_directive", asset, source_note, data, "checks.ssh")],
        }
        if vector:
            fields.update(with_vector(vector))
            fields["tags"] = fields["tags"] + ["cvss_estimated"]
        findings.append(estimated(asset, f"{CHECK_PREFIX}-{check_id}", key, **fields))

    # --- authentication -----------------------------------------------------
    empty_pw, d, default = _value(facts, directives, "PermitEmptyPasswords")
    if empty_pw in {"yes", "true"}:
        add("EMPTY-PW", "PermitEmptyPasswords",
            "SSH permite cuentas con contraseña vacía",
            Severity.CRITICAL,
            "Cualquier cuenta sin contraseña puede autenticarse por SSH sin credenciales; "
            "el acceso resultante es interactivo y hereda los privilegios de la cuenta.",
            "Establecer `PermitEmptyPasswords no` y auditar cuentas con hash vacío en /etc/shadow.",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    root_login, d, default = _value(facts, directives, "PermitRootLogin")
    if root_login in {"yes", "true", "without-password", "prohibit-password", "forced-commands-only"}:
        sev = Severity.HIGH if root_login in {"yes", "true"} else Severity.MEDIUM
        add("ROOT-LOGIN", "PermitRootLogin",
            f"SSH permite inicio de sesión de root ({root_login})",
            sev,
            "Un login directo de root elimina la trazabilidad por usuario y convierte cualquier "
            "credencial o clave comprometida en control administrativo total.",
            "`PermitRootLogin no`; usar cuentas nominales y `sudo` con registro de auditoría.",
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" if sev is Severity.HIGH else None)

    password_auth, d, default = _value(facts, directives, "PasswordAuthentication")
    if password_auth in {"yes", "true"}:
        add("PASSWORD-AUTH", "PasswordAuthentication",
            "SSH acepta autenticación por contraseña",
            Severity.MEDIUM,
            "Habilita ataques de fuerza bruta y reutilización de credenciales desde cualquier red "
            "con alcance al puerto; la resistencia depende por completo de la política de contraseñas.",
            "Migrar a claves o certificados SSH, o al menos exigir MFA y limitar `AllowUsers`/`Match Address`.",
            tags=["authentication"])

    # --- protocol surface ---------------------------------------------------
    x11, d, default = _value(facts, directives, "X11Forwarding")
    if x11 in {"yes", "true"}:
        add("X11-FORWARD", "X11Forwarding",
            "SSH permite reenvío de X11",
            Severity.LOW,
            "Amplía la superficie de ataque del canal SSH (proxy X11, DISPLAY spoofing) sin ser "
            "necesario en servidores.",
            "`X11Forwarding no` salvo requisito explícito.")

    agent_fwd, d, default = _value(facts, directives, "AllowAgentForwarding")
    if agent_fwd in {"yes", "true"}:
        add("AGENT-FORWARD", "AllowAgentForwarding",
            "Reenvío del agente SSH habilitado (default)",
            Severity.LOW,
            "Cada sesión reenviada expone el socket del agente a la máquina remota; es la precondición "
            "de CVE-2023-38408 y de robo de identidad de clave en hosts comprometidos.",
            "`AllowAgentForwarding no` y usar `ProxyJump` en lugar de reenvío de agente.",
            tags=["authentication"])

    protocol, d, default = _value(facts, directives, "Protocol")
    if protocol.strip() in {"1", "1,2", "2,1"}:
        add("PROTO1", "Protocol",
            "SSH protocolo 1 habilitado",
            Severity.CRITICAL,
            "SSH-1 tiene debilidades criptográficas estructurales (CRC-32 compensation) que permiten "
            "inyección en el canal.",
            "Eliminar `Protocol 1`; usar exclusivamente SSH-2.",
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")

    max_auth, d, default = _value(facts, directives, "MaxAuthTries")
    try:
        tries = int(max_auth)
    except ValueError:
        tries = 6
    if tries > 4:
        add("MAX-AUTH", "MaxAuthTries",
            f"MaxAuthTries={tries} permite demasiados intentos por conexión",
            Severity.LOW,
            "Más intentos por conexión reducen el coste de la fuerza bruta y retrasan el bloqueo.",
            "`MaxAuthTries 3` y `MaxStartups 10:30:60`; complementar con fail2ban o equivalente.",
            detail={"max_auth_tries": tries})

    loglevel, d, default = _value(facts, directives, "LogLevel")
    if loglevel.upper() not in {"VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3", "INFO"}:
        add("LOG-LEVEL", "LogLevel",
            f"LogLevel={loglevel} reduce la evidencia de autenticación",
            Severity.LOW,
            "Sin registro de intentos fallidos y de la clave usada, la detección forense de fuerza "
            "bruta o de acceso con clave robada se degrada.",
            "`LogLevel VERBOSE` y envío a un colector central.")

    if first_directive(directives, "AllowUsers") is None and first_directive(directives, "AllowGroups") is None:
        add("NO-ALLOWLIST", "AllowUsers",
            "Sin AllowUsers/AllowGroups: cualquier cuenta válida puede autenticarse",
            Severity.LOW,
            "No existe una segunda barrera de autorización: una cuenta de servicio con shell y "
            "credencial filtrada obtiene acceso SSH.",
            "Declarar `AllowGroups ssh-operators` (o `AllowUsers`) y mantener las cuentas de servicio "
            "con shell `nologin`.")

    # --- cryptography -------------------------------------------------------
    for key, weak, label, sev in (
        ("Ciphers", WEAK_CIPHERS, "cifrados débiles", Severity.MEDIUM),
        ("MACs", WEAK_MACS, "MACs débiles", Severity.MEDIUM),
        ("KexAlgorithms", WEAK_KEX, "intercambios de claves débiles", Severity.HIGH),
    ):
        directive = first_directive(directives, key)
        if directive is None:
            continue
        configured = [c.strip() for c in directive["value"].split(",") if c.strip()]
        # A leading '-' removes an algorithm; '+'/'^' append/prepend. Only the
        # explicit list matters for this check.
        hits = [c for c in configured if any(w in c for w in weak)]
        if hits:
            data = {
                "directive": key,
                "algorithmas_debiles": hits,
                "configurados": configured,
                "source": f"{directive['file']}:{directive['line']}",
            }
            findings.append(estimated(
                asset, f"{CHECK_PREFIX}-WEAK-{key.upper()}", key,
                title=f"Algoritmos de {label} habilitados en SSH: {', '.join(hits[:3])}",
                category="ssh_cryptography",
                severity=sev,
                impact="Algoritmos con debilidades conocidas (SHA-1, MD5, 3DES, DH group1) permiten "
                       "degradación criptográfica o facilitan ataques de captura y descifrado.",
                remediation=f"Restringir `{key}` a la lista moderna (chacha20-poly1305, aes-gcm, "
                            "curve25519-sha256, hmac-sha2-512-etm) y validar compatibilidad antes de aplicar.",
                confidence=CONFIRMED,
                validation_state=OBSERVED,
                tags=["configuration", "ssh", "cryptography"],
                references=["https://infosec.mozilla.org/guidelines/openssh"],
                evidence=[evidence("config_directive", asset,
                                   f"{key} en {directive['file']}:{directive['line']}", data, "checks.ssh")],
                notes=f"`{key} {directive['value'][:120]}`",
            ))
    return findings
