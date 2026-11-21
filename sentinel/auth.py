"""Authentication and protection-mechanism analysis (Tier 1 + bounded Tier 2).

What this module does
---------------------
* Evaluates the *local* password policy from `login.defs`, PAM and
  `pwquality`, and the account database from `/etc/passwd`, including file
  permissions on `/etc/shadow` and `/etc/sudoers`.
* Statically evaluates session cookies and security headers that were already
  collected by :mod:`sentinel.discovery`.
* Optionally fingerprints a login endpoint with **one** unauthenticated GET,
  looking only at response headers that indicate rate limiting or version
  disclosure.

What it deliberately does *not* do (ADR-005)
--------------------------------------------
No credential submission of any kind: no default-account login, no password
spraying, no lockout testing by deliberate failure.  Those actions change
server state, can lock out real users, and produce reusable attack tooling.
The API exists and raises :class:`~sentinel.errors.CapabilityBlocked`, so the
control is testable rather than merely documented.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, NoReturn

from .errors import CapabilityBlocked
from .model import Confidence, Finding, Severity, Tier, ValidationState
from .scope import ScopeGuard

WEAK_HASHES = {
    "md5": "MD5 (roto, colisiones triviales)",
    "des": "DES crypt (56 bits, fuerza bruta factible)",
    "sha256": "SHA-256 simple (sin sal por usuario ni coste configurable)",
    "sha512": "SHA-512 simple (sin sal por usuario ni coste configurable)",
}
STRONG_HASHES = ("yescrypt", "argon2", "bcrypt", "gost-yescrypt", "scrypt")

MIN_LENGTH_RECOMMENDED = 12
MAX_AGE_MAX = 365


def _finding(asset: str, check_id: str, key: str, **fields: Any) -> Finding:
    return Finding(asset=asset, check_id=check_id, fingerprint_seed=f"{asset}|{check_id}|{key}", **fields)


def _cfg(text: str | None, key: str) -> str | None:
    if not text:
        return None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if parts[0] == key:
            return parts[1].strip() if len(parts) > 1 else ""
    return None


def analyze_password_policy(facts) -> list[Finding]:
    asset = facts.host
    login_defs = facts.files.get("login_defs")
    pam = facts.files.get("pam_common_password")
    pwquality = facts.files.get("pwquality")
    findings: list[Finding] = []

    min_len = _cfg(login_defs, "PASS_MIN_LEN")
    min_len_int = int(min_len) if min_len and min_len.isdigit() else None
    if min_len_int is None or min_len_int < MIN_LENGTH_RECOMMENDED:
        findings.append(_finding(
            asset, "AUTH-PW-MINLEN", "minlen",
            title="Longitud mínima de contraseña ausente o insuficiente",
            category="authentication",
            severity=Severity.MEDIUM,
            impact=("Sin un mínimo efectivo, el espacio de búsqueda de credenciales se reduce a "
                    "valores triviales. NIST SP 800-63B exige ≥8 y recomienda ≥12 para cuentas con "
                    "privilegios; el valor no está definido en login.defs ni en pwquality."),
            remediation=("Definir `minlen = 12` en /etc/security/pwquality.conf (que prevalece sobre "
                         "login.defs) y bloquear contraseñas filtradas contra una lista de brechas."),
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "password_policy", {"PASS_MIN_LEN": min_len, "pwquality_present": bool(pwquality),
                                                     "source": "/etc/login.defs"})],
            references=["https://pages.nist.gov/800-63-3/sp800-63b.html#password"],
            tags=["authentication", "policy"],
        ))

    max_days = _cfg(login_defs, "PASS_MAX_DAYS")
    if max_days and max_days.isdigit() and int(max_days) > MAX_AGE_MAX:
        findings.append(_finding(
            asset, "AUTH-PW-MAXAGE", "maxage",
            title=f"Las contraseñas no expiran (PASS_MAX_DAYS={max_days})",
            category="authentication",
            severity=Severity.LOW,
            impact=("Una credencial comprometida permanece válida indefinidamente. NIST no exige "
                    "rotación periódica, pero solo si existe detección de compromiso; sin ella, la "
                    "ausencia de caducidad amplía la ventana de uso de credenciales filtradas."),
            remediation=("Alinear con la política corporativa: mantener sin caducidad forzada solo si hay "
                         "verificación de contraseñas filtradas y MFA; en caso contrario, fijar "
                         "PASS_MAX_DAYS ≤ 365."),
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "password_policy", {"PASS_MAX_DAYS": max_days})],
            references=["https://pages.nist.gov/800-63-3/sp800-63b.html#password"],
            tags=["authentication", "policy"],
        ))

    pam_text = (pam or "").lower()
    login_method = _cfg(login_defs, "ENCRYPT_METHOD")
    used_strong = any(h in pam_text for h in STRONG_HASHES)
    if pam and not used_strong:
        selected = "desconocido"
        for weak, label in WEAK_HASHES.items():
            if weak in pam_text:
                selected = label
                break
        findings.append(_finding(
            asset, "AUTH-PW-HASH", "hash",
            title=f"Esquema de hash de contraseñas débil o sin coste configurable: {selected}",
            category="authentication",
            severity=Severity.HIGH if any(w in pam_text for w in ("md5", "des")) else Severity.MEDIUM,
            impact=("Un hash rápido sin sal por usuario ni factor de coste permite recuperar contraseñas "
                    "a velocidad de GPU si /etc/shadow se filtra."),
            remediation=("Usar `pam_unix.so yescrypt` (o argon2/bcrypt) y rehashear en el próximo login. "
                         "Verificar que ENCRYPT_METHOD en login.defs no contradiga a PAM."),
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "password_policy", {"pam_line": _pam_line(pam), "ENCRYPT_METHOD": login_method})],
            references=["https://www.man7.org/linux/man-pages/man8/pam_unix.8.html"],
            tags=["authentication", "cryptography"],
        ))

    if not pwquality or not (_cfg(pwquality, "minlen") or "").strip():
        findings.append(_finding(
            asset, "AUTH-PW-COMPLEXITY", "pwquality",
            title="Sin política de calidad de contraseñas activa (pwquality)",
            category="authentication",
            severity=Severity.LOW,
            impact=("No hay verificación de longitud, diccionario ni repetición en el cambio de "
                    "contraseña, de modo que la política declarada no se aplica en la práctica."),
            remediation=("Instalar/activar `pam_pwquality.so` en /etc/pam.d/common-password con minlen ≥12, "
                         "`dictcheck=1` y `maxrepeat=3`."),
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "password_policy", {"pwquality_readable": bool(pwquality),
                                                     "minlen": _cfg(pwquality, "minlen")})],
            tags=["authentication", "policy"],
        ))
    return findings


def analyze_account_database(facts) -> list[Finding]:
    asset = facts.host
    findings: list[Finding] = []
    accounts = facts.accounts or []
    perms = facts.permissions or {}

    uid0 = [a["name"] for a in accounts if a.get("uid") == 0]
    if len(uid0) > 1:
        findings.append(_finding(
            asset, "AUTH-UID0-MULTIPLE", "uid0",
            title=f"Múltiples cuentas con UID 0: {', '.join(uid0)}",
            category="authentication",
            severity=Severity.HIGH,
            impact="Cualquier cuenta con UID 0 es root; una credencial de la cuenta extra no es distinguible "
                   "de root en los registros de auditoría.",
            remediation="Dejar una sola cuenta UID 0 (root bloqueado) y usar sudo con cuentas nominales.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "accounts", {"uid0_accounts": uid0})],
            tags=["authentication", "accounts"],
        ))

    empty = [line.split(":", 1)[0] for line in (facts.files.get("passwd") or "").splitlines()
             if line.count(":") >= 6 and line.split(":")[1] == ""]
    if empty:
        findings.append(_finding(
            asset, "AUTH-EMPTY-PASSWORD", "empty",
            title=f"Cuentas sin contraseña en /etc/passwd: {', '.join(empty[:5])}",
            category="authentication",
            severity=Severity.CRITICAL,
            impact="El segundo campo vacío desactiva la autenticación para esas cuentas en los servicios que "
                   "consultan /etc/passwd directamente.",
            remediation="Bloquear las cuentas (`passwd -l`) y migrar a `shadow` con hash válido o `!`.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "accounts", {"accounts": empty})],
            tags=["authentication", "accounts"],
        ))

    hashes_in_passwd = [line.split(":", 1)[0] for line in (facts.files.get("passwd") or "").splitlines()
                        if line.count(":") >= 6 and line.split(":")[1] not in ("", "x", "*", "!")]
    if hashes_in_passwd:
        findings.append(_finding(
            asset, "AUTH-NO-SHADOW", "noshadow",
            title="Hashes de contraseña almacenados en /etc/passwd (sin shadow)",
            category="authentication",
            severity=Severity.CRITICAL,
            impact="/etc/passwd es legible por todos: cualquier usuario local puede volcar los hashes y "
                   "atacarlos offline.",
            remediation="Habilitar shadow (`pwconv`) y asegurar /etc/shadow en 0640 root:shadow.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "accounts", {"accounts": hashes_in_passwd[:5]})],
            tags=["authentication", "accounts"],
        ))

    shadow = perms.get("shadow") or {}
    if shadow.get("present"):
        world = shadow.get("other_read")
        mode = shadow.get("mode_octal")
        if world:
            findings.append(_finding(
                asset, "AUTH-SHADOW-PERMS", "shadow-world",
                title=f"/etc/shadow es legible por otros usuarios ({shadow.get('mode')})",
                category="authentication",
                severity=Severity.CRITICAL,
                impact="Cualquier usuario local puede leer los hashes y atacarlos offline sin dejar rastro en "
                       "los registros de autenticación.",
                remediation="`chmod 640 /etc/shadow && chown root:shadow /etc/shadow`.",
                confidence=Confidence.CONFIRMED,
                validation_state=ValidationState.OBSERVED,
                evidence=[_ev(asset, "file_permissions", shadow)],
                tags=["authentication", "permissions"],
            ))
        elif mode not in ("0o640", "0o600", "0o000"):
            findings.append(_finding(
                asset, "AUTH-SHADOW-PERMS", "shadow-mode",
                title=f"Permisos de /etc/shadow no estándar ({mode})",
                category="authentication",
                severity=Severity.MEDIUM,
                impact="Un modo más permisivo que 0640 root:shadow amplía el conjunto de lectores de hashes.",
                remediation="`chmod 640 /etc/shadow`.",
                confidence=Confidence.CONFIRMED,
                validation_state=ValidationState.OBSERVED,
                evidence=[_ev(asset, "file_permissions", shadow)],
                tags=["authentication", "permissions"],
            ))

    sudoers = perms.get("sudoers") or {}
    if sudoers.get("present") and sudoers.get("other_read"):
        findings.append(_finding(
            asset, "AUTH-SUDOERS-PERMS", "sudoers-read",
            title="/etc/sudoers es legible por cualquier usuario",
            category="authentication",
            severity=Severity.HIGH,
            impact="Expone la política de privilegios completa (comandos, NOPASSWD, usuarios), que es el mapa "
                   "directo para elegir un vector de escalamiento.",
            remediation="`chmod 440 /etc/sudoers` y validar con `visudo -c`.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "file_permissions", sudoers)],
            tags=["permissions"],
        ))

    service_shells = [a["name"] for a in accounts if a.get("is_system") and a.get("login_shell")]
    if service_shells:
        findings.append(_finding(
            asset, "AUTH-SERVICE-SHELL", "service-shell",
            title=f"Cuentas de sistema con shell interactivo: {', '.join(service_shells[:6])}",
            category="authentication",
            severity=Severity.LOW,
            impact="Amplía las cuentas utilizables para autenticación interactiva y para movimiento lateral "
                   "si se compromete un servicio.",
            remediation="Fijar `/usr/sbin/nologin` en las cuentas de servicio que no requieran shell.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(asset, "accounts", {"accounts": service_shells[:10]})],
            tags=["authentication", "accounts"],
        ))
    return findings


# --------------------------------------------------------------------- cookies
def parse_set_cookie(header_value: str) -> dict[str, Any]:
    parts = [p.strip() for p in header_value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    value = parts[0].split("=", 1)[1].strip() if "=" in parts[0] else ""
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
             for p in parts[1:]}
    return {"name": name, "value": value, "attributes": attrs, "raw_length": len(value)}


def estimate_token_strength(value: str) -> dict[str, Any]:
    """Shannon entropy per character × length = a *lower bound* on token bits.

    This is an estimate of the observed alphabet, not a proof of randomness:
    a hash of a timestamp also looks random.  Reported as such.
    """
    if not value:
        return {"length": 0, "alphabet": 0, "entropy_bits": 0.0, "lower_bound_bits": 0.0}
    counts = Counter(value)
    total = len(value)
    per_char = -sum((c / total) * math.log2(c / total) for c in counts.values())
    alphabet = len(counts)
    return {
        "length": total,
        "alphabet": alphabet,
        "entropy_bits": round(per_char, 3),
        "lower_bound_bits": round(per_char * total, 1),
    }


def analyze_cookies(asset: str, cookies: list[str], secure_context: bool) -> list[Finding]:
    findings: list[Finding] = []
    for raw in cookies:
        parsed = parse_set_cookie(raw)
        attrs = parsed["attributes"]
        name = parsed["name"] or "<unnamed>"
        missing = []
        if secure_context and not attrs.get("secure"):
            missing.append("Secure")
        if not attrs.get("httponly"):
            missing.append("HttpOnly")
        if not attrs.get("samesite"):
            missing.append("SameSite")
        strength = estimate_token_strength(parsed["value"])
        if missing:
            findings.append(_finding(
                asset, "AUTH-COOKIE-FLAGS", f"cookie:{name}",
                title=f"Cookie '{name}' sin atributos de protección: {', '.join(missing)}",
                category="session_management",
                severity=Severity.MEDIUM if "Secure" in missing or "HttpOnly" in missing else Severity.LOW,
                impact=("Sin HttpOnly la cookie es accesible desde JavaScript (robo vía XSS); sin Secure puede "
                        "viajar en claro; sin SameSite queda expuesta a CSRF."),
                remediation="Emitir la cookie con `Secure; HttpOnly; SameSite=Lax` (o Strict) y `Path` acotado.",
                confidence=Confidence.CONFIRMED,
                validation_state=ValidationState.OBSERVED,
                evidence=[_ev(asset, "http_header", {"set_cookie": raw, "parsed": parsed,
                                                     "token_strength": strength})],
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                tags=["session", "http"],
            ))
        if strength["length"] >= 8 and strength["lower_bound_bits"] < 64:
            findings.append(_finding(
                asset, "AUTH-COOKIE-ENTROPY", f"entropy:{name}",
                title=f"Cookie '{name}' con entropía estimada baja ({strength['lower_bound_bits']} bits)",
                category="session_management",
                severity=Severity.MEDIUM,
                impact="Un identificador de sesión predecible permite fijación o adivinación de sesión.",
                remediation="Generar el identificador con un CSPRNG y al menos 128 bits (p. ej. 32 bytes base64url).",
                confidence=Confidence.INFERRED,
                validation_state=ValidationState.INFERRED,
                notes="La entropía se estima sobre una única muestra observada: es una cota inferior, no una prueba.",
                evidence=[_ev(asset, "http_header", {"cookie": name, "token_strength": strength})],
                tags=["session", "cryptography"],
            ))
    return findings


# ------------------------------------------------------- login endpoint probe
def fingerprint_login_endpoint(guard: ScopeGuard, host: str, port: int, path: str = "/") -> dict[str, Any]:
    """One unauthenticated GET.  No credentials, no state change."""
    from .discovery import http_probe  # local import to avoid a cycle

    result = http_probe(guard, host, port, path=path, method="GET", max_body=0,
                        action="auth_probe:login_fingerprint")
    headers = result.get("headers", {})
    lowered = {k.lower(): v for k, v in headers.items()}
    rate_headers = {k: v for k, v in lowered.items() if k.startswith(("x-ratelimit", "ratelimit", "retry-after"))}
    result["rate_limit_headers"] = rate_headers
    result["server_header"] = lowered.get("server")
    result["has_captcha_marker"] = any("captcha" in str(v).lower() for v in headers.values())
    return result


def credential_attack_guard(*_args: Any, **_kwargs: Any) -> NoReturn:
    """Always refuses.  Kept as an explicit, testable control surface (ADR-005)."""
    raise CapabilityBlocked(
        "REFUSED credential attack: this agent does not submit credentials, guess passwords or "
        "deliberately trigger lockouts. Use the authentication *policy* analysis and validate "
        "manually with the account owner's written approval."
    )


login_endpoint_attack = credential_attack_guard
password_spray = credential_attack_guard
default_credential_test = credential_attack_guard


def analyze_login_endpoint(host: str, port: int, probe: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if probe.get("error"):
        return findings
    if not probe.get("rate_limit_headers"):
        findings.append(_finding(
            host, "AUTH-LOGIN-RATE", f"{port}",
            title="El endpoint de login no anuncia limitación de tasa",
            category="authentication",
            severity=Severity.LOW,
            impact=("Sin cabeceras de rate limiting ni Retry-After no hay señal de control de intentos; "
                    "la resistencia a fuerza bruta no puede confirmarse desde fuera."),
            remediation=("Implementar limitación por cuenta y por IP con respuesta 429 y Retry-After, "
                         "backoff progresivo y bloqueo temporal; verificar con una prueba autorizada."),
            confidence=Confidence.INFERRED,
            validation_state=ValidationState.NOT_VALIDATED,
            notes=("No se enviaron credenciales ni se provocaron fallos de autenticación. La ausencia de "
                   "cabeceras es indicio, no prueba, de ausencia de control."),
            evidence=[_ev(host, "http_headers", {"port": port, "status": probe.get("status"),
                                                 "headers": probe.get("headers", {})})],
            tags=["authentication", "http"],
        ))
    if probe.get("server_header"):
        findings.append(_finding(
            host, "AUTH-LOGIN-BANNER", f"{port}",
            title=f"El endpoint de login revela la versión del servidor: {probe['server_header']}",
            category="information_disclosure",
            severity=Severity.LOW,
            impact="Facilita la selección de exploits y de CVEs aplicables sin trabajo de fingerprinting.",
            remediation="Suprimir `Server`/`X-Powered-By` o reducirlos a un valor genérico.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[_ev(host, "http_headers", {"server": probe["server_header"]})],
            tags=["http", "disclosure"],
        ))
    return findings


def _pam_line(pam: str | None) -> str | None:
    if not pam:
        return None
    for line in pam.splitlines():
        if not line.strip().startswith("#") and "pam_unix.so" in line:
            return line.strip()
    return None


def _ev(asset: str, kind: str, data: dict[str, Any]) -> Any:
    from .model import Evidence

    return Evidence(kind=kind, asset=asset, summary=f"evidencia {kind}", data=data, source="auth")
