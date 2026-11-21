"""HTTP/TLS configuration checks (Tier 1 analysis over Tier 2 observations).

The findings here are *observations*: the header was absent from a real
response, the negotiated protocol really was TLS 1.2, the certificate really
expired on that date.  Impact statements are inferences and are labelled as
such in the report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..auth import analyze_cookies
from ..model import Confidence, Finding, Severity, ValidationState
from .common import OBSERVED, evidence, estimated

SECURITY_HEADERS = (
    # (header, severity, title, rationale, remediation)
    ("Strict-Transport-Security", Severity.MEDIUM,
     "HSTS no configurado",
     "Sin HSTS, la primera petición puede hacerse por HTTP en claro y ser interceptada "
     "(SSL stripping) antes de la redirección.",
     "Añadir `Strict-Transport-Security: max-age=31536000; includeSubDomains` en todas las "
     "respuestas HTTPS, tras verificar que no hay recursos mixtos."),
    ("Content-Security-Policy", Severity.MEDIUM,
     "Content-Security-Policy ausente",
     "Sin CSP no hay una segunda barrera contra XSS: el navegador ejecuta cualquier script inline "
     "o de origen inyectado.",
     "Definir una CSP restrictiva (`default-src 'self'`) y desplegarla en modo report-only antes de "
     "aplicarla."),
    ("X-Content-Type-Options", Severity.LOW,
     "X-Content-Type-Options ausente",
     "Permite MIME sniffing: un archivo subido puede interpretarse como HTML/JS y ejecutarse.",
     "Añadir `X-Content-Type-Options: nosniff`."),
    ("Referrer-Policy", Severity.LOW,
     "Referrer-Policy ausente",
     "La URL completa (incluidos tokens en query string) puede filtrarse en cabeceras Referer a "
     "terceros.",
     "Añadir `Referrer-Policy: strict-origin-when-cross-origin`."),
)

FRAME_PROTECTION = ("X-Frame-Options", "frame-ancestors")


def _pick(headers: dict[str, str], name: str) -> str | None:
    lowered = {k.lower(): v for k, v in headers.items()}
    return lowered.get(name.lower())


def analyze_http(host: str, port: int, http: dict[str, Any]) -> list[Finding]:
    if not http or not http.get("ok"):
        return []
    headers = http.get("headers", {}) or {}
    is_tls = bool(http.get("tls"))
    findings: list[Finding] = []
    asset = host

    for header, severity, title, rationale, remediation in SECURITY_HEADERS:
        if header == "Strict-Transport-Security" and not is_tls:
            continue
        if _pick(headers, header) is None:
            findings.append(estimated(
                asset, "WEB-HEADER", f"{port}:{header}",
                title=f"{title} ({host}:{port})",
                category="web_configuration",
                severity=severity,
                impact=rationale,
                remediation=remediation,
                confidence=Confidence.CONFIRMED,
                validation_state=OBSERVED,
                port=port,
                evidence=[evidence("http_response_headers", asset,
                                   f"Cabeceras observadas en {host}:{port}",
                                   {"status": http.get("status"), "headers": headers}, "checks.web")],
                references=["https://owasp.org/www-project-secure-headers/"],
                tags=["http", "hardening"],
                notes="Ausencia observada en la respuesta real; no se evaluó el resto de rutas de la aplicación.",
            ))

    xfo = _pick(headers, "X-Frame-Options")
    csp = _pick(headers, "Content-Security-Policy") or ""
    if xfo is None and "frame-ancestors" not in csp.lower():
        findings.append(estimated(
            asset, "WEB-FRAME", f"{port}",
            title=f"Sin protección contra clickjacking ({host}:{port})",
            category="web_configuration",
            severity=Severity.LOW,
            impact="La página puede embeberse en un iframe de terceros y superponerse para capturar clics.",
            remediation="Añadir `X-Frame-Options: DENY` o `Content-Security-Policy: frame-ancestors 'none'`.",
            confidence=Confidence.CONFIRMED,
            validation_state=OBSERVED,
            port=port,
            evidence=[evidence("http_response_headers", asset, "cabeceras anti-framing",
                               {"x_frame_options": xfo, "csp": csp[:200]}, "checks.web")],
            tags=["http", "hardening"],
        ))

    server = _pick(headers, "Server")
    powered = _pick(headers, "X-Powered-By")
    if server or powered:
        findings.append(estimated(
            asset, "WEB-BANNER", f"{port}",
            title=f"Divulgación de tecnología en cabeceras ({host}:{port})",
            category="information_disclosure",
            severity=Severity.LOW,
            impact=("La versión exacta del servidor y del framework reduce el trabajo de reconocimiento "
                    "y permite seleccionar exploits y CVEs aplicables."),
            remediation="Suprimir `Server` y `X-Powered-By` o reducirlos a valores genéricos "
                        "(`ServerTokens Prod`, `expose_php = Off`).",
            confidence=Confidence.CONFIRMED,
            validation_state=OBSERVED,
            port=port,
            evidence=[evidence("http_response_headers", asset, "cabeceras de tecnología",
                               {"server": server, "x_powered_by": powered}, "checks.web")],
            tags=["http", "disclosure"],
        ))

    cookies = http.get("set_cookies") or []
    if cookies:
        findings.extend(analyze_cookies(asset, cookies, secure_context=is_tls))

    if not is_tls and port not in (80,):
        findings.append(estimated(
            asset, "WEB-PLAINTEXT", f"{port}",
            title=f"Servicio HTTP sin cifrado en el puerto {port}",
            category="transport_security",
            severity=Severity.MEDIUM,
            impact="Credenciales y cookies de sesión viajan en claro y pueden capturarse en la red.",
            remediation="Publicar el servicio detrás de TLS (HSTS + redirección 301) y deshabilitar el "
                        "listener en claro cuando sea posible.",
            confidence=Confidence.CONFIRMED,
            validation_state=OBSERVED,
            port=port,
            evidence=[evidence("http_response_headers", asset, "respuesta sin TLS",
                               {"port": port, "status": http.get("status")}, "checks.web")],
            tags=["http", "transport"],
        ))
    return findings


def analyze_tls(host: str, port: int, tls: dict[str, Any]) -> list[Finding]:
    if not tls or not tls.get("ok"):
        return []
    asset = host
    findings: list[Finding] = []
    protocol = str(tls.get("protocol") or "")
    cipher = str(tls.get("cipher") or "")
    cert = tls.get("certificate") or {}

    if protocol in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
        findings.append(estimated(
            asset, "TLS-PROTOCOL", f"{port}:{protocol}",
            title=f"Protocolo TLS obsoleto negociado: {protocol} ({host}:{port})",
            category="transport_security",
            severity=Severity.HIGH,
            impact="TLS 1.0/1.1 y SSLv3 tienen ataques prácticos (BEAST, POODLE) y están deprecados por RFC 8996.",
            remediation="Configurar `SSLProtocol TLSv1.2 TLSv1.3` y deshabilitar versiones anteriores.",
            confidence=Confidence.CONFIRMED,
            validation_state=OBSERVED,
            port=port,
            evidence=[evidence("tls_handshake", asset, "parámetros negociados",
                               {"protocol": protocol, "cipher": cipher}, "checks.web")],
            references=["https://datatracker.ietf.org/doc/rfc8996/"],
            tags=["tls", "transport"],
        ))
    elif protocol == "TLSv1.2":
        findings.append(estimated(
            asset, "TLS-VERSION", f"{port}:{protocol}",
            title=f"TLS 1.2 negociado; TLS 1.3 no se observó ({host}:{port})",
            category="transport_security",
            severity=Severity.LOW,
            impact=("TLS 1.2 sigue siendo aceptable, pero TLS 1.3 elimina suites heredadas y reduce la "
                    "superficie de ataque del handshake."),
            remediation="Habilitar TLS 1.3 manteniendo 1.2 como fallback controlado.",
            confidence=Confidence.INFERRED,
            validation_state=ValidationState.OBSERVED,
            port=port,
            evidence=[evidence("tls_handshake", asset, "versión negociada",
                               {"protocol": protocol, "cipher": cipher}, "checks.web")],
            tags=["tls", "transport", "informational"],
            notes="Se observó la versión que el servidor eligió para esta conexión; no se enumeraron "
                  "todas las versiones soportadas.",
        ))

    upper = cipher.upper()
    non_aead = not any(marker in upper for marker in ("GCM", "CHACHA20", "POLY1305", "CCM"))
    if non_aead or any(marker in upper for marker in ("RC4", "3DES", "NULL", "ANON", "DES_", "CBC")):
        findings.append(estimated(
            asset, "TLS-CIPHER", f"{port}:{cipher}",
            title=f"Suite criptográfica débil negociada: {cipher} ({host}:{port})",
            category="transport_security",
            severity=Severity.MEDIUM,
            impact=("Las suites sin AEAD (CBC, RC4, 3DES) son vulnerables a padding oracle o están rotas; "
                    "solo GCM/CHACHA20-POLY1305/CCM ofrecen autenticación integrada."),
            remediation="Restringir a AEAD: `TLS_AES_256_GCM_SHA384`, `ECDHE-*-GCM`, `CHACHA20-POLY1305`.",
            confidence=Confidence.CONFIRMED,
            validation_state=OBSERVED,
            port=port,
            evidence=[evidence("tls_handshake", asset, "cipher suite",
                               {"cipher": cipher, "bits": tls.get("cipher_bits")}, "checks.web")],
            tags=["tls", "cryptography"],
        ))

    if cert.get("decoded"):
        findings.extend(_certificate_findings(asset, port, cert))
    elif cert:
        findings.append(estimated(
            asset, "TLS-CERT-DECODE", f"{port}",
            title=f"No se pudo decodificar el certificado presentado en {host}:{port}",
            category="transport_security",
            severity=Severity.LOW,
            impact="Sin decodificación no se pudieron evaluar vigencia ni nombres alternativos.",
            remediation="Repetir la validación con `openssl s_client -showcerts` de forma manual.",
            confidence=Confidence.INFERRED,
            validation_state=ValidationState.NOT_VALIDATED,
            port=port,
            evidence=[evidence("tls_certificate", asset, "certificado no decodificado",
                               {k: cert.get(k) for k in ("sha256", "size_bytes", "decode_error")}, "checks.web")],
            tags=["tls"],
        ))

    verification = tls.get("verification")
    if verification and verification.startswith("disabled"):
        findings.append(estimated(
            asset, "TLS-VERIFY-METHOD", f"{port}",
            title="La cadena de confianza no fue validada durante la observación",
            category="methodology",
            severity=Severity.LOW,
            impact=("El agente deshabilitó la verificación para poder observar certificados inválidos. "
                    "Las conclusiones sobre confianza se limitan a lo verificable estáticamente "
                    "(vigencia, autofirma, nombres)."),
            remediation="Verificar la cadena con `openssl s_client -verify_return_error` y con el "
                        "almacén de confianza del cliente real.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.NOT_VALIDATED,
            port=port,
            evidence=[evidence("tls_handshake", asset, "modo de verificación",
                               {"verification": verification}, "checks.web")],
            tags=["tls", "methodology", "informational"],
        ))
    return findings


def _certificate_findings(asset: str, port: int, cert: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    not_after = cert.get("not_after")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            expiry = None
        if expiry is not None and expiry < datetime.now(timezone.utc):
            findings.append(estimated(
                asset, "TLS-CERT-EXPIRED", f"{port}:{cert.get('sha256')}",
                title=f"Certificado TLS vencido (expiró {not_after}) en {asset}:{port}",
                category="transport_security",
                severity=Severity.HIGH,
                impact=("Los clientes que validan la cadena rechazan la conexión o muestran una advertencia; "
                        "los usuarios suelen ignorarla, lo que normaliza aceptar certificados inválidos."),
                remediation="Renovar el certificado y automatizar la renovación (ACME) con alertas a 30/15/7 días.",
                confidence=Confidence.CONFIRMED,
                validation_state=OBSERVED,
                port=port,
                evidence=[evidence("tls_certificate", asset, "vigencia del certificado",
                                   {"not_before": cert.get("not_before"), "not_after": not_after,
                                    "sha256": cert.get("sha256")}, "checks.web")],
                tags=["tls", "certificate"],
            ))

    if cert.get("self_signed"):
        findings.append(estimated(
            asset, "TLS-CERT-SELFSIGNED", f"{port}:{cert.get('sha256')}",
            title=f"Certificado autofirmado en {asset}:{port}",
            category="transport_security",
            severity=Severity.MEDIUM,
            impact=("Sin una CA de confianza no hay autenticación del servidor: un atacante en la red "
                    "puede presentar su propio certificado y el cliente no puede distinguirlo."),
            remediation="Emitir el certificado desde una CA interna gestionada o pública, y distribuir la "
                        "CA raíz a los clientes por un canal seguro.",
            confidence=Confidence.CONFIRMED,
            validation_state=OBSERVED,
            port=port,
            evidence=[evidence("tls_certificate", asset, "subject == issuer",
                               {"subject": cert.get("subject"), "issuer": cert.get("issuer"),
                                "sha256": cert.get("sha256")}, "checks.web")],
            tags=["tls", "certificate"],
        ))
    return findings


def analyze_service_web(service) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(analyze_tls(service.host, service.port, service.tls or {}))
    findings.extend(analyze_http(service.host, service.port, service.http or {}))
    return findings
