"""Exposure checks for service ports and version-based advisory correlation.

Both are **inference**, not verification: an open port says something listens;
a banner says which software (the service can lie); a version match says "this
release is listed as affected".  None of these proves exploitability, and the
findings are labelled accordingly (``confidence=inferred``,
``validation_state=inferred``) so the report cannot present them as validated.

No authentication is attempted against any of these services and no request is
sent beyond what :mod:`sentinel.discovery` already collected.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from ..model import Confidence, Finding, Severity, ValidationState
from ..versions import Version
from .common import advisory_vector, evidence, estimated

ADVISORY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "advisories.json")

# port -> (service, severity, title, rationale, remediation)
EXPOSED_SERVICES: dict[int, dict[str, Any]] = {
    21: {
        "service": "ftp",
        "severity": Severity.MEDIUM,
        "title": "Servicio FTP expuesto",
        "impact": ("FTP transmite credenciales y datos en claro; además suele permitir escritura anónima "
                   "o reutilización de credenciales del sistema."),
        "remediation": "Sustituir por SFTP/FTPS, deshabilitar login anónimo y restringir por origen.",
    },
    23: {
        "service": "telnet",
        "severity": Severity.HIGH,
        "title": "Servicio Telnet expuesto",
        "impact": "Telnet no cifra nada: usuario, contraseña y sesión completa son capturables en la red.",
        "remediation": "Deshabilitar telnet y migrar a SSH con claves.",
    },
    445: {
        "service": "smb",
        "severity": Severity.HIGH,
        "title": "SMB expuesto en la red evaluada",
        "impact": ("SMB es un objetivo principal de movimiento lateral y ransomware (EternalBlue, "
                   "SMBGhost). La exposición aumenta el impacto de cualquier credencial comprometida."),
        "remediation": "Filtrar 445 en el perímetro, exigir SMB signing, deshabilitar SMBv1 y aplicar parches.",
    },
    3389: {
        "service": "rdp",
        "severity": Severity.HIGH,
        "title": "RDP expuesto",
        "impact": "RDP expuesto a redes no confiables habilita fuerza bruta, BlueKeep y ransomware.",
        "remediation": "Publicar RDP solo a través de VPN/bastion, con NLA, MFA y bloqueo por intentos.",
    },
    2375: {
        "service": "docker_api",
        "severity": Severity.CRITICAL,
        "title": "API de Docker expuesta sin TLS",
        "impact": ("La API de Docker permite crear contenedores con acceso al filesystem del host; sin "
                   "autenticación equivale a ejecución de comandos como root en el host."),
        "remediation": "Eliminar el listener TCP o exigir TLS mutuo; nunca exponer 2375 fuera de localhost.",
    },
    6379: {
        "service": "redis",
        "severity": Severity.HIGH,
        "title": "Redis expuesto",
        "impact": "Redis sin autenticación permite leer/escribir datos y, según configuración, escribir "
                  "archivos arbitrarios (persistencia, claves SSH, cron).",
        "remediation": "Bind a localhost, `requirepass`/ACL, `protected-mode yes` y filtrado de red.",
    },
    9200: {
        "service": "elasticsearch",
        "severity": Severity.HIGH,
        "title": "Elasticsearch expuesto",
        "impact": "Sin autenticación, la API HTTP expone todos los índices (datos personales, logs con "
                  "credenciales) y permite borrarlos.",
        "remediation": "Habilitar seguridad (xpack/OpenSearch security), TLS y filtrado por red.",
    },
    27017: {
        "service": "mongodb",
        "severity": Severity.HIGH,
        "title": "MongoDB expuesto",
        "impact": "Instalaciones sin auth permiten lectura/escritura completa y son objetivo de ransomware.",
        "remediation": "Habilitar autenticación, bind a localhost/interfaz interna y TLS.",
    },
    3306: {
        "service": "mysql",
        "severity": Severity.MEDIUM,
        "title": "MySQL accesible desde la red evaluada",
        "impact": "Amplía la superficie de ataque a credenciales débiles y a vulnerabilidades del motor.",
        "remediation": "Restringir por origen, exigir TLS y usar cuentas con privilegios mínimos.",
    },
    5432: {
        "service": "postgresql",
        "severity": Severity.MEDIUM,
        "title": "PostgreSQL accesible desde la red evaluada",
        "impact": "Expone autenticación a intentos de fuerza bruta y a vulnerabilidades del motor.",
        "remediation": "`pg_hba.conf` con `scram-sha-256`, TLS y filtrado por origen.",
    },
    5900: {
        "service": "vnc",
        "severity": Severity.HIGH,
        "title": "VNC expuesto",
        "impact": "VNC suele usar autenticación débil y sin cifrado; da control interactivo del escritorio.",
        "remediation": "Tunelizar por SSH/VPN, deshabilitar VNC directo y usar contraseñas fuertes.",
    },
}


@dataclass
class Advisory:
    id: str
    products: list[str]
    introduced: str
    fixed: str
    vector: str
    summary: str
    preconditions: list[str]
    references: list[str]


def load_advisories(path: str = ADVISORY_PATH) -> list[Advisory]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [
        Advisory(
            id=e["id"],
            products=[p.lower() for p in e["products"]],
            introduced=e["introduced"],
            fixed=e["fixed"],
            vector=e["vector"],
            summary=e["summary"],
            preconditions=e.get("preconditions", []),
            references=e.get("references", []),
        )
        for e in data["entries"]
    ]


def match_advisories(product: str | None, version: str | None,
                     advisories: list[Advisory] | None = None) -> list[Advisory]:
    if not product or not version:
        return []
    advisories = advisories if advisories is not None else load_advisories()
    current = Version.parse(version)
    if current is None:
        return []
    matches = []
    for advisory in advisories:
        if product.lower() not in advisory.products:
            continue
        low = Version.parse(advisory.introduced)
        high = Version.parse(advisory.fixed)
        if low is None or high is None:
            continue
        if low <= current < high:
            matches.append(advisory)
    return matches


def analyze_exposure(service) -> list[Finding]:
    rule = EXPOSED_SERVICES.get(service.port)
    if not rule or service.state != "open":
        return []
    return [estimated(
        service.host, "EXP-PORT", f"{service.port}",
        title=f"{rule['title']} ({service.host}:{service.port})",
        category="exposure",
        severity=rule["severity"],
        impact=rule["impact"],
        remediation=rule["remediation"],
        confidence=Confidence.INFERRED,
        validation_state=ValidationState.NOT_VALIDATED,
        port=service.port,
        evidence=[evidence("port_state", service.host,
                           f"Puerto {service.port} acepta conexiones TCP",
                           {"port": service.port, "banner": service.banner,
                            "inferred_service": rule["service"]}, "checks.exposure")],
        references=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
        tags=["exposure", "network"],
        notes=("Exposición observada. No se intentó autenticación ni se envió ninguna petición "
               "específica del protocolo."),
    )]


def analyze_advisories(service, advisories: list[Advisory] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for advisory in match_advisories(service.product, service.version, advisories):
        fields = advisory_vector(advisory.vector)
        findings.append(estimated(
            service.host, "ADV-MATCH", f"{service.port}:{advisory.id}",
            title=f"{advisory.id}: {service.product} {service.version} figura como afectado",
            category="vulnerability",
            severity=fields["severity"],
            impact=(f"{advisory.summary} La explotabilidad real depende de: "
                    + "; ".join(advisory.preconditions) + "."),
            remediation=("Actualizar a una versión posterior a la corrección indicada y verificar el "
                         "paquete real instalado (`dpkg -l | grep <paquete>`); la versión del banner "
                         "puede no coincidir con la del binario corregido por el proveedor."),
            confidence=Confidence.INFERRED,
            validation_state=ValidationState.INFERRED,
            port=service.port,
            prerequisites=advisory.preconditions,
            cvss_vector=fields["cvss_vector"],
            cvss_score=fields["cvss_score"],
            manual_validation_required=True,
            evidence=[evidence("advisory_match", service.host,
                               f"Coincidencia de versión con {advisory.id}",
                               {"product": service.product, "observed_version": service.version,
                                "advisory": {"id": advisory.id, "introduced": advisory.introduced,
                                             "fixed": advisory.fixed, "vector": advisory.vector},
                                "banner": service.banner},
                               "checks.advisories")],
            references=advisory.references,
            tags=["vulnerability", "inferred", "cve"],
            notes=("Correlación por versión contra un subconjunto curado y offline de avisos. No se "
                   "envió ningún payload: la coincidencia no demuestra explotabilidad."),
        ))
    return findings


def analyze_service(service, advisories: list[Advisory] | None = None) -> list[Finding]:
    return analyze_exposure(service) + analyze_advisories(service, advisories)
