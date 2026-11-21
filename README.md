# sentinel — agente de evaluación de seguridad con controles verificables

Agente de **evaluación** de seguridad (reconocimiento, fingerprint, evaluación de configuración,
correlación de avisos con CVSS v3.1, análisis de escalamiento de privilegios e informes con evidencia
verificable) diseñado para trabajar **solo dentro de un alcance autorizado** y **sin explotación**.

> Este repositorio es el entregable de una evaluación de capacidades: incluye arquitectura,
> código funcional, tests, decisiones de seguridad y una matriz que distingue lo implementado de lo
> que es solo diseño. Nada de lo marcado como `partial` o `blocked` se ejecuta.

## Qué hace (y qué no)

| | Capacidad | Estado |
|---|---|---|
| ✅ | Descubrimiento de activos y servicios (TCP connect, banner, HTTP, TLS) | implementado |
| ✅ | Identificación de configuraciones débiles (sshd, cabeceras HTTP, TLS, PAM, permisos) | implementado |
| ✅ | Correlación versión → aviso (CVE) con CVSS v3.1 base calculado localmente | implementado |
| ✅ | Análisis de escalamiento de privilegios (sudo, SUID, capabilities, cron, systemd, PATH) | parcial: hipótesis, sin validación |
| ✅ | Análisis de resistencia de autenticación (política, hashes, cookies, entropía) | parcial: sin ataques de credenciales |
| ✅ | Informes Markdown/HTML/JSON con evidencia, impacto y remediación | implementado |
| ❌ | Explotación, payloads, post-explotación | **bloqueado en código** (ADR-002) |
| ❌ | Fuerza bruta, spraying, credenciales por defecto | **bloqueado en código** (ADR-005) |
| ❌ | Validación activa de rutas de escalamiento | **bloqueado en código** (ADR-006) |

## Inicio rápido

Sin dependencias externas (solo stdlib, Python ≥ 3.10):

```bash
python3 -m sentinel.webapp --port 8765
# abrir http://127.0.0.1:8765; por defecto solo escucha en loopback
```

En la interfaz cargá un JSON de alcance **propio y autorizado** (Tier 2, `host`/`cidr`, puertos concretos) y ejecutá las tres fases en orden. `ESCANEAR` hace conexiones TCP reales; `ANALIZAR` usa los módulos `checks.exposure` y `checks.web` sobre los servicios observados, sin conexiones adicionales; `INFORME` invoca `report.write_reports` y permite ver/descargar Markdown, HTML y JSON. Los runs/auditorías quedan en `evidence/web/`.

Se puede configurar otra interfaz explícitamente con `--host HOST`, pero Sentinel Web no incluye autenticación ni transporte TLS: escuchar en una interfaz accesible por otras máquinas expone sus operaciones y datos. No lo publiques en redes compartidas ni lo consideres un servicio remoto seguro.

El archivo de alcance de ejemplo `examples/scope-local.json` solo autoriza evaluación local Tier 1 y no habilita reconocimiento de red. No uses un scope de ejemplo en un sistema real sin reemplazar la autorización y declarar el objetivo y los puertos exactos.

```bash
python3 -m sentinel.cli self-check --out evidence     # ejercita controles + pipeline
python3 -m sentinel.cli assess --scope examples/scope-local.json --mode local --out evidence
python3 -m sentinel.cli capabilities                  # matriz de capacidades
python3 -m unittest discover -s tests -t . -v         # 222 tests
```

CLI: `evidence/report-<engagement>-<run>.md|.html|.json` y `evidence/audit-*.jsonl`.
Web: `evidence/web/<run-id>/` con alcance, auditoría e informes del escaneo.

## Controles de seguridad (implementados, no solo documentados)

1. **Alcance con allowlist y default deny** — sin `host:puerto` declarado no hay acción (`sentinel/scope.py`).
2. **Declaración de autorización obligatoria** — se exigen `authorized`, referencia y aprobador, pero son datos autoafirmados; el parser no verifica autorización externa.
3. **Vigencia temporal** — el engagement vence y no se puede reanudar.
4. **Tiers** — 1 detectar, 2 validar (no destructivo), 3 explotar: el 3 se rechaza siempre.
5. **Presupuesto y rate limit** — token bucket + contador duro por corrida.
6. **Kill switch** — `touch STOP` detiene la ejecución en la siguiente acción.
7. **Cadena de auditoría hash** — permite verificar consistencia interna de los registros presentes; no garantiza por sí sola inmutabilidad, autoría ni completitud. La actividad web en memoria no es un registro persistente.
8. **Redacción de secretos** — el agente no lee `/etc/shadow` ni cuerpos de respuesta por defecto.
9. **Bloqueo de direcciones peligrosas** — metadatos cloud (169.254.169.254), link-local, multicast y
   rangos reservados; direcciones públicas requieren doble opt-in.

## Documentación

| Documento | Contenido |
|---|---|
| [docs/EVALUACION.md](docs/EVALUACION.md) | Respuesta a los requisitos de evaluación: capacidades, riesgo de intrusión, detección vs validación vs explotación |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Arquitectura, componentes, flujo, modelo de datos, fronteras de confianza |
| [docs/CAPABILITY_MATRIX.md](docs/CAPABILITY_MATRIX.md) | Capacidad → estado → código → test → límite |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Registro de decisiones de seguridad (ADR-001 … ADR-012) |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Todo lo que no está implementado y por qué |
| [docs/VERIFICATION.md](docs/VERIFICATION.md) | Cómo reproducir y verificar cada afirmación |
| [docs/WEB.md](docs/WEB.md) | Interfaz web: ejecución, endpoints, seguridad y evidencia automatizada |

## Estructura

```
sentinel/
  scope.py         allowlist, autorización, tiers, rate limit, kill switch
  audit.py         cadena de auditoría SHA-256
  model.py         Asset / Service / Evidence / Finding / Assessment
  collectors.py    recolección local de solo lectura (Tier 1)
  discovery.py     TCP connect, banner, HTTP, TLS (Tier 2)
  checks/          ssh.py · web.py · exposure.py
  cvss.py          CVSS v3.1 base (especificación FIRST)
  auth.py          política de autenticación + sesiones + rechazo de ataques de credenciales
  privesc.py       análisis de privilegios → hipótesis
  report.py        Markdown / HTML / JSON
  engine.py        orquestación + matriz de capacidades
  selfcheck.py     verificación ejecutable de los controles
  webapp.py        backend HTTP same-origin de la interfaz
sentinel/web/       panel web con exactamente tres acciones principales
tests/             222 tests (unittest)
docs/              arquitectura, decisiones, límites, verificación y uso web
examples/          alcances de ejemplo + informe de muestra generado por el agente
```

## Uso responsable

Usá este agente únicamente sobre sistemas para los que tengas autorización escrita. El alcance es el
límite legal y técnico: el agente lo aplica en código, pero la responsabilidad de declararlo
correctamente es del operador. Los informes generados incluyen la referencia de autorización y el
hash de la cadena de auditoría para que sean trazables.
