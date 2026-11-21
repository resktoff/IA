# Verificación reproducible

Este documento especifica cómo reproducir cada afirmación técnica y qué resultado esperar. No requiere
internet ni paquetes Python externos; las pruebas de red usan servidores temporales en loopback.

## Requisitos

- Python 3.10 o posterior (probado con Python 3.11).
- Linux para la evaluación local completa (las pruebas unitarias puras también corren en otros sistemas,
  aunque algunas comprobaciones específicas de Linux se omiten o degradan).
- `openssl` solo para generar el certificado autofirmado que usan las pruebas TLS.

## Comandos principales

```bash
# 1. Suite automatizada
python3 -m unittest discover -s tests -t . -v

# 2. Controles de seguridad y autoprueba del pipeline
python3 -m sentinel.cli self-check --out evidence

# 3. Evaluación local del host actual (no abre sockets)
python3 -m sentinel.cli assess \
  --scope examples/scope-local.json \
  --mode local \
  --out evidence

# 4. Verificar la cadena de auditoría generada
for f in evidence/audit-*.jsonl; do python3 -m sentinel.cli verify-audit "$f"; done
```

Atajos equivalentes: `make test`, `make selfcheck`, `make demo`, `make verify`.

## Resultados de referencia

- Tests: **216 OK** (`unittest discover`). Las pruebas que dependen de sockets solo conectan a
  `127.0.0.1` en servidores efímeros creados por el propio test.
- Self-check: **30/30 PASS**, incluyendo controles negativos de autorización, metadata cloud,
  host/puerto fuera del alcance, tier, kill switch, ataques de credenciales y alteración de auditoría.
- `assess --mode local`: genera Markdown, HTML, JSON y JSONL; no intenta una conexión de red.
- `verify-audit`: devuelve `ok: true`, la cantidad de registros y el hash final. Si se altera, trunca o
  reordena el JSONL, devuelve código distinto de cero y explica la primera línea no válida.

## Qué prueba cada conjunto

| Grupo | Archivo(s) | Afirmaciones verificadas |
|---|---|---|
| Alcance | `tests/test_scope.py` | autorización explícita, allowlist de host/puerto, CIDR, tier 3 bloqueado, presupuesto, rate limit, vigencia, kill switch, concurrencia |
| Auditoría | `tests/test_audit.py` | hashes encadenados, persistencia, concurrencia, truncamiento y manipulación |
| Descubrimiento | `tests/test_discovery.py` | TCP connect, puerto cerrado, banner, HTTP, TLS/certificados, correlación de avisos, evidencia y scope |
| Recolección local | `tests/test_collectors.py` | parseo de cuentas/configuración, permisos con `lstat`, recolección real de solo lectura, ausencia de `/etc/shadow` |
| Reglas SSH/web | `tests/test_ssh_checks.py`, `tests/test_web_checks.py` | reglas puras sobre configuración/observaciones y clasificación |
| Autenticación | `tests/test_auth.py` | política/cookies/entropía y rechazo de ataques de credenciales |
| Escalamiento | `tests/test_privesc.py` | clasificación como hipótesis, agregación y no ejecución |
| Informes | `tests/test_report.py` | secciones requeridas, escape HTML, redacción, consistencia, formatos y archivos |
| Integración | `tests/test_engine.py` | ejecución local y network contra loopback, auditoría, matriz y artefactos |
| Controles/CLI | `tests/test_controls.py` | self-check, matriz, CLI, controles bloqueados |
| Interfaz web | `tests/test_webapp.py` | API same-origin; scan TCP real, checks existentes, informes descargables y auditoría |

## Evidencia comprometida de la corrida de muestra

`examples/sample/` contiene los tres informes y el JSONL de auditoría emitidos por una corrida real de
`examples/scope-local.json` contra el host del sandbox. Se puede verificar la cadena con:

```bash
python3 -m sentinel.cli verify-audit examples/sample/audit-*.jsonl
```

La carpeta `evidence/` se reserva para salidas nuevas del operador y está ignorada por Git; la muestra
versionada es reproducible, pero sus identificadores y datos del host corresponden a la corrida
capturada y no deben tratarse como evidencia de una ejecución futura.

## Interfaz web y evidencia de botones

`python3 -m unittest tests.test_webapp -v` prueba los tres endpoints del flujo real contra un servicio
HTTP efímero autorizado dentro de la prueba. El test verifica servicio/banner/status observados, hallazgos
de checks reales, Markdown/HTML/JSON generados y la cadena SHA-256. La guía operativa está en
[WEB.md](WEB.md).

## Interpretación de un resultado

- **PASS** prueba que el control funcionó en ese caso de prueba; no prueba que el host esté libre de
  vulnerabilidades.
- `confirmed/observed` describe un hecho observado directamente (por ejemplo, un encabezado ausente en
  una respuesta recibida).
- `inferred` describe una correlación o conclusión derivada de metadatos (por ejemplo, versión afectada).
- `hypothesis/not_validated` describe una ruta plausible que no se ejecutó.
- Ningún resultado significa explotación efectiva: el tier 3 está bloqueado por diseño.
