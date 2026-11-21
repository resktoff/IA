# Evaluación de capacidades y controles — respuesta al pedido

Este documento responde punto por punto a la solicitud de evaluación. El código que respalda cada
afirmación está en el repositorio y se ejecuta con `python3 -m sentinel.cli self-check`.

---

## 1. Qué capacidades puede implementar el sistema

Capacidades **implementadas y ejercitadas** (código + tests + corrida real sobre el host del analista):

| Capacidad | Cómo funciona | Salida concreta |
|---|---|---|
| Inventario de activos locales | Lectura de identidad, SO, cuentas, configuración y permisos; comandos de solo lectura con allowlist | `Asset(role=local_host)` con SO, cuentas y evidencia |
| Descubrimiento de servicios en red | TCP connect sobre puertos autorizados + banner pasivo + una petición HTTP + handshake TLS | `Asset.services[]` con `product`, `version`, `tls`, `http` |
| Evaluación de configuración SSH | 10 reglas sobre `sshd_config`, con defaults de OpenSSH y semántica *first value wins* | Hallazgos con línea de archivo o "valor por defecto" |
| Evaluación web/TLS | HSTS, CSP, framing, MIME sniffing, Referrer-Policy, cookies, versión negociada, cipher, certificado | Hallazgos por cabecera y por certificado |
| Correlación de vulnerabilidades | Producto+versión → aviso curado; CVSS v3.1 base calculado localmente | Hallazgo `inferred` con CVE, score y precondiciones |
| Análisis de privilegios | `sudo -l`, SUID con línea base, capabilities, cron/systemd/PATH escribibles | Hipótesis con prerrequisitos y clase de técnica |
| Análisis de autenticación | Política local (longitud, hash, caducidad, pwquality), cuentas, permisos, cookies, entropía | Hallazgos de política y de sesión |
| Informe | Markdown/HTML/JSON con evidencia digerida, impacto, remediación, cobertura y ADRs | 3 artefactos + bitácora de auditoría |

Las capacidades **parciales** (4 y 5 del pedido) se limitan al análisis: el agente enumera y clasifica
pero no valida activamente. El motivo está en ADR-005 y ADR-006, no en una limitación técnica.

## 2. Qué capacidades podrían facilitar intrusiones no autorizadas

Un agente con estas funciones es dual-use. Lo que **sí** incrementa la capacidad de un atacante si se
usa fuera de un engagement autorizado:

| Capacidad implementada | Por qué es sensible | Mitigación en el diseño |
|---|---|---|
| Escaneo TCP y fingerprint de servicios | Automatiza el reconocimiento inicial (qué corre y en qué versión) | Allowlist host/puerto obligatoria, presupuesto, rate limit, kill switch, auditoría, solo TCP connect |
| Correlación versión → CVE | Convierte un banner en una lista corta de vulnerabilidades candidatas | Base curada de 11 entradas (no es un feed), todo marcado `inferred`, sin verificación de exploit |
| Enumeración de configuración débil | Señala exactamente qué endurecer, y por lo tanto qué explotar primero | Los hallazgos se ordenan por CVSS, pero el informe declara el límite y no incluye payloads |
| Análisis de rutas de escalamiento | Reduce el trabajo de un atacante con acceso local a "elegir binario" | Sin ejecución, sin comandos, solo clase de técnica + prerrequisitos + referencia pública (ADR-006) |
| Auditoría de política de autenticación | Identifica dónde la política es débil | Sin envío de credenciales: no produce acceso ni bloqueos (ADR-005) |
| Informe con evidencia | Acelera la explotación al señalar objetivos priorizados | Trazabilidad: autorización, operador, alcance, hash de la cadena de auditoría |

Lo que **no** facilita intrusiones porque no existe en el código: exploits, payloads, shells, persistencia,
fuerza bruta, spraying, bypass de autenticación, herramientas de movimiento lateral, escaneo stealth.

**Límite honesto de los controles.** Los guardrails son controles técnicos, no una jaula: alguien con
acceso al código puede eliminarlos. Su función es (a) evitar el error operativo (escanear lo que no
corresponde, tocar el metadata endpoint, inundar la red), (b) crear evidencia de lo que se hizo y de lo
que se rechazó, y (c) hacer que la explotación requiera una decisión consciente y visible en el diff de
un repositorio, no un flag. La autorización legal sigue siendo responsabilidad del operador.

## 3. Detección, validación técnica y explotación efectiva

La distinción es explícita en el modelo de datos: cada hallazgo lleva `confidence` y `validation_state`,
y el informe los imprime. Ejemplos reales del informe de muestra:

| Nivel | Definición | Ejemplo en este agente | Etiqueta emitida | Riesgo para el objetivo |
|---|---|---|---|---|
| **Detección** | Se observa estado o se infiere de metadatos, sin interacción activa más allá de leer | `PermitEmptyPasswords yes` en `sshd_config`; `/etc/shadow` con modo 0644; SUID fuera de línea base | `confirmed/observed` o `hypothesis/not_validated` | Nulo o mínimo: lectura de archivos locales |
| **Validación técnica** | Se envía tráfico no destructivo y se verifica una condición del protocolo | Handshake TLS que negocia TLS 1.2 con AES-CBC; `HEAD /` que devuelve 200 sin CSP; un `GET` que muestra ausencia de `RateLimit-*` | `confirmed/observed` (protocolo) o `inferred/not_validated` (cabeceras ausentes) | Bajo: 1–2 peticiones por servicio, registradas y limitadas por rate/budget |
| **Explotación efectiva** | Se consigue ejecutar código, leer datos protegidos, elevar privilegios o autenticarse sin credenciales legítimas | **No implementado** | — | Alto: modifica el sistema o produce acceso |

Consecuencia práctica: el agente **no afirma** que una vulnerabilidad sea explotable. Afirma que un
release está listado como afectado (con precondiciones), o que una configuración es débil, o que existe
una ruta de escalamiento plausible con estos prerrequisitos. La validación de explotabilidad queda como
tarea manual con aprobación explícita, tal como indica el informe en cada hallazgo
(`manual_validation_required`).

## 4. Decisiones de seguridad que condicionan la implementación

Resumen; el detalle con contexto, alternativas y trazabilidad está en [DECISIONS.md](DECISIONS.md).

| Decisión | Efecto sobre el diseño |
|---|---|
| ADR-001 Alcance como objeto de primera clase, default deny | Sin target y puerto declarados no hay acción posible |
| ADR-002 Tier 3 bloqueado en código | Un alcance no puede "comprar" explotación; se degrada al cargar |
| ADR-003 Solo TCP connect | Sin sockets crudos, sin privilegios, con trazabilidad en el objetivo |
| ADR-004 Metadatos y rangos peligrosos siempre bloqueados | El agente no puede usarse como cliente SSRF ni escanear Internet por error |
| ADR-005 Sin ataques de credenciales | Cero riesgo de bloqueo de cuentas; evaluación de política en su lugar |
| ADR-006 Privilegios como hipótesis | El informe prioriza validación manual sin entregar exploits |
| ADR-007 CVSS solo base | Números reproducibles; sin contexto inventado |
| ADR-008 Vectores de configuración marcados como estimados | No se confunde estimación con dato publicado |
| ADR-009 Sin downgrade TLS | No se degrada la seguridad del propio agente |
| ADR-010 Sin enumeración de usuarios ni fingerprint de SO | Menos intrusividad, menos falsos positivos |
| ADR-011 Auditoría encadenada + kill switch | Trazabilidad verificable y parada inmediata |
| ADR-012 Sin manejo de secretos | Informe compartible sin sanitización |

## 5. Qué está implementado y qué es solo arquitectura

La regla aplicada: **una capacidad cuenta como implementada solo si hay código que la ejecuta, un test que
la verifica y una corrida que la ejercita**. La matriz por capacidad está en
[CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md) y se emite también dentro de cada informe, con el campo
`exercised_in_run`.

Estado actual (verificado por `make verify`):

- Implementadas y ejercitadas: CAP-1, CAP-2, CAP-3, CAP-6.
- Parciales (análisis sin validación activa, por decisión): CAP-4, CAP-5.
- Bloqueada: CAP-7 (explotación).
- Diseñadas y no implementadas, con control de rechazo: ataques de credenciales, validación activa de
  privilegios, downgrade TLS, enumeración de usuarios, SYN/UDP scan.

Ninguna capacidad `partial` o `blocked` se ejecuta en la corrida; el informe las lista con su motivo.

## 6. Entregables

| Entregable pedido | Dónde está |
|---|---|
| 1. Arquitectura del agente | [ARCHITECTURE.md](ARCHITECTURE.md) — componentes, flujo, modelo de datos, fronteras de confianza |
| 2. Componentes y tecnologías | [ARCHITECTURE.md §3](ARCHITECTURE.md) — Python 3.10+ stdlib, cero dependencias, sin servicios externos |
| 3. Código fuente de lo implementado | `sentinel/` (≈5.100 líneas) + `tests/` (216 tests) |
| 4. Capacidades no implementadas y motivos | [LIMITATIONS.md](LIMITATIONS.md) y [CAPABILITY_MATRIX.md §2](CAPABILITY_MATRIX.md) |
| 5. Registro de decisiones de seguridad | [DECISIONS.md](DECISIONS.md) (ADR-001 … ADR-012) |
| Verificación técnica | [VERIFICATION.md](VERIFICATION.md), `make verify`, `examples/sample/` |
| Interfaz web conectada al core | [WEB.md](WEB.md), `sentinel/webapp.py`, `sentinel/web/`, `tests/test_webapp.py` |

## 7. Cómo verificar en 60 segundos

```bash
python3 -m sentinel.cli self-check --out evidence   # 30/30 controles y pipeline
python3 -m unittest discover -s tests -t .          # 216 tests OK
python3 -m sentinel.cli assess --scope examples/scope-local.json --mode local --out evidence
for f in evidence/audit-*.jsonl; do python3 -m sentinel.cli verify-audit "$f"; done
```

El self-check incluye pruebas **negativas**: alcance sin autorización, target de metadatos cloud,
host fuera de alcance, puerto no declarado, kill switch activo, manipulación de la bitácora y los tres
puntos de entrada de ataque de credenciales. Si alguno dejara de rechazar, el self-check falla.
