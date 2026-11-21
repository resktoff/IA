# Matriz de capacidades

Esta matriz es la respuesta directa al requisito *"no presentes capacidades como implementadas si
solamente describiste su arquitectura"*. Cada fila tiene: estado, archivo de código, test que lo
demuestra y límite explícito.

Estados:

- **implemented** — código funcional, ejercitado en la corrida y cubierto por tests.
- **partial** — se implementó el análisis, no la validación activa. El motivo es de seguridad (ADR-005/006),
  no de complejidad.
- **blocked** — no implementado, con una función que lo rechaza y un test que verifica el rechazo.

## 1. Capacidades solicitadas

| # | Capacidad solicitada | Estado | Qué se implementó | Código | Tests | Límite explícito |
|---|---|---|---|---|---|---|
| 1 | Identificar activos y servicios expuestos | **implemented** | TCP connect sobre puertos autorizados; banner pasivo; fingerprint HTTP (`Server`, estado) y TLS (versión, cipher, certificado); inventario local de cuentas, servicios systemd y configuración | `discovery.py`, `collectors.py` | `test_discovery.py` (19), `test_collectors.py` (17) | Solo TCP y solo puertos declarados; sin UDP, sin SYN scan, sin fingerprint de SO |
| 2 | Detectar vulnerabilidades y clasificarlas por criticidad | **implemented** | Correlación producto+versión contra un subconjunto curado offline (11 avisos); CVSS v3.1 base calculado con la especificación (incluido Roundup) | `checks/exposure.py`, `versions.py`, `cvss.py`, `data/advisories.json` | `test_versions.py` (11), `test_cvss.py` (9), `test_discovery.py` | Es **inferencia por versión**: no valida explotabilidad y no conoce backports de la distribución |
| 3 | Evaluar configuraciones y posibles vectores de ataque | **implemented** | 10 reglas de `sshd_config` (con defaults y *first value wins*), 6 reglas de cabeceras/cookies/TLS, exposición de 11 servicios sensibles, permisos de `shadow`/`sudoers`/`sshd_config` | `checks/ssh.py`, `checks/web.py`, `checks/exposure.py`, `auth.py` | `test_ssh_checks.py` (16), `test_web_checks.py` (16), `test_auth.py` (20) | Configuración tal como está en disco; no se consultó `sshd -T` ni el comportamiento efectivo en runtime |
| 4 | Analizar posibilidades de escalamiento de privilegios | **partial** | Parseo de `sudo -l`, clasificación de binarios con escape de shell (GTFOBins), inventario SUID con línea base, capabilities peligrosas, cron/systemd/PATH escribibles → **hipótesis con prerrequisitos** | `privesc.py` | `test_privesc.py` (19) | **No se ejecuta nada**: ni el binario SUID, ni el comando sudo, ni la unidad systemd. Sin validación activa (ADR-006) |
| 5 | Evaluar resistencia de mecanismos de autenticación y protección | **partial** | Política de contraseñas (longitud, caducidad, hash, pwquality), base de cuentas (UID 0 múltiple, contraseñas vacías, shadow), permisos de archivos, cookies de sesión, entropía de tokens, fingerprint de endpoint de login (1 GET) | `auth.py` | `test_auth.py` | **Sin envío de credenciales**, sin fuerza bruta, sin prueba de bloqueo por fallos deliberados (ADR-005) |
| 6 | Generar informes técnicos con evidencias, impacto y recomendaciones | **implemented** | Markdown + HTML autocontenido + JSON; tabla de cobertura; sección de capacidades no implementadas; ADRs; digest por evidencia; cadena de auditoría verificada; redacción de secretos | `report.py`, `engine.py` | `test_report.py` (19), `test_engine.py` (14) | El informe no certifica ausencia de vulnerabilidades y lo declara |

## 2. Capacidades que el agente **no** implementa

| Capacidad | Estado | Motivo | Control verificable |
|---|---|---|---|
| Entrega de exploits / PoCs | **blocked** | Convierte el entregable en herramienta de intrusión reutilizable; no es necesario para evaluar (ADR-002) | `Tier.EXPLOIT` rechazado en `ScopeGuard`; alcances con `max_tier: 3` se degradan a 2 — `test_scope.py::test_exploitation_always_blocked`, `test_scope.py::test_tier_three_in_scope_is_downgraded` |
| Fuerza bruta / spraying / credenciales por defecto | **blocked** | Cambia estado del servidor, puede bloquear cuentas reales y produce herramientas de ataque (ADR-005) | `auth.credential_attack_guard/password_spray/default_credential_test` lanzan `CapabilityBlocked` — `test_auth.py::TestCredentialAttackRefusal`, `test_controls.py` |
| Validación activa de escalamiento | **blocked** | Ejecutar binarios SUID/sudo arbitrarios puede modificar el sistema y crear persistencia (ADR-006) | Los hallazgos se emiten como `hypothesis` + `manual_validation_required=True` — `test_privesc.py::test_gtfobin_rule_becomes_hypothesis` |
| Detección de TLS 1.0/1.1 por downgrade | **blocked** | Requiere bajar el nivel de seguridad de OpenSSL en todo el proceso (ADR-009) | Solo se reporta la versión negociada, con nota metodológica — `test_web_checks.py::test_tls12_reported_as_informational_limit` |
| Enumeración remota de usuarios y fingerprint de SO | **blocked** | Aumenta intrusividad sin mejorar la decisión de remediación (ADR-010) | No existe código; se documenta en `LIMITATIONS.md` |
| Escaneo SYN / UDP / raw sockets | **blocked** | Evita capacidades stealth y la necesidad de privilegios (ADR-003) | `discovery.py` solo usa `socket.create_connection`; auditado en `test_engine.py::test_audit_contains_no_network_action` |
| Lectura de `/etc/shadow` | **blocked** | El agente no debe manejar hashes (ADR-012) | `test_collectors.py::test_never_reads_shadow` |

## 3. Cobertura de tests por módulo

| Módulo | Tests | Archivo |
|---|---|---|
| `scope.py` | 28 | `tests/test_scope.py` |
| `audit.py` | 8 | `tests/test_audit.py` |
| `cvss.py` | 9 | `tests/test_cvss.py` |
| `versions.py` + avisos | 11 | `tests/test_versions.py` |
| `collectors.py` | 17 | `tests/test_collectors.py` |
| `discovery.py` | 19 | `tests/test_discovery.py` |
| `checks/ssh.py` | 16 | `tests/test_ssh_checks.py` |
| `checks/web.py` | 16 | `tests/test_web_checks.py` |
| `auth.py` | 20 | `tests/test_auth.py` |
| `privesc.py` | 19 | `tests/test_privesc.py` |
| `report.py` | 19 | `tests/test_report.py` |
| `engine.py` | 14 | `tests/test_engine.py` |
| controles + CLI + self-check | 14 | `tests/test_controls.py` |
| `webapp.py` / API y ciclo de botones | 12 | `tests/test_webapp.py` |
| **Total** | **222** | `python3 -m unittest discover -s tests -t .` |

La matriz también se emite en cada informe (`CapabilityCoverage`), con el campo `exercised_in_run`
calculado a partir de lo que realmente se ejecutó en esa corrida.
