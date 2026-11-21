# Registro de decisiones de seguridad (ADR)

Cada decisión documenta el contexto, la decisión, sus consecuencias, las alternativas descartadas y
dónde está implementada. Todas las que dicen "implementada" tienen un control ejecutable y un test.

---

## ADR-001 — El alcance es un objeto de primera clase, con default deny

**Contexto.** Un agente de evaluación necesita saber qué puede tocar. Si el alcance es un flag
(`--target x`) o una lista de IPs sin validación, un error de tipeo se convierte en tráfico hacia un
tercero.

**Decisión.** El agente solo actúa sobre targets declarados en un archivo JSON con esquema versionado,
que incluye declaraciones de autorización, vigencia, puertos y tier máximo. Los campos `authorized`,
`reference` y `approved_by` no se verifican contra una fuente externa ni prueban consentimiento. Sin match
exacto de host y puerto, la acción se rechaza. Los rechazos del `ScopeGuard` se registran en la cadena;
algunos rechazos HTTP/scope capturados por el handler se reflejan en la actividad en memoria; rechazos tempranos (como Origin) pueden no registrarse y esos eventos no se garantizan en la cadena.

**Consecuencias.**
- (+) Es imposible "escanear un /16 por accidente": los hosts se expanden solo desde un CIDR declarado y
  los puertos son obligatorios.
- (+) Los rechazos del guard de alcance quedan en la cadena de la ejecución; no todas las solicitudes inválidas del plano HTTP se persisten.
- (−) Más fricción operativa: hay que escribir el alcance antes de empezar. Es intencional.

**Alternativas descartadas.** Lista de IPs por CLI (sin vigencia ni autorización); confiar en un firewall
externo (no impide que el agente intente).

**Implementación.** `sentinel/scope.py::Scope.from_dict`, `ScopeGuard.check`, `ScopeGuard._match_target`.
**Tests.** `tests/test_scope.py::TestGuard`, `TestScopeLoading`.

---

## ADR-002 — El Tier 3 (explotación) está bloqueado en código

**Contexto.** El pedido incluía un agente "ofensivo". La explotación efectiva (payloads, bypass de
mitigaciones, post-explotación) no aporta a la decisión de remediación cuando ya existe evidencia de
configuración y de versión afectada, y convierte el artefacto en una herramienta de intrusión reutilizable
contra cualquier objetivo.

**Decisión.** `Tier.EXPLOIT` se rechaza siempre, incluso si el archivo de alcance pide `max_tier: 3`; al
cargar, el valor se degrada a 2 y el informe lo refleja. No existe ninguna ruta de código que envíe un
payload.

**Consecuencias.**
- (+) El agente es seguro de ejecutar en producción dentro de un alcance autorizado.
- (+) La capacidad no se puede "activar" editando JSON: requiere modificar código, lo que es una decisión
  consciente y revisable.
- (−) No se puede confirmar explotabilidad; se entrega evidencia + hipótesis y se deriva la validación.

**Alternativas descartadas.** Explotación con "modo laboratorio" (el código es el mismo y se filtra a
producción); PoC automáticos (mantenimiento y riesgo desproporcionados).

**Implementación.** `sentinel/scope.py` (`Tier`, `Scope.from_dict`, `ScopeGuard.check`), `sentinel/engine.py`.
**Tests.** `test_scope.py::test_exploitation_always_blocked`, `test_tier_three_in_scope_is_downgraded`;
`test_controls.py::test_exploitation_is_blocked_and_not_exercised`.

---

## ADR-003 — Un único tipo de escaneo: TCP connect

**Contexto.** SYN scan y sockets crudos permiten escaneos rápidos y "stealth", y requieren privilegios.

**Decisión.** Solo `socket.create_connection`. Sin sockets crudos, sin manipulación de flags TCP, sin
retransmisiones manuales.

**Consecuencias.**
- (+) El escaneo se completa con el handshake, así que queda registrado en el objetivo (trazabilidad).
- (+) No requiere root/CAP_NET_RAW; el agente corre con el usuario del operador.
- (−) Más lento y más visible que un SYN scan; aceptable para el tamaño de alcance previsto.

**Implementación.** `sentinel/discovery.py::_connect`, `scan_host`.
**Tests.** `test_discovery.py::test_scan_evidence_reports_scan_type`.

---

## ADR-004 — Direcciones peligrosas bloqueadas; públicas con doble opt-in

**Contexto.** Un agente que acepta cualquier `host` habilita dos errores graves: escanear Internet por
accidente y usar el agente como cliente SSRF contra el endpoint de metadatos cloud.

**Decisión.**
- Siempre bloqueados: `0.0.0.0/8`, `169.254.0.0/16` (incluye 169.254.169.254), `fd00:ec2::254`,
  `224.0.0.0/4`, `240.0.0.0/4`, `fe80::/10`, `ff00::/8`, broadcast. Los CIDR que contengan cualquiera
  de los endpoints de metadata también se rechazan; el guard vuelve a bloquear cada IP autorizada.
- Direcciones globales: requieren `allow_public: true` **en el target y en el scope**.
- Nombres de host como target: rechazados (solo IP/CIDR), para que la resolución DNS no pueda cambiar el
  destino después de la validación.

**Consecuencias.**
- (+) El metadata endpoint es inalcanzable incluso con un alcance mal escrito.
- (−) Un engagement real contra IPs públicas requiere dos flags explícitos y deja rastro en el JSON.

**Implementación.** `sentinel/scope.py::_validate_network_target`, `ALWAYS_BLOCKED_NETWORKS`,
`METADATA_ADDRESSES`, `ScopeGuard._match_target`.
**Tests.** `test_scope.py::test_metadata_endpoint_always_blocked`,
`test_ipv6_metadata_inside_cidr_is_blocked`, `test_scopeguard_blocks_metadata_even_if_scope_is_injected`,
`test_public_address_requires_double_opt_in`, `test_hostname_target_rejected`.

---

## ADR-005 — Sin ataques de credenciales

**Contexto.** Fuerza bruta, spraying y prueba de credenciales por defecto son las técnicas que más
fácilmente convierten un assessment en un incidente: bloquean cuentas reales, generan alertas y, si
tienen éxito, producen acceso no autorizado efectivo.

**Decisión.** No se envía ninguna credencial. La evaluación de autenticación se limita a: política local
(longitud, hash, caducidad, pwquality), base de cuentas, permisos de `shadow`/`sudoers`, atributos de
cookies, entropía estimada de tokens y un único `GET` al endpoint de login para observar si anuncia rate
limiting. Las funciones de ataque existen y lanzan `CapabilityBlocked` (control explícito y testeable).

**Consecuencias.**
- (+) Cero riesgo de bloqueo de cuentas y de acceso efectivo.
- (+) La ausencia de rate limiting se reporta como **indicio** (`inferred`, `not_validated`), no como
  hecho.
- (−) No se puede afirmar si una contraseña débil es explotable; se reporta la política que la permite.

**Implementación.** `sentinel/auth.py::credential_attack_guard`, `login_endpoint_attack`, `password_spray`,
`default_credential_test`, `analyze_login_endpoint`.
**Tests.** `test_auth.py::TestCredentialAttackRefusal`, `TestLoginEndpointFindings`.

---

## ADR-006 — Escalamiento de privilegios: hipótesis, nunca exploits

**Contexto.** Enumerar SUID, sudo, capabilities y cron es análisis; ejecutar el binario o el comando es
explotación y deja el sistema modificado.

**Decisión.** El agente enumera y clasifica, y emite hallazgos con `confidence=hypothesis`,
`validation_state=not_validated`, `manual_validation_required=True` y `prerequisites` (qué más debe ser
cierto). Se publica la **clase** de técnica ("shell escape desde el editor") y una referencia
(GTFOBins), no una secuencia de comandos.

**Consecuencias.**
- (+) Informe útil para priorizar trabajo de validación manual sin entregar un exploit.
- (+) Un test verifica que el hallazgo no contiene tokens ejecutables.
- (−) El informe requiere una fase humana de validación para cerrar esas filas.

**Implementación.** `sentinel/privesc.py` (analizadores y `analyze_all`).
**Tests.** `test_privesc.py::test_gtfobin_rule_becomes_hypothesis`, `test_no_command_sequence_in_the_finding`,
`test_posture_summary_states_no_exploitation`.

---

## ADR-007 — CVSS v3.1 solo grupo base

**Contexto.** CVSS tiene grupos temporal y ambiental. El temporal depende de madurez de exploit y de
existencia de parche reportado; el ambiental, de la criticidad del activo para el cliente. El agente no
tiene esos datos.

**Decisión.** Se implementa solo el grupo base, con las ecuaciones y el `Roundup` de la especificación.
Se rechazan vectores con métricas temporales/ambientales en lugar de ignorarlas silenciosamente.

**Consecuencias.**
- (+) Los números son reproducibles y verificables contra la calculadora oficial.
- (−) El score no incorpora contexto del cliente; el informe lo advierte y deja la priorización al cliente.

**Implementación.** `sentinel/cvss.py`.
**Tests.** `test_cvss.py::TestKnownScores` (9 vectores con valor publicado), `test_rejects_temporal_metrics`.

---

## ADR-008 — Vectores CVSS de configuración marcados como estimados

**Contexto.** Una cabecera ausente no tiene CVE ni vector publicado. Asignarle un número sin decirlo
produce falsa precisión.

**Decisión.** Los hallazgos sin aviso llevan un vector elegido por el agente, se etiquetan
`cvss_estimated` y el informe imprime "(estimado)". Los hallazgos con CVE usan el vector publicado y se
imprimen como "(publicado)". Los hallazgos de hardening menor (X11, LogLevel, banner) llevan severidad
cualitativa y **no** llevan score.

**Consecuencias.**
- (+) Se puede ordenar por criticidad sin confundir estimación con dato.
- (−) Dos fuentes de severidad conviven; el renderer las distingue explícitamente.

**Implementación.** `sentinel/checks/common.py::with_vector`, `sentinel/report.py::_fmt_score`.
**Tests.** `test_report.py::test_marks_estimated_vectors`.

---

## ADR-009 — Sin downgrade de TLS

**Contexto.** Detectar soporte de TLS 1.0/1.1 requiere ofrecer esas versiones, lo que en OpenSSL 3 exige
bajar `SECLEVEL` globalmente (afecta a todo el proceso) o recompilar.

**Decisión.** Se reporta la versión **negociada** y se documenta el límite. No se altera la configuración
global de OpenSSL. El certificado se inspecciona con verificación deshabilitada (para poder observar
certificados inválidos) y ese modo se declara en el informe.

**Consecuencias.**
- (+) No se degrada la seguridad del propio agente.
- (−) Un servidor que soporta TLS 1.0 pero negocia 1.3 no se detecta; queda como comprobación manual.

**Implementación.** `sentinel/discovery.py::tls_handshake`, `sentinel/checks/web.py::analyze_tls`.
**Tests.** `test_web_checks.py::test_tls12_reported_as_informational_limit`,
`test_discovery.py::TestTls` (handshake real contra servidor loopback con certificado autofirmado).

---

## ADR-010 — Sin enumeración remota de usuarios ni fingerprint de SO

**Contexto.** Ambas técnicas son ruidosas, propensas a falsos positivos y no cambian la recomendación de
remediación (actualizar/endurecer).

**Decisión.** No se implementan. Se documentan como límite y, cuando aplica, se reporta el aviso
correspondiente por versión (p. ej. CVE-2018-15473) sin intentar explotarlo.

**Implementación.** Ausencia por diseño; ver `docs/LIMITATIONS.md`.
**Tests.** `test_versions.py::test_old_openssh_matches_user_enumeration` (el aviso se reporta, no se prueba).

---

## ADR-011 — Auditoría encadenada y kill switch

**Contexto.** Un informe sin traza de lo que hizo el agente no es defendible ante el cliente ni ante un
incidente.

**Decisión.** Los eventos que llaman a `AuditLog.record` se escriben en un JSONL con
`hash = SHA-256(prev_hash + canonical_json(registro))`, génesis de 64 ceros, `fsync` por registro y
verificación embebida en el informe. Esto comprueba consistencia interna, pero no garantiza inmutabilidad,
autoría ni completitud: una cola truncada coherentemente o una cadena recalculada requieren una cabeza
retenida externamente para detectarse. La actividad HTTP de la interfaz se mantiene en memoria (máximo
200 eventos); solicitudes rechazadas y cancelaciones no son necesariamente eventos individuales de la
cadena. Un archivo `STOP` (configurable) detiene la ejecución en la siguiente acción.

**Consecuencias.**
- (+) Editar, borrar o reordenar registros dentro de la cadena presente rompe la verificación.
- (+) El operador puede solicitar detener el escaneo; la cancelación es cooperativa.
- (−) Sin ancla externa no se puede probar autoría ni detectar de forma general el truncamiento de cola.

**Implementación.** `sentinel/audit.py`, `ScopeGuard._check_killswitch`, `sentinel/cli.py verify-audit`.
**Tests.** `test_audit.py` (6 casos de manipulación), `test_scope.py::test_killswitch_blocks_everything`,
`test_controls.py::test_verify_audit_exit_codes`.

---

## ADR-012 — El agente no maneja secretos

**Contexto.** Leer `/etc/shadow`, cuerpos de respuesta o cookies en claro convierte el informe en un
objeto sensible y al agente en un objetivo.

**Decisión.** No se lee `/etc/shadow` (solo se verifican sus permisos). No se leen cuerpos de respuesta
por defecto (`max_body=0`). El renderer redacta valores de claves sensibles, tokens `Bearer`, claves
privadas y el valor de las cookies (conservando nombre y atributos, que son la evidencia).

**Consecuencias.**
- (+) El informe se puede compartir con el cliente sin sanitización manual.
- (−) Ciertos hallazgos que requieren inspeccionar contenido (p. ej. datos personales en un índice de
  Elasticsearch) quedan fuera de alcance por diseño.

**Implementación.** `sentinel/redact.py`, `sentinel/collectors.py::READABLE_FILES`,
`sentinel/discovery.py::probe_http(max_body=0)`.
**Tests.** `test_report.py::TestRedactionGranularity`, `test_collectors.py::test_never_reads_shadow`.
