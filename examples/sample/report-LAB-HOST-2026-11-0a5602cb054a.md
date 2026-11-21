# Informe técnico — Evaluación de seguridad

| Campo | Valor |
|---|---|
| Engagement | `LAB-HOST-2026-11` |
| Cliente | Laboratorio interno (host del analista) |
| Operador | analista@example.invalid |
| Run ID | `0a5602cb054a` |
| Modo | `local_host` |
| Inicio / fin | 2026-11-21T12:42:23+00:00 → 2026-11-21T12:42:23+00:00 |
| Autorización | LAB-AUTH-2026-11-001 (aprobada por responsable de plataforma) |
| Clasificación del documento | Confidencial — partes autorizadas |

## 1. Resumen ejecutivo

Se identificaron **14 hallazgos** sobre **1 activos**: 2 crítico, 1 alto, 4 medio, 7 bajo.

| ID | Severidad | Hallazgo | Activo | Confianza |
|---|---|---|---|---|
| F-3a49dc4e85 | CRÍTICO | SSH permite cuentas con contraseña vacía | e2b.local | confirmado |
| F-dd53f91e13 | ALTO | SSH permite inicio de sesión de root (yes) | e2b.local | confirmado |
| F-ad1a12758b | CRÍTICO | La cuenta 'user' puede ejecutar cualquier comando como ALL, ALL : ALL sin contraseña | e2b.local | confirmado |
| F-8e6abeb538 | MEDIO | Longitud mínima de contraseña ausente o insuficiente | e2b.local | confirmado |
| F-cbdab8ad02 | MEDIO | Directorio del PATH escribible por el usuario: /usr/local/bin | e2b.local | hipótesis |

**Qué se hizo en esta ejecución**

- Identificación de activos y servicios expuestos — implemented: Inventario local (identidad, SO, cuentas, configuración, permisos). El descubrimiento de red (Tier 2) no se ejecutó en este modo.
- Detección de vulnerabilidades y clasificación por criticidad — implemented: Correlación versión->aviso contra un subconjunto curado y cálculo CVSS v3.1 base propio. Es inferencia por versión, no validACIÓN de explotabilidad.
- Evaluación de configuraciones y vectores de ataque — implemented: Reglas deterministas sobre sshd_config, cabeceras HTTP, TLS, PAM/pwquality y permisos de archivos
- Análisis de posibilidades de escalamiento de privilegios — partial: Enumeración y clasificación de sudo/SUID/capabilities/cron/systemd/PATH con hipótesis y prerrequisitos. No se ejecuta ningún binario ni comando privilegiado: no hay validación ni explotación (ADR-006).
- Resistencia de mecanismos de autenticación y protección — partial: Análisis de política (longitud, hash, caducidad, pwquality, permisos de shadow/sudoers) y de cookies/atributos. Sin envío de credenciales ni pruebas de bloqueo (ADR-005).
- Informes técnicos con evidencias, impacto y recomendaciones — implemented: Markdown + HTML autocontenido + JSON, con digest SHA-256 por evidencia y cadena de auditoría verificada

**Qué no se hizo (y por qué)**

- No se envió ningún exploit ni payload y no se intentó post-explotación (ADR-002).
- No se enviaron credenciales ni se provocaron bloqueos de cuenta (ADR-005).
- No se ejecutaron binarios SUID, comandos sudo ni unidades systemd para validar hipótesis (ADR-006).
- Las coincidencias CVE por versión son **inferencias**, no pruebas de explotabilidad.

## 2. Autorización, alcance y controles

| Campo | Valor |
|---|---|
| Referencia de autorización | LAB-AUTH-2026-11-001 |
| Aprobada por | responsable de plataforma |
| Vigencia | 2026-11-01T00:00:00+00:00 → 2026-12-15T23:59:59+00:00 |
| Tier máximo permitido | 1 |
| Presupuesto de peticiones | 50 |
| Tasa máxima | 5.0 req/s |
| Kill switch | STOP |
| Archivo de alcance | examples/scope-local.json |

**Objetivos declarados**

| Tipo | Objetivo | Puertos | Tier máx. |
|---|---|---|---|
| local_host | self | 65000 | 1 |

Controles activos durante la ejecución (implementados en código, no solo documentados):

| Control | Implementación |
|---|---|
| Allowlist default-deny de hosts y puertos | `sentinel/scope.py::ScopeGuard.check` |
| Autorización explícita obligatoria | `Scope.from_dict` rechaza alcances sin `authorized=true` |
| Tier 3 (explotación) inalcanzable | `Tier.EXPLOIT` rechazado antes de cualquier I/O |
| Presupuesto y rate limit | token bucket + contador duro por engagement |
| Kill switch | archivo de parada comprobado en cada acción |
| Auditoría encadenada | `sentinel/audit.py`, SHA-256 por registro |
| Redacción de secretos | `sentinel/redact.py` en el renderer |

## 3. Metodología y límites

| Tier | Nombre | Qué incluye | Estado en el agente |
|---|---|---|---|
| 1 | DETECT | Lectura de configuración y hechos locales, correlación offline | implementado |
| 2 | VALIDATE | TCP connect, banner, una petición HTTP, handshake TLS | implementado |
| 3 | EXPLOIT | Entrega de exploits, credenciales, post-explotación | **bloqueado** |

Escala de confianza usada en todos los hallazgos:

- **confirmado**: el estado se observó directamente (cabecera ausente, directiva presente, permiso de archivo).
- **inferido**: derivado de un banner o de una versión; puede ser falso si el servicio miente o el paquete está parcheado sin cambiar la versión.
- **hipótesis**: ruta plausible de escalamiento o de ataque; requiere validación manual.

## 4. Cobertura de capacidades

| ID | Capacidad | Estado | Ejercitada en esta corrida | Detalle |
|---|---|---|---|---|
| CAP-1 | Identificación de activos y servicios expuestos | implemented | sí | Inventario local (identidad, SO, cuentas, configuración, permisos). El descubrimiento de red (Tier 2) no se ejecutó en este modo. |
| CAP-2 | Detección de vulnerabilidades y clasificación por criticidad | implemented | sí | Correlación versión->aviso contra un subconjunto curado y cálculo CVSS v3.1 base propio. Es inferencia por versión, no validACIÓN de explotabilidad. |
| CAP-3 | Evaluación de configuraciones y vectores de ataque | implemented | sí | Reglas deterministas sobre sshd_config, cabeceras HTTP, TLS, PAM/pwquality y permisos de archivos |
| CAP-4 | Análisis de posibilidades de escalamiento de privilegios | partial | sí | Enumeración y clasificación de sudo/SUID/capabilities/cron/systemd/PATH con hipótesis y prerrequisitos. No se ejecuta ningún binario ni comando privilegiado: no hay validación ni explotación (ADR-006). |
| CAP-5 | Resistencia de mecanismos de autenticación y protección | partial | sí | Análisis de política (longitud, hash, caducidad, pwquality, permisos de shadow/sudoers) y de cookies/atributos. Sin envío de credenciales ni pruebas de bloqueo (ADR-005). |
| CAP-6 | Informes técnicos con evidencias, impacto y recomendaciones | implemented | sí | Markdown + HTML autocontenido + JSON, con digest SHA-256 por evidencia y cadena de auditoría verificada |
| CAP-7 | Explotación efectiva y post-explotación | blocked | **no** | No implementado por diseño (ADR-002): sin payloads, sin entrega de exploits, sin persistencia |

Estados: `implemented` (código funcional con tests), `partial` (análisis sin validación activa por diseño), `blocked` (no implementado, con control explícito que lo impide).

## 5. Hallazgos

### 5.1 Tabla resumen

| ID | Sev. | CVSS | Confianza | Validación | Hallazgo | Activo |
|---|---|---|---|---|---|---|
| F-3a49dc4e85 | CRÍTICO | 9.8 (estimado) | confirmado | observado | SSH permite cuentas con contraseña vacía | e2b.local |
| F-dd53f91e13 | ALTO | 8.1 (estimado) | confirmado | observado | SSH permite inicio de sesión de root (yes) | e2b.local |
| F-ad1a12758b | CRÍTICO | — | confirmado | observado | La cuenta 'user' puede ejecutar cualquier comando como ALL, ALL : ALL sin contraseña | e2b.local |
| F-8e6abeb538 | MEDIO | — | confirmado | observado | Longitud mínima de contraseña ausente o insuficiente | e2b.local |
| F-cbdab8ad02 | MEDIO | — | hipótesis | no validado | Directorio del PATH escribible por el usuario: /usr/local/bin | e2b.local |
| F-4f04760da9 | MEDIO | — | hipótesis | no validado | Directorio del PATH escribible por el usuario: /usr/local/games | e2b.local |
| F-cf6bf87d9e | MEDIO | — | confirmado | observado | SSH acepta autenticación por contraseña | e2b.local |
| F-26e715c6ad | BAJO | — | confirmado | observado | Sin política de calidad de contraseñas activa (pwquality) | e2b.local |
| F-0f6811fda1 | BAJO | — | confirmado | observado | Las contraseñas no expiran (PASS_MAX_DAYS=99999) | e2b.local |
| F-a4ffe3e6cd | BAJO | — | confirmado | observado | Cuentas de sistema con shell interactivo: sync | e2b.local |
| F-8f4c5c304e | BAJO | — | confirmado | observado | Reenvío del agente SSH habilitado (default) | e2b.local |
| F-f04daa1482 | BAJO | — | confirmado | observado | MaxAuthTries=6 permite demasiados intentos por conexión | e2b.local |
| F-aa5acc3b58 | BAJO | — | confirmado | observado | Sin AllowUsers/AllowGroups: cualquier cuenta válida puede autenticarse | e2b.local |
| F-02f4e592c4 | BAJO | — | confirmado | observado | SSH permite reenvío de X11 | e2b.local |

### 5.2 Detalle

#### F-3a49dc4e85 — SSH permite cuentas con contraseña vacía

| Campo | Valor |
|---|---|
| Severidad | CRÍTICO (critical) |
| CVSS v3.1 base | 9.8 (estimado) |
| Vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Categoría | ssh_hardening |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `SSH-EMPTY-PW` |

**Impacto.** Cualquier cuenta sin contraseña puede autenticarse por SSH sin credenciales; el acceso resultante es interactivo y hereda los privilegios de la cuenta.

**Recomendación.** Establecer `PermitEmptyPasswords no` y auditar cuentas con hash vacío en /etc/shadow.

> `PermitEmptyPasswords yes` en /etc/ssh/sshd_config:124

**Evidencia**

- `config_directive` — `PermitEmptyPasswords yes` en /etc/ssh/sshd_config:124
  - fuente: `checks.ssh` · sha256: `3f0303dd89147222b492ab9bdf70cbbd…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "directive": "PermitEmptyPasswords",
  "effective_value": "yes",
  "from_default": false,
  "source": "/etc/ssh/sshd_config:124",
  "config_file_present": true
}
```

**Referencias**

- https://www.ssh.com/academy/ssh/sshd_config
- https://cisecurity.org/controls

#### F-dd53f91e13 — SSH permite inicio de sesión de root (yes)

| Campo | Valor |
|---|---|
| Severidad | ALTO (high) |
| CVSS v3.1 base | 8.1 (estimado) |
| Vector | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Categoría | ssh_hardening |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `SSH-ROOT-LOGIN` |

**Impacto.** Un login directo de root elimina la trazabilidad por usuario y convierte cualquier credencial o clave comprometida en control administrativo total.

**Recomendación.** `PermitRootLogin no`; usar cuentas nominales y `sudo` con registro de auditoría.

> `PermitRootLogin yes` en /etc/ssh/sshd_config:123

**Evidencia**

- `config_directive` — `PermitRootLogin yes` en /etc/ssh/sshd_config:123
  - fuente: `checks.ssh` · sha256: `0f1b458c482502d5714f7a1ec665b5cf…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "directive": "PermitRootLogin",
  "effective_value": "yes",
  "from_default": false,
  "source": "/etc/ssh/sshd_config:123",
  "config_file_present": true
}
```

**Referencias**

- https://www.ssh.com/academy/ssh/sshd_config
- https://cisecurity.org/controls

#### F-ad1a12758b — La cuenta 'user' puede ejecutar cualquier comando como ALL, ALL : ALL sin contraseña

| Campo | Valor |
|---|---|
| Severidad | CRÍTICO (critical) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | privilege_escalation |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `PRIV-SUDO-ALL` |

**Impacto.** No existe una frontera de privilegios que escalar para esta cuenta: ya es administrativa. El riesgo relevante es que una credencial de esta cuenta comprometida otorga control total, y NOPASSWD la hace utilizable sin segundo factor ni interacción.

**Recomendación.** Sustituir las reglas `ALL` por comandos concretos, eliminar NOPASSWD, habilitar MFA en sudo (pam_google_authenticator) y registrar la sesión (`log_output`) en un destino remoto.

> Hecho observado, no vulnerabilidad: describe el nivel de privilegio de la cuenta con la que corre la evaluación. Es la línea base contra la que se miden las demás hipótesis.

**Evidencia**

- `sudo_policy` — evidencia sudo_policy
  - fuente: `privesc` · sha256: `fd1c1917bffc15b6949bd816ff3bc0c4…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "identity": "user",
  "rules": [
    {
      "runas": "ALL : ALL",
      "command": "ALL",
      "nopasswd": "[REDACTED]",
      "all": true
    },
    {
      "runas": "ALL : ALL",
      "command": "ALL",
      "nopasswd": "[REDACTED]",
      "all": true
    },
    {
      "runas": "ALL",
      "command": "ALL",
      "nopasswd": "[REDACTED]",
      "all": true
    },
    {
      "runas": "ALL : ALL",
      "command": "ALL",
      "nopasswd": "[REDACTED]",
      "all": true
    }
  ],
  "normalised": [
    "(ALL : ALL) ALL",
    "(ALL : ALL) NOPASSWD: ALL",
    "(ALL) NOPASSWD: ALL",
    "(ALL : ALL) NOPASSWD: ALL"
  ],
  "raw_listing": "Matching Defaults entries for user on e2b:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin, use_pty\n\nUser user may run the following commands on e2b:\n    (ALL : ALL) ALL\n    (ALL : ALL) NOPASSWD: ALL\n    (ALL) NOPASSWD: ALL\n    (ALL : ALL) NOPASSWD: ALL"
}
```

**Referencias**

- https://www.sudo.ws/docs/man/sudoers.man/

#### F-8e6abeb538 — Longitud mínima de contraseña ausente o insuficiente

| Campo | Valor |
|---|---|
| Severidad | MEDIO (medium) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | authentication |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `AUTH-PW-MINLEN` |

**Impacto.** Sin un mínimo efectivo, el espacio de búsqueda de credenciales se reduce a valores triviales. NIST SP 800-63B exige ≥8 y recomienda ≥12 para cuentas con privilegios; el valor no está definido en login.defs ni en pwquality.

**Recomendación.** Definir `minlen = 12` en /etc/security/pwquality.conf (que prevalece sobre login.defs) y bloquear contraseñas filtradas contra una lista de brechas.

**Evidencia**

- `password_policy` — evidencia password_policy
  - fuente: `auth` · sha256: `ad95369f510d23dc7a30c385637f31d5…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "PASS_MIN_LEN": "[REDACTED]",
  "pwquality_present": false,
  "source": "/etc/login.defs"
}
```

**Referencias**

- https://pages.nist.gov/800-63-3/sp800-63b.html#password

#### F-cbdab8ad02 — Directorio del PATH escribible por el usuario: /usr/local/bin

| Campo | Valor |
|---|---|
| Severidad | MEDIO (medium) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | privilege_escalation |
| Activo | e2b.local |
| Confianza | hipótesis |
| Estado de validación | no validado |
| Check | `PRIV-PATH-WRITABLE` |
| Validación manual requerida | sí |
| Prerrequisitos | un proceso privilegiado resuelve comandos a través del PATH |

**Impacto.** Si un script privilegiado invoca un binario por nombre sin ruta absoluta, se puede interceptar colocando un ejecutable en este directorio.

**Recomendación.** Retirar directorios escribibles del PATH de root y de los servicios; usar rutas absolutas en scripts privilegiados.

**Evidencia**

- `path_permissions` — evidencia path_permissions
  - fuente: `privesc` · sha256: `a11b69f717afd4ec863016f16c747763…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "path": "/usr/local/bin",
  "present": true,
  "mode": "drwxrwxrwx",
  "mode_octal": "0o777",
  "uid": 0,
  "gid": 0,
  "owner": "root",
  "group": "root",
  "is_symlink": false,
  "symlink_target": null,
  "other_write": true,
  "other_read": true,
  "world_writable": true,
  "writable_by_current_user": 2
}
```

#### F-4f04760da9 — Directorio del PATH escribible por el usuario: /usr/local/games

| Campo | Valor |
|---|---|
| Severidad | MEDIO (medium) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | privilege_escalation |
| Activo | e2b.local |
| Confianza | hipótesis |
| Estado de validación | no validado |
| Check | `PRIV-PATH-WRITABLE` |
| Validación manual requerida | sí |
| Prerrequisitos | un proceso privilegiado resuelve comandos a través del PATH |

**Impacto.** Si un script privilegiado invoca un binario por nombre sin ruta absoluta, se puede interceptar colocando un ejecutable en este directorio.

**Recomendación.** Retirar directorios escribibles del PATH de root y de los servicios; usar rutas absolutas en scripts privilegiados.

**Evidencia**

- `path_permissions` — evidencia path_permissions
  - fuente: `privesc` · sha256: `54cf1ff327edecdd97d4a25e9c80bb27…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "path": "/usr/local/games",
  "present": true,
  "mode": "drwxrwxrwx",
  "mode_octal": "0o777",
  "uid": 0,
  "gid": 0,
  "owner": "root",
  "group": "root",
  "is_symlink": false,
  "symlink_target": null,
  "other_write": true,
  "other_read": true,
  "world_writable": true,
  "writable_by_current_user": 2
}
```

#### F-cf6bf87d9e — SSH acepta autenticación por contraseña

| Campo | Valor |
|---|---|
| Severidad | MEDIO (medium) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | ssh_hardening |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `SSH-PASSWORD-AUTH` |

**Impacto.** Habilita ataques de fuerza bruta y reutilización de credenciales desde cualquier red con alcance al puerto; la resistencia depende por completo de la política de contraseñas.

**Recomendación.** Migrar a claves o certificados SSH, o al menos exigir MFA y limitar `AllowUsers`/`Match Address`.

> `PasswordAuthentication yes` en /etc/ssh/sshd_config:125

**Evidencia**

- `config_directive` — `PasswordAuthentication yes` en /etc/ssh/sshd_config:125
  - fuente: `checks.ssh` · sha256: `d0eafce731418a638f3f985497234a71…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "directive": "PasswordAuthentication",
  "effective_value": "yes",
  "from_default": false,
  "source": "/etc/ssh/sshd_config:125",
  "config_file_present": true
}
```

**Referencias**

- https://www.ssh.com/academy/ssh/sshd_config
- https://cisecurity.org/controls

#### F-26e715c6ad — Sin política de calidad de contraseñas activa (pwquality)

| Campo | Valor |
|---|---|
| Severidad | BAJO (low) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | authentication |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `AUTH-PW-COMPLEXITY` |

**Impacto.** No hay verificación de longitud, diccionario ni repetición en el cambio de contraseña, de modo que la política declarada no se aplica en la práctica.

**Recomendación.** Instalar/activar `pam_pwquality.so` en /etc/pam.d/common-password con minlen ≥12, `dictcheck=1` y `maxrepeat=3`.

**Evidencia**

- `password_policy` — evidencia password_policy
  - fuente: `auth` · sha256: `3c0e630303735d431bfeac9f389e51bc…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "pwquality_readable": false,
  "minlen": null
}
```

#### F-0f6811fda1 — Las contraseñas no expiran (PASS_MAX_DAYS=99999)

| Campo | Valor |
|---|---|
| Severidad | BAJO (low) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | authentication |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `AUTH-PW-MAXAGE` |

**Impacto.** Una credencial comprometida permanece válida indefinidamente. NIST no exige rotación periódica, pero solo si existe detección de compromiso; sin ella, la ausencia de caducidad amplía la ventana de uso de credenciales filtradas.

**Recomendación.** Alinear con la política corporativa: mantener sin caducidad forzada solo si hay verificación de contraseñas filtradas y MFA; en caso contrario, fijar PASS_MAX_DAYS ≤ 365.

**Evidencia**

- `password_policy` — evidencia password_policy
  - fuente: `auth` · sha256: `44d1f7a7cb9fee7d1c503b2ad580a530…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "PASS_MAX_DAYS": "[REDACTED]"
}
```

**Referencias**

- https://pages.nist.gov/800-63-3/sp800-63b.html#password

#### F-a4ffe3e6cd — Cuentas de sistema con shell interactivo: sync

| Campo | Valor |
|---|---|
| Severidad | BAJO (low) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | authentication |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `AUTH-SERVICE-SHELL` |

**Impacto.** Amplía las cuentas utilizables para autenticación interactiva y para movimiento lateral si se compromete un servicio.

**Recomendación.** Fijar `/usr/sbin/nologin` en las cuentas de servicio que no requieran shell.

**Evidencia**

- `accounts` — evidencia accounts
  - fuente: `auth` · sha256: `1ea4d72c6f80a4db5b11b3f401fa79ee…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "accounts": [
    "sync"
  ]
}
```

#### F-8f4c5c304e — Reenvío del agente SSH habilitado (default)

| Campo | Valor |
|---|---|
| Severidad | BAJO (low) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | ssh_hardening |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `SSH-AGENT-FORWARD` |

**Impacto.** Cada sesión reenviada expone el socket del agente a la máquina remota; es la precondición de CVE-2023-38408 y de robo de identidad de clave en hosts comprometidos.

**Recomendación.** `AllowAgentForwarding no` y usar `ProxyJump` en lugar de reenvío de agente.

> `AllowAgentForwarding` no está definido; se aplica el valor por defecto de OpenSSH (yes)

**Evidencia**

- `config_directive` — `AllowAgentForwarding` no está definido; se aplica el valor por defecto de OpenSSH (yes)
  - fuente: `checks.ssh` · sha256: `e0bbfbdb06d827df2923092d3fafc432…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "directive": "AllowAgentForwarding",
  "effective_value": "yes",
  "from_default": true,
  "source": "compiled default",
  "config_file_present": true
}
```

**Referencias**

- https://www.ssh.com/academy/ssh/sshd_config
- https://cisecurity.org/controls

#### F-f04daa1482 — MaxAuthTries=6 permite demasiados intentos por conexión

| Campo | Valor |
|---|---|
| Severidad | BAJO (low) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | ssh_hardening |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `SSH-MAX-AUTH` |

**Impacto.** Más intentos por conexión reducen el coste de la fuerza bruta y retrasan el bloqueo.

**Recomendación.** `MaxAuthTries 3` y `MaxStartups 10:30:60`; complementar con fail2ban o equivalente.

> `MaxAuthTries` no está definido; se aplica el valor por defecto de OpenSSH (6)

**Evidencia**

- `config_directive` — `MaxAuthTries` no está definido; se aplica el valor por defecto de OpenSSH (6)
  - fuente: `checks.ssh` · sha256: `029cc8a9573e6bb1a8ce4d72f58be0e5…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "directive": "MaxAuthTries",
  "effective_value": "6",
  "from_default": true,
  "source": "compiled default",
  "config_file_present": true,
  "max_auth_tries": 6
}
```

**Referencias**

- https://www.ssh.com/academy/ssh/sshd_config
- https://cisecurity.org/controls

#### F-aa5acc3b58 — Sin AllowUsers/AllowGroups: cualquier cuenta válida puede autenticarse

| Campo | Valor |
|---|---|
| Severidad | BAJO (low) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | ssh_hardening |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `SSH-NO-ALLOWLIST` |

**Impacto.** No existe una segunda barrera de autorización: una cuenta de servicio con shell y credencial filtrada obtiene acceso SSH.

**Recomendación.** Declarar `AllowGroups ssh-operators` (o `AllowUsers`) y mantener las cuentas de servicio con shell `nologin`.

> `AllowUsers` no está definido; se aplica el valor por defecto de OpenSSH (n/d)

**Evidencia**

- `config_directive` — `AllowUsers` no está definido; se aplica el valor por defecto de OpenSSH (n/d)
  - fuente: `checks.ssh` · sha256: `f5f8478a73410c5f2bb492c80daf673e…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "directive": "AllowUsers",
  "effective_value": "",
  "from_default": true,
  "source": "compiled default",
  "config_file_present": true
}
```

**Referencias**

- https://www.ssh.com/academy/ssh/sshd_config
- https://cisecurity.org/controls

#### F-02f4e592c4 — SSH permite reenvío de X11

| Campo | Valor |
|---|---|
| Severidad | BAJO (low) |
| CVSS v3.1 base | — |
| Vector | — |
| Categoría | ssh_hardening |
| Activo | e2b.local |
| Confianza | confirmado |
| Estado de validación | observado |
| Check | `SSH-X11-FORWARD` |

**Impacto.** Amplía la superficie de ataque del canal SSH (proxy X11, DISPLAY spoofing) sin ser necesario en servidores.

**Recomendación.** `X11Forwarding no` salvo requisito explícito.

> `X11Forwarding yes` en /etc/ssh/sshd_config:90

**Evidencia**

- `config_directive` — `X11Forwarding yes` en /etc/ssh/sshd_config:90
  - fuente: `checks.ssh` · sha256: `93f35bd5b195d26803d00547e7b31473…` · recolectado: 2026-11-21T12:42:23+00:00

```json
{
  "directive": "X11Forwarding",
  "effective_value": "yes",
  "from_default": false,
  "source": "/etc/ssh/sshd_config:90",
  "config_file_present": true
}
```

**Referencias**

- https://www.ssh.com/academy/ssh/sshd_config
- https://cisecurity.org/controls

## 6. Capacidades no implementadas

| Capacidad | ADR | Motivo |
|---|---|---|
| Explotación de vulnerabilidades | ADR-002 | Entrega de payloads, weaponización de PoCs, bypass de mitigaciones y post-explotación. Convierte el entregable en una herramienta de intrusión reutilizable y no es necesario para el objetivo de evaluación. |
| Ataques de credenciales | ADR-005 | Fuerza bruta, password spraying, prueba de credenciales por defecto y prueba de bloqueo por fallos deliberados. Cambia el estado del servidor y puede dejar cuentas reales bloqueadas. |
| Validación activa de escalamiento de privilegios | ADR-006 | Ejecución de binarios SUID vulnerables, comandos sudo o unidades systemd creadas por el agente. Se entrega la hipótesis con prerrequisitos y se delega la validación al operador en laboratorio. |
| Detección de versiones TLS heredadas por downgrade | ADR-009 | Probar TLS 1.0/1.1 requiere bajar el nivel de seguridad de OpenSSL en todo el proceso. Se reporta solo la versión negociada observada. |
| Enumeración de usuarios remota y fingerprinting de SO | ADR-010 | Aumenta el ruido y la intrusividad sin mejorar la decisión de remediación; se prioriza la evidencia de configuración. |

## 7. Registro de decisiones de seguridad

| ADR | Decisión | Consecuencia |
|---|---|---|
| ADR-001 | Default deny con allowlist de alcance y autorización explícita | Toda acción requiere engagement válido, referencia de autorización y host/puerto declarados. |
| ADR-002 | Tier 3 (explotación) bloqueado en código, no en documentación | `Tier.EXPLOIT` se rechaza aunque el archivo de alcance lo pida; el alcance se degrada al cargar. |
| ADR-003 | Un solo tipo de escaneo: TCP connect | Sin sockets crudos ni SYN scan: el escaneo queda registrado por el objetivo y no sirve como scanner stealth. |
| ADR-004 | Rangos públicos y metadatos cloud bloqueados sin doble opt-in | 169.254.0.0/16, multicast, reservados y direcciones globales quedan fuera salvo flag explícito por target y por scope. |
| ADR-005 | Sin ataques de credenciales | La superficie existe y lanza `CapabilityBlocked`; el análisis se limita a política y atributos observados. |
| ADR-006 | Privilegios: hipótesis, no exploits | Se publica clase de técnica y prerrequisitos; no se incluyen secuencias de comandos ni payloads. |
| ADR-007 | CVSS v3.1 solo base | Sin métricas temporales ni ambientales: no se dispone de madurez de exploit ni de criticidad del activo. |
| ADR-008 | Vectores CVSS de configuración marcados como estimados | Los hallazgos sin CVE llevan vector elegido por el agente y se rotulan `(estimado)`. |
| ADR-009 | Sin downgrade de TLS | No se baja el security level de OpenSSL; se reporta la versión negociada y se documenta el límite. |
| ADR-010 | Sin enumeración remota de usuarios ni fingerprint de SO | Coste/beneficio desfavorable y mayor intrusividad. |
| ADR-011 | Auditoría encadenada por hash y kill switch por archivo | Cada acción y cada rechazo se registran antes de ejecutarse; `touch STOP` detiene la ejecución. |
| ADR-012 | Sin secretos en el informe | No se leen /etc/shadow ni cuerpos de respuesta por defecto; el renderer redacta claves sensibles. |

El detalle completo, con alternativas descartadas y trazabilidad al código, está en `docs/DECISIONS.md`.

## 8. Anexos

### A. Cadena de auditoría

| Campo | Valor |
|---|---|
| Archivo | examples/sample/audit-LAB-HOST-2026-11-0a5602cb054a.jsonl |
| Integridad | OK |
| Registros | 13 |
| Hash de cabeza | `6cd82b1165177d84050ffa836e2e0e8fc16234dd6707fcdac3512a4cb0537242` |

Cualquier modificación, borrado o reordenamiento de registros invalida la verificación (`python -m sentinel.cli verify-audit <archivo>`).

### B. Comprobaciones no ejecutadas

| Check | Motivo |
|---|---|
| CAP-1.network | modo local: no se abrieron conexiones TCP (el objetivo elegido es el propio host) |

### C. Reproducibilidad

```bash
python -m sentinel.cli assess --scope <scope.json> --mode local_host --out evidence
python -m sentinel.cli verify-audit examples/sample/audit-LAB-HOST-2026-11-0a5602cb054a.jsonl
python -m unittest discover -s tests -v
```

### D. Limitaciones aplicables

- La correlación CVE usa un subconjunto curado offline de avisos; no sustituye a un feed con backports de la distribución.
- El escaneo de puertos cubre exclusivamente los puertos declarados en el alcance.
- Los hallazgos de configuración evalúan el archivo tal como está en disco; no se consultó la configuración efectiva via `sshd -T`.
- No se evaluó comportamiento en runtime (WAF, rate limiting real, lógica de negocio).

---

_Informe generado por `sentinel` a partir de evidencia recolectada en la ejecución indicada. Las capacidades marcadas como `partial` o `blocked` no fueron ejecutadas y no deben interpretarse como validadas. Este documento no certifica la ausencia de vulnerabilidades._