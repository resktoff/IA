# Capacidades no implementadas y límites

Este documento existe para que el informe no pueda leerse como una promesa de cobertura total.

## 1. No implementado por decisión de seguridad

| Capacidad | Por qué no | Qué se entrega en su lugar |
|---|---|---|
| Explotación de vulnerabilidades | Herramienta de intrusión reutilizable; no es necesaria para decidir una remediación (ADR-002) | Evidencia + versión afectada + precondiciones + CVSS publicado |
| Post-explotación, persistencia, movimiento lateral | Idem, y modifica el sistema evaluado | Recomendaciones de detección y de segmentación |
| Fuerza bruta / spraying / credenciales por defecto | Bloquea cuentas reales y puede producir acceso efectivo (ADR-005) | Análisis de política, hashes, bloqueo declarado, cookies, entropía |
| Validación activa de escalamiento | Puede modificar el sistema (ADR-006) | Hipótesis con prerrequisitos y `manual_validation_required=True` |
| Payloads, shells inversas, C2 | Fuera del propósito de un assessment de configuración | — |
| TLS 1.0/1.1 por downgrade | Requiere bajar `SECLEVEL` de OpenSSL para todo el proceso (ADR-009) | Versión negociada observada + nota metodológica |
| Enumeración remota de usuarios | Ruido y falsos positivos (ADR-010) | Aviso por versión cuando corresponde |
| Escaneo SYN, UDP, raw sockets | Necesita privilegios y produce capacidades stealth (ADR-003) | TCP connect sobre puertos autorizados |

## 2. Límites técnicos de lo que sí está implementado

### 2.1 Correlación de vulnerabilidades

- La base de avisos es **un subconjunto curado de 11 entradas** en `sentinel/data/advisories.json`
  (actualizado 2026-11-01). No es un feed: no reemplaza a un escáner con base de datos completa.
- El matching es **por versión declarada en el banner**. Un servicio puede mentir, y las distribuciones
  aplican backports sin cambiar la versión: un `OpenSSL 1.1.1n` de Debian puede estar parcheado aunque la
  versión parezca anterior a un fix upstream. El informe lo advierte y pide verificar el paquete real.
- No se consultan fuentes en línea: el agente no tiene dependencias de red en runtime (ni telemetría).
- Solo se evalúan avisos con rango `introduced <= v < fixed`; los avisos con condiciones de build no se
  modelan.

### 2.2 Configuración SSH

- Se evalúa el archivo en disco y sus `Include` (hasta 2 niveles), con semántica *first value wins*.
- No se ejecuta `sshd -T`, así que no se capturan defaults compilados distintos de los de OpenSSH
  estándar (documentados como `DEFAULTS` en `checks/ssh.py`) ni directivas aplicadas por `Match`.
- Los bloques `Match` se parsean como directivas globales: puede haber falsos positivos/negativos en
  configuraciones con `Match` (no hay evaluación contextual).

### 2.3 Red

- Solo TCP y solo puertos declarados. Un servicio en un puerto no declarado no se descubre (por diseño).
- Una petición HTTP por servicio, sobre `/` y sin seguir redirecciones: no se evalúan rutas internas,
  autenticación, lógica de negocio ni WAF.
- El handshake TLS deshabilita la verificación de cadena para poder observar certificados inválidos; el
  informe declara ese modo. No se validan revocación (OCSP/CRL) ni pinnning.
- CIDR: máximo 256 hosts por target; 4 workers; timeout 2,5 s; sin reintentos.
- La entropía de cookies es una **cota inferior** calculada sobre una muestra; no prueba aleatoriedad.

### 2.4 Escalamiento de privilegios

- Se apoya en lo que el usuario del agente puede leer: si `sudo -n -l` requiere contraseña, la
  comprobación queda como "no ejecutada" (visible en el anexo B del informe).
- No se inspeccionan todos los directorios de unidades systemd ni todos los archivos del sistema: se
  limita a rutas conocidas y a un máximo de 200 unidades.
- La línea base de SUID es una lista de nombres habituales en Debian; en otras distribuciones puede
  requerir ajuste (y por eso los hallazgos son hipótesis, no conclusiones).
- No se evalúan vectores que requieren ejecución: `LD_PRELOAD`, `ptrace`, race conditions, escapes de
  contenedor.

### 2.5 Autenticación

- Sin pruebas de credenciales: no se puede afirmar que una cuenta con contraseña débil sea
  efectivamente comprometible.
- El fingerprint de login hace **un** `GET` y mira cabeceras; la ausencia de `RateLimit-*` es un indicio,
  no una prueba de ausencia de control (puede estar en el gateway).
- No se evalúan MFA, SSO, Kerberos ni la fortaleza real de los hashes (no se leen).

### 2.6 Informe

- No incluye métricas temporales/ambientales de CVSS (ADR-007).
- No incluye criticidad de negocio del activo: la priorización final es del cliente.
- El informe no certifica la ausencia de vulnerabilidades y lo declara en el pie de página.

## 3. Fuera de alcance del agente (no del engagement)

- Pruebas autenticadas (post-login), lógica de negocio, IDOR, control de acceso a nivel de aplicación.
- Ingeniería social, phishing, acceso físico.
- Evaluación de código fuente, dependencias (SCA) y cadena de suministro.
- Cumplimiento normativo (ISO 27001, PCI DSS): el agente aporta evidencia técnica, no certificación.
