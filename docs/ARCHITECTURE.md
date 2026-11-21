# Arquitectura

## 1. Principios

| Principio | Consecuencia de diseño |
|---|---|
| **Default deny** | Sin un target declarado y un puerto autorizado no existe ninguna acción posible. El alcance es un objeto de primera clase, no un flag. |
| **Tiers explícitos** | Toda función que toca el objetivo declara el tier que requiere (1 detectar, 2 validar, 3 explotar). El guard rechaza por encima del máximo autorizado y rechaza el 3 siempre. |
| **Evidencia primero** | Un hallazgo sin `Evidence` con digest SHA-256 no se puede construir; `Finding.evidence` es la fuente de verdad del informe. |
| **Honestidad epistémica** | `confidence` (confirmed/inferred/hypothesis) y `validation_state` (observed/inferred/not_validated) son obligatorios en todo hallazgo y se imprimen en todos los formatos. |
| **Separación recolectar / interpretar** | Los `checks/*` son funciones puras sobre datos ya recolectados. Eso los hace testeables con fixtures y evita que un check abra sockets por su cuenta. |
| **Sin capacidades latentes** | Si una acción no está implementada, existe una función que la rechaza y un test que verifica el rechazo. No hay "código dormido" de explotación. |

## 2. Diagrama de componentes

```
                    ┌──────────────────────────────────────────────┐
                    │                 CLI (cli.py)                 │
                    │ scope-check · assess · verify-audit ·        │
                    │ capabilities · self-check                    │
                    └───────────────┬──────────────────────────────┘
                                    │
                    ┌───────────────▼──────────────────────────────┐
                    │              engine.py                       │
                    │  orquesta: alcance → guard → recolección →   │
                    │  checks → agregación → informe → auditoría   │
                    └───┬───────────┬───────────────┬──────────────┘
                        │           │               │
        ┌───────────────▼──┐  ┌─────▼─────────┐  ┌──▼─────────────────┐
        │ scope.py         │  │ collectors.py │  │ discovery.py       │
        │ ScopeGuard       │  │ Tier 1 local  │  │ Tier 2 red         │
        │ · allowlist      │  │ solo lectura  │  │ · TCP connect      │
        │ · autorización   │  │ · identidad   │  │ · banner           │
        │ · tiers          │  │ · cuentas     │  │ · HTTP (1 request) │
        │ · presupuesto    │  │ · sshd/PAM    │  │ · TLS handshake    │
        │ · rate limit     │  │ · sudo/SUID   │  │                    │
        │ · kill switch    │  │ · cron/PATH   │  │                    │
        └───────┬──────────┘  └─────┬─────────┘  └──┬─────────────────┘
                │                   │               │
                │           ┌───────▼───────────────▼───────────┐
                │           │            checks/              │
                │           │ ssh.py · web.py · exposure.py     │
                │           │ auth.py · privesc.py             │
                │           │ cvss.py · versions.py            │
                │           └───────────────┬──────────────────┘
                │                           │ Finding[]
        ┌───────▼──────────┐        ┌───────▼──────────────┐
        │ audit.py         │        │ report.py            │
        │ cadena SHA-256   │        │ MD · HTML · JSON     │
        └──────────────────┘        └──────────────────────┘
```

## 3. Componentes y responsabilidades

| Módulo | Responsabilidad | Tier | Entradas | Salidas |
|---|---|---|---|---|
| `scope.py` | Cargar/validar el alcance; autorizar o rechazar cada acción y registrarla | — | JSON de alcance, host/puerto/tier | `Scope`, decisión allow/deny, registro de auditoría |
| `audit.py` | Traza append-only encadenada; verificación de integridad | — | acción, resultado, detalle | JSONL con `prev_hash`/`hash`, informe de verificación |
| `collectors.py` | Hechos locales de solo lectura (identidad, SO, cuentas, sshd, PAM, sudo, SUID, capabilities, cron, PATH, systemd, permisos) | 1 | `ScopeGuard` | `LocalFacts` + evidencia |
| `discovery.py` | Fingerprint de servicios: TCP connect, banner pasivo, una petición HTTP, handshake TLS con certificado | 2 | `ScopeGuard`, host, puertos autorizados | `Asset`/`Service` + evidencia |
| `checks/ssh.py` | Reglas sobre `sshd_config` con semántica *first value wins* y defaults | 1 | `LocalFacts` | `Finding[]` |
| `checks/web.py` | Cabeceras de seguridad, cookies, framing, TLS (versión, cipher, certificado) | 1 sobre observaciones 2 | `Service.http`, `Service.tls` | `Finding[]` |
| `checks/exposure.py` | Servicios peligrosamente expuestos y correlación versión → CVE | 1 | `Service` | `Finding[]` |
| `cvss.py` | CVSS v3.1 base (ecuaciones y Roundup de la especificación) | — | vector | score, severidad |
| `versions.py` | Comparación de versiones tolerante a sufijos de distribución | — | strings | orden/None |
| `auth.py` | Política de contraseñas, base de cuentas, permisos, cookies, entropía; **rechazo** de ataques de credenciales | 1 (+2 opcional para fingerprint de login) | `LocalFacts`, cabeceras | `Finding[]` |
| `privesc.py` | Enumeración y clasificación de rutas de escalamiento → hipótesis con prerrequisitos | 1 | `LocalFacts` | `Finding[]`, postura, skipped |
| `report.py` | Render Markdown/HTML/JSON, redacción, matriz de capacidades y decisiones | — | `Assessment` | 3 archivos |
| `engine.py` | Orquestación, cobertura de capacidades, cierre de auditoría | — | alcance + modo | `RunResult` |
| `selfcheck.py` | Verificación ejecutable de los controles y del pipeline | — | — | `CheckResult[]` |
| `webapp.py` + `sentinel/web/` | UI y API same-origin; orquesta escaneo, análisis offline e informes sin reemplazar el core | 2 | JSON de alcance validado | operaciones, findings, reportes |

## 4. Flujo de una ejecución

1. **Carga del alcance** (`Scope.from_file`): esquema, autorización explícita, vigencia, targets,
   puertos, presupuesto. Cualquier fallo aborta antes de tocar el sistema.
2. **Apertura de auditoría**: se crea/reanuda el JSONL y se registra `run_start`.
3. **Instanciación del guard**: rate limiter y contadores por corrida.
4. **Recolección**:
   - modo `local`: `collect_local_facts` con `guard.check_local(...)` por cada bloque;
   - modo `network`: por cada host del alcance, `scan_host` con `guard.check(host, port, Tier.VALIDATE)`
     por cada puerto y por conexión.
5. **Interpretación**: checks puros → `Finding[]` con evidencia.
6. **Agregación**: deduplicación por fingerprint estable, orden por score, matriz de cobertura
   (`partial`/`blocked` incluidos) y lista de comprobaciones no ejecutadas.
7. **Cierre**: `finished_at`, `run_finish`, verificación de la cadena de auditoría embebida en el informe.
8. **Render**: Markdown, HTML autocontenido y JSON con digests.

## 5. Modelo de datos

```
Scope ──1:N── Target(kind, value, ports, max_tier, allow_public)
Assessment
 ├── assets[]        Asset(host, role, os, services[], evidence[])
 │                    └── Service(host, port, state, banner, product, version, tls{}, http{}, evidence[])
 ├── findings[]      Finding(check_id, title, category, severity, cvss_vector, cvss_score,
 │                           confidence, validation_state, evidence[], impact, remediation,
 │                           prerequisites[], manual_validation_required, tags[])
 ├── coverage[]      CapabilityCoverage(id, status, exercised_in_run, code_ref, test_ref)
 ├── skipped[]       {check, reason}
 └── audit_chain     {ok, records, head}
```

`Finding.id` es un hash estable de `(asset, port, check_id, título)`: dos corridas sobre el mismo estado
producen los mismos IDs, lo que permite comparar informes en el tiempo.

`Evidence.digest()` = SHA-256 de la representación canónica de `{kind, asset, data}`. El informe imprime
el digest y el JSON completo, de modo que un tercero puede recomputarlo.

## 6. Fronteras de confianza

| Frontera | Qué la cruza | Control |
|---|---|---|
| Operador → agente | archivo de alcance, flags | validación de esquema, autorización obligatoria, vigencia |
| Agente → host local | lecturas de archivos y comandos whitelisteados | tier 1, allowlist de rutas, `subprocess` sin shell, timeouts, sin escritura |
| Agente → red | conexiones TCP, HTTP, TLS | allowlist host/puerto, tier 2, rate limit, presupuesto, sin payloads |
| Agente → Internet | nada por defecto | sin dependencias de red en runtime: avisos curados offline, sin telemetría |
| Agente → informe | hallazgos y evidencia | redacción de secretos, digests, etiquetas de confianza |

## 7. Modos de ejecución

- **`local`** (Tier 1): no abre sockets. Inventaría el host donde corre el agente y evalúa su
  configuración. Es el modo usado en la demostración.
- **`network`** (Tier 2): escanea exclusivamente los puertos declarados en el alcance, con una petición
  por servicio. Máximo 256 hosts por target CIDR (`MAX_HOSTS_PER_TARGET`), 4 workers, timeout 2,5 s.

## 8. Extensión

- **Nuevo check**: función pura `analyze_x(datos) -> Finding[]` + test con fixture + entrada en
  `coverage_table` si representa una capacidad nueva.
- **Nuevo aviso**: agregar entrada a `sentinel/data/advisories.json` con vector CVSS v3.1 completo; los
  tests verifican que todos los vectores son parseables y que los rangos son coherentes.
- **Nuevo observador de red**: implementarlo en `discovery.py` pasando por `guard.check(...)`; nunca
  dentro de un check.

## 9. Interfaz web

`sentinel.webapp` entrega una UI estática sin dependencias frontend y una API JSON en el mismo origen.
Las rutas `POST /api/scan`, `/api/analyze` y `/api/report` llaman respectivamente a `ScopeGuard` +
`discovery.scan_host`, a `checks.exposure`/`checks.web`, y a `report.write_reports`. La captura se
conserva en memoria para esa sesión y los artefactos/auditoría en disco. Ver [WEB.md](WEB.md) para el
flujo y los límites.

## 10. Despliegue

- Se ejecuta desde el host del analista o desde un jump host autorizado; no requiere agentes remotos.
- No necesita privilegios: si `sudo -n -l` no está disponible, lo reporta como comprobación no ejecutada.
- La evidencia se guarda en `evidence/` (ignorado por git). Retención y cifrado quedan a cargo del
  proceso de gestión del engagement.
- Para detener una corrida en curso: `touch STOP` en el directorio de trabajo (o el `killswitch_path`
  declarado en el alcance).
