# Interfaz web Sentinel

## Ejecutar

No requiere paquetes externos (Python stdlib):

```bash
python3 -m sentinel.webapp --host 0.0.0.0 --port 8765
```

Abrí `http://localhost:8765`. En Arena, el proceso puede publicarse como preview; el frontend usa
rutas relativas (`/api/...`) y el servidor escucha en `0.0.0.0`. Para instalar el entry point del
proyecto: `python3 -m pip install -e .` y luego `sentinel-web --port 8765`.

Los artefactos web se guardan en `evidence/web/<run-id>/`. Se excluyen de Git como cualquier otra salida
de `evidence/`. El estado de la sesión (selección de escaneo y botones habilitados) permanece en memoria
del proceso; los informes y auditorías quedan en disco.

## Flujo de las tres acciones

1. **ESCANEAR** — cargar o pegar un JSON de alcance vigente y autorizado. El backend llama
   `Scope.from_dict`, persiste el documento recibido, lo vuelve a cargar con `Scope.from_file` y exige al
   menos un target `host`/`cidr` en Tier 2. Antes de cualquier socket valida autorización, fechas,
   allowlist, direcciones bloqueadas, público con doble opt-in, puertos y presupuesto mediante
   `ScopeGuard`. Después ejecuta `discovery.scan_host` puerto por puerto (máximo 512 pares por corrida,
   256 hosts por target, timeout ≤5 s). No existe un target por defecto ni se inventa una autorización.
   Cada conexión/rechazo entra en la cadena de auditoría SHA-256. El botón cambia a **CANCELAR ESCANEO**;
   la cancelación cooperativa se atiende al completar la conexión actual, acotada por timeout.
2. **ANALIZAR** — ejecuta `checks.exposure.analyze_service` y
   `checks.web.analyze_service_web` sobre los objetos `Service` recolectados. No abre sockets ni repite
   la captura. Los hallazgos, confidence, validation_state y evidence se muestran desde los objetos reales
   `Finding` del core. Fuerza bruta, credenciales y explotación siguen bloqueadas/no implementadas.
3. **INFORME** — llama `report.write_reports` con el `Assessment` real y crea los archivos Markdown,
   HTML autocontenido y JSON. El HTML se muestra en un iframe sandbox; hay enlaces de descarga para los
   tres formatos. La auditoría incluye los eventos de análisis y generación y se verifica antes del render.

Los estados visibles son los de cada operación real (`queued`, `running`, `completed`, `cancelled`,
`error`), no una animación de éxito. Errores de validación se devuelven en la interfaz. El panel de
actividad se alimenta del registro de operaciones del backend.

## Alcance y advertencias

- El JSON debe ser emitido/aprobado por quien autoriza la prueba; los campos de ejemplo de repositorio
  no constituyen autorización real.
- Hostnames no se aceptan: el core requiere IP/CIDR explícitos y bloquea metadata/link-local/multicast/
  rangos reservados según ADR-004.
- Direcciones públicas requieren `allow_public: true` tanto a nivel de scope como de target. La interfaz
  no puede desactivar ese control.
- Un target `local_host` es válido para `assess --mode local`, no para reconocimiento de red Tier 2.
- Se recomienda desplegar solo en una máquina de confianza y mantener el puerto de UI accesible al
  operador del engagement. La aplicación no trae autenticación de usuarios: el alcance escrito es el
  control de autorización del scanner, no control de acceso web multiusuario.
- No hay endpoints CORS; los `POST` verifican `Origin` cuando está presente, exigen JSON, limitan el
  body a 1 MB y usan IDs aleatorios de sesión. Para uso compartido/remoto, poner detrás de autenticación
  y TLS administrados por la organización.
- Cancelar es cooperativo (no aborta el socket del sistema operativo en mitad del connect/lectura).
  Analizar e informar son fases locales cortas; no usan conexiones de red y no se cancelan.

## Evidencia automatizada de integración

`tests/test_webapp.py::test_scan_analyze_and_report_call_real_backend_and_download_evidence` levanta un
servidor HTTP efímero ligado a loopback para la prueba automatizada, declara ese puerto dinámico como
alcance explícito y recorre el mismo API que consumen los botones:

- `POST /api/scan` → comprueba un servicio abierto y la respuesta HTTP real (status 200/banner) más una
  cadena de auditoría íntegra.
- `POST /api/analyze` → exige hallazgos reales de `WEB-HEADER`, `WEB-BANNER` y `ADV-MATCH`; comprueba
  que el número de servicios analizados es el capturado.
- `POST /api/report` → exige artefactos reales de más de 1 KB en Markdown/HTML/JSON, vista previa con
  `WEB-HEADER` y verificación independiente de la auditoría.

Es una fixture temporal de unittest, no una demo ni un servicio persistente. Para repetir solo esa prueba:

```bash
python3 -m unittest tests.test_webapp -v
```

El test además comprueba rechazo de scopes sin autorización, doble opt-in de destinos públicos,
solicitudes cross-origin, orden obligatorio de fases y cancelación cooperativa. La suite completa incluye
estos 9 tests web sin modificar los 207 tests previos.
