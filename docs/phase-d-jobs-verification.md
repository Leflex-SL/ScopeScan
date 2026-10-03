# D05–D08: comprobación del implementador

Fecha: 2026-10-03. Esta evidencia corresponde al constructor de jobs/worker/scheduler; la aceptación integral de D requiere la revisión y suite independientes.

Tras las reparaciones de snapshot del alcance, observaciones Grype por ocurrencia y fencing al commit:

```text
.venv/Scripts/python.exe -m pytest tests/test_durable_jobs.py tests/test_ssh_verification_binding.py tests/test_precision_feeds.py tests/test_enrichment.py tests/test_software_evidence.py -q --basetemp=.test-tmp-d-jobs-finalgate
155 passed, 1 warning in 102.95s
```

Ruff pasa en los archivos del worker, cola, scheduler, DB, servicio, CLI, routers centrales, colectores, MSRC, ExploitDB, store de software y regresiones relacionadas. La advertencia de pruebas es la de Starlette sobre TestClient/httpx y estaba presente antes de D. No se añade ninguna dependencia.

## Escenarios ejercitados

- Dos procesos Python independientes compiten por el mismo claim y sólo uno obtiene el trabajo; el límite global de workers se comprueba dentro de la transacción SQLite.
- Un reinicio conserva la cola. La migración repetida captura órdenes antiguas reconstruibles y convierte estados activos sin ownership duradero en errores de revisión.
- Propietario antiguo, lease vencida, cancelación y borrado impiden escrituras y finalización. Una transacción que pierde la lease antes del commit revierte su evidencia. Los exports dentro del handler conservan el fence y su snapshot de lectura.
- La cancelación persistente detiene un proceso Python real silencioso mediante el runner común. SSH/WinRM y ExploitDB usan el mismo runner con límites, deadlines y cancelación. Las pruebas no contactan hosts reales.
- Una reserva de scan queda retenida hasta completar el plan y entregar QUEUE.submit. El worker no reclama el plan a medio preparar. Un alcance cuya autorización cambia después del encolado falla antes de construir Nmap.
- El panel encola antes de responder y una segunda petición no duplica el enriquecimiento. El startup conserva el scan y lease de un worker vivo. El detalle `/jobs/ID` se renderiza y los límites ASGI rechazan cuerpos declarados y fragmentados antes del parser multipart.
- La planificación autenticada web puede carecer de identidad. El worker rechaza esa ejecución sin identidad, y el reintento con identidad/puerto correctos evalúa el control afectado sin cerrar otro listener.
- Dos procesos de scheduler producen un único slot. Límite por programación, cambio de autorización, ventana UTC y rollback entre scan/job/slot impiden duplicados y filas huérfanas. Un éxito con la misma evidencia no genera otro evento.
- Los reintentos de escritura externa incierta requieren reconciliación explícita y respetan el límite de intentos. Un scan que ya persistió su estado terminal no se reejecuta por perder el worker antes del cierre del job.
- Los secretos se rechazan en encargos; errores y resultados los redactan, incluyendo userinfo de URI. Repetir set_status(done) no vuelve a reconciliar ni inventa otra fecha de inventario.
- Un reporte Grype con dos versiones del mismo paquete/CVE, o dos ubicaciones de una versión, conserva cada componente y observación. La identidad lógica del componente permanece estable, mientras cada ocurrencia del documento conserva un ID separado; entradas idénticas tampoco colisionan.

Una comprobación adicional del archivo de software tras reparar la ocurrencia pasó 31 pruebas en 23.38s. Una combinación anterior de regresiones web/DB/seguridad/verificación pasó 190 pruebas en 143.19s; es evidencia previa a los últimos fences, por lo que no sustituye la puerta integral final.

Los cambios están sin commit del implementador. No se han ejecutado escaneos reales, consultas remotas autenticadas, descargas de herramientas o feeds, escrituras en servidores externos, ni programaciones sobre datos reales. La ejecución se comprobó en Windows/Python 3.13; Linux y otras versiones siguen a cargo de la matriz CI.

## Reparación posterior del grant activo

La revisión independiente detectó que los enriquecimientos activos sobre un scan terminado podían usar sus hosts históricos después de revocar su alcance. Se añadió `operation_grants.py`, compartido por los productores CLI/web y el worker. El grant se captura junto al job y estado queued en la misma transacción; conserva el alcance exacto y selecciona endpoints/módulos sin ejecutar herramientas. Se compara antes de entrar al colector y antes de cada destino o grupo MSF. La evaluación de feeds y el inventario local explícito conservan sus flujos históricos sin autorizar contacto con hosts retirados.

```text
.venv/Scripts/python.exe -m pytest tests/test_enrichment_grants.py tests/test_durable_jobs.py tests/test_enrichment.py tests/test_msf.py -q --basetemp=.test-tmp-d-jobs-grants
105 passed, 1 warning in 120.69s
```

La matriz nueva incluye 24 combinaciones de Linux/Windows/MSF verificación/MSF acción con autorización vacía, exclusiones, eliminación, perfil, límites y resolución cambiados. También prueba captura revocada con rollback, selección ampliada, grant ausente, ejecución válida con listener preciso, tres evaluadores históricos offline, loopback local explícito y revocación entre destinos. La revisión independiente repitió siete casos posteriores a la reparación y confirmó rechazo antes del colector junto con mantenimiento de los flujos válidos/históricos; su evidencia está en `phase-d-antipatterns.md`.

La repetición final de `tests/test_enrichment_grants.py` sobre las fuentes congeladas pasó 33 pruebas en 28.94s. Ruff pasó en el módulo de grants, cola, DB, worker, CLI, MSF, inventarios Linux/Windows y sus regresiones.
