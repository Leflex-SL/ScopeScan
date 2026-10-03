# Evidencia de conectores D02, D03 y D08

Fecha: 2026-10-03. Esta evidencia corresponde a la implementación y comprobación focal de conectores; la aceptación independiente y el gate global de la fase D siguen pendientes.

## Comprobaciones realizadas

```text
.venv\Scripts\python.exe -m pytest -q tests/test_integration_connectors.py --basetemp=.test-tmp-d-connectors-final --tb=short
29 passed, 1 warning in 36.74s
```

El warning proviene de la deprecación Starlette/TestClient con httpx; no afecta al resultado. Ruff aplicado a los nueve módulos Python de conectores y su archivo de pruebas terminó con `All checks passed!`.

Las pruebas usan bases SQLite aisladas, un servidor HTTP falso local y socketpair GMP. Verifican multipart Generic Findings Import, import/reimport y los dos tipos de respuesta, procesamiento/fracaso, persistencia del ID remoto, idempotencia y conciliación solo por GET ante un resultado ambiguo. Comprueban los envelopes reales Faraday con `count`, paginación, cookies de login y padres Host/Service. GMP prueba comandos XML reales, framing fragmentado en conexión persistente, cancelación de socket silencioso y límites de DTD, profundidad, documento y token sin consumir.

Se comprueban referencias de credenciales en entorno, redacción de contraseñas incluso si el servidor las devuelve en texto libre, bloqueo de redirects, ausencia de proxy ambiental, conservación del archivo original y su hash, fechas originales, candidatos externos y validación del alcance antes de escribir. El worker rechaza una autorización de alcance modificada después de encolar. CLI y app FastAPI real prueban importación, exportación, formularios con CSRF, UploadFile multipart, entrega encolada, detalles, raw e historial paginado.

## Implementación e interfaces

Los archivos nuevos son `destinations.py`, `integrations_store.py`, `_integration_http.py`, `defectdojo.py`, `faraday.py`, `greenbone.py`, `integrations_service.py`, `integrations_cli.py`, `web/integrations.py`, su plantilla y `tests/test_integration_connectors.py`. La guía de uso y las fuentes primarias están en [integrations.md](integrations.md).

Las interfaces centrales son `integrations_store.migrate(conn)` solo al inicializar la base, `integrations_service.register_jobs()`, `integrations_cli.register_cli(subparsers)` y `web.integrations.router`. La integración central incluye esas interfaces y limita los uploads antes del parser multipart, según [durable-workers-scheduling.md](durable-workers-scheduling.md). Las escrituras usan el guard de lease de `db.connect()` sin ejecutar migraciones en runtime.

No se añadieron dependencias ni se copiaron plataformas externas. No se realizaron conexiones a plataformas reales, entregas externas, consultas a feeds, descargas de herramientas ni escaneos. Tampoco se hicieron commits de esta fase desde la tarea de conectores.

## Límites de la evidencia

La compatibilidad comprobada es contractual con fixtures y servidores falsos; no equivale a una prueba contra instalaciones completas de terceros. Las lecturas externas aportan candidatos y cobertura parcial, sin cerrar hallazgos propios por ausencia ni tomar QoD/confirmed remotos como confirmación local. Raw es evidencia normalizada saneada y no una copia forense original.

Un POST externo cuyo resultado es desconocido requiere intervención y conciliación; no se reenvía automáticamente. No se garantiza exactamente una entrega en la ventana entre el POST y la persistencia de su respuesta. Los límites de tamaño y tiempo pueden requerir dividir informes grandes o ajustar el timeout permitido del destino.
