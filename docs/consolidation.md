# Consolidación de ScopeScan

El proyecto ejecutable vive ahora en `C:\Users\hugoo\ScopeScan`: fuentes, tests,
CI, configuración y datos. Los archivos originales de `CumScanner` se conservan.
No se trasladó su entorno virtual: se creó `.venv` y se instaló el proyecto con
`python -m pip install -e ".[dev]"` en ese entorno nuevo.

## Ejecutar desde PowerShell

```powershell
Set-Location C:\Users\hugoo\ScopeScan
.\.venv\Scripts\scopescan.exe --help
.\.venv\Scripts\scopescan.exe self-test
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
```

El CLI instalado importa `ScopeScan/src/scopescan`. Los datos locales existentes
siguen en `ScopeScan/data`; instalaciones fuera del checkout sin datos previos
usan `%LOCALAPPDATA%/ScopeScan` en Windows o `$XDG_DATA_HOME/scopescan` en Unix
(por defecto `~/.local/share/scopescan`). `SCOPESCAN_DATA` tiene prioridad y
`MEDSCAN_DATA` sigue siendo compatible.

## Datos y recuperación

`scripts/consolidate_data.py` copia artefactos con comprobación SHA-256 y hace
snapshots SQLite con la API `backup`, incorporando datos WAL confirmados.
Rechaza destinos no vacíos y rutas anidadas. Para una captura consistente entre
base y archivos, detener el panel antiguo antes de reutilizar este script.
En Windows, leer una base con WAL puede requerir permisos para crear sidecars
SQLite temporales; la copia no cambia filas en la base original.

```powershell
.\.venv\Scripts\python.exe scripts\consolidate_data.py `
    C:\Users\hugoo\CumScanner\data C:\ruta\a\un\destino\vacio `
    --legacy-data-root C:\Users\hugoo\Nessus_con_medicacion\data
```

Se conservan tres bases, el XML raw y dos informes HTML. La base principal
mantiene 1 escaneo, 1 host, 6 puertos, 3 hallazgos, 15 controles y los inventarios,
candidatas y cachés existentes. Se verificó `PRAGMA integrity_check=ok`.
La ruta histórica del XML del escaneo 1 se cambió únicamente en la copia,
desde `Nessus_con_medicacion/data/raw` al artefacto conservado en ScopeScan.

`data/consolidation-recovery` contiene snapshots previos a reescribir rutas;
`data/consolidation-manifest.json` registra conteos, hashes y cambios.
El hash `recovery_sha256` pertenece al snapshot inmutable anterior a cambiar
rutas. `sha256` registra el archivo copiado al terminar la migración: una base
en uso puede cambiar después al inicializar tablas o actualizar resultados.
El manifiesto inicial de esta consolidación se capturó antes de hacer checkpoint
de la reescritura histórica del XML: su digest de la base principal representa
el estado previo, pese al contador `path_updates=1`. La evidencia posterior está
en `data/consolidation-verification/<timestamp>/verification.json`, con snapshots
consistentes, rutas actuales y `current_snapshot_sha256` separados de recovery.
`scripts/verify_consolidation.py data` verifica hashes inmutables, conteos heredados
e integridad y crea un snapshot nuevo sin sobrescribir la recuperación original.
`data-consolidation-failed` conserva el intento inicial fallido bajo sandbox
(una base demo vacía, sin evidencia original). Estas carpetas están ignoradas
por Git. No borrar las copias de recuperación hasta verificar el historial.

## Fiabilidad de procesos

`SCOPESCAN_SCAN_TIMEOUT` limita un escaneo completo a 3600 segundos por defecto
(máximo 86400). La cancelación y el deadline se comprueban cada 50 ms aunque no
haya salida; al finalizar se termina el árbol de procesos y se cierran pipes.
La salida retenida en memoria se limita a 2 MiB por canal y señala truncamiento;
el XML y logs externos siguen siendo la evidencia completa.
En Windows, un launcher espera antes de abrir el motor: se asocia primero a un
Job Object con `KILL_ON_JOB_CLOSE` y solo después recibe los argumentos por stdin.
Esto evita que el motor cree hijos antes de pertenecer al job y funciona con
jobs anidados del sandbox; no depende de `taskkill` ni de enumerar procesos.
Los jobs anidados requieren Windows 8/Server 2012 o posterior. Si no se puede
asociar el launcher al job, la ejecución falla antes de abrir el motor; las
guardas de binarios, alcance y autorización de Nmap/MSF siguen en sus servicios.
Referencia: [Job Objects de Microsoft](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
El sondeo del entorno se cachea 30 segundos y admite refresco manual.
Los escaneos y enriquecimientos comparten el límite de workers; borrar un scan
activo queda pendiente hasta terminar sus escrituras, mientras enriquecimientos
activos impiden borrado.
El rechazo de claims/borrado se serializa en SQLite (`BEGIN IMMEDIATE`), incluido
el intervalo entre respuesta HTTP y envío del trabajo al pool. Un borrado pendiente
persiste en `scans.deletion_pending` y bloquea claims nuevos y arranque del scan.
