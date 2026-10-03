# Revisión independiente de calidad — fase D

Revisión sobre la implementación D01–D08 en `codex/scopescan-roadmap`, con el
contrato de `implementation-plan.md`. Se aplicó `code-review-structured` y se
leyó el hub vigente del Cerebro. El código actual prevalece sobre los antiguos
contadores de pruebas del hub. No se ejecutaron escaneos ni operaciones contra
destinos reales. La suite integral y la distribución corresponden a la puerta
final del coordinador, no a esta revisión focal.

## 🐛 BUGS

1. **P2 — colisión de observaciones de componentes simultáneos, corregida.**
   **Ubicación:** `software_store.persist`, identificador e inserción de
   `software_observations`.
   **Descripción:** la identidad lógica elimina la versión para seguir el
   componente entre documentos. Usarla directamente como clave de una
   observación del documento hacía colisionar dos artifacts Grype del mismo
   paquete/CVE/proveedor. Una importación válida fallaba con `IntegrityError`
   y revertía toda la evidencia. El probe independiente reprodujo tanto dos
   versiones como dos ubicaciones del mismo paquete.
   **Fix aplicado:** separar la identidad lógica del componente de la identidad
   de la ocurrencia de observación, conservando referencia/detalle y ordinal.
   **Verificación:** el mismo probe tras la reparación conserva dos componentes
   con identidad lógica común y dos observaciones distintas para ambos casos.

2. **P2 — vencimiento de lease dentro de una transacción, corregido.**
   **Ubicación:** `db.connect`, comprobación de ownership antes de `yield` y
   confirmación de la transacción.
   **Descripción:** claim de dos segundos, entrada al contexto de conexión,
   espera de 2,2 segundos e inserción persistían una fila después del vencimiento.
   Un claim posterior recuperaba el mismo job con otro propietario. El bloqueo
   SQLite impedía un propietario simultáneo dentro de esa transacción, pero no
   cumplía el contrato de rechazar persistencia tras perder la lease.
   **Fix aplicado:** comprobar owner, estado, lease, cancelación y borrado con
   la misma conexión justo antes de confirmar, sin otro `BEGIN`; revertir si
   dejó de ser válido.
   **Verificación:** el mismo probe con espera real de 2,2 segundos produce
   `JobLost`, revierte la fila y permite recuperación con otro propietario.

3. **P1 — autorización obsoleta en enriquecimientos activos, corregido.**
   **Ubicación:** encolado de enriquecimientos, `operation_grants`, worker y
   callbacks anteriores a cada colector/grupo MSF.
   **Descripción:** la revisión posterior de anti-patrones detectó que un
   inventario remoto o una acción MSF podía utilizar hosts históricos sin
   volver a comprobar cambios/revocación del alcance. Esta detección procede
   de esa revisión independiente, posterior al primer pase de este documento.
   **Fix aplicado:** capturar el grant y snapshot de alcance en la misma
   transacción que encola; fijar targets y listeners/módulos/acciones efectivos;
   revalidar antes del handler y antes de cada target/grupo/ejecución activa.
   NVD/MSRC/ExploitDB mantienen acceso a evidencia histórica porque no contactan
   los targets; el inventario local exige selección explícita de un loopback.
   **Verificación adicional propia:** cambiar el listener efectivo MSF de 22 a
   2222 después del encolado produce fallo antes del runner. Cancelar desde un
   contexto externo durante el primer colector de un batch de dos hosts impide
   contactar al segundo y deja el job cancelado. Ambos probes usan mocks.

No quedan bugs bloqueantes detectados en esta revisión.

## 🔒 SEGURIDAD

No se detectaron vulnerabilidades de seguridad evidentes pendientes en el alcance
revisado. El vencimiento anterior del control de ownership quedó corregido y
reverificado.

Se comprobaron límites JSON/XML y parsers sin entidades externas, SQL
parametrizado, destinos sin credenciales en URL, referencias de entorno en
configuración, HTTP sin proxy ambiente ni redirecciones, TLS verificado y
redacción de secretos conocidos. La interfaz utiliza el middleware común de
autenticación/CSRF; los formularios solo encolan ejecución remota. Syft exige
fuentes explícitas y rutas dentro de raíces del worker; la red de registry
requiere autorización explícita. Grype desactiva actualizaciones y conserva
procedencia de su base de datos. La cobertura importada no demuestra cierre
de hallazgos locales ni certificación SCAP.
El pase final también leyó `operation_grants`, la captura transaccional, los
callbacks Linux/Windows/MSF y las regresiones de `test_enrichment_grants.py`.

## ⚡ RENDIMIENTO

No se encontraron bloqueos adicionales que impidan aceptar la fase. Hay
presupuestos de bytes, nodos, profundidad, procesos, deadlines y paginación.
GMP limita tokens XML incompletos para contener el coste del parser incremental.
SQLite limita claims y slots entre procesos y deduplica eventos programados
cuando la evidencia no cambia. Las transacciones de persistencia deben seguir
siendo cortas para no impedir heartbeats; la reparación de lease cubre la
expiración si una transacción tarda más de su presupuesto.

## 🔧 MEJORAS

Mantener las regresiones de ocurrencias de paquetes y lease durante la
transacción: comprueban condiciones reales que no quedaban cubiertas por los
casos iniciales. Los errores de motores ausentes, datos parciales y escrituras
externas inciertas son visibles en CLI/panel. Los checkpoints Dojo rehúsan
reenviar un POST ambiguo y permiten reconciliar el ID remoto antes del polling.

## 📋 RESUMEN

- **Severidad global:** 🟢 Bajo, sin hallazgos pendientes de esta revisión.
- **Top 3 cambios prioritarios:**
  1. Mantener grants exactos de operaciones activas y revalidación por target.
  2. Mantener identidad de ocurrencia separada de identidad lógica del paquete.
  3. Completar la puerta integral y de distribución sobre las fuentes finales.
- **Puntos positivos:** contratos externos simulados sobre HTTP/socket reales;
  separación web/worker; cobertura/procedencia explícitas; negativos importados
  sin cierres locales; slots y ownership persistentes; schemas oficiales.

Evidencia focal independiente del primer pase: **12 pruebas pasaron en 32,67 s**. Incluyen dos
procesos reclamando, propietario obsoleto, proceso silencioso cancelado, dos
schedulers, eventos de evidencia idéntica, exportación dentro del fence, Dojo
async/sync y POST ambiguo, cookie/parents Faraday, framing GMP, CSRF de navegador
y historial de entrega. Un warning heredado del TestClient sobre httpx no
produjo fallos.

Validación adicional fuera de esa suite: los cuatro cruces CycloneDX 1.6/SPDX
2.3 pasan los schemas oficiales completos y roundtrip purl con jsonschema
4.25.1. Se reutilizaron las copias descargadas de schemas sin red ni escrituras
externas; SHA256 iguales a los registrados en `software-compliance.md`.
Los probes propios usan exclusivamente `.test-tmp-d-quality` como datos.

Reverificación final adicional: el worker rechazó cambios independientes de
autorización, perfil, IPs fijadas, límite de hosts, exclusiones y resoluciones
entre encolado y ejecución. Los seis casos terminaron fallidos con error
accionable antes de llamar a `nmap_runner.build_argv`, sustituido por un mock
que fallaría ante cualquier invocación. No se inició ningún proceso Nmap.

**Veredicto de calidad:** D01–D08 son aceptables en el alcance revisado, una vez
que la puerta integral/distribución del coordinador pase sobre estas fuentes
finales. Esta revisión no sustituye esa puerta ni una prueba de aceptación
contra instalaciones externas reales.

El pase posterior a la reparación P1 añade los **dos probes independientes
anteriores, ambos PASS**, sobre las fuentes de grants finales. Los contadores
integrales de pruebas se registran en la verificación final del coordinador;
los resultados del primer pase no se presentan como una suite integral de las
fuentes posteriores. No quedan hallazgos pendientes de calidad en este pase.
