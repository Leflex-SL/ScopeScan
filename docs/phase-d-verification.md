# Verificación independiente final — fase D

La implementación D01–D08 y las regresiones A/B/C superaron la puerta local
final sobre las fuentes corregidas de `codex/scopescan-roadmap`. Se leyó el hub
vigente del Cerebro y los contratos de `implementation-plan.md`. La primera
ejecución de 710 pruebas fue evidencia preliminar: se reconstruyó y volvió a
verificar todo tras reparar la autorización de los enriquecimientos activos.

## Puerta integral sobre las fuentes finales

```text
.venv/Scripts/python.exe -m pytest -q --basetemp=.test-tmp-d-final-corrected-integral --tb=short
743 passed, 1 warning in 622.54s (0:10:22)
.venv/Scripts/python.exe -m ruff check .
All checks passed!
.venv/Scripts/python.exe -m pip check
No broken requirements found.
```

El aviso conocido procede de Starlette/TestClient y httpx. El self-test supera
sus seis comprobaciones tanto en desarrollo como con el launcher instalado de
la rueda. Estas comprobaciones no ejecutan Nmap ni contactan objetivos.

La suite incluye SBOM CycloneDX/SPDX, procesos Syft/Grype simulados con argv y
entorno reales, fechas/purl/distribución/procedencia y secretos; SCAP XCCDF/ARF
y sus ocho estados; DefectDojo import/reimport/poll y POST ambiguo; Faraday
cookies/paginación/parents y GMP framing/cancelación/límites XML. Los servidores
HTTP y sockets GMP usados son fixtures locales, no instalaciones de terceros.

Jobs y scheduler cubren persistencia, reinicio, leases, heartbeat, ownership,
cancelación, borrado coordinado, presupuesto global y slots únicos entre
procesos. Los finales repetidos no generan observaciones nuevas. El panel
encola los encargos; los colectores SSH/WinRM ejecutan en el worker y comparten
cancelación, límites de salida y deadline. La autorización se vuelve a validar
al ejecutar y antes de cada colector/módulo. Cambiar autorización, exclusiones,
perfil, resolución, límites o eliminar el alcance impide ejecutar el encargo.

## Probes independientes adicionales

Se extrajeron las fuentes C reales de Git, checkpoint `4b9a292`, y se creó una
base histórica con scan, host, puerto, finding y activos. La migración a D dos
veces conservó exactamente las 26 tablas históricas y sus 10 filas. Después,
inicializar dos veces con un claim vivo conservó propietario, estado running
y heartbeat. El probe final empleó una base nueva aislada.

Dos procesos Python reales compitieron por cuatro trabajos y devolvieron
`[[1, null], [2, null]]`: dos claims distintos, capacidad SQLite global de dos
y los otros dos encargos pendientes. La suite prueba además dos procesos
reclamando el mismo job y dos schedulers creando un solo slot.

Los cuatro cruces de exportación CycloneDX 1.6/SPDX 2.3 pasaron los schemas
oficiales completos y conservaron purl con jsonschema 4.25.1 en un destino
temporal. Se reutilizaron schemas descargados y sus SHA256 documentados en
`software-compliance.md`, sin red ni cambios de dependencias. La lectura del
validador requirió acceso fuera del sandbox por su ACL, autorizado por la
revisión automática.

## Distribución

La construcción `python -m build --no-isolation` produjo rueda y sdist nuevos
tras las reparaciones. **91 archivos Python/HTML/CSS/YAML, incluidos 74 Python**,
coinciden byte a byte con las fuentes y entre ambas distribuciones. Se incluyen
`operation_grants.py`, las nuevas rutas/plantillas y ambos YAML de Nuclei.
Los **37 archivos Python de tests**, con conftest, y los scripts de consolidación
también coinciden. Se comprobaron MIT/LICENSE, entry point, dependencia directa
defusedxml y ambos lockfiles sin cambios.

Desde el sdist extraído se recogieron **743 pruebas en 15,37 s**; una selección
significativa superó **48 casos en 39,47 s**, con 27 deseleccionados. Incluye
imports/exports, estados SCAP, Grype, CLI/UI y contratos HTTP/GMP, junto a las
24 combinaciones de revocación de grants activos. La colección no se presenta
como ejecución de todas las pruebas del sdist.

Se instaló la rueda sin dependencias en un destino nuevo. Se verificaron **32
módulos** D/B/C importados desde esa instalación, el registry real de
Nuclei/SSLyze y los hashes de ambas plantillas. El launcher instalado responde
en once grupos CLI, incluidos software/integration/jobs/worker/schedule y los
comandos anteriores. Siete rutas de panel/API/CSS devolvieron 200 con un cliente
loopback. Dos roundtrips SBOM conservaron purl/fecha original, hash recibido y
bytes del archivo; eliminaron secretos. Imports CLI adicionales de SCAP, Grype
y GMP conservaron originales, candidatos, fecha GMP y evidencia saneada.

Tras la aceptación se repaquetaron los documentos finales en el sdist y se
comprobaron sus bytes, manteniendo idénticas las fuentes ya verificadas. Los
hashes de los artefactos se comunican aparte para evitar una autorreferencia
entre este informe y el archivo que lo contiene.

## Límites y revisiones

La verificación local usa **Windows y Python 3.13.5**. No se ejecutó la matriz
remota Linux/Python 3.11. No se instalaron ni ejecutaron herramientas externas,
escaneos, colectores remotos reales, evaluaciones SCAP, consultas a feeds ni
entregas externas. Todas las bases y pruebas usan directorios temporales
aislados; la base de usuario no se empleó para estos probes.

Los contratos externos se prueban con fixtures y transportes simulados; no
equivalen a aceptación contra instalaciones completas de terceros. Un POST
incierto requiere conciliación; no se afirma exactamente una entrega. Los
resultados importados no certifican SCAP ni cierran hallazgos locales por
ausencia. No se añadieron dependencias a las auditadas en las fases anteriores.

Las revisiones independientes finales de calidad, anti-patrones y checkpoint
no dejaron bloqueos tras reparar colisiones de observaciones Grype, expiración
de lease antes del commit y grants de enriquecimientos activos. Su evidencia
complementaria está en `phase-d-review.md` y `phase-d-antipatterns.md`.
