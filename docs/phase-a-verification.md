# Verificación independiente de la fase A

Fecha: 2026-10-03. Entorno ejecutado: Windows, Python 3.13.5, entorno virtual de `ScopeScan`. La puerta local de A01–A14 pasa. Las fases B, C y D siguen pendientes; este informe no acredita su implementación.

## Resultados ejecutados

| Comprobación | Resultado |
| --- | --- |
| `.venv/Scripts/python.exe -m pytest -q --basetemp=.test-tmp-a-verify` | 278 pasan, 1 advertencia, 95,85 s; código 0. |
| `.venv/Scripts/ruff.exe check .` | `All checks passed!`; código 0. |
| `.venv/Scripts/python.exe -m pip check` | `No broken requirements found.`; código 0. |
| `.venv/Scripts/scopescan.exe self-test` con `SCOPESCAN_DATA` temporal | Código, plantillas, estáticos, SQLite, CLI y entorno pasan; código 0. |
| `.venv/Scripts/python.exe -m build --no-isolation --outdir dist/phase-a-verify` | Rueda y sdist construidos desde la versión final; código 0. |
| Instalación de rueda con `pip install --no-deps --no-index --target dist/phase-a-verify/wheel-installed …whl` | Instalación correcta. Importación comprobada desde ese destino, fuera de `src`; entrypoint instalado ejecuta self-test con datos temporales y código 0. |
| Colección desde el sdist extraído, con `PYTHONPATH` apuntando a su propio `src` | 278 pruebas recogidas; importación de ScopeScan comprobada dentro del sdist; código 0. |
| `python -m pytest -q tests/test_consolidation.py --basetemp=…/sdist-test-data` desde el sdist | 3 pasan en 0,35 s; código 0. |

La advertencia de la suite procede de `fastapi/testclient.py`: `StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.` Es una deprecación del cliente de pruebas en las dependencias fijadas. No hubo advertencias de hilos, pipes ni recursos sin cerrar. El mismo aviso aparece al recoger las pruebas del sdist.

Durante la comprobación de distribución se encontraron dos omisiones: los scripts usados por las pruebas y `tests/conftest.py` no estaban en el sdist. Se corrigió `MANIFEST.in` y se volvió a construir e inspeccionar el archivo final. No cambió código del producto ni de pruebas después de la suite completa.

La rueda final contiene `License-Expression: MIT`, `License-File: LICENSE`, el texto MIT exacto y el entrypoint `scopescan.cli:main`. Sus ocho plantillas HTML y el CSS coinciden byte por byte con las fuentes. El sdist incluye los dos scripts de consolidación/verificación, todas las pruebas y sus fixtures, los dos locks, `LICENSE` y `SECURITY.md`.

Los artefactos locales finales están en `dist/phase-a-verify`; sus hashes SHA-256 son:

- Rueda `scopescan-0.2.0-py3-none-any.whl`: `903b45c98963064993b920782558ebc93f83b3f011b1e5d846448f52b97569e4`.
- Sdist `scopescan-0.2.0.tar.gz`: `d2015ea8861ca12219b343195d395334b1d0f3c019c11c5e7c97d8ec09c1737b`.

## Aceptación por requisito

| Requisito | Verificación local |
| --- | --- |
| A01 | Fuentes, pruebas, CI y venv presentes en ScopeScan. Las tres bases de recuperación conservan sus hashes, conteos e integridad SQLite; raw XML y los dos informes coinciden con manifiesto y originales de CumScanner. La base de trabajo conserva 1 scan, 1 host, 6 puertos, 3 hallazgos y 15 controles; la ruta raw copiada existe. Los snapshots adicionales verifican el estado después de relocalización/migración. |
| A02 | Regresiones de rangos mixtos privados/públicos, rangos completos, IPv6 y bloques reservados. Un host público concreto no puede llegar al runner MSF mediante un scan marcado privado. |
| A03 | Verificación enlazada a host, puerto efectivo, protocolo y módulo; se rechazan puertos diferentes, UDP, puertos ambiguos y veredictos de otro endpoint. Ejecuciones incompletas no autorizan explotación. |
| A04 | Dos hallazgos equivalentes con TCP y UDP se conservan separados. |
| A05 | APK mantiene nombres y revisiones completas; metadatos distinguen desconocido, recorte, registros sin interpretar y completitud. El bloque real de reinicio se prueba con rutas aisladas para Debian/Ubuntu y RPM/Alpine. |
| A06 | Procesos locales simulados prueban cancelación sin salida, deadline, ambos canales, límites de salida y limpieza tras excepción. El hijo que conserva pipes muere al cancelar; si falla la asignación del Job Object en Windows el motor no llega a abrirse. MSF con salida positiva y fallo/timeout/cancelación/recorte queda como ERROR y conserva la causa. |
| A07 | Futures y eventos terminados desaparecen; el borrado espera la última escritura del scan. Claims y borrado se serializan en SQLite y `deletion_pending` impide claims tardíos; las regresiones ejercitan carreras reales y callbacks tardíos. |
| A08 | Host y Origin tienen configuración independiente. Puertos/orígenes inválidos se rechazan sin 500. Basic configurado exige 401 con challenge también en loopback y acepta credenciales Unicode válidas. Formularios y fetch de navegador requieren CSRF; tokens Unicode/malformados devuelven 403. Cabeceras de proxy no conceden acceso. Despliegue, proxy y TLS documentados. |
| A09 | CSV neutraliza prefijos de fórmula incluso tras espacios/controles; JSON conserva el texto original. |
| A10 | Solo un claim gana entre reclamantes concurrentes; escaneos y enriquecimientos comparten presupuesto de workers. La ventana entre HTTP y BackgroundTask también queda protegida frente al borrado. |
| A11 | TTL, refresco explícito y cambios de configuración invalidan correctamente el caché del entorno. Instalaciones sin checkout/datos usan una ruta del usuario; datos existentes y variables compatibles conservan prioridad. |
| A12 | Paginación y búsqueda de scans/hallazgos e inventarios bajo demanda. Comprobación adicional con HTMLParser: títulos sin markup, enlaces de paginación dentro del body y navegación a página 2 real en dashboard y hallazgos. Cobertura de paquetes y valores desconocidos se muestran en detalle, informe y página de paquetes. Estado MSF `partial` y su causa aparecen realmente en el panel. |
| A13 | Una escritura concurrente no mezcla versiones en el snapshot SQLite. El ZIP reutiliza un payload, incluye manifiesto con hashes/tamaños y conserva JSON original. Descarga desde archivo temporal y limpieza ante fallo/respuesta verificadas; el panel no usa el API legado que devuelve el ZIP completo en memoria. |
| A14 | MIT en fuente y rueda, SECURITY.md, política de datos, locks con versiones/hashes y CI con `contents: read` y actions fijadas a SHA. La auditoría estricta conservada contiene 60 dependencias seleccionadas en Windows y cero advisories; instalación/build/distribución local comprobados. |

## Preservación y límites de lo comprobado

Las bases de recuperación y los snapshots de `data/consolidation-verification/20261003T132918Z` se leyeron con URI SQLite `mode=ro&immutable=1`; sus hashes, `integrity_check` y conteos coinciden. El hash de la base de trabajo puede cambiar después de relocalizar rutas o migrar el esquema: el manifiesto inicial es histórico y los snapshots adicionales registran el estado posterior. No se interpreta esa mutabilidad como pérdida de evidencia.

La suite, self-tests, instalación de rueda y fixtures adicionales usaron directorios de datos temporales. No se realizaron escaneos ni inventarios contra objetivos reales, ni se ejecutó MSF. Las pruebas de subprocesses solo abrieron intérpretes locales simulados; las del colector Linux ejecutaron el bloque del shell con rutas privadas de fixture.

La matriz CI configura Windows/Ubuntu y Python 3.11/3.13, pero aquí solo se ejecutó Windows/Python 3.13.5. No se acredita ejecución remota de CI, ni el audit de dependencias seleccionadas únicamente en Linux. Se inspeccionó el resultado de auditoría existente; no se repitió la consulta de advisories al no cambiar locks. Cero advisories conocidos no acredita ausencia de vulnerabilidades nuevas.

La rueda se instaló sin red y usó las dependencias ya verificadas del venv; no se simuló un sistema limpio sin dependencias. Nmap/MSF y servicios externos requieren comprobación operativa cuando estén configurados. La cola de esta fase sigue siendo de proceso único; leases, jobs persistentes, scheduler y separación web/worker pertenecen a D y siguen abiertos.
