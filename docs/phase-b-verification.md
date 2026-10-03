# Verificación independiente de la fase B

Fecha: 2026-10-03. Entorno ejecutado: Windows, Python 3.13.5 y entorno virtual
del proyecto. La puerta local B01–B09 pasa y fue aceptada tras verificación
independiente y revisión fresca. C y D siguen pendientes.

## Comprobaciones finales ejecutadas

| Comprobación | Resultado |
| --- | --- |
| `.venv/Scripts/python.exe -m pytest -q --basetemp=.test-tmp-b-final-verify` | 439 pasan, 1 advertencia, 319,54 s; código 0. |
| `.venv/Scripts/ruff.exe check .` | `All checks passed!`; código 0. |
| `.venv/Scripts/python.exe -m pip check` | `No broken requirements found.`; código 0. |
| `.venv/Scripts/scopescan.exe self-test` con `SCOPESCAN_DATA=.test-tmp-b-final-self-test` | Código, plantillas, estáticos, SQLite, CLI y entorno pasan; código 0. No ejecuta Nmap. |
| `.venv/Scripts/python.exe -m build --no-isolation --outdir dist/phase-b-final` | Rueda y sdist construidos; código 0. |
| Instalación con `pip install --no-deps --no-index --target dist/phase-b-final/wheel-installed …whl` | Código 0. Se comprueba el origen instalado de los módulos B y metadatos, fuera de `src`. |
| Entrypoint de la rueda instalada | Self-test: 6 comprobaciones. Importación CLI, búsqueda de activos y vigentes funcionan con una fixture; panel `/assets` y API devuelven 200. |
| Colección desde sdist extraído, usando su propio `src` | 439 pruebas recogidas, código 0; origen de importación comprobado en el sdist. |
| Smoke de distribución desde sdist | 10 pasan, 1 advertencia, 15,75 s; código 0. Incluye consolidación, ciclo de remediación, cierre renderizado, operaciones CLI y los cuatro casos del positivo parcial. |

La advertencia única de pytest procede de FastAPI/Starlette TestClient con httpx:
`StarletteDeprecationWarning: Using httpx with starlette.testclient is deprecated; install httpx2 instead.`
Es la misma deprecación conocida de A. No hubo fallos ni advertencias de procesos,
hilos o recursos sin cerrar.

Los 38 módulos Python, las nueve plantillas HTML y el CSS de la rueda coinciden
byte por byte con las fuentes finales. Sus metadatos contienen
`Requires-Dist: defusedxml>=0.7.1`, `License-Expression: MIT` y el entrypoint
`scopescan.cli:main`; el texto de licencia coincide con `LICENSE`.
Los módulos, todas las pruebas/fixtures, los dos locks y ambos scripts de
consolidación del sdist también coinciden con las fuentes.

Artefactos finales en `dist/phase-b-final`, con SHA-256:

- Rueda `scopescan-0.2.0-py3-none-any.whl`: `e35d39aa7293a1fb85ff7c4c61ba287d0c1530f3d269eed3bc51da550b9609bb`.
- Sdist `scopescan-0.2.0.tar.gz`: `a36e6b68b1d7593199c9aa299fd3861824047107b55dda5ba6db3dc531b33982`.

La instalación aislada usó las dependencias existentes del venv, sin red: no
equivale a un sistema limpio sin dependencias. `dist/phase-b-verify` conserva el
build previo al último arreglo de baseline; no es el artefacto final acreditado.
El sdist conserva el documento de verificación tal como estaba al construirlo;
este informe se finalizó después de ejecutar las comprobaciones del artefacto.

## Probes independientes adicionales

| Comprobación | Resultado |
| --- | --- |
| Entrypoint instalado `--help`, `verify --help`, `scope --help` | Operaciones nuevas presentes; código 0. |
| Migración desde esquema real de fase A, generada en un SQLite temporal | Conserva 1 scan, 1 host, 1 puerto y 1 hallazgo; integridad SQLite correcta. Inicialización B repetida conserva título/evidencia, namespace `scan:1` y cobertura desconocida. |
| Upload HTTP con tipos estructurales inválidos | Cuatro documentos con `coverage.status` lista/diccionario, `coverage.protocols=null` o IP booleana devuelven 400 y no crean scans. Cookie y token CSRF válidos; datos temporales. |
| Confianza de observaciones locales frente a importaciones | Un informe externo posterior con puerto cerrado no sustituye el snapshot local. Otro informe externo que omite el host no adelanta su fecha de evaluación. Una corrección local posterior a la observación local resuelve el hallazgo. |
| Recuperación de baseline de hallazgo al borrar un positivo | Positivos con reglas v1/v2; al borrar v2 se restaura exactamente v1. Un negativo posterior con reglas v2 queda sin evaluar. |
| Riesgo por endpoint | Asociar y observar un alias público conserva el riesgo del hallazgo observado originalmente en una IP privada. |
| Resumen de activo con 200 hallazgos grandes | `list_assets(limit=1)` conserva el contador 200 y genera 1.023 bytes de JSON para el elemento; cada evidencia original tenía 16.000 caracteres. |
| Comprobación local de candidatos importados | Con el mismo XML de origen y puertos 23/22 cerrados localmente, Telnet pasa a resuelto y OpenSSH antiguo permanece sin evaluar: retirar una exposición no acredita instalar un parche. |
| Reconstrucción de endpoints tras borrado | Tres escaneos dirigidos 22→80→443 conservan los tres puertos. Borrar el tercero conserva 22/80; borrar después el primero retira únicamente 22. |
| Baseline de positivos parciales | Positivos `failed`, `cancelled` o `done` con cobertura parcial guardan su cobertura/versión exactas. Un negativo posterior v1 no resuelve ninguno de los cuatro casos. |

Para la migración se cargó únicamente `src/scopescan/db.py` del checkpoint local
de fase A mediante `git show HEAD:src/scopescan/db.py`, dentro de un módulo aislado.
Ese código creó la base temporal sin columnas/tablas B; después se ejecutó dos
veces `db.init_db()` actual. No se leyó ni modificó la base histórica del usuario.

## Aceptación por requisito

| Requisito | Evidencia ejecutada |
| --- | --- |
| B01 | Reescaneos conservan IDs aunque cambien títulos/versiones; namespaces separan redes y alias requieren decisión explícita. Cada hallazgo mantiene dirección concreta y protocolo. Historial, búsqueda por endpoint original y migración previa a B comprobados. |
| B02 | Deltas de hosts, puertos, servicios y hallazgos; puertos omitidos siguen sin evaluar. Cobertura desconocida/parcial, reglas distintas, host ausente, NSE sin negativo reconocido y cancelación no producen cierres. Borrados reconstruyen endpoints supervivientes con protocolo/alias y confianza. |
| B03 | Reescaneos no multiplican contadores vigentes; histórico permanece separado. Hallazgos resueltos/cerrados o sin evidencia no inflan riesgo ni conteos. |
| B04 | Alta→reescaneo→corrección→cierre en DB y panel; cierre prematuro rechazado, reapertura ante nuevo positivo, responsable/excepción y evidencia. El historial de acciones es inmutable y se conserva al borrar informes. |
| B05 | Contribuciones y fórmula visibles; candidatos no se confirman por puntuación. Criticidad, KEV desconocido frente a ausencia comprobada, fechas/EPSS y exposición de cada endpoint probados. Un alias público no altera el riesgo de otro endpoint privado. |
| B06 | Resolución DNS fijada, exclusiones, IPv6, límite de hosts y rechazo de familias mezcladas. Edición no muta jobs históricos. Preview firmado con caducidad y rechazo de modificaciones/tokens malformados. |
| B07 | Planes y ejecuciones dirigidos a controles/endpoints propios; repetición conserva namespace y revalida IDs, reglas, alcance, autorización e identidad. SSH observado en 2222 no verifica el listener 22. Cierre autenticado usa el predicado real; controles ausentes permanecen desconocidos. |
| B08 | XML/JSON bounded con raw único, hash, fecha, versión y procedencia; entidades prohibidas y DTD normal aceptado. Imports no conceden ejecución ni confirmación. Tipos inválidos, CVSS no finito y fechas externas superiores a UTC actual+5 min se rechazan; skew de 4 min permitido. |
| B09 | Operaciones reales de CLI/API/panel, escape de evidencia externa, CSRF, filtros y enlaces de paginación a página 2. API de 200 hallazgos grandes acota la respuesta y permite factores/endpoints/historia bajo demanda; informe/export conserva cobertura y procedencia. |

La suite final incluye regresiones de los defectos hallados en revisión y probes:
precedencia de evidencia local, fechas futuras importadas, cobertura del positivo
parcial y reconstrucción de endpoints al borrar informes. La verificación negativa
usa la cobertura exacta del último positivo aceptado, incluida su condición parcial.

## Límites

La suite, instalación y probes usaron directorios privados temporales. No hubo
escaneos ni inventarios contra objetivos reales ni escrituras en destinos externos.
La matriz remota CI/Linux/Python 3.11 no se ha ejecutado en esta sesión. La
deprecación conocida de Starlette/TestClient con httpx permanece y no es un fallo
de producto. La evidencia de dependencias B está en `phase-b-dependencies.md`.

Nmap y colectores autenticados se simularon donde se necesitaba observar un resultado;
no se acredita conexión operativa con SSH/WinRM reales. Durante colección autenticada,
la cancelación evita cierre negativo pero espera la llamada acotada (180 s SSH,
120 s WinRM). Cancelación inmediata de esos colectores y separación de identidades
pertenecen a D05/D07. Jobs durables/scheduler y motores adicionales C/D no quedan
acreditados por esta puerta.
