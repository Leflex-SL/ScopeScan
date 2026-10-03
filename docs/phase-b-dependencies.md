# Dependencias de la fase B

Comprobadas el 2026-10-03 en Windows/Python 3.13.5. `defusedxml>=0.7.1`, usado por la importación XML, queda como dependencia directa del producto: la instalación de runtime no depende de que exista el extra de desarrollo.

Los dos locks existentes son `requirements.lock` (runtime) y `requirements-dev.lock`. Se regeneraron con uv 0.12.22, resolución universal para Python 3.11 y hashes, desde el caché local (`--offline`), seleccionando explícitamente el intérprete del proyecto y desactivando descubrimiento/descarga de Python gestionado. Los comandos completos están en sus cabeceras.

- Los 23 pins anteriores de runtime conservan sus versiones; solo se añade `defusedxml==0.7.1` con los dos hashes de distribución existentes en el lock de desarrollo.
- Los 61 pins de desarrollo conservan sus versiones. La anotación de `defusedxml` ahora registra también su dependencia directa y la restricción del lock runtime.
- `python -m pip --isolated install --require-hashes -r requirements-dev.lock` termina con código 0. Las dependencias ya estaban instaladas: esta ejecución comprueba el lock y requisitos, pero no equivale a descargar y verificar de nuevo todos los artefactos.
- La instalación editable con `--no-deps --no-build-isolation` termina con código 0; sus metadatos contienen `defusedxml>=0.7.1`. La versión instalada es 0.7.1.
- `python -m pip check`: `No broken requirements found.`
- Auditoría estricta actual con `pip_audit --strict --disable-pip --no-deps -r requirements-dev.lock`: cero vulnerabilidades conocidas y código 0. Resultado íntegro en `dependency-audit-phase-b-2026-10-03.json`; se consultaron advisories públicos de PyPI con caché dentro del proyecto.

La auditoría evalúa las dependencias seleccionadas en Windows; no acredita la matriz Linux ni una ejecución con Python 3.11. Una resolución universal compatible y cero advisories conocidos tampoco garantizan ausencia de vulnerabilidades nuevas. No se modificó la evidencia histórica de la fase A.
