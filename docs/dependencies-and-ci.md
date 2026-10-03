# Dependencias reproducibles y CI

`requirements.lock` fija la ejecucion y `requirements-dev.lock` añade las herramientas
de desarrollo. Ambos contienen hashes de distribuciones y marcadores para Python
3.11 o posterior, Windows y Linux. El lock de desarrollo queda restringido por el de
ejecucion para mantener las mismas versiones del producto.

Instalacion desde una raiz consolidada (activar antes un entorno virtual propio):

```console
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check
```

En despliegues, instalar `requirements.lock` y la rueda de ScopeScan usando
`--no-deps`; la construccion de esa rueda se hace en el entorno de desarrollo con
`python -m build --no-isolation`. Los requisitos declarados en `pyproject.toml`
expresan compatibilidad; los locks describen las versiones verificadas del entorno.

Para actualizar deliberadamente, revisar los cambios de version y generar otra vez:

```console
python -m uv pip compile pyproject.toml --universal --python-version 3.11 --no-python-downloads --generate-hashes --upgrade --output-file requirements.lock
python -m uv pip compile pyproject.toml --extra dev --constraint requirements.lock --universal --python-version 3.11 --no-python-downloads --generate-hashes --upgrade --output-file requirements-dev.lock
python -m pip_audit --strict --disable-pip --no-deps -r requirements-dev.lock
```

Usar uv 0.12.22 o una version posterior revisada. Su [documentacion de locks](https://docs.astral.sh/uv/pip/compile/)
describe compilacion, restricciones y actualizaciones. La auditoria consulta advisories
de PyPI segun el [contrato de pip-audit](https://github.com/pypa/pip-audit).
Los hashes garantizan la identidad de los paquetes elegidos; no equivalen a una
auditoria de su comportamiento. Los advisories cambian y deben consultarse de nuevo.

CI prueba Python 3.11 y 3.13 en Windows y Ubuntu. Instala con hashes, audita el lock,
ejecuta Ruff, pytest y self-test, y construye rueda/sdist. Los fallos de auditoria o
consulta no se ignoran. Los marcadores seleccionan dependencias por plataforma;
la matriz cubre tambien paquetes que no se instalan en Windows (por ejemplo uvloop).

Las acciones estan fijadas a commits comprobados con `git ls-remote` sobre los tags
oficiales el 3 de octubre de 2026:

- checkout v4.2.2: `11bd71901bbe5b1630ceea73d27597364c9af683`
- setup-python v5.6.0: `a26af69be951a213d495a4c3e4e4022e16d87065`

El token de CI tiene solo `contents: read`. Actualizar estos commits requiere
comprobar su procedencia y volver a ejecutar la matriz; no usar tags mutables.

La auditoria local del 3 de octubre de 2026, ejecutada en Windows con el lock de
desarrollo, termino con codigo 0 y sin advisories conocidos para las dependencias
seleccionadas. Su salida se conserva en
[dependency-audit-2026-10-03.json](dependency-audit-2026-10-03.json).
La [verificacion de fase A](phase-a-verification.md) registra `pip check`, build,
instalacion de la rueda sin red y comprobacion del sdist en Windows/Python 3.13.5.
La matriz de GitHub requiere una ejecucion remota para verificar Linux/Python 3.11.
