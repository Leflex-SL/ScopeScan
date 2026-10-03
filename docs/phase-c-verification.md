# Verificación independiente de la fase C

Estado: **puerta C superada y aceptada**. La suite integral y la distribución se verificaron después de todas las reparaciones de las revisiones independientes. C01–C06 están completas; D permanece pendiente.

## Entorno y aislamiento

Windows, Python 3.13.5 y el entorno `.venv` del proyecto. Todos los inventarios, informes, respuestas HTTP y motores son fixtures o programas Python locales; no se lanzaron escaneos, SSH, SSLyze/Nuclei reales, consultas de feeds ni escrituras a conectores. Las bases de datos de verificación usan directorios temporales exclusivos y `SCOPESCAN_DATA`. No se tocó la base de datos del usuario.

## Resultados obtenidos

- Suite global final independiente: **610 pasan**, un aviso conocido de Starlette/httpx, **447,88 s**. Comando: `.venv/Scripts/python.exe -m pytest -q --basetemp=.test-tmp-c-final-integral`. Incluye las regresiones A/B y las fuentes C finales; no comparte directorio temporal con ejecuciones anteriores.
- Ruff sobre el proyecto: pasa. `pip check`: sin requisitos rotos. El self-test de la instalación aislada de rueda supera sus **seis comprobaciones**.
- El sdist final recoge **610 tests**, **10,51 s**; una selección de contratos, registry real, imports CLI Vuls/Linux y bytes de plantillas supera **14 casos**, **8,37 s**. La colección se distingue de la ejecución.
- Las revisiones finales independientes de calidad y anti-patrones no dejaron bloqueos. No se realizó commit desde la verificación.

## Probes independientes

Se cargó la implementación de `db.py` del checkpoint B desde Git en un módulo aislado: su base inicial no contenía `engine_results`. Tras crear un escaneo y host históricos, inicializar C dos veces conservó ambas filas e `integrity_check=ok`; la migración fue idempotente.

Dos procesos Python distintos compitieron por seis reservas del mismo presupuesto SQLite: se aceptaron cinco y el deadline rechazó la sexta. No se simularon conexiones a una sola base en memoria. También se verificaron epoch/tilde/backport Debian, epoch/caret RPM y saneado de raw/normalizado sin alterar el timestamp exacto de la observación.

Dos probes adicionales sobre la fuente final verificaron que una respuesta NVD sin `totalResults` se rechaza sin crear caché vacía fresca, y que tres HTTP 429 con `Retry-After` de 0/0/9 segundos dejan la pausa final de nueve segundos en SQLite aunque el job falle. Ambos usan transportes falsos.

## Distribución final

La construcción sin aislamiento produjo rueda y sdist en `dist/phase-c-final`. Se compararon **63 archivos Python/HTML/CSS/YAML byte a byte** contra las fuentes finales: coincidieron; licencia MIT, LICENSE, entry point y dependencia directa defusedxml fueron comprobados. El sdist incluyó los 32 archivos Python de tests —incluido conftest— y ambos scripts de consolidación. C no añadió dependencias; la auditoría de las 60 dependencias seleccionadas en Windows de la fase B sigue siendo la última auditoría realizada.

En un destino de instalación nuevo se verificó que once módulos C se importaban desde la rueda, ambos adapters se construían por el registry real y los SHA-256 del catálogo Nuclei coincidían con sus bytes instalados. Las importaciones CLI Vuls y Linux conservaron el timestamp original de inventario de 2025, hash del informe original y origen candidato; eliminaron secretos de configuración y URI de repositorio, y dejaron intacto el archivo original. Panel `/engines`, detalle, API de resultados y CSS respondieron 200 desde un cliente loopback, con dos resultados persistidos.

## Regresiones de la revisión

El registry construye el módulo SSLyze real. Solo las observaciones positivas pueden llevar Findings, tanto en el constructor como al persistir un objeto alterado. Un host observado únicamente como desconocido conserva `hosts_up=0`. Las URI con userinfo se sanean en raw, evidencia, metadatos de proveedor y exportaciones; un grant con credenciales URI se rechaza antes de escribir en la base.

La identidad de hallazgos y la cobertura negativa incluyen Host/SNI y semántica HTTP/HTTPS/TLS por endpoint. Dos virtual hosts con la misma IP/puerto pueden coexistir: el negativo de uno solo resuelve su propio positivo compatible y conserva el componente original del plugin. Un cambio de transporte o trust store no cierra evidencia incompatible. Las pruebas de regresión y el ciclo completo se incluyen en las 610 pruebas finales.

## Contratos y límites

Se consultaron fuentes primarias de [Nuclei 3.11.1](https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/pkg/output/output.go), [SSLyze 6.3.1](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/json/json_output.py), [RPM 6.0](https://rpm.org/docs/6.0.x/man/rpm-version.7) y el [esquema CVE API NVD 2.2.4](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema). Las fixtures se construyeron con sus campos; no son capturas de herramientas ejecutadas contra objetivos reales. Vuls conserva la distinción documentada entre release 0.41.0 comprobada y contrato de modelos consultado en master oficial.

Las cuotas NVD son una política local conservadora, no una afirmación sobre cuotas contractuales actuales. Linux se evalúa contra avisos suministrados y origen de repositorio comprobado; APK continúa con comparación desconocida. Importaciones y ausencias de CVEs no cierran evidencia local. MSRC conserva la cobertura del boletín mensual elegido. Los attack paths siguen siendo correlaciones heurísticas.

No se ejecutó la matriz CI remota Linux/Python 3.11. Los binarios externos fijados siguen siendo opcionales y deben instalarse/configurarse para operar contra alcances autorizados. La ejecución durable, separación de workers y cancelación de los colectores heredados se verifican en D.
