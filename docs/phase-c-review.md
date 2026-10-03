# Revisión independiente de calidad y anti-patrones — fase C

Revisión C01–C06 frente al checkpoint B `b381b614`, con fuentes congeladas y relectura de las dos reparaciones detectadas durante esta revisión. No se han modificado fuentes, checklists ni commits desde esta revisión. Se ha aplicado `code-review-structured`.

## 🐛 BUGS

1. **P1 corregido, registro SSLyze.** `engine_service.ADAPTERS` referenciaba `scopescan.sslyze`, pero el módulo existente es `scopescan.sslyze_adapter`. El probe inicial de importación detectó la discrepancia. El mapping final utiliza el módulo existente y el probe real `engine_service.adapter('sslyze')` devuelve `SSLyzeAdapter`.
2. **P2 corregido, observación contradictoria.** Una observación `unknown` o `negative` podía incluir `Finding`. Un probe propio con DB temporal demostró que el caso `unknown` creaba un hallazgo vigente `observed`. El constructor ahora exige Finding exclusivamente para `positive`; `engine_store.validate` repite esa condición. El recheck independiente verifica rechazo de ambos outcomes en constructor y almacenamiento, incluso tras alterar deliberadamente el objeto, con cero filas de escaneos.

No se detectaron bugs evidentes pendientes dentro del alcance revisado.

## 🔒 SEGURIDAD

No se detectaron vulnerabilidades de seguridad evidentes pendientes. Se verificaron autorización por IP concreta, hostname aportado por operador y fijado al alcance, grants host sin listener inventado, plantillas HTTP permitidas y SHA de sus bytes, entorno aislado, evidencia saneada y validación previa a persistencia. Vuls conserva campos permitidos y omite configuración y texto libre susceptible de contener credenciales. Los resultados importados quedan como candidatos y no aportan negativos fiables para cierre local.

La lectura de contratos oficiales SSLyze 6.3.1 confirma `hostname:port{IP}`, `--json_out` con archivo, `--quiet`, `--slow_connection` y configuración Mozilla desactivada. Se revisó también el modelo oficial Vuls `master`; no se afirma haber recuperado el raw del tag 0.41.0 ni ejecutado herramientas reales.

## ⚡ RENDIMIENTO

La planificación pagina activos y puertos; su límite de endpoints es explícito. NVD comparte reservas SQLite, lease por CPE y cooldown del proveedor; la deduplicación no depende de un caché exclusivo del proceso. Consultas, normalización y archivos de salida tienen límites visibles. El deadline del motor se comparte entre disponibilidad y endpoints.

Un proceso Python local silencioso produjo un archivo de 50.000 bytes sobre un límite de 1.000 y permanecía durmiendo 15 segundos. El runner terminó el árbol con `file_limit_exceeded=True`, motivo `Output file exceeded byte limit`, en 4,59 segundos incluidos launcher y limpieza Windows. Un umbral artificial inicial de cuatro segundos resultó demasiado estricto; el recheck funcional registra el tiempo real y no afirma latencia inferior.

## 🔧 MEJORAS

Los límites operativos de fase D siguen pendientes en esta puerta: jobs durables, scheduler y separación web/worker, así como cancelación común de todos los colectores anteriores. No se consideran realizados por esta revisión C.

La documentación distingue feed suministrado, repositorio desconocido, fuente/binario Linux, proveedores/versiones CVSS, cobertura mensual MSRC y correlación heurística de attack paths. La negativa de HSTS/nosniff prueba presencia del encabezado, sin afirmar validez de su política. La cobertura completa local y versiones de motor/reglas/templates/feeds compatibles condicionan los cierres.

## 📋 RESUMEN

- **Severidad global final:** 🟢 Bajo; sin bloqueos concretos pendientes C01–C06 después de los rechecks.
- **Top 3 cambios prioritarios:** las dos reparaciones anteriores están verificadas; continuar con la puerta de empaquetado C y después con D05–D07.
- **Puntos positivos:** contratos acotados, decisiones conservadoras ante evidencia desconocida, procedencia explícita, imports saneados, presupuestos compartidos y pruebas con transportes/procesos falsos.

### Evidencia propia

- `python -m pytest -q tests/test_engine_contracts.py tests/test_engine_store.py tests/test_precision_feeds.py tests/test_vuls_linux_adapters.py tests/test_engine_ui_cli.py`: **85 pasan**, 47,95 s, un warning conocido de Starlette/TestClient. Este resultado precede a las últimas regresiones del guard de outcomes; el recheck propio del guard se ejecutó posteriormente.
- Dos SHA del catálogo Nuclei coinciden exactamente con sus archivos locales.
- Un entorno con proxy y variable NUCLEI secreta del padre no los transmite al proceso; tampoco hereda PATH.
- Ciclo propio: positivo local → negativo con feed distinto/importado/parcial conserva el hallazgo; negativo completo local con versiones exactas lo resuelve.
- Recheck final: registro SSLyze resuelve; `unknown`/`negative` con Finding se rechazan en constructor y almacenamiento antes de crear filas.

No se ejecutó la suite global desde esta revisión, ni escaneos reales, feeds remotos, acciones externas, CI Linux o instalación de herramientas opcionales. La puerta integral y los artefactos de distribución pertenecen al verificador independiente.

Fuentes primarias consultadas: [CLI SSLyze 6.3.1](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/cli/command_line_parser.py), [parser de destinos](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/cli/server_string_parser.py) y [modelo Vuls](https://raw.githubusercontent.com/future-architect/vuls/master/models/scanresults.go).

## Revisión fresca tras las últimas reparaciones C

Se releyeron `engine_store`, `continuity.covered`, contratos, redacción Vuls y NVD tras los cambios de identidad SNI, URI userinfo, contador de hosts y paginación/backoff. La revisión de anti-patrones independiente detectó estos problemas y el equipo de implementación los reparó; este apartado verifica su resultado final sin atribuirse esa detección.

Un script propio con DB temporal y transporte HTTP falso confirma:

- **Identidad de virtual host:** dos nombres comparten IP/443 y conservan dos hallazgos. Cambiar `App.Review.Test` a `app.review.test` y reagrupar el plan conserva la identidad lógica; el prefijo del componente original del plugin permanece. Un negativo de B cierra solo B. Un negativo de A con el alias de servicio `https-alt` cierra A, por su condición canónica, sin depender del fingerprint del plan global.
- **Estado desconocido:** una ejecución con una única observación unknown conserva `hosts_total=1`, `hosts_up=0`.
- **URI Vuls:** una URL de repositorio con userinfo, dirección IPv6, puerto y path pierde las credenciales en el resultado de biblioteca, raw saneado, normalizado, almacenamiento y JSON exportado. Conserva host/puerto/path y SHA-256 del documento original. La persistencia sanea también texto de procedencia y rechaza grants que contengan credenciales URI.
- **Paginación NVD:** una respuesta sin `totalResults` no reemplaza la caché anterior por un resultado vacío fresco. Se conserva el candidato, su fecha original y `feed_stale=true` con error explícito.
- **Retry-After final:** una secuencia falsa de tres HTTP 429 con pausas 0, 0 y 7.200 segundos registra también la pausa de la tercera respuesta antes de comunicar el fallo. El probe utiliza un presupuesto falso y no espera dos horas ni contacta NVD.

**Veredicto final de calidad:** no quedan P0/P1/P2 concretos pendientes en C01–C06 dentro del alcance revisado. Esta segunda revisión no ejecutó una suite global duplicada; el resultado global final y el build siguen a cargo del verificador. La fase D conserva sus requisitos pendientes.
