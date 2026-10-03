# Paquetes Linux y feeds de vulnerabilidades

ScopeScan distingue una versión upstream de una versión mantenida por la distribución. El inventario Debian conserva epoch, revisión, arquitectura, paquete fuente y su versión; filtra estados que no son `installed`. RPM conserva `EPOCHNUM:VERSION-RELEASE`, arquitectura y vendor. Estos datos no prueban por sí solos el repositorio de instalación. La clasificación inicial del origen es `unknown`.

`package_versions.py` compara versiones Debian y RPM siguiendo sus reglas nativas, incluidas `~`, epoch y revisiones; RPM incorpora `^`. No utiliza SemVer. APK y otros formatos todavía devuelven comparación desconocida en este evaluador; el inventario conserva sus versiones completas. Un banner/CPE no demuestra si se ha aplicado un backport.

El adaptador `linux-advisories` evalúa un inventario fechado contra el formato normalizado `scopescan.linux-advisories.v1`. Es una importación de avisos aportados por el operador, no un descargador de todos los avisos de cada proveedor. El documento requiere `provider`, `distro`, `release`, `feed_version`, `observed_at` con zona horaria y una lista `advisories`; cada aviso contiene `id`, `package`, `fixed_version`, `repository`, `cves` y opcionalmente `arch`. Proveedor/distribución/release deben coincidir; si el aviso se refiere al paquete fuente se compara `source_version`, nunca la versión binaria.

La cobertura se llama `advisories_supplied`. Una versión anterior a la corrección produce una candidata y conserva si el origen del repositorio está comprobado. Una versión corregida permite una observación negativa solamente cuando `repository_class=distribution` y el repositorio coincide con el aviso. Una versión corregida con origen desconocido o tercero queda sin evaluar; tampoco se cierra por no observar el paquete. La identidad incluye arquitectura y componente para separar instalaciones paralelas. Ni una candidata ni un resultado importado confirma explotabilidad.

El `inventory.observed_at` tiene que ser la fecha original de observación del inventario; la fecha del feed no la sustituye. El adaptador requiere un endpoint host explícitamente autorizado `Endpoint(ip, None, "host")`. Se puede evaluar desde CLI/panel mediante el contrato de motores con inventario JSON y feed normalizado; ningún adaptador importa credenciales ni ejecuta scripts de los informes.

## Vuls

`VulsImportAdapter(payload, host=ip)` importa el objeto JSON `ScanResult` de Vuls. Conserva familia/release, versión de herramienta, fecha, paquetes completos, arquitectura/repositorio/vendor/repositoryClass, `SrcPackages`, CVEs, `affectedPackages` con `fixedIn`/`fixState`/`notFixedYet`, identificadores y fechas de avisos de distribución y nombres de proveedores. Los providers sin versión declarada se registran como `version_not_reported`. La ausencia de CVEs no produce observaciones negativas. Errores/warnings hacen que el resultado sea parcial; un paquete afectado sin inventario queda desconocido.

El operador asocia el informe con una IP autorizada. Si hay IPs declaradas tienen que contener esa IP; `serverName` no se resuelve por DNS. Informes de contenedores se rechazan en este adaptador de hosts y deben entrar por componentes/SBOM. El plan fija SHA-256 del payload y las reglas concretas. No se lanza Vuls con configuración arbitraria.

La salida raw conservada es un documento saneado mediante una lista de campos permitidos: se omiten `config`, campos desconocidos, texto de errores/warnings y payload libre de `cveContents`. Incluye SHA-256 del documento original y manifiesto de redacciones; la persistencia de motores calcula también SHA-256 del raw saneado. El archivo original del operador permanece intacto. No se conserva un JSON original que pueda contener contraseñas.

Se verificó la publicación Vuls 0.41.0 (commit `f7331a921fd3237bca383d28a241c03c085301de`). El acceso raw al tag no estaba disponible en esta sesión: el contrato leído procede de `master` oficial el 2026-10-03, no se presenta como una descarga del tag. Las fixtures de pruebas son documentos construidos con esos campos oficiales y versión explícita; no son capturas de un escaneo real.

## NVD y MSRC

Todos los clientes NVD del mismo directorio de datos comparten reservas SQLite atómicas: política conservadora de cinco solicitudes por treinta segundos, también con API key. Esta política local no afirma cuál sea una cuota contractual vigente de NVD. El API key existe solo en configuración/env y en la cabecera de petición. Nunca se usa como clave de presupuesto, ni se escribe en la base de datos.

Una lease por CPE evita refrescos simultáneos; tras adquirirla se relee la caché. La duración de lease cubre el deadline total de consulta más margen. Las peticiones de un mismo CPE se deduplican entre hosts/puertos de un enriquecimiento. Se hacen hasta tres intentos por página ante 429/5xx/fallos de red, se comparte `Retry-After` completo entre clientes y las esperas comprueban cancelación/deadline cada 100 ms. El deadline limita la espera del job sin acortar la pausa solicitada por el proveedor. Un fallo de refresh comparte un enfriamiento de treinta segundos y su fecha no se adelanta al servir de nuevo el error.

Cada consulta tiene un deadline total por defecto de 120 s; las peticiones individuales usan hasta veinte segundos, respuestas hasta 16 MB, hasta 2.000 CVEs por página y 10.000 en total/seis páginas. Una página fuera de secuencia o incompleta falla explícitamente. La cancelación no devuelve una caché vencida como si fuera una operación realizada.

La caché válida dura siete días. Si falla su actualización se puede devolver la última caché con `feed_stale=true`, `feed_error` y `feed_fetched_at` original; el resultado no renueva su fecha y el enriquecimiento queda parcial. Incluso una caché vacía conserva ese estado mediante `last_status` y el registro de refresh. Sin caché utilizable el fallo se comunica. El esquema esperado es NVD API CVE 2.2.4. `affected` sin `configurations` se conserva como aplicabilidad no comprobada; no se descarta como versión no afectada.

CVSS conserva todas las métricas válidas y su proveedor/versión. La política de selección es versión más reciente (4.0, 3.1, 3.0, 2.0), seguida de `Primary` dentro de esa versión. No se aceptan bool, NaN, infinito o puntuaciones fuera de 0–10. El proveedor se muestra explícitamente; ninguna puntuación es una probabilidad de explotación.

MSRC conserva proveedor `Microsoft MSRC`, versión de API, esquema CVRF y boletín mensual elegido. `current` significa actualizado respecto a los builds corregidos del boletín y producto evaluados. No afirma cobertura de todo el historial de CVEs Windows. Las puntuaciones no finitas se ignoran.

## Fuentes y verificación

- [Debian Policy, campo Version](https://www.debian.org/doc/debian-policy/ch-controlfields.html#version), versión 4.7.4.1 consultada.
- [RPM 6.0, rpm-version(7)](https://rpm.org/docs/6.0.x/man/rpm-version.7).
- [Vuls releases](https://github.com/future-architect/vuls/releases), [ScanResult](https://github.com/future-architect/vuls/blob/master/models/scanresults.go), [Packages/SrcPackages](https://github.com/future-architect/vuls/blob/master/models/packages.go), [VulnInfo/avisos](https://github.com/future-architect/vuls/blob/master/models/vulninfos.go).
- [NVD esquema API CVE 2.2.4](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema).
- [MSRC API oficial](https://api.msrc.microsoft.com/cvrf/v3.0/).

Las pruebas `test_precision_feeds.py` y `test_vuls_linux_adapters.py` cubren orden nativo/backports/source version, IP y autorización host, saneado Vuls, resultados parciales, contratos malformados, dos clientes concurrentes, ownership de leases, presupuesto compartido, Retry-After largo y deadline/cancelación, caché vencida sin fechas falsas y múltiples métricas/proveedores CVSS. Toda red se sustituye por transporte falso; no se consulta un feed ni se inventaría un host real en las pruebas.
