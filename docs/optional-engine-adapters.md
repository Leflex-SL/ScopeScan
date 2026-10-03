# Adaptadores opcionales HTTP y TLS

`NucleiAdapter` requiere Nuclei **3.11.1** y `SSLyzeAdapter` requiere SSLyze **6.3.1**.
Son procesos opcionales encontrados en PATH: ScopeScan no los instala ni descarga
plantillas, almacenes de confianza o actualizaciones. La detección de disponibilidad
usa `nuclei -version -duc` y `sslyze --help`; una versión distinta devuelve una
explicación accionable. SSLyze se ejecuta como herramienta externa y no se incorpora
su biblioteca AGPL. Las plantillas propias de ScopeScan tienen licencia MIT.

El plan compartido exige un alcance autorizado, IP canónica, puerto TCP y servicio
identificado. HTTP/HTTPS alimenta Nuclei; TLS directo alimenta SSLyze. No se deduce
HTTP/TLS solamente por el número de puerto. STARTTLS queda fuera de estos perfiles.
Un hostname procede explícitamente del operador y debe figurar en las resoluciones
fijadas del alcance. Nuclei conecta a una URL con IP literal y utiliza Host/SNI
explícitos cuando existen. SSLyze usa `hostname:puerto{IP}`; IPv6 sin hostname usa
`[IPv6]:puerto{IPv6}`. Los nombres detectados por Nmap no autorizan destinos nuevos.

El catálogo HTTP incluye dos GET `/`: ausencia de X-Content-Type-Options y, solo en
HTTPS, ausencia de Strict-Transport-Security. Son exposiciones de configuración y
no hallazgos CVE. El significado del negativo es **presencia del encabezado**, sin
afirmar que su valor cumpla una política de endurecimiento. Cada plantilla tiene
un SHA-256 fijado en código: se leen sus bytes una sola vez, se verifica el hash y
se ejecuta una copia privada. Un manifiesto personalizado no añade plantillas
revisadas. No hay redirecciones, OAST, raw requests, workflows, headless, código,
JavaScript o protocolos de ejecución local. El proceso recibe `-pt http`, `-dr`,
`-ni`, `-duc`, concurrencia y batch de uno, dos solicitudes/segundo, cero retries,
timeout de solicitud de cinco segundos y respuesta limitada a 65536 bytes.

Cada proceso recibe un entorno reducido sin proxies, credenciales cloud ni
variables NUCLEI del usuario. HOME, USERPROFILE, APPDATA, LOCALAPPDATA,
XDG_CONFIG_HOME, NUCLEI_CONFIG_DIR y NUCLEI_TEMPLATES_DIR apuntan a directorios
privados vacíos, porque Nuclei puede combinar configuración implícita incluso
cuando se proporciona `-config`. Los directorios se eliminan al terminar.

Un evento Nuclei debe corresponder exactamente a IP, puerto **string**, esquema,
URL y plantilla. `matcher-status` debe ser booleano y no debe haber error. El
adaptador analiza una cabecera HTTP completa, rechaza duplicados/malformaciones y
comprueba que el resultado del matcher concuerde con el encabezado observado.
Salida vacía, múltiples eventos ambiguos, respuesta truncada o un error producen
`unknown`; nunca demuestran ausencia del problema. Se conservan cabeceras
sanitizadas y prueba normalizada; no se guardan cuerpo, request ni cookies.

SSLyze recibe `--json_out` con un archivo administrado, `--quiet`,
`--slow_connection`, `--mozilla_config disable`, `--certinfo` y pruebas de SSL2,
SSL3, TLS1.0 y TLS1.1. No utiliza flags inventados `--version`, `--json_outfile` o
`--max_connections`. Se validan versión JSON, conexión directa, IP/puerto,
hostname/SNI, conectividad y estado COMPLETED de cada comando. ERROR y
NOT_SCHEDULED quedan desconocidos. Un protocolo no soportado requiere una prueba
completa con ciphers rechazados; una lista vacía no se interpreta como seguridad.

Los controles de certificado separan SAN, expiración, fecha de inicio y confianza.
La identidad utiliza DNS-ID/IP-ID SAN según RFC 9525, comparación DNS sin
distinción de mayúsculas y wildcard completo solo en la etiqueta izquierda; no
hay fallback a Common Name. SAN ausente/malformado, fechas inválidas o proveedor
de confianza ausente quedan desconocidos. Se conservan cadena recibida, SAN,
fechas y resultado por trust store con su nombre/versión y error. Un certificado
rechazado por todos los almacenes evaluados demuestra el problema de confianza;
una aceptación corresponde al conjunto explícito de proveedores observado.
Un problema en cualquier deployment demuestra un positivo; un negativo exige
evaluación completa de todos. Los proveedores/versiones forman `Provenance.feeds`.

Un deadline monotónico único cubre disponibilidad y todos los endpoints del job;
no se reinicia entre procesos. El runner limita stdout/stderr y vigila los archivos
durante la ejecución, incluso si el motor está silencioso. Cancelación, deadline,
archivo no regular o crecimiento excesivo terminan el árbol de procesos mediante
job de Windows o grupo POSIX. Los resultados interrumpidos son parciales o
cancelados; sus negativos no autorizan cierres de continuidad. Los timestamps
normalizados son tiempos de colección local, no fechas reclamadas por JSON externo.
La evidencia elimina encabezados y campos sensibles antes de devolverse al core,
que aplica nuevamente redacción y validación antes de persistir.

Las pruebas usan solamente programas Python locales y fixtures del esquema; no
ejecutan escaneos reales. Cubren entorno, integridad, IPv6/Host/SNI, resultados
vacíos y parciales, versiones, SAN/cadena/fechas/proveedores, límites silenciosos,
deadline total y cancelación. Constructor `command=(...)` permite únicamente
integración confiable y pruebas; CLI/panel no admiten argumentos binarios arbitrarios.

Fuentes primarias verificadas:

- [Flags Nuclei 3.11.1](https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/cmd/nuclei/main.go),
  [eventos JSON](https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/pkg/output/output.go),
  [configuración](https://raw.githubusercontent.com/projectdiscovery/nuclei/v3.11.1/pkg/catalog/config/constants.go).
- [CLI SSLyze 6.3.1](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/cli/command_line_parser.py),
  [destinos](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/cli/server_string_parser.py),
  [JSON principal](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/json/json_output.py),
  [certificados](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/plugins/certificate_info/json_output.py),
  [ciphers](https://raw.githubusercontent.com/nabla-c0d3/sslyze/6.3.1/sslyze/plugins/openssl_cipher_suites/json_output.py).
- [RFC 9525: identidad del servicio TLS](https://www.rfc-editor.org/rfc/rfc9525.html).
