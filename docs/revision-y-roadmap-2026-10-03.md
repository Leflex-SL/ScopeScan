# ScopeScan: revisión y roadmap

Fecha: 3 de octubre de 2026. Revisión del código real de `C:\Users\hugoo\CumScanner\src\scopescan`, sus tests y CI, y de README/pyproject en `C:\Users\hugoo\ScopeScan`.

## 📋 Resumen ejecutivo

ScopeScan tiene una base útil: distingue exposición, candidata y comprobación positiva; combina Nmap, inventario autenticado, NVD, KEV/EPSS y MSRC, y conserva evidencia exportable. Mi recomendación es evolucionarlo hacia evaluación continua de activos: identidad estable, comparación entre escaneos, remediación y motores opcionales con resultados normalizados.

Antes de ampliar motores hay defectos concretos de alcance, identidad de endpoints, cancelación y exportación que conviene resolver. Los tests existentes pasan, pero las reproducciones de esta revisión muestran casos no cubiertos. Las propuestas siguientes son recomendaciones; no se han implementado ni aprobado como convenciones del proyecto.

### Alcance y validación

- El checkout de ScopeScan contiene `.git`, README y pyproject, pero Git marca `src/`, `tests/` y CI como borrados. El código, entorno virtual y datos continúan en CumScanner. El nombre lógico está cambiado; la instalación física permanece repartida.
- El contenido de los archivos fuente encontrados coincide con HEAD `2a933ff` al normalizar CRLF/LF. Se revisó el código real, no solamente la documentación.
- Se copiaron fuentes y tests a un directorio temporal aislado para verificar sin modificar datos reales.
- Resultado: **150 tests pasan**, Ruff pasa y `scopescan self-test` pasa. Hay dos avisos de deprecación de las dependencias del TestClient.
- Se realizaron reproducciones con fixtures, mocks y un proceso Python local silencioso. No se lanzaron escaneos, inventarios remotos ni explotación.
- Esta revisión cubre los flujos principales y la estructura del proyecto. No constituye una auditoría exhaustiva de todas las combinaciones de reglas, versiones externas y sistemas operativos.

## 🐛 BUGS

### 1. [P1] Un rango público puede clasificarse como privado

**Ubicación:** [targets.py:67](C:/Users/hugoo/CumScanner/src/scopescan/targets.py:67), especialmente línea 88; guardas de verificación en [msf.py:95](C:/Users/hugoo/CumScanner/src/scopescan/msf.py:95).

**Reproducción:** `parse_targets('10-11.0.0.1')` devuelve dos hosts, `all_private=True` y ningún aviso. El segundo host, `11.0.0.1`, no pertenece al bloque privado `10.0.0.0/8`.

**Causa e impacto:** `_parse_octet_range` comprueba solamente la primera dirección. La verificación MSF usa esa clasificación del conjunto para su guarda de objetivos públicos. La explotación directa dispone de una comprobación adicional por host; el fallo señalado afecta a clasificación y verificación, y no demuestra que se eluda esa segunda guarda.

**Fix:** comprobar conservadoramente toda la cobertura del rango frente a la política de redes permitidas; revalidar también cada IP concreta del plan antes de cualquier motor. No enumerar rangos enormes para efectuar esta comprobación. Añadir tests de rangos que atraviesan fronteras privadas/públicas.

### 2. [P1] La verificación previa MSF no está ligada al puerto solicitado

**Ubicación:** [msf.py:219](C:/Users/hugoo/CumScanner/src/scopescan/msf.py:219).

**Reproducción:** con un veredicto vulnerable para host/módulo en 445/TCP, `_validated_exploit_context(..., port=1445, ...)` acepta el contexto.

**Causa e impacto:** el predicado compara host, módulo y resultado, pero omite puerto y protocolo. Una comprobación positiva de un servicio no justifica actuar contra otro endpoint del mismo equipo.

**Fix:** resolver primero el puerto efectivo y exigir identidad completa: host, puerto, protocolo, módulo y veredicto. Si el usuario omite el puerto y hay varias verificaciones posibles, exigir selección inequívoca. El predicado, una vez resuelto el puerto, debe incluir:

```python
and r['port'] == effective_port
and r['protocol'] == 'tcp'
```

### 3. [P2] La planificación MSF trata puertos UDP como TCP

**Ubicación:** [msf.py:47](C:/Users/hugoo/CumScanner/src/scopescan/msf.py:47), `_cve_map` y `_rows_from`.

**Reproducción:** un fixture con servicio `ssh` en 22/UDP produce el módulo TCP `auxiliary/scanner/ssh/ssh_version`. La salida se persiste con protocolo TCP.

**Fix:** declarar transportes soportados en el catálogo, filtrar antes de planificar y propagar protocolo en claves y resultados. Mientras el catálogo sea TCP, descartar explícitamente puertos UDP.

### 4. [P2] Cancelar depende de que el proceso escriba una línea

**Ubicación:** [nmap_runner.py:122](C:/Users/hugoo/CumScanner/src/scopescan/nmap_runner.py:122). El runner MSF presenta un patrón similar que también debe revisarse.

**Reproducción:** proceso local sin stdout durante 0,8 segundos; señal de cancelación a los 0,1 segundos. El runner espera su salida normal y devuelve `cancelled=False`, pese a que el evento está activado.

**Fix:** separar la lectura de salida del control del proceso; comprobar cancelación y deadline periódicamente aunque no haya stdout. Añadir timeout total configurable al flujo de escaneo: `service.execute` actualmente no pasa uno al runner. Garantizar cierre de pipes y terminación si falla un callback de progreso.

### 5. [P2] La deduplicación elimina hallazgos de otro protocolo

**Ubicación:** [analysis.py:335](C:/Users/hugoo/CumScanner/src/scopescan/analysis.py:335).

**Reproducción:** dos hallazgos con mismo host, número de puerto, título y fuente, uno TCP y otro UDP, se convierten en uno.

**Fix inmediato:**

```python
key = (finding.host, finding.port, finding.protocol,
       finding.title, finding.source)
```

A medio plazo, sustituir el título por un identificador estable de regla/template. El texto mostrado puede cambiar sin que cambie la identidad del problema.

### 6. [P2] El inventario Alpine separa incorrectamente paquete y versión

**Ubicación:** [linux_inventory.py:158](C:/Users/hugoo/CumScanner/src/scopescan/linux_inventory.py:158).

**Reproducción:** `openssl-3.3.2-r0` se guarda como nombre `openssl-3.3.2` y versión `r0`.

**Fix:** obtener nombre y versión en campos separados desde metadatos APK; si se mantiene el texto, usar un parser de la gramática completa, incluida revisión `-rN`, nombres con guiones y versiones especiales. Esto debe corregirse antes de conectar el inventario a un proveedor de CVE por paquetes.

### 7. [P2] Un puerto inválido en Origin provoca HTTP 500

**Ubicación:** [web/app.py:136](C:/Users/hugoo/CumScanner/src/scopescan/web/app.py:136).

**Reproducción:** POST local con `Origin: http://foreign.example:invalid` devuelve 500. Acceder a `parsed.port` lanza `ValueError`.

**Fix:** capturar errores de parseo de URL/puerto y rechazar el origen. La validación de entradas debe producir una respuesta controlada, no una excepción del servidor.

### 8. [P2] La instalación física está dividida

**Ubicación:** directorios ScopeScan/CumScanner y estado del checkout.

**Impacto:** instalar y desarrollar desde ScopeScan no encuentra sus fuentes; la base, artefactos y entorno virtual permanecen en otra raíz. No se atribuye esta situación a un error del rename lógico: se describe el estado observado.

**Fix propuesto:** consolidar la raíz cuando termine la sesión que mueve los archivos, comprobar historial y artefactos, y recrear/reinstalar el entorno virtual. Revisar rutas absolutas guardadas en SQLite y configuración editable. Validar después CLI, tests y exports. No hacer una restauración desde Git que sustituya datos o trabajo existente.

## 🔒 SEGURIDAD

### [P1] La confianza en loopback no valida el Host del panel

**Ubicación:** [web/app.py:74](C:/Users/hugoo/CumScanner/src/scopescan/web/app.py:74) y comparación de origen.

**Evidencia:** un cliente loopback con `Host: foreign.example:8000` recibe 200 en `/openapi.json`; con Origin del mismo dominio, la comprobación de escritura también devuelve True. El hostname que el propio cliente aporta se usa como referencia de confianza.

**Implicación:** faltan guardas frente a DNS rebinding. También hay que revisar el despliegue tras proxy: si este conecta por loopback, el middleware puede considerar local una petición remota. No se realizó una explotación en navegador; la evidencia reproduce la aceptación de Host/origen y el riesgo depende del navegador y la topología.

**Mejora:** Host permitido por configuración, origen esperado independiente de la petición, autenticación también para loopback cuando esté habilitada y token CSRF para acciones del navegador. Definir explícitamente cómo se confía en un proxy. Basic Auth remoto debe usarse con TLS.

### [P2] El CSV conserva fórmulas controladas por datos del objetivo

**Ubicación:** [export.py:163](C:/Users/hugoo/CumScanner/src/scopescan/export.py:163).

**Reproducción:** una evidencia `=1+1` queda igual en la celda CSV. `csv.DictWriter` escapa la sintaxis CSV, pero no desactiva fórmulas de hojas de cálculo.

**Mejora:** neutralizar en el export para hojas de cálculo los prefijos de fórmula, teniendo en cuenta espacios y controles iniciales. Mantener la evidencia original en JSON. Añadir pruebas de `=`, `+`, `-`, `@` y variantes con tabuladores.

### Guardas adicionales recomendadas

- Claim atómico de enriquecimientos: las rutas hacen leer-estado/escribir-estado en operaciones separadas. Dos peticiones concurrentes pueden lanzar el mismo trabajo. Usar una transición condicional en una transacción y comprobar si obtuvo el claim.
- Coordinar borrado con trabajos activos: solicitar cancelación no garantiza que el worker haya terminado antes de borrar filas. Definir un estado de borrado pendiente y finalizar después de liberar el trabajo.
- Separar el proceso web del componente que necesita privilegios. El panel actual puede ejecutar con la identidad que tiene acceso a WinRM/SSH y, si es administrador, con esos permisos amplios.
- Añadir lock de dependencias, auditoría de paquetes, permisos mínimos y acciones CI fijadas a commits. Los mínimos abiertos de pyproject no describen un entorno reproducible. No se afirma que las versiones instaladas estén afectadas por una CVE concreta: no se hizo un análisis completo de advisories.
- Antes de distribuir: LICENSE elegida por el propietario, SECURITY.md, política de vulnerabilidades y contrato de datos exportados.

## ⚡ RENDIMIENTO

1. **Futures retenidos:** [jobs.py:26](C:/Users/hugoo/CumScanner/src/scopescan/jobs.py:26). Se eliminan eventos, pero no futures completados. Reproducción: tres tareas terminadas dejan tres entradas y ningún activo. Limpiar referencias al terminar, con cuidado de las carreras entre registro y callback.
2. **Sondeo del entorno por petición:** [config.py:312](C:/Users/hugoo/CumScanner/src/scopescan/config.py:312) ejecuta `nmap --version`; el dashboard vuelve a solicitarlo al refrescar. Cachearlo con TTL y botón de refresco. No se midió su latencia en producción.
3. **Pantallas muy grandes:** dashboard limitado a 25 escaneos, hallazgos a 300 y detalle con inventarios completos, incluidos miles de paquetes. Añadir paginación real, búsqueda y carga bajo demanda; indicar cuándo una lista está limitada.
4. **Exports repetidos:** bundle genera HTML/JSON/CSV y reconstruye varias vistas. Crear una instantánea consistente por export, reutilizarla y evitar cargar todo el ZIP en RAM cuando el volumen crezca.
5. **Feed NVD:** el rate limit vive en cada cliente, no en todos los jobs. Centralizar presupuesto de peticiones, deduplicación de CPE, reintentos con backoff y caché vencida señalizada cuando el proveedor falla.
6. **Cola y enriquecimientos separados:** los escaneos usan executor acotado y las integraciones `BackgroundTasks`. Unificar límites, estados y cancelación; registrar jobs durables en SQLite antes de introducir Redis/Celery por necesidades aún no medidas.

## 🔧 MEJORAS

### Producto: funciones que más valor aportarían

| Prioridad | Función | Resultado visible |
|---|---|---|
| Alta | Comparación entre escaneos compatibles | Puertos nuevos/cerrados, servicios cambiados, hallazgos nuevos, persistentes y resueltos |
| Alta | Identidad estable de activos y hallazgos | Un mismo problema mantiene historial aunque cambie el título o la IP del activo |
| Alta | Flujo de remediación | Responsable, estado, fecha objetivo, excepción con caducidad y evidencia de cierre |
| Alta | Riesgo por activo y explicación | Combina gravedad, evidencia, exposición, KEV/EPSS y criticidad del activo con razones visibles |
| Alta | Alcance reutilizable | Targets, exclusiones, nombres resueltos y perfil; vista previa de qué comprobará cada motor |
| Alta | Reescaneo de verificación | Comprobar los endpoints y controles afectados después de corregirlos |
| Media | Importar Nmap XML y resultados externos | Analizar un resultado obtenido por otro operador o desde una red aislada |
| Media | Programación persistente | Ventanas de ejecución, política de concurrencia y aviso solo ante cambios útiles |
| Media | Parches Linux por distribución | Comparar paquetes completos y advisories del proveedor, respetando backports |
| Media | TLS con nombre/SNI y confianza | Revisar cadena, hostname, vigencia y configuración, además de cifrados y protocolos |
| Media | Software/SBOM y contenedores | Evaluar componentes que no se identifican con un banner de red |
| Media | Export con manifiesto de evidencia | Versiones de motores/reglas/feeds, timestamps, hash de artefactos y datos ausentes |

Una desaparición no basta para marcar un problema como resuelto: si cambian perfil, alcance, privilegios, conectividad o cobertura, el resultado debe quedar «no observado/no evaluado». Este criterio es imprescindible para que los deltas sean útiles.

El dashboard actual suma hallazgos de todos los escaneos. Añadir dos vistas: estado más reciente por activo e histórico. De lo contrario, repetir una evaluación hace crecer los contadores aunque el entorno no haya empeorado.

En inventarios y plantillas, presentar booleanos desconocidos como «sin dato»: algunas expresiones de UI convierten `None` en un texto negativo. Revisar también truncamiento de paquetes, metadatos de actualización antiguos y cobertura MSRC: la evaluación actual consulta un boletín mensual, no todo el historial de CVE de Windows.

### Arquitectura propuesta

Mantener el núcleo Python, SQLite y FastAPI. Definir contratos antes de añadir conectores:

- `ScanScope`: IPs/nombres, puertos/protocolos, exclusiones, política y autorización del operador.
- `EngineAdapter`: disponibilidad/versión, planificación, ejecución acotada, cancelación y parseo.
- `Observation`: servicio, configuración o paquete observado, con origen y fecha.
- `Finding`: identificador estable, endpoint, evidencia, estado de aplicabilidad, severidad y remediación.
- `Job`: queued/running/partial/done/failed/cancelled, ownership, heartbeat y transición atómica.

Persistir versiones de reglas y proveedores con cada evaluación. Conservar raw y resultado normalizado. Usar rutas de datos independientes de la ubicación del paquete instalado; actualmente la ruta por defecto se deriva de `__file__`.

Las «attack paths» actuales consolidan evidencia de host/puerto/CVE/PoC/MSF; no modelan conectividad, credenciales ni una cadena real entre activos. Mejorar primero esa consolidación y explicar sus límites; un grafo de rutas de ataque requiere esas observaciones adicionales.

## 🔍 Repositorios interesantes y aplicación práctica

Fuentes primarias consultadas el 3 de octubre de 2026. Los datos de licencia son metadatos publicados por cada proyecto; no se han tomado decisiones sobre incorporar su código. Las versiones indicadas corresponden a las releases consultadas, no a versiones instaladas o probadas aquí.

| Repositorio | Aportación comprobada | Cómo encaja en ScopeScan | Límite/coste |
|---|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei), [releases](https://github.com/projectdiscovery/nuclei/releases), MIT; 3.11.1 | Motor de checks definidos en YAML, filtros y salidas estructuradas | Adaptador opcional para servicios web descubiertos, con perfiles revisados | Plantillas activas pueden ser intrusivas; fijar motor y conjunto de templates |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates), MIT | Checks mantenidos por la comunidad y firmas | Catálogo revisado por producto/CVE para ampliar cobertura | Una firma no demuestra que el check sea apropiado para el objetivo |
| [Vuls](https://github.com/future-architect/vuls), [releases](https://github.com/future-architect/vuls/releases), GPL-3.0; 0.41.0 | Evaluación por paquetes, OVAL y avisos de distribuciones; remoto/local | Primera referencia para mejorar la precisión del inventario Linux | Alimentación de datos y reglas por distribución; importar JSON o usar adaptador externo |
| [Syft](https://github.com/anchore/syft), [releases](https://github.com/anchore/syft/releases), Apache-2.0; 1.54.0 | Inventarios de componentes/SBOM | Importación/exportación de SBOM y colección desde imágenes o artefactos | No determina por sí mismo que una vulnerabilidad sea explotable |
| [Grype](https://github.com/anchore/grype), [releases](https://github.com/anchore/grype/releases), Apache-2.0; 0.119.0 | Vulnerabilidades en imágenes, filesystems y SBOM; OpenVEX | Motor para analizar SBOM importadas o producidas por Syft | Necesita datos de componentes, distribución y estado de su base |
| [SSLyze](https://github.com/nabla-c0d3/sslyze), [releases](https://github.com/nabla-c0d3/sslyze/releases), AGPL-3.0; 6.3.1 | Biblioteca/herramienta de análisis TLS | Adaptador TLS con resultados estructurados | Revisar licencia y excepciones antes de incorporar la biblioteca |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo), BSD-3-Clause | Gestión de vulnerabilidades e importación de resultados | Modelo de triage y salida hacia un gestor ya existente | Mejor integrar cuando se necesita colaboración amplia; duplicar toda su plataforma tendría un coste alto |
| [Faraday](https://github.com/infobyte/faraday), GPL-3.0 | Centralización y automatización de herramientas de seguridad | Referencia para adaptadores y workspaces de auditoría | Elegir un destino externo según uso, sin implementar simultáneamente dos gestores |
| [gvm-tools](https://github.com/greenbone/gvm-tools), [releases](https://github.com/greenbone/gvm-tools/releases), GPL-3.0; 26.1.1 | Cliente Python/CLI para controlar Greenbone mediante GMP/OSP | Conector opcional a un servidor Greenbone existente | Es un cliente de otro stack, no un escáner autónomo que baste instalar |
| [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content), [licencia](https://raw.githubusercontent.com/ComplianceAsCode/content/master/LICENSE) BSD de tres cláusulas | Contenido de automatización SCAP, Bash y Ansible | Referencia para controles y futura importación de evaluaciones SCAP | Un benchmark incluye alcance y criterios que deben conservarse; no equivale a certificación |

**Orden de adopción recomendado:** Vuls como referencia para paquetes Linux; Nuclei como primer motor nuevo; Syft/Grype para SBOM; DefectDojo como salida de gestión. SSLyze encaja si TLS resulta prioritario. Greenbone merece un conector cuando ya se disponga de su servidor.

No se instalaron ni ejecutaron estos repositorios. La propuesta de encaje es una inferencia a partir de sus capacidades documentadas y del código de ScopeScan.

### Estado reciente que afecta a las integraciones

Nuclei publicó un [advisory sobre bypass de firmas en DAST](https://github.com/projectdiscovery/nuclei/security/advisories/GHSA-jpf4-98qj-qr67): identifica como afectadas versiones anteriores a 3.10.0 desde 3.0.0 y señala 3.10.0 como parche. También existe un [reporte abierto de caché de verificación](https://github.com/projectdiscovery/nuclei/issues/7663), que es un reporte de issue, no una confirmación independiente de esta revisión. El diseño del adaptador debería usar templates revisados, impedir protocolos con ejecución local innecesaria y registrar hashes; no confiar solamente en firma/etiquetas o activarlo todo por defecto.

[Trivy](https://github.com/aquasecurity/trivy) es otra opción para componentes, configuración y contenedores. Su [advisory oficial del incidente de marzo de 2026](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) documenta una release y tags de Actions comprometidos. Si se elige, fijar artefactos verificados y acciones por SHA; no copiar una instalación automática basada en tags mutables. No se concluye que su versión actual esté comprometida.

## 📋 RESUMEN

**Severidad global:** alta por los defectos de clasificación del alcance y vinculación de verificaciones, más la falta de validación de Host. La herramienta conserva buenas guardas, pero estos casos justifican corregir primero el núcleo.

**Top 3 cambios prioritarios:**

1. Consolidar la instalación y corregir alcance, identidad host/puerto/protocolo y acceso al panel.
2. Hacer jobs fiables: cancelación independiente de stdout, claims atómicos, límites y ciclo de vida coordinado.
3. Añadir deltas, estado vigente por activo y remediación; después ampliar cobertura con adaptadores.

### Fases propuestas y criterios de aceptación

| Fase | Entrega | Criterio verificable |
|---|---|---|
| A: fiabilidad | Correcciones de bugs, Host/CSV, raíz consolidada y regresiones | Reproducciones descritas resueltas; datos/artefactos conservados; CLI/tests/exports funcionan desde una única raíz |
| B: seguimiento | Activos, fingerprints, deltas y estados de hallazgos | Reescaneo conserva identidad; solo cierra con cobertura comparable; contadores reflejan estado vigente |
| C: más precisión | Paquetes por distribución y Nuclei opcional | Resultados normalizados con fuente, confianza y versión; alcance y cancelación comunes |
| D: integración | SBOM/Syft/Grype, salida a gestor y tareas programadas | Jobs persistentes e importaciones versionadas; fallos parciales visibles y reintentos controlados |

El esfuerzo depende del volumen real y del uso individual o de equipo; no se han estimado plazos sin esas condiciones. Mantendría SQLite y el frontend actual durante A/B. Multiusuario, escáneres distribuidos, más automatización ofensiva y grafos complejos quedarían para una necesidad concreta.

**Puntos positivos:** separación de evidencia y gravedad, XML como fuente, ausencia de shell en Nmap, SQLite con WAL/transacciones, compatibilidad de configuración y BD antiguas, exportación autocontenida y tests aislados.

### Registro de reproducciones

```text
mixed_range: private=True, warnings=[], hosts=2
alpine_package: name=openssl-3.3.2, version=r0
protocol_dedup: input=2, output=1
foreign_host: HTTP 200; matching Origin passes write check=True
invalid_origin_port: HTTP 500
different_msf_port_accepted: True
udp_msf_plan: UDP 22 -> auxiliary/scanner/ssh/ssh_version
csv_formula: =1+1
silent_cancel: event_set=True, cancelled=False, duration~0.99s
completed_futures: retained=3, active=[]
source_changes_vs_HEAD_ignoring_EOL: []
pytest: 150 passed, 2 warnings
ruff: All checks passed
self-test: completado
```
