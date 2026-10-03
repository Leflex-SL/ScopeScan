# Destinos y conectores

ScopeScan exporta Generic Findings Import para DefectDojo y lee informes externos de Faraday API v3 y Greenbone GMP 22.5. Los conectores son opcionales: no se instala ni se copia ninguna de esas plataformas. Los formatos externos crean candidatos; `confirmed`, QoD o un estado cerrado remoto no constituyen comprobación local ni permiten cerrar hallazgos propios.

## Configuración y ejecución

`scopescan integration add nombre defectdojo https://dojo.example --options '{"token_env":"SCOPESCAN_DOJO_TOKEN","timeout":120}'` guarda exclusivamente una referencia de entorno. Define `SCOPESCAN_DOJO_TOKEN` en el proceso worker. Faraday requiere `username_env`, `password_env` y `workspace`; GMP requiere `username_env`, `password_env`. La página `/integrations` ofrece los mismos formularios, listas paginadas, lectura, entrega, conciliación e importación local.

Los destinos HTTP requieren HTTPS con certificados comprobados. Solo un destino de desarrollo loopback puede usar HTTP, con `allow_http_loopback:true` explícito. No se admiten credenciales en URL, query o fragment. No se heredan proxies, cookies ni credenciales del entorno de red del proceso; las cookies de Faraday viven exclusivamente en su sesión worker. Se rechazan todos los redirects: configura la URL final. GMP usa `tls://host:9390` con confianza y hostname comprobados, o `unix:///ruta/absoluta/socket` en un worker con soporte Unix. No es una API HTTP.

`integration destinations|imports|deliveries --limit 50 --offset 0` consulta las colecciones. `integration detail ID`, `raw ID` y `delivery ID` muestran evidencia o estado persistido. La API equivalente está bajo `/api/integrations`. Los archivos originales nunca se modifican; se conserva su SHA-256, fecha de observación original y evidencia normalizada saneada. El documento original sensible se omite de la copia raw: raw significa la representación normalizada saneada, no un archivo forense sin redacciones.

Todas las entregas y lecturas remotas crean jobs SQLite. El proceso web no hace esas solicitudes ni resuelve secretos. Usa `scopescan worker --once` o el worker persistente documentado en [durable-workers-scheduling.md](durable-workers-scheduling.md). Si falta una variable de credenciales, el job comunica qué referencia necesita; no devuelve su contenido. Una importación local de hasta 8 MB se valida antes de persistir y no necesita conexión a una herramienta externa.

## DefectDojo

`scopescan integration export SCAN_ID` devuelve un JSON del parser oficial **Generic Findings Import**. Incluye endpoints/protocolo, CVEs, fecha de colección, gravedad, mitigación, identidad estable por hallazgo y regla, evidencia y procedencia. Las métricas CVSS desconocidas conservan su puntuación/proveedor en descripción; los vectores v3/v4 utilizan sus campos oficiales. Los candidatos NVD/MSRC se exportan con `verified:false`; solamente evidencia propia confirmada da `verified:true`. Se omite `type` para mantener el Test Type genérico en reimportaciones.

Después de revisar el export y el destino:

```text
scopescan integration deliver DESTINATION_ID SCAN_ID --engagement-id 7 --yes
scopescan integration deliver DESTINATION_ID SCAN_ID --test-id 42 --yes
```

La primera forma envía `/api/v2/import-scan/`; la segunda `/api/v2/reimport-scan/`. El multipart usa `scan_type=Generic Findings Import`, `background_import=true`, `minimum_severity=Info` y **`close_old_findings=false`** también para reimport. No fuerza un `verified` global que sobreescriba cada hallazgo. Un import parcial o una ausencia nunca cierra hallazgos remotos.

Una respuesta background contiene `test_id`, `status` y `findings_parsed`; el contador es de elementos leídos, no de hallazgos creados. Se guarda el ID antes de consultar `/api/v2/tests/{id}/` hasta `Processed` o `Failed`. La respuesta síncrona usa `statistics`, sin asumir esos campos en background. Los polls comparten un deadline total y esperan de forma cancelable.

La entrega conserva payload/hash, fingerprint del destino, engagement/test, referencia remota y estado. Repetir la preparación del mismo snapshot/destino/contexto devuelve la misma entrega/job. Se marca `posting` atómicamente antes del POST. Si hay timeout, cancelación, pérdida del worker o respuesta ambigua, no se vuelve a enviar automáticamente. La página muestra conciliación; comprueba el test en DefectDojo y usa `integration poll DELIVERY_ID --remote-test-id ID_REAL`. Si el ID ya se conoce basta `integration poll DELIVERY_ID`. Ese job solo hace GET. No se afirma garantía de exactamente una entrega ante un crash entre el POST y la persistencia de su respuesta.

## Faraday

`integration pull DESTINATION_ID SCOPE_ID` hace login cookie en `/_api/login` con `email/password`, después lee hosts, services y vulns bajo `/_api/v3/ws/{workspace}/`. Se recorre `page/page_size=100`; hosts usan `rows[{id,key,value}],count`, services usan `services[{id,key,value}],count`, y vulns usan `vulnerabilities[{id,key,value}],count`. El servicio de salida contiene `port` aunque el formato de creación acepte `ports`.

Un snapshot local importable es un JSON con `hosts`, `services`, `vulns`, `observed_at` con zona y `engine_version`. Los registros pueden ser los valores de esas colecciones; conserva `_id` o `remote_id`. `integration import faraday archivo.json --scope-id ID` comprueba las IPs contra el alcance fijado. La lectura registra su fecha de recepción como `observed_at` con `timestamp_inferred:true`: el API ofrece estados actuales y fechas de objeto, no una fecha de ejecución común. Las fechas originales de cada objeto quedan en el snapshot. Los padres Host/Service ligan correctamente IP/puerto/protocolo; padres ausentes, severidades desconocidas o servicios no interpretables dan estado parcial. No se resuelven DNS ni se descargan adjuntos.

## Greenbone

`integration pull DESTINATION_ID SCOPE_ID --report-id UUID` solicita un informe existente mediante `authenticate` y `get_reports report_id="UUID" details="1" filter="first=1 rows=-1"`. No inicia tareas ni escaneos. `integration import greenbone report.xml --scope-id ID` admite un único XML detallado. Se preservan UUID, GMP, estado de scan, fechas, resultados, NVT OID, CVEs, puertos/protocolos y QoD; QoD sigue siendo metadata externa.

El framing XML tolera fragmentos en un socket persistente. Se prohíben DTD/entidades externas e internas y se limita documento a 8 MB, 100.000 nodos, profundidad 64, 10.000 resultados y token XML sin consumir a 64 KiB. En Expat con reparse deferral se piden callbacks inmediatos bajo esos límites para reconocer la respuesta sin esperar un cierre de conexión. Reportes incompletos, severidades desconocidas y listas cuya cantidad no coincide permanecen parciales. Se retienen los negativos externos solo como metadata; no son prueba de cierre.

## Contratos y límites

Fuentes primarias consultadas el 2026-10-03: [parser genérico](https://docs.defectdojo.com/supported_tools/parsers/file/generic/), [API v2 y background import](https://docs.defectdojo.com/automation/api/api-v2-docs/), [overrides de import](https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/api_v2/serializers.py), [Faraday API](https://docs.faradaysec.com/API-Server/), [hosts](https://raw.githubusercontent.com/infobyte/faraday/master/faraday/server/api/modules/hosts_base.py), [services](https://raw.githubusercontent.com/infobyte/faraday/master/faraday/server/api/modules/services_base.py), [vulns](https://raw.githubusercontent.com/infobyte/faraday/master/faraday/server/api/modules/vulns_base.py), [GMP 22.5](https://docs.greenbone.net/API/GMP/gmp-22.5.html) y [Expat incremental](https://docs.python.org/3/library/pyexpat.html#xmlparser.SetReparseDeferralEnabled).

La compatibilidad se verifica con contratos/fixtures y servidores HTTP/GMP locales falsos. No se han realizado entregas a plataformas reales, escaneos ni consultas a feeds externos. Servidores con esquemas distintos fallan de forma accionable; revisa su API antes de cambiar el adaptador. No se promete cobertura exhaustiva de Faraday/GMP, equivalencia a explotación ni certificación.
