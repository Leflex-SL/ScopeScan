# Motor, alcance y evidencia

`engine_contracts.py` comparte el modelo `models.Finding` existente. `ScanScope` contiene una autorización, namespace e IPs concretas; `Endpoint` conserva dirección, puerto, protocolo y servicio. Un endpoint `port=None, protocol=host` autoriza evaluar paquetes/controles del host, sin inventar un listener SSH. Las resoluciones de hostname son del operador, quedan fijadas a las IPs y se usan para Host/SNI; el reverse DNS de un informe no otorga autorización.

`EngineAdapter` ofrece `available()`, `plan(scope, timeout=...)` y `execute(plan, cancel=...)`. El plan es inmutable y contiene reglas, endpoints, límites y opciones tipadas. `EngineResult` contiene estado complete/partial/failed/cancelled, procedencia versionada, observaciones positive/negative/unknown y raw acotado. Cada observación lleva regla, endpoint, evidencia y fecha con zona horaria. Los adapters opcionales no se instalan ni descargan automáticamente.

`engine_store` valida el grant, identidad, límites y normalización antes de crear filas. Guarda SHA256 de bytes recibidos y saneados, plan/hash, versiones de motor/reglas/templates/feeds, resultado estructurado y lista de errores. El raw JSON/JSONL elimina campos de credenciales/configuración y cabeceras sensibles; un raw opaco se omite y conserva el hash recibido. La evidencia normalizada y los errores eliminan cabeceras de autorización/cookies y valores de password/token/secret/API key. No se pretende reconocer secretos arbitrarios sin marca; el adapter debe entregar evidencia saneada y no recoger credenciales.

Las fechas de observación se conservan en el raw normalizado. El estado continuo de una ejecución local usa la última fecha de sus observaciones; una importación con fechas distintas requiere resultados separados. Una importación antigua no desplaza un positivo más reciente, y ninguna importación desplaza evidencia local protegida. Los positivos importados son candidatos sin confirmación. El feed publicado no sustituye la fecha del inventario.

Resolver exige una observación negativa explícita del mismo endpoint/regla, éxito completo local y versiones compatibles de motor/reglas/templates/feeds. El fingerprint de evidencia incluye trust stores TLS. Cambiar la confianza o los avisos no sirve como prueba compatible de corrección. Omitir resultados, desconocidos, fallos, cancelación o ausencia de CVE en un informe no resuelve. Las observaciones unknown no fabrican un puerto abierto y conservan el estado de red previo.

La identidad por aplicación incluye el hostname/SNI autorizado y el servicio/transport: dos virtual hosts en una IP/puerto mantienen hallazgos distintos. El componente original del plugin se conserva y añade un identificador de condición por endpoint; el negativo debe corresponder a esa misma condición. Los nombres de hostname se comparan en minúsculas. Los alias HTTP/http-alt/www y HTTPS/https-alt/ssl-http de la clasificación de servicio se normalizan dentro de su mismo esquema; HTTP y HTTPS siguen separados. No se compara un hash global de todos los endpoints para cerrar un hallazgo individual.

La redacción reconoce userinfo de URIs de cualquier esquema con autoridad, incluso credenciales codificadas, y conserva host/IPv6/puerto/path. Se aplica a raw JSON/JSONL, evidencia de hallazgos, errores y procedencia; el manifiesto declara los cambios y el hash original del informe Vuls permanece disponible. Los grants de ejecución rechazan credenciales URI: la identidad debe configurarse fuera del plan.

## Uso

```
scopescan engine list
scopescan engine preview nuclei 1 --ports 80 --service http
scopescan engine preview sslyze 1 --ports 443 --service https
scopescan engine run sslyze 1 --ports 443 --service https --yes
scopescan engine import vuls report.json --scope-id 1 --host 192.0.2.10
scopescan engine import linux-advisories feed.json --scope-id 1 --host 192.0.2.10 --inventory-scan-id 15
scopescan engine results --scan-id 16
scopescan engine detail 1
scopescan engine raw 1
```

Sin puertos explícitos, el preview pagina todos los servicios TCP observados del alcance, hasta 65536. Para puertos todavía sin inventario, el operador declara http/https/tls con `--service`; el número de puerto no se usa para adivinar el protocolo. El panel `/engines` ofrece los mismos previews, ejecución, importaciones y evidencia. Un preview web caduca a los 15 minutos, se usa una vez y vuelve a validar autorización/Host/SNI. Los jobs usan la cola común y su cancelación. La persistencia de leases y separación de worker se completa en D.

JSON de exportación incluye la evidencia del motor con hashes y versiones. Las rutas `/api/engines/results` y `/api/engines/results/{id}/raw` permiten consultar el resultado; las tablas muestran vistas acotadas. Las correlaciones de attack paths siguen siendo heurísticas: no prueban explotación ni forman un grafo exhaustivo.

## Verificación local

Las pruebas de contratos/almacenamiento/CLI/panel usan fixtures, DB temporales y adapters falsos sin destinos reales. Incluyen límites, grant de hostname, scope cambiado, importaciones antiguas, raw/normalizado saneado, positivos/cierre exacto, trust stores incompatibles, negativos fallidos/partial/cancelados/importados, estado de red unknown y servicios/activos en la posición 101. La puerta C independiente registra los resultados finales.
