# Fase C: revisión independiente de patrones problemáticos

Revisión realizada el 2026-10-03 sobre las fuentes finales de C01–C06. Esta puerta
comprueba límites e integridad de evidencia; la suite global y el empaquetado tienen
su informe separado. No modifica el checklist ni autoriza un commit.

## 🐛 BUGS

No quedan bloqueos en las rutas examinadas. Se reprodujeron inicialmente cuatro
defectos de comportamiento y se comprobaron sus reparaciones mediante procesos
Python nuevos, fixtures y bases SQLite temporales:

1. **Identidad Host/SNI.** Un positivo para `a.example.test` seguido de un negativo
   para `b.example.test`, con la misma IP/puerto/regla, resolvía el primer hallazgo.
   Ahora permanecen separados. Dos positivos tienen IDs diferentes; el negativo
   de B resuelve únicamente B y el negativo posterior de A resuelve A. La cobertura
   basal del positivo conserva su condición exacta. Cambiar HTTPS por HTTP no
   permite cerrar; mayúsculas DNS y `https-alt` equivalen a la identidad canónica.
2. **Contador de hosts.** Un resultado SSLyze parcial con todas sus observaciones
   desconocidas contaba un host activo. La reproducción final registra `hosts_up=0`,
   `hosts_total=1`, estado `unknown` y cero puertos inventados.
3. **Último Retry-After.** Tres respuestas HTTP 429 simuladas con pausas `0, 0, 3600`
   ignoraban la última pausa. La reproducción final falla la consulta y conserva
   en SQLite una pausa compartida de al menos 3600 segundos.
4. **Respuesta NVD incompleta.** `{"vulnerabilities":[]}` sin `totalResults` generaba
   una caché vacía reciente. Ahora produce error y no crea caché. Con una entrada
   vencida conserva su CVE y fecha originales, marcando `feed_stale` y el error.

## 🔒 SEGURIDAD

Se reprodujo y reparó una fuga de credenciales en URLs de repositorios Vuls. Una
URL con usuario y contraseña ficticios ahora conserva host/ruta y elimina userinfo
antes de devolver el resultado del adaptador y antes de persistirlo. No aparece el
sentinela en raw, observaciones, hallazgos ni exportaciones JSON/CSV. El SHA-256 del
payload original permanece correcto; hay manifiesto de redacción y el original
no se modifica. También se comprobó redacción recursiva de claves JSON y de URLs
anidadas que emplean `%40`.

El barrido de Nuclei/SSLyze no encontró carga arbitraria de plantillas, workflows,
protocolos de ejecución local, shell/eval, configuración externa implícita,
proxies o credenciales cloud heredados, ni actualizaciones automáticas. Las
plantillas propias se verifican por bytes/hash y se ejecutan desde copias privadas.
Los destinos son IP fijadas; Host/SNI procede de resoluciones autorizadas.

## ⚡ RENDIMIENTO

Un deadline monotónico cubre todos los procesos del job. El runner vigila salida y
archivos silenciosos; NVD limita las respuestas HTTP. La enumeración de activos y
puertos recorre páginas completas y rechaza planes excesivos, sin limitar el plan
a los primeros 100 activos. La cuota NVD y la propiedad de refrescos viven en
SQLite; fechas de caché vencida no se actualizan cuando falla el refresco.

## 🔧 MEJORAS

No se requieren cambios adicionales para esta puerta. Las importaciones mantienen
fechas y procedencia; los negativos incompletos/importados o con versiones de
evidencia incompatibles no permiten resolver hallazgos locales. Versiones Debian
y RPM conservan epoch/revisión; formatos no soportados quedan desconocidos.
La configuración de empaquetado incluye YAML de plantillas y fuerza LF; la prueba
de bytes en wheel/sdist pertenece a la verificación de empaquetado independiente.

## 📋 RESUMEN

- **Severidad global final:** 🟢 Bajo; sin bloqueos pendientes en este barrido.
- **Prioridades verificadas:** identidad por contexto de aplicación, redacción de
  credenciales y preservación conservadora de cobertura/caché ante errores.
- **Evidencia:** barrido `rg` y lectura de flujos; dos invocaciones independientes
  de `.venv/Scripts/python.exe -` con assertions sobre los cinco defectos y sus
  variantes. La primera comprobó contadores/credenciales/SNI; la segunda comprobó
  baseline/esquema/canonicalización y NVD. No se ejecutaron escáneres, consultas
  HTTP reales ni escrituras en servicios externos o datos de producción.
