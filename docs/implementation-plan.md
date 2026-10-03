# Implementación del roadmap de ScopeScan

Objetivo autorizado: «implementa todo», referido a `revision-y-roadmap-2026-10-03.md`.
Licencia del código propio elegida por el usuario: MIT.

Este fichero conserva el alcance y las puertas de verificación. Una casilla se cierra con evidencia de código y pruebas, no por existir un stub, una página o un test que solo repita la implementación. Los motores y servidores externos son opcionales: sus adaptadores deben funcionar cuando están configurados, y fallar de forma explícita cuando no están disponibles. No se lanzan escaneos ni acciones contra objetivos reales para verificar el desarrollo.

## A. Consolidación y fiabilidad

- [x] A01 Una raíz de desarrollo/instalación ScopeScan, entorno virtual válido, historial y artefactos preservados con copia de recuperación.
- [x] A02 Clasificación completa de rangos privados/públicos y comprobación concreta por host en MSF.
- [x] A03 Verificación MSF ligada a host, puerto efectivo, protocolo y módulo; UDP no recibe módulos TCP.
- [x] A04 Deduplicación distingue protocolos.
- [x] A05 Inventario APK conserva versión/revisión y expresa truncamiento/datos desconocidos.
- [x] A06 Nmap/MSF cancelables sin stdout, deadlines y limpieza de procesos/pipes ante excepciones; salida acotada.
- [x] A07 Cola limpia futures terminados; borrado coordinado con trabajos activos.
- [x] A08 Host/origen permitidos por configuración independiente; Origin inválido rechazado; auth configurada aplica a loopback; CSRF de navegador y despliegue/proxy/TLS documentados.
- [x] A09 CSV neutraliza fórmulas y JSON conserva evidencia original.
- [x] A10 Claims atómicos de enriquecimientos y límites de concurrencia.
- [x] A11 Cache TTL del entorno con refresco explícito; rutas de datos válidas fuera de checkout.
- [x] A12 Paginación/búsqueda reales, límites visibles, inventarios grandes bajo demanda y booleanos desconocidos correctos.
- [x] A13 Exportación sobre snapshot consistente, reutilización de datos y manifiesto de evidencia; salida de ZIP adecuada para volúmenes grandes.
- [x] A14 MIT, SECURITY.md, política de datos/exportación, dependencias reproducibles/auditadas y CI con permisos mínimos/actions fijadas.

Puerta A: suite/regresiones, lint, self-test e instalación; verificación independiente, revisión de calidad y búsqueda de anti-patrones.

## B. Evaluación continua

- [ ] B01 Identidad estable de activos con alias y observaciones históricas, identificadores de reglas/hallazgos independientes del título.
- [ ] B02 Deltas de hosts/puertos/servicios/hallazgos y cobertura compatible; ausencias no evaluadas no se cierran como resueltas.
- [ ] B03 Estado vigente por activo separado del histórico y contadores sin duplicar reescaneos.
- [ ] B04 Flujo de remediación: responsable, estado, vencimiento, excepción con caducidad y evidencia de cierre; historial de acciones.
- [ ] B05 Riesgo explicable por activo: gravedad/evidencia/exposición, KEV/EPSS y criticidad configurada.
- [ ] B06 Alcances guardados con objetivos, exclusiones, resolución de nombres, perfil y autorización; preview por motor.
- [ ] B07 Reescaneo de verificación dirigido a endpoints/controles afectados, sin resolver por falta de cobertura.
- [ ] B08 Importación Nmap XML y resultados externos con procedencia/cobertura explícita.
- [ ] B09 Panel y CLI para todas estas operaciones; búsqueda, filtros y documentación de uso.

Puerta B: escenarios completos alta→reescaneo→corrección→cierre y cobertura distinta→no evaluado, migración histórica, panel renderizado y contratos CLI/API.

## C. Precisión y motores

- [ ] C01 Contratos ScanScope, EngineAdapter, Observation, Finding y Job con resultados/versiones/procedencia normalizados.
- [ ] C02 Adaptador Nuclei con plantillas revisadas/fijadas, verificación de integridad, planificación por servicio y límites/timeout/cancelación comunes; sin protocolos innecesarios de ejecución local.
- [ ] C03 Evaluación Linux por avisos/paquetes de distribución y versiones completas/backports; integración/importación Vuls documentada y probada.
- [ ] C04 TLS especializado con SNI/hostname/cadena/confianza, adaptador SSLyze y resultados estructurados.
- [ ] C05 Presupuesto NVD compartido entre jobs, deduplicación de solicitudes, backoff/reintentos y caché vencida explícita; CVSS/proveedor y cobertura MSRC explicados.
- [ ] C06 Persistencia de versiones de motores/reglas/templates/feeds y raw junto al resultado normalizado; consolidación de evidencia con límites de attack paths claros.

Puerta C: fixtures oficiales/versionados, procesos de motor simulados con protocolo real, fallos parciales/cancelación/límites/alcance, y documentación de herramientas externas.

## D. Integraciones y ejecución persistente

- [ ] D01 Importar/exportar SBOM CycloneDX/SPDX y adaptar Syft/Grype para imágenes/componentes; conservar purl/distribución/procedencia.
- [ ] D02 Exportación compatible y conector DefectDojo import/reimport, polling/fallos y secretos solo por configuración.
- [ ] D03 Conectores/importaciones opcionales de Faraday y Greenbone (GMP), con verificación de contratos oficiales.
- [ ] D04 Importación de evaluaciones SCAP/ComplianceAsCode preservando control, criterio, resultado, cobertura y versión; sin asumir certificación.
- [ ] D05 Jobs durables SQLite para escaneo e integraciones, claim/ownership/heartbeat, recuperación de worker, cancelación y reintentos controlados.
- [ ] D06 Scheduler persistente: ventanas, alcance/perfil, límites y registro de eventos únicamente ante cambios relevantes/fallo/acción requerida.
- [ ] D07 Separación web/worker para operaciones con identidad o privilegios; acciones remotas no dependen de elevar el proceso web.
- [ ] D08 Panel/CLI de motores, importaciones, destinos, jobs y programación, con errores accionables y estado parcial real.

Puerta D: reinicio con jobs pendientes, reclamación por dos workers, leases/cancelación/borrado, scheduler sin duplicados, importaciones y conectores con servidores HTTP/GMP falsos; verificación integral final.

## Alcance de alternativas del informe

Trivy se presentó como alternativa a Syft/Grype y se mantiene como formato de importación si aporta compatibilidad; no se instala una alternativa redundante automáticamente. Vuls, Faraday, Greenbone y ComplianceAsCode se integran mediante contratos externos/importaciones, no copiando sus plataformas completas. Multiusuario, Redis/Celery, escáneres distribuidos, automatización ofensiva adicional y grafos de ataque completos estaban expresamente pospuestos en el informe y no son requisitos de esta implementación.

## Estado de ejecución

Fase A verificada localmente el 2026-10-03: 278 pruebas pasan, Ruff, self-test, pip check, construcción e instalación aislada de rueda y verificación del sdist. Evidencia y límites en `phase-a-verification.md`. B, C y D siguen pendientes; la matriz remota Linux/Python 3.11 no se ha ejecutado en esta sesión.
