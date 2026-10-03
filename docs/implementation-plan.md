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

- [x] B01 Identidad estable de activos con alias y observaciones históricas, identificadores de reglas/hallazgos independientes del título.
- [x] B02 Deltas de hosts/puertos/servicios/hallazgos y cobertura compatible; ausencias no evaluadas no se cierran como resueltas.
- [x] B03 Estado vigente por activo separado del histórico y contadores sin duplicar reescaneos.
- [x] B04 Flujo de remediación: responsable, estado, vencimiento, excepción con caducidad y evidencia de cierre; historial de acciones.
- [x] B05 Riesgo explicable por activo: gravedad/evidencia/exposición, KEV/EPSS y criticidad configurada.
- [x] B06 Alcances guardados con objetivos, exclusiones, resolución de nombres, perfil y autorización; preview por motor.
- [x] B07 Reescaneo de verificación dirigido a endpoints/controles afectados, sin resolver por falta de cobertura.
- [x] B08 Importación Nmap XML y resultados externos con procedencia/cobertura explícita.
- [x] B09 Panel y CLI para todas estas operaciones; búsqueda, filtros y documentación de uso.

Puerta B: escenarios completos alta→reescaneo→corrección→cierre y cobertura distinta→no evaluado, migración histórica, panel renderizado y contratos CLI/API.

## C. Precisión y motores

- [x] C01 Contratos ScanScope, EngineAdapter, Observation, Finding y Job con resultados/versiones/procedencia normalizados.
- [x] C02 Adaptador Nuclei con plantillas revisadas/fijadas, verificación de integridad, planificación por servicio y límites/timeout/cancelación comunes; sin protocolos innecesarios de ejecución local.
- [x] C03 Evaluación Linux por avisos/paquetes de distribución y versiones completas/backports; integración/importación Vuls documentada y probada.
- [x] C04 TLS especializado con SNI/hostname/cadena/confianza, adaptador SSLyze y resultados estructurados.
- [x] C05 Presupuesto NVD compartido entre jobs, deduplicación de solicitudes, backoff/reintentos y caché vencida explícita; CVSS/proveedor y cobertura MSRC explicados.
- [x] C06 Persistencia de versiones de motores/reglas/templates/feeds y raw junto al resultado normalizado; consolidación de evidencia con límites de attack paths claros.

Puerta C: fixtures oficiales/versionados, procesos de motor simulados con protocolo real, fallos parciales/cancelación/límites/alcance, y documentación de herramientas externas.

## D. Integraciones y ejecución persistente

- [x] D01 Importar/exportar SBOM CycloneDX/SPDX y adaptar Syft/Grype para imágenes/componentes; conservar purl/distribución/procedencia.
- [x] D02 Exportación compatible y conector DefectDojo import/reimport, polling/fallos y secretos solo por configuración.
- [x] D03 Conectores/importaciones opcionales de Faraday y Greenbone (GMP), con verificación de contratos oficiales.
- [x] D04 Importación de evaluaciones SCAP/ComplianceAsCode preservando control, criterio, resultado, cobertura y versión; sin asumir certificación.
- [x] D05 Jobs durables SQLite para escaneo e integraciones, claim/ownership/heartbeat, recuperación de worker, cancelación y reintentos controlados.
- [x] D06 Scheduler persistente: ventanas, alcance/perfil, límites y registro de eventos únicamente ante cambios relevantes/fallo/acción requerida.
- [x] D07 Separación web/worker para operaciones con identidad o privilegios; acciones remotas no dependen de elevar el proceso web.
- [x] D08 Panel/CLI de motores, importaciones, destinos, jobs y programación, con errores accionables y estado parcial real.

Puerta D: reinicio con jobs pendientes, reclamación por dos workers, leases/cancelación/borrado, scheduler sin duplicados, importaciones y conectores con servidores HTTP/GMP falsos; verificación integral final.

## Alcance de alternativas del informe

Trivy se presentó como alternativa a Syft/Grype y se mantiene como formato de importación si aporta compatibilidad; no se instala una alternativa redundante automáticamente. Vuls, Faraday, Greenbone y ComplianceAsCode se integran mediante contratos externos/importaciones, no copiando sus plataformas completas. Multiusuario, Redis/Celery, escáneres distribuidos, automatización ofensiva adicional y grafos de ataque completos estaban expresamente pospuestos en el informe y no son requisitos de esta implementación.

## Estado de ejecución

Fase A verificada localmente el 2026-10-03: 278 pruebas pasan, Ruff, self-test, pip check, construcción e instalación aislada de rueda y verificación del sdist. Evidencia y límites en `phase-a-verification.md`.

Fase B completada y aceptada el 2026-10-03: 439 pruebas pasan, Ruff, self-test, pip check, build e instalación aislada final; el sdist recoge 439 pruebas y supera 10 casos de distribución. Verificación independiente, revisión fresca y escenarios de ciclo de remediación/cobertura registrados en `phase-b-verification.md`.

Fase C completada y aceptada: 610 pruebas integrales pasan tras las reparaciones finales, Ruff, pip check y seis comprobaciones de self-test en instalación aislada. La rueda conserva exactamente 63 archivos Python/HTML/CSS/YAML; el sdist recoge 610 pruebas y supera 14 casos de distribución. Contratos reales simulados, migración desde B, dos procesos compartiendo presupuesto NVD, cobertura Host/SNI y revisiones independientes registrados en `phase-c-verification.md`.

Fase D completada y aceptada: 743 pruebas integrales finales pasan en 622,54 s, Ruff, pip check y seis comprobaciones de self-test. Rueda/sdist conservan exactamente 91 archivos Python/HTML/CSS/YAML; el sdist contiene los 37 archivos Python de tests, recoge 743 casos y supera una selección de 48. Instalación aislada, CLI/UI, migración desde C, dos procesos con presupuesto SQLite y scheduler, grants por colector y revisiones independientes registrados en `phase-d-verification.md`. A/B/C/D quedan completadas en el alcance autorizado. La verificación local usa Windows/Python 3.13.5; la matriz remota Linux/Python 3.11 sigue sin ejecutarse en esta sesión.
