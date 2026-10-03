# Evaluación continua

ScopeScan mantiene el informe de cada ejecución y una vista vigente separada por activo.
Un alcance guardado proporciona el namespace de identidad; los informes históricos sin
alcance se migran con un namespace por escaneo. Un hostname o una MAC compartidos no
fusionan activos. Una dirección privada en dos alcances representa dos activos distintos.
Los alias de dirección requieren una decisión explícita y quedan auditados. Cambiar IP
conserva el activo cuando se registra un alias, pero crea un endpoint y hallazgo nuevos:
no se presupone que dos direcciones publiquen el mismo servicio.

La identidad de hallazgo usa activo, dirección concreta, protocolo/puerto, fuente,
identificador lógico de regla y componente; el título, CVSS y versión observada no forman
parte de la clave. Los scripts NSE que presentan varias CVE mantienen un resultado lógico
por script: cambiar su lista de referencias no inventa otro control.

Los deltas distinguen alta, persistencia, servicio cambiado, endpoint cerrado y ausencia
no evaluada. Un puerto cerrado requiere evidencia explícita de ese puerto. Los contadores
agrupados de Nmap no atribuyen por sí mismos cierre a endpoints concretos. Puertos fuera
del reescaneo dirigido conservan su última observación con evaluación `not_assessed`.
Un hallazgo solo pasa a `resolved` con ejecución terminada correctamente, cobertura
completa del endpoint/control y versiones de motor/reglas compatibles. Un cambio de perfil,
datos desconocidos, timeout, filtro de red, ausencia de versión o script no ejecutado
no demuestra corrección. La cobertura de referencia es la última observación positiva
del hallazgo, no la de un escaneo posterior que haya omitido su control.

Para NSE se exige una salida negativa reconocida por una comprobación propia; texto
genérico sin hallazgos no sirve. Los controles autenticados requieren predicados observados
con resultado positivo y evidencia del inventario. Cerrar un puerto elimina exposición
de servicio; no demuestra instalar un parche ni corregir un control dentro del equipo.
Las importaciones conservan procedencia y fecha del origen. Un informe antiguo nunca
sustituye estado más reciente y un claim externo no degrada comprobaciones locales.
Una comprobación local compatible puede verificar un claim importado.

Remediación ofrece responsable, `open`/`in_progress`/`exception`/`closed`, fecha objetivo,
caducidad y evidencia. La excepción necesita motivo y fecha futura; su caducidad se muestra
explícitamente y no reduce el riesgo. El cierre manual exige evidencia significativa y un
escaneo de verificación dirigido a ese identificador que haya probado `resolved`.
Cada modificación registra antes/después, actor, fecha y evidencia en historial inmutable.

Riesgo `local-v1` expone factores por hallazgo: gravedad, evidencia (candidata 0,35;
exposición 0,7; comprobación 1), clasificación pública de la dirección, KEV/EPSS y criticidad
configurada 1–5. La clasificación IP no prueba alcance desde Internet. KEV y EPSS ausentes
se muestran desconocidos con disponibilidad/fechas del feed, no como evidencia negativa.
La fórmula queda visible y los candidatos siguen sin confirmar; el riesgo no es CVSS ni
una probabilidad de explotación. Los datos no evaluados conservan su última evidencia.

Observaciones de red y enriquecimientos conservan historias separadas: consultar NVD o
recoger inventario no sustituye cobertura, timestamp ni delta de la ejecución Nmap original.
Al borrar un informe se elimina su evidencia histórica; la vista vigente se reconstruye
con observaciones supervivientes o queda `evidence_unavailable`, excluida de contadores y
riesgo. Los registros de remediación y decisiones de alias/criticidad se conservan como
auditoría y pueden incluir la evidencia y estado previos al borrado del informe.

Las listas de activos devuelven resúmenes sin evidencia de hallazgos ni snapshots históricos.
El detalle limita sus factores y endpoints a 100 y publica sus totales y enlaces paginados
(`risk-factors`, `ports` y `current-findings`); el score usa todos los hallazgos pendientes.
La historia se consulta por páginas, con evidencia completa únicamente cuando se solicita
una observación concreta. Cada factor clasifica la dirección de su propio endpoint; otro
alias del activo no modifica su contribución. Al borrar evidencia, se restaura la cobertura
exacta de la observación positiva superviviente, o cobertura desconocida si falta.
