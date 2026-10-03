# Trabajos persistentes y workers

El panel guarda encargos SQLite y responde antes de ejecutarlos. Arranca `scopescan worker` en otro proceso con la identidad Windows/OpenSSH necesaria. El worker comparte la misma configuración `SCOPESCAN_DATA`; el proceso web no necesita privilegios ni credenciales remotas. `scopescan worker --once` ejecuta un trabajo disponible y `--job-id ID --once` selecciona uno concreto. La CLI de escaneo, verificación, motores y enriquecimientos también guarda primero el trabajo y después lo ejecuta mediante este mismo worker.

`scopescan jobs list`, `jobs show ID`, `jobs cancel ID` y `jobs retry ID` muestran y controlan los encargos. El panel `/jobs` incluye detalle, errores, reintentos y programación. Un encargo retenido mientras se completa su plan indica «Awaiting finalized scan plan submission»: no puede ser reclamado hasta la entrega final. Si la preparación se interrumpe, bórralo y vuelve a revisar/encolar el alcance. Los resultados importados no reservan trabajos ejecutables.

Los claims usan `BEGIN IMMEDIATE`, propietario aleatorio y lease de 30 segundos renovada cada 10 segundos. El límite de concurrencia se cuenta en SQLite entre procesos, incluyendo escaneos y enriquecimientos. Una pérdida de lease, cancelación persistente o borrado bloquea cada transacción de escritura del handler; el runner detiene el árbol de procesos. Un propietario antiguo no puede finalizar ni guardar nuevos resultados. El borrado pendiente se completa al terminar el propietario o al recuperar su lease vencida.

Los encargos de lectura pueden volver a la cola tras una lease vencida, con un máximo de intentos. Una operación de escritura externa incierta se marca fallida para revisión; no se repite automáticamente. `jobs retry ID --acknowledge-uncertain` exige haber reconciliado sus efectos y mantiene las restricciones adicionales del conector. Los checkpoints del destino, no la bandera del reintento, determinan si una entrega se puede continuar. Los escaneos que ya guardaron un estado terminal no se ejecutan de nuevo por una caída entre el guardado y la finalización del job.

La migración conserva los escaneos e históricos existentes: una orden antigua en cola con objetivos fijados o plan de motor se captura; operaciones antiguas ya en ejecución o sin parámetros reconstruibles reciben un error de revisión. Reiniciar el panel conserva leases y workers vivos. Las escrituras posteriores a una cancelación se rechazan, por lo que no generan evidencia negativa ni cierres nuevos. Repetir el mismo estado terminal tampoco crea observaciones de inventario nuevas.

SSH usa un comando de colector fijo, citado y con LF; WinRM usa el script PowerShell fijo codificado. Ambos usan el runner común, cancelación durante procesos silenciosos, plazo máximo de 180/120 segundos y ocho millones de caracteres de salida. La verificación autenticada web puede planificarse sin identidad local: el worker vuelve a validar la identidad y el listener SSH al ejecutarla. Los procesos heredan sólo variables del sistema y las necesarias para el agente OpenSSH; no heredan secretos del panel.

Los enriquecimientos que contactan objetivos (SSH, WinRM y Metasploit) también guardan un grant exacto dentro de la transacción de encolado: autorización vigente, perfil, IPs fijadas, exclusiones, resoluciones, límite de hosts y selección de endpoints/módulos. El worker lo vuelve a comprobar antes de ejecutar y antes de cada destino o grupo de módulos. Un alcance eliminado, revocado o modificado exige revisar y encolar otra vez; un inventario histórico no sustituye esa autorización. Los encargos adhoc conservan su selección IP/CIDR/rango original y no resuelven nombres otra vez ni amplían el encargo a nuevos hosts del histórico. El inventario local explícito se limita a un host loopback de la propia máquina; NVD, MSRC y ExploitDB pueden evaluar evidencia histórica aunque su alcance se haya retirado, porque no contactan con aquellos objetivos.

## Programación UTC

Crear una programación es una acción explícita sobre un alcance guardado autorizado; no se crean programaciones automáticamente. Por ejemplo:

```text
scopescan schedule create 1 --name "Revisión semanal" --starts-at 2026-10-04T03:00:00+00:00 --interval 604800 --window-start 03:00 --window-end 05:00
scopescan schedule list
scopescan schedule events
scopescan schedule disable 1
```

El worker continuo evalúa la programación; `schedule tick` también materializa los slots disponibles. Inicio, fin y ventanas son UTC explícito; una ventana con horas iguales cubre el día entero. Sólo se materializa el slot vigente, sin ráfagas para recuperar todos los periodos perdidos. La clave única `(schedule_id, slot)` y la creación de scan/job en una transacción impiden duplicados entre procesos. El límite por programación incluye trabajos en cola y activos. La ejecución programada usa el perfil fijado con capacidades sin privilegios capturadas; no eleva la web.

Se conserva un snapshot de IPs fijadas, resolución, exclusiones, perfil, autorización y límite de hosts. Un cambio de alcance desactiva la programación y genera una acción requerida; el worker vuelve a comprobar snapshot, ventana y vigencia antes de empezar. Debe crearse una programación nueva para aceptar ese cambio. Desactivar una programación evita nuevas ejecuciones; para detener una ya activa cancela su job.

Los eventos registran cambios en hosts/endpoints/servicios y hallazgos, fallos, resultados parciales o cancelaciones. Las fechas de ejecución no forman parte de la comparación, y un éxito con la misma evidencia no genera otro evento. No se han creado programaciones ni ejecutado escaneos reales al desarrollar o verificar esta función.
