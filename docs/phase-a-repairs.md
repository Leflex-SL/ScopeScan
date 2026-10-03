# Reparaciones de la verificación independiente

La autenticación Basic configurada devuelve 401 con challenge cuando faltan
credenciales o son incorrectas; una conexión remota sin autenticación configurada
sigue rechazándose con 403. Usuario y contraseña se comparan como UTF-8 sin
cortocircuito. Los tokens CSRF exigen la forma ASCII/hex generada por el servidor;
valores Unicode o malformados producen 403, sin excepciones del servidor.

La cobertura Linux aparece en detalle, informe y página de paquetes: lectura,
total, recorte, entradas sin interpretar y completitud. Inventarios anteriores
sin metadatos muestran «sin dato», sin acreditar cobertura completa.
El reboot marker se interpreta en Ubuntu/Debian: presente indica reinicio;
ausente solo indica «no» si está instalado el notifier conocido. En RPM/Alpine
y sistemas sin mecanismo reconocido queda desconocido. La existencia del
notifier está documentada por [Ubuntu](https://packages.ubuntu.com/jammy/all/update-notifier-common/filelist).
El script viaja como bytes UTF-8 para evitar introducir CRLF al enviarlo desde
Windows a un shell POSIX. Las pruebas ejecutan el bloque real contra rutas aisladas.

Claims y borrado usan transacciones SQLite de escritura. El claim ya cuenta como
trabajo activo antes del BackgroundTask: el borrado lo rechaza, aunque aún no haya
Future. Si el borrado se marca primero, `deletion_pending` impide nuevos claims.
Los callbacks tardíos no recrean jobs y un motor no arranca para un scan borrado.
El scan también reclama su inicio de forma condicional antes de preparar el motor.

MSF conserva resultados parciales como evidencia; un proceso fallido, cancelado,
con deadline agotado o salida truncada produce ERROR, nunca una confirmación de
sesión. El estado del job conserva failed/cancelled/partial y explica la causa.
Un fallo de explotación no sobrescribe las verificaciones anteriores.

La navegación de dashboard y hallazgos se genera en el contenido, fuera del
`title`; las pruebas inspeccionan anchors y siguen la URL real hacia la página 2.
