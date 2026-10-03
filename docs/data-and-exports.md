# Contrato de datos y exportaciones

SQLite y los artefactos raw contienen identidades de activos, banners, inventarios,
versiones, evidencia de controles y posibles vulnerabilidades. Protege el directorio
de datos con permisos de usuario/grupo y copias de seguridad cifradas según tu
política. ScopeScan no envía automáticamente los informes a terceros.

Los exports pueden contener secretos que un objetivo devuelve en banners o salidas
raw. Revisa el contenido antes de compartirlo. El export no añade credenciales de
configuración; tampoco promete redactar todas las cadenas arbitrarias del objetivo.
La retención y eliminación de copias entregadas es responsabilidad del operador.
Borrar una fila de escaneo no borra por sí mismo los exports ya compartidos.

## Formatos

JSON (`schema_version: 1`) conserva la evidencia textual original; el CSV es para
hojas de cálculo y prefija con apóstrofo las celdas que comienzan con `=`, `+`, `-`
o `@`, incluso tras espacios, tabuladores y controles Unicode. Esta transformación
se limita al CSV y debe tenerse en cuenta al importarlo de vuelta.

HTML, JSON y CSV de un ZIP se generan desde la misma instantánea de lectura SQLite.
Una evaluación que progresa durante la exportación aparece coherentemente con el
estado capturado; no convierte evidencia parcial en un resultado completo.

El bundle incluye `manifest.json` con fecha UTC, versión disponible de ScopeScan,
perfil/objetivos/estado, estados de enriquecimientos, cobertura y hash SHA-256 de
cada archivo incluido salvo el propio manifiesto. Los hashes sirven para comprobar
integridad, no son una firma autenticada. Versiones de motores/feeds que un escaneo
antiguo no registró aparecen como información ausente, sin valores inventados.

Solo se incluyen artefactos de explotación dentro del raw_dir gestionado. Cada
artefacto está limitado por defecto a 2 MB; si se trunca lleva un marcador explícito.
El hash corresponde a los bytes incluidos. Los errores al leer artefactos se
registran en `artifact_errors`. Los archivos raw no comparten una transacción con
SQLite; un log todavía activo puede cambiar y el manifiesto identifica la copia
incluida, no garantiza que sea el log final.

El panel construye el ZIP en un archivo temporal bajo raw/exports y lo transmite
mediante FileResponse con eliminación después de la respuesta. El export CLI a
archivo escribe directamente; el API heredado `render_bundle()` devuelve bytes y
está destinado a compatibilidad y conjuntos pequeños. El fichero temporal usa los
permisos del usuario del servicio; restringe las ACL del directorio en Windows.
Una terminación abrupta del servidor puede dejar temporales huérfanos: inclúyelos
en la política de limpieza local y nunca publiques raw/exports como estáticos.
