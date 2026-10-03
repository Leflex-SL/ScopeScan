# Software, SBOM y controles

ScopeScan guarda recursos de software por namespace, tipo y nombre o digest explícito. Una imagen o componente no se convierte en una dirección IP. Los documentos y observaciones son históricos; importar un SBOM, una coincidencia Grype o un resultado SCAP no cierra hallazgos de red ni confirma explotación.

## Intercambio y consulta

El panel **Software y controles** permite subir CycloneDX JSON 1.6, SPDX JSON 2.3, Grype JSON y XCCDF/ARF XML, con un máximo de 8 MB. El namespace y recurso son obligatorios. Hay búsqueda, paginación de documentos/componentes/observaciones, historial por recurso, detalle JSON, evidencia saneada y exportación CycloneDX/SPDX. Se mantienen el SHA256 recibido, SHA256 de evidencia saneada, productor, versión, purl, hashes, propiedades, distribución, referencias y relaciones originales. Las URLs con credenciales reconocibles se redactan antes de guardar o exportar.

```powershell
scopescan software import sbom inventory.json --namespace laboratorio --resource image@sha256:... --resource-kind image
scopescan software import scap result.xml --namespace laboratorio --resource servidor --resource-kind host-compliance
scopescan software list --search image --limit 50 --offset 0
scopescan software components 1 --limit 50 --offset 0
scopescan software observations 2
scopescan software detail 1
scopescan software export 1 --format spdx
```

Los exports son documentos canónicos válidos para el formato elegido; conservan información específica del formato de origen en propiedades CycloneDX o sourceInfo/comment SPDX. La fecha de creación del export y la fecha informada por la evidencia son distintas: la segunda se conserva en metadatos y se restaura al reimportar. Una fecha de evidencia desconocida permanece desconocida. Los exports que exceden 8 MB al preservar metadatos devuelven un error y ofrecen la evidencia saneada. No se resuelven enlaces externos.

La identidad estable del componente usa recurso y purl sin la versión observada, conservando sus calificadores de arquitectura/distribución; sin purl usa tipo, nombre y grupo/proveedor. Las distintas referencias del productor conservan ocurrencias separadas. Cambiar la versión observada no cambia la identidad del componente. Los candidatos Grype conservan proveedor/namespace del aviso, coincidencias, CVSS/fix/avisos relacionados y versión instalada.

## Workers y motores opcionales

Los procesos externos se ejecutan mediante trabajos SQLite durables en un worker separado. El panel encola; la CLI `software run` también encola y muestra un job_id. `software preview` muestra el recurso, fuente, autorización y fingerprint antes de encolar. La ejecución revalida el JSON y la evidencia referenciada. No se instala ningún motor al abrir el panel.

Syft soportado: **1.54.0**. Solo se aceptan fuentes explícitas `registry:`, `docker-archive:`, `oci-archive:`, `oci-dir:`, `file:` y `dir:`. Las rutas locales absolutas deben pertenecer a `SCOPESCAN_SOFTWARE_ROOTS` configurado en el worker, separadas por el separador de rutas del sistema. La fuente registry requiere `--allow-registry`, acepta una referencia OCI sin credenciales y autoriza acceso de red a esa imagen. No hay elección implícita Docker/registry.

Grype soportado: **0.119.0**. Solo procesa un documento SBOM gestionado y del mismo recurso. El worker requiere `SCOPESCAN_GRYPE_DB_CACHE_DIR` apuntando a una base actualizada previamente por el operador. Se desactivan actualización de aplicación y descarga de base; se mantienen validación de hash y edad del motor. Base ausente/inválida produce un error. La importación conserva fecha, esquema y estado de la base; edad mayor de cinco días o fecha desconocida produce resultado parcial. El worker calcula SHA256 de la base reportada dentro de la caché configurada y el mismo deadline; una ruta no reportada deja SHA256 desconocido y resultado parcial.

```powershell
scopescan software preview syft --namespace laboratorio --resource imagen --resource-kind image --source oci-archive:C:\trusted\image.tar --authorized-by operador
scopescan software run syft --namespace laboratorio --resource imagen --resource-kind image --source oci-archive:C:\trusted\image.tar --authorized-by operador --yes
scopescan software run grype --document-id 1 --namespace laboratorio --resource imagen --resource-kind image --authorized-by operador --yes
scopescan worker --once
```

Ambos motores usan el ejecutable localizado por el worker y versión verificada, argv sin shell, directorio/home/config temporal privado, entorno mínimo sin PATH, proxies ni credenciales heredadas, límite total de tiempo, cancelación de árbol de procesos y salida hasta 8 MB. No se emplea `--fail-on`; un resultado de coincidencias exitoso no se interpreta como explotación confirmada. Las credenciales para registries privados no se heredan automáticamente; esta primera integración admite fuentes públicas explícitas o archivos locales autorizados.

## XCCDF y ARF

La importación usa defusedxml, prohíbe DTD/entidades y limita profundidad, nodos y reglas. Acepta un TestResult XCCDF 1.1/1.2, contenido en Benchmark o ARF 1.1. Múltiples TestResult o múltiples targets requieren dividir el documento; no se inventa una asociación de IP. Conserva benchmark/versión, perfil, regla, criterio/check, referencias, mensajes, fecha y estado `pass`, `fail`, `error`, `unknown`, `notapplicable`, `notchecked`, `informational` o `fixed`. Error/unknown/notchecked dejan cobertura parcial. La cobertura es **solo las reglas reportadas**; no supone todos los controles ni certificación. ScopeScan importa los resultados de OpenSCAP/ComplianceAsCode; no ejecuta evaluaciones ni descarga contenidos en esta integración.

## Contratos primarios y validación

- [CycloneDX 1.6, esquema oficial](https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json).
- [SPDX 2.3, esquema oficial](https://raw.githubusercontent.com/spdx/spdx-spec/support/2.3/schemas/spdx-schema.json).
- [Syft 1.54.0: fuentes y CLI](https://raw.githubusercontent.com/anchore/syft/v1.54.0/cmd/syft/internal/commands/scan.go), [configuración](https://oss.anchore.com/docs/reference/syft/configuration/).
- [Grype 0.119.0: modelo de resultado](https://raw.githubusercontent.com/anchore/grype/v0.119.0/grype/presenter/models/document.go), [estado real de proveedor](https://raw.githubusercontent.com/anchore/grype/v0.119.0/grype/vulnerability/provider.go), [configuración](https://oss.anchore.com/docs/reference/grype/configuration/).
- [OpenSCAP](https://www.open-scap.org/tools/openscap-base/) y [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content).

Los cuatro caminos CycloneDX→CycloneDX, CycloneDX→SPDX, SPDX→CycloneDX y SPDX→SPDX se validaron contra los esquemas oficiales completos con jsonschema **4.25.1** instalado solo en una carpeta temporal ignorada; ninguna dependencia del proyecto cambió. SHA256 del esquema CycloneDX: `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d`; SPDX: `ca7fd7cc2c8107c3b6b5976058bb72363e8c072f0e446609d4fe7234860c2894`. Las referencias auxiliares CycloneDX SPDX/JSF fueron descargadas exclusivamente de su repositorio oficial, sin resolución arbitraria de red. La suite focal usa procesos Python falsos para demostrar argv, entorno privado, ausencia de updates, cancelación y límites; no se ejecutaron Syft/Grype reales, evaluaciones SCAP ni escaneos de objetivos.
