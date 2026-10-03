# Evaluacion continua: panel y CLI

**Escaneos / Hallazgos** muestran observaciones historicas; **Activos / Vigentes**
muestran identidades estables y la evaluacion mas reciente. Los contadores vigentes
excluyen cierres y hallazgos resueltos sin multiplicarlos por cada reescaneo.
Las [reglas de identidad, cobertura y riesgo](continuous-model.md) describen el modelo.

## Un alcance repetible

En **Alcances**, guarda nombre, objetivos, exclusiones, perfil, limite de hosts y
responsable de autorizacion. Los nombres se resuelven al guardar; las IP quedan
fijadas para la ejecucion. Editar y guardar vuelve a resolver. El preview usa las
IP guardadas y muestra comando, recuento y avisos. La confirmacion del panel vence
a los 15 minutos y se rechaza si el alcance cambia. Las observaciones anteriores
conservan sus objetivos y cobertura originales. La lista permite buscar y paginar.

```console
scopescan scope create --name laboratorio --targets 192.0.2.10 192.0.2.11 --exclusions 192.0.2.11 --profile rapido --authorized-by Operaciones
scopescan scope list --search laboratorio --limit 50 --offset 0
scopescan scope show 1
scopescan scope preview 1
scopescan scope run 1 --yes
scopescan scope update 1 --name laboratorio --targets 192.0.2.10 --profile completo --authorized-by Operaciones
```

`scope run` y `verify --run` ejecutan trabajo real y esperan el resultado. Un fallo
o plan parcialmente ejecutable devuelve codigo 1; falta de `--yes` o entrada
invalida devuelve 2. `preview` no ejecuta motores. Los comandos nuevos producen JSON.

## Activos, cobertura y riesgo

**Activos** busca direcciones y alias, y filtra por ID de alcance. El detalle muestra
criticidad de 1 a 5, alias IP explicitos, endpoints vigentes, historial paginado y
riesgo con contribuciones de gravedad, evidencia, exposicion, KEV/EPSS y criticidad.
El riesgo es una prioridad local. Una IP publica no acredita accesibilidad desde
Internet; feeds ausentes son desconocidos y los candidatos siguen sin confirmar.
Una IP que ya pertenece a otro activo no se fusiona automaticamente.

```console
scopescan assets --search 192.0.2 --scope-id 1 --limit 50 --offset 0
scopescan asset ID_ACTIVO --criticality 5 --alias 192.0.2.12 --actor Operaciones
scopescan asset-history ID_ACTIVO --limit 25 --offset 25
scopescan current-findings --asset-id ID_ACTIVO --status in_progress --min-severity 2 --assessment exposure --lifecycle observed --search telnet
scopescan historical-findings --search telnet --min-severity 2 --limit 50 --offset 0
scopescan list --search laboratorio --offset 0
scopescan delta ID_ESCANEO
```

**Cambios y cobertura** en el detalle del escaneo muestra hosts, puertos, servicios
y hallazgos nuevos, persistentes, resueltos o no evaluados. Ausencia de host, otro
protocolo, cobertura parcial o control omitido no acreditan correccion. Los informes
antiguos se conservan sin sustituir observaciones mas recientes. Las exportaciones
JSON e informes incluyen procedencia y deltas del mismo snapshot.

## Remediar y verificar

En **Vigentes**, abre el hallazgo y registra responsable, estado, vencimiento o
excepcion con caducidad y motivo. El historial muestra autor, fecha y cambios.
`open`, `in_progress`, `exception` y `closed` son estados operativos; `observed`,
`resolved` y `not_assessed` describen la evaluacion tecnica por separado.
Las fechas deben incluir zona horaria, por ejemplo `2026-10-20T12:00:00Z`.

```console
scopescan remediate ID_HALLAZGO --owner Operaciones --status in_progress --due-at 2026-10-20T12:00:00Z
scopescan remediate ID_HALLAZGO --status exception --exception-until 2026-11-01T00:00:00Z --evidence "Excepcion aprobada hasta completar la migracion"
scopescan verify ID_HALLAZGO --authorized-by Operaciones
scopescan verify ID_HALLAZGO --authorized-by Operaciones --run --yes
scopescan remediate ID_HALLAZGO --status closed --verification-scan-id ID_VERIFICACION --evidence "Correccion observada por el control dirigido y evidencia adjunta"
scopescan remediate ID_HALLAZGO --history
```

**Verificar** prepara un plan de endpoints y controles afectados. Nmap ejecuta
puertos y comprobaciones propias permitidas; los identificadores importados no
son instrucciones ejecutables. Un control sin motor o identidad aparece con su
motivo y queda sin evaluar. Los controles autenticados usan la identidad del worker:
`SCOPESCAN_VERIFY_LINUX_IDENTITY=1` habilita OpenSSH con agente/claves (usuario/puerto
opcionales: `SCOPESCAN_VERIFY_SSH_USER` / `SCOPESCAN_VERIFY_SSH_PORT`);
`SCOPESCAN_VERIFY_WINDOWS_IDENTITY=1` habilita el contexto WinRM configurado.
El cierre requiere verificacion local dirigida, completada con cobertura compatible
y evidencia significativa. Una importacion o ausencia parcial no acreditan cierre.
Borrar un informe elimina su evidencia asociada; el historial inmutable de acciones
de remediacion se conserva y la evidencia vigente perdida queda indicada.

## Importar observaciones externas

**Importar** acepta Nmap XML o JSON `scopescan.external.v1`. El navegador envia el
fichero directamente con el token CSRF; limite 8 MB. La CLI admite 32 MiB. Los
originales se conservan con hash, motor/version, fecha y cobertura. Las afirmaciones
externas se tratan como candidatas aunque el proveedor diga que las verifico.

```console
scopescan import nmap observacion.xml --namespace laboratorio --authorized-by Operaciones
scopescan import external resultado.json --namespace laboratorio
```

Reutiliza un namespace para comparar el mismo entorno. Vacio aisla cada importacion;
los imports no pertenecen automaticamente a un alcance guardado. Las identidades
historicas sin alcance siguen aisladas: se evita mezclar entornos con las mismas IP.

Ejemplo minimo de resultado externo:

```json
{
  "schema": "scopescan.external.v1", "engine": "evaluador", "engine_version": "1.0",
  "rules_version": "2026-10", "observed_at": "2026-10-03T10:00:00Z",
  "coverage": {"status": "partial", "protocols": {"tcp": [23]}, "rules": ["telnet"]},
  "hosts": [{"address": "192.0.2.10", "state": "up", "ports": [
    {"port": 23, "protocol": "tcp", "state": "open", "service": {"name": "telnet"}}
  ]}],
  "findings": [{"host": "192.0.2.10", "port": 23, "protocol": "tcp",
    "rule_id": "telnet", "title": "Telnet expuesto", "severity": "high",
    "evidence": "Banner observado"}]
}
```

La API de consulta expone `/api/assets`, `/api/current-findings` y
`/api/scans/{id}/delta`, con busqueda/filtros y limites de pagina. Los uploads van a
`POST /api/imports/nmap` o `/api/imports/external` con cuerpo raw y parametros
`name`, `namespace`, `authorized_by`. Basic Auth, Host/Origin y CSRF siguen aplicando:
navegadores requieren cookie firmada y `X-CSRF-Token`; clientes sin contexto de
navegador mantienen el contrato stateless. Las respuestas de error explican el
formato invalido, falta de evidencia, limite o comprobacion que requiere configuracion.

El panel acota las vistas previas de evidencia y las tablas grandes con limites
visibles. El detalle completo del activo se obtiene bajo demanda en
`/api/assets/{id}`; `/api/assets/{id}/observations?offset=N` devuelve una observacion
completa. El riesgo usa todos los factores aunque se muestren los primeros 100;
los deltas mantienen todos los cambios aunque cada tabla muestre 200.
