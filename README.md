# ScopeScan

Repositorio: [Olmen023/ScopeScan](https://github.com/Olmen023/ScopeScan).

Escáner de puertos y vulnerabilidades al estilo Nessus, construido sobre nmap.
Escanea los 65535 puertos de un objetivo, detecta servicio y versión, ejecuta los
scripts NSE de la categoría `vuln`, clasifica los hallazgos por severidad y lo
presenta todo en un panel web con informe exportable.

```
   objetivo  ->  nmap (-p- -sV --script vuln)  ->  XML  ->  análisis  ->  SQLite  ->  panel + informe
```

## Qué hace, exactamente

| Fase | Quién la hace | Resultado |
|---|---|---|
| Validación del objetivo | `targets.py` | IP, CIDR, rango o host; recuento de hosts; aviso si es público |
| Escaneo | `nmap` como subproceso | XML con puertos, servicios, versiones y salida NSE |
| Interpretación | `analysis.py` + `rules.py` | Exposiciones, indicios por versión y comprobaciones NSE |
| Enriquecimiento opcional | `nvd.py` | CVE candidatas por CPE, separadas de los hallazgos |
| Priorización de CVE | `threat_intel.py` | CISA KEV y probabilidad EPSS, con caché local |
| Parches Windows | `msrc.py` | Producto y build acumulativo frente al CVRF oficial de Microsoft |
| Inventario autenticado | `windows_inventory.py` | Windows, KB, software, BIOS, Intel ME y configuración SMB/RDP |
| Inventario Linux | `linux_inventory.py` | Distribución, kernel, paquetes y configuración efectiva por OpenSSH |
| Controles locales | `authenticated_checks.py` + `compliance.py` | Hallazgos y estados cumple/falla/sin datos |
| Persistencia | `db.py` (SQLite) | Histórico consultable de escaneos, hosts, puertos y hallazgos |
| Presentación | `web/` + `report.py` | Panel en vivo e informe HTML autocontenido |

La diferencia con lanzar `nmap` a mano está en la tercera fila. nmap dice *"el
script `smb-vuln-ms17-010` devolvió este texto"*; ScopeScan decide si eso es un
hallazgo, con qué severidad, qué CVE lleva asociado y qué hay que hacer al
respecto — que es el trabajo que en Nessus hace un plugin.

## Instalación

Para actualizar una instalacion anterior, desinstala el paquete antiguo con
`python -m pip uninstall medscan` y vuelve a instalar el proyecto. El comando
es ahora `scopescan` y el paquete Python es `scopescan`. Las variables
`SCOPESCAN_*` tienen prioridad sobre los alias anteriores `MEDSCAN_*`.
Las credenciales del panel se leen juntas del mismo prefijo.
Desde el checkout, el historial se guarda en `data/scopescan.sqlite3`. Una
instalación fuera del checkout sin datos previos usa `%LOCALAPPDATA%/ScopeScan`
en Windows o `$XDG_DATA_HOME/scopescan` en Unix (por defecto
`~/.local/share/scopescan`). `SCOPESCAN_DATA` permite elegir el directorio;
`MEDSCAN_DATA` sigue siendo compatible. Si solo existe `medscan.sqlite3` en ese
directorio, se reutiliza para conservar los escaneos.
Los informes ya exportados y las copias de seguridad conservan su contenido original.

ScopeScan necesita **nmap instalado en el sistema**. En Windows:

```bash
winget install -e --id Insecure.Nmap
```

Se recomienda Nmap 7.94 o posterior para no depender de firmas y scripts NSE
obsoletos. `scopescan doctor` avisa cuando detecta una versión anterior.

El instalador incluye Npcap, necesario para el SYN scan y la detección de sistema
operativo. Después, reinicia la terminal para que `nmap` entre en el PATH.

Luego el proyecto:

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
.venv\Scripts\python.exe -m pip check
```

Los locks fijan las dependencias verificadas. Para instalar una rueda y actualizar
los locks, consulta [Dependencias y CI](docs/dependencies-and-ci.md).

Comprueba que todo está en su sitio:

```bash
.venv\Scripts\scopescan.exe doctor
.venv\Scripts\scopescan.exe self-test
```

## Uso

### Panel web

```bash
.venv\Scripts\scopescan.exe serve
```

Abre <http://127.0.0.1:8000>. Desde ahí se lanzan escaneos, se sigue el progreso
en vivo (nmap reporta el porcentaje cada 5 segundos), se filtran los hallazgos
por severidad y se exporta el informe HTML, JSON completo o CSV de hallazgos.
El launcher `serve` solo escucha en loopback. Si configuras usuario y contraseña
del panel, Basic Auth se exige también a los clientes locales. Las escrituras de
navegador requieren CSRF; Host y los orígenes admitidos se validan con listas
independientes. Consulta [Seguridad del panel](docs/panel-security.md) para
configurar autenticación, puertos, proxy y TLS.

### Línea de comandos

```bash
scopescan scan 192.168.1.10                          # perfil de vulnerabilidades, por defecto
scopescan scan 192.168.1.0/24 -p descubrimiento      # solo qué hosts están vivos
scopescan scan 10.0.0.5 -p completo -r informe.html  # 65535 puertos + informe
scopescan list                                       # histórico
scopescan show 3                                     # resultado de un escaneo
scopescan self-test                                  # chequeo local sin nmap ni red
scopescan report 3 -o auditoria.html                 # informe de uno ya hecho
scopescan export 3 -f json -o auditoria.json         # datos completos para automatizar
scopescan export 3 -f csv -o hallazgos.csv           # hallazgos para hoja de calculo
scopescan export 3 -f bundle -o entrega.zip          # HTML + JSON + CSV + artefactos MSF
scopescan enrich 3                                   # CVE candidatas por CPE en NVD
scopescan exploitdb 3                                # PoC publicas por CVE via SearchSploit
scopescan msf 3                                      # verificacion Metasploit (scanner/check)
scopescan msf-catalog                                # modulos MSF allowlistados y guardas
scopescan msf-rc 3 --host 192.168.1.10 --port 445 \
  --module exploit/windows/smb/ms17_010_eternalblue # prepara .rc para msfconsole
scopescan inventory 3 --host 10.0.0.5                # inventario remoto Windows por WinRM
scopescan inventory 3 --host 10.0.0.5 --local        # si ScopeScan corre en ese equipo
scopescan inventory-linux 3 --host 10.0.0.8 --user audit  # claves o agente OpenSSH
scopescan patches 3                                  # build Windows frente a MSRC
scopescan profiles                                   # ver los perfiles disponibles
```

### Integraciones opcionales

Metasploit y Exploit-DB son opcionales. Si estan instalados, `scopescan doctor`
los detecta; si no, el panel deshabilita sus botones sin impedir escanear.

Variables utiles:

| Variable | Uso |
|---|---|
| `SCOPESCAN_MSFCONSOLE` | Ruta a `msfconsole` si no esta en `PATH` |
| `SCOPESCAN_ENABLE_EXPLOIT` | `1` habilita el disparo directo de exploits desde el panel; por defecto solo `.rc` |
| `SCOPESCAN_LHOST` | IP local que recibira el payload reverse de Metasploit |
| `SCOPESCAN_LPORT` | Puerto local del payload reverse; por defecto `4444` |
| `SCOPESCAN_SEARCHSPLOIT` | Ruta a `searchsploit` si no esta en `PATH` |
| `SCOPESCAN_PANEL_USER` / `SCOPESCAN_PANEL_PASSWORD` | Basic Auth para todos los clientes cuando se configura |
| `SCOPESCAN_PANEL_HOSTS` | Nombres Host exactos adicionales admitidos |
| `SCOPESCAN_PANEL_ORIGINS` | Lista completa de orígenes admitidos para escrituras de navegador |

La integracion Exploit-DB solo guarda referencias de SearchSploit. No descarga
ni ejecuta PoC; calcula una relevancia contextual por puerto, servicio y
producto para separar una PoC generica de una que encaja con lo observado. Para la fase ofensiva controlada, scopescan puede preparar un
resource script de Metasploit (`.rc`) descargable desde el panel o por CLI
(`scopescan msf-rc`) despues de una verificacion vulnerable/probable. El operador
lo lanza manualmente con su `msfconsole`. `scopescan msf-catalog` muestra el
catalogo allowlistado de modulos y sus guardas. La explotacion directa desde el panel
queda separada, registrada, exige confirmacion explicita y ademas requiere
`SCOPESCAN_ENABLE_EXPLOIT=1`.

`scopescan serve` sigue limitado a loopback aunque configures autenticación.
Para un despliegue remoto con un comando ASGI propio, configura Basic Auth,
Host y orígenes admitidos, y un proxy TLS siguiendo
[Seguridad del panel](docs/panel-security.md). Sin credenciales configuradas,
el middleware rechaza conexiones no locales. Basic Auth no sustituye CSRF en
las escrituras de navegador.

El bundle ZIP incluye informe, JSON, CSV y artefactos MSF generados por ScopeScan.
Para evitar entregables enormes por logs de consola, cada artefacto MSF se
incluye completo hasta 2 MB; si supera ese tamaño, el ZIP conserva el inicio del
fichero y añade una nota de truncado dentro del propio artefacto.

## Perfiles

| Perfil | Qué hace |
|---|---|
| `descubrimiento` | Solo host discovery (`-sn`), sin tocar puertos |
| `rapido` | 1000 puertos más comunes con detección de versión |
| `completo` | 65535 puertos + versión + SO + scripts `default and safe` |
| `vulnerabilidades` | **Por defecto.** 65535 puertos + versión + NSE `vuln` marcados `safe` |
| `vulnerabilidades-profundo` | NSE `vuln` y cifrados TLS; excluye `dos` y `exploit` |
| `auditoria-tls` | Enumera certificados, protocolos y cifrados TLS en todos los puertos |
| `udp-comun` | 200 puertos UDP frecuentes + versión + scripts seguros; requiere administrador |
| `udp-completo` | Los 65535 puertos UDP; requiere administrador y puede tardar muchas horas |
| `sigiloso` | Todos los puertos con `-T2`, menos ruido y mucho más lento |

Los perfiles describen la intención; los argumentos de nmap se calculan al
lanzar, porque dependen de los privilegios: con administrador se usa SYN scan
(`-sS`) y detección de SO (`-O`); sin él, connect scan (`-sT`), que es más lento
y deja rastro en los logs del objetivo.

Los perfiles UDP son independientes de los TCP para que su coste sea explícito.
UDP no completa un handshake: muchos puertos quedan como `open|filtered` y el
escaneo espera timeouts, por lo que `udp-completo` no debe ser el perfil cotidiano.
ScopeScan aplica reglas específicas a DNS, NTP, SNMP, TFTP, SSDP, CLDAP y NetBIOS;
un número de puerto UDP nunca dispara por sí solo una regla diseñada para TCP.

## Cómo se asigna la severidad

En este orden de preferencia:

1. Lo que declare el propio script NSE: `Risk factor`, `CVSS`, `State: VULNERABLE`.
2. Una tabla de severidades conocidas por id de script, para los que no lo declaran.
3. Heurística sobre el texto, como último recurso.

Si nada da señal, **no se crea hallazgo**: la salida del script se guarda y queda
visible bajo el puerto, pero no ensucia la lista. Un `State: NOT VULNERABLE`
nunca genera hallazgo, y un `LIKELY VULNERABLE` no llega nunca a crítico.

Los cortes son los de CVSS v3: ≥9.0 crítica, ≥7.0 alta, ≥4.0 media, >0 baja.
La salida de `ssl-enum-ciphers` se considera comprobación positiva cuando acepta
TLS 1.0/1.1 o cifrados de grado C o peor. `ssl-cert` genera un hallazgo confirmado
si el certificado está caducado o vence en menos de 30 días.

Además de los scripts NSE, `rules.py` aplica reglas propias sobre el servicio
detectado: exposiciones que nmap ve pero no denuncia (telnet, FTP en claro, SMB,
RDP, VNC, X11, bases de datos accesibles, SNMP) y versiones claramente fuera de
soporte. Si el objetivo está fuera de rango privado, la exposición sube un nivel.

Cada resultado indica qué demuestra la evidencia: **exposición observada**,
**posible afectación** por versión o **comprobación NSE positiva**. Las CVE obtenidas
de NVD aparecen en un apartado independiente como **candidatas**. El CVSS de una
CVE no confirma que ese equipo sea vulnerable. Las reglas de versión ponderan
menos en el riesgo agregado porque puede haber parches retroportados.

## Enriquecimiento NVD

En la ficha de un escaneo terminado se puede pulsar **Buscar CVE candidatas en
NVD**, o ejecutar `scopescan enrich ID`. Es una acción voluntaria: envía los CPE de
servicios con versión concreta a la API pública de NVD. ScopeScan convierte los CPE
simples de nmap a CPE 2.3, consulta coincidencias marcadas como vulnerables,
pagina resultados y guarda una caché de siete días en SQLite. `NVD_API_KEY` es
opcional y se lee del entorno; nunca se guarda en la base de datos.

Para cada coincidencia se conserva el criterio CPE de NVD. ScopeScan distingue
versión exacta, intervalo de versiones y criterios que afectan a todas las
versiones; descarta las versiones que quedan fuera del intervalo. Si la expresión
de aplicabilidad exige además otro sistema operativo o componente, lo indica como
condición pendiente. También muestra la fuente y el vector CVSS y enlaza el aviso
del fabricante cuando NVD lo identifica.

Las candidatas se priorizan con el catálogo CISA Known Exploited Vulnerabilities
(KEV) y con EPSS de FIRST. KEV señala explotación conocida; EPSS estima la
probabilidad de explotación durante los próximos 30 días. Ambos feeds se guardan
durante 20 horas en SQLite. Si uno no responde, se mantienen las candidatas de NVD
y el estado del enriquecimiento deja constancia del fallo parcial.

Un CPE ausente, genérico o ambiguo se omite. El CPE de hardware Intel AMT de
nmap solo se transforma en CPE de firmware cuando el inventario autenticado
devuelve `ME_System.FWVersion` **y** se selecciona expresamente la casilla del
panel o `scopescan enrich ID --include-firmware`. Esta opcion envia a NVD la
version de firmware obtenida del equipo. Una coincidencia de NVD sigue necesitando
comprobar configuración y avisos del fabricante. Si NVD falla, se conservan
los resultados anteriores y se muestra el error.

## Aplicabilidad de parches Windows

Tras el inventario Windows, `scopescan patches ID` descarga el CVRF mensual público
de Microsoft MSRC. El documento solicitado solo depende del mes: el inventario no
se envía a Microsoft. ScopeScan exige una coincidencia exacta de edición, versión y
arquitectura, y compara `Build.UBR` con `FixedBuild`. Si el build instalado es
inferior, guarda las CVE pendientes, CVSS, KB y enlace al catálogo. Si MSRC no
publica un build evaluable, el resultado queda parcial en vez de asumir que está
corregido. El feed se conserva 20 horas en SQLite.

## Inventario Windows autenticado

En la ficha del escaneo, **Inventario Windows autenticado** consulta un host ya
escaneado. Usa PowerShell Remoting/WinRM con la identidad Windows que ejecuta
ScopeScan, o `--local` desde la CLI si el host escaneado es loopback. Esta
restriccion evita atribuir al objetivo remoto el inventario del equipo local. No hay campo
de contraseña ni se almacenan credenciales. El administrador debe habilitar
WinRM y dar permisos WMI/registro. Con IP y autenticación integrada puede ser
necesario HTTPS o configurar TrustedHosts en el cliente.

Se recogen compilación y revisión de Windows, KB que devuelve `Get-HotFix`,
software registrado en HKLM y versión de BIOS. Si está instalado el proveedor
WMI `root\Intel_ME`, también se lee `ME_System.FWVersion`; si no, el informe
indica «sin dato». `Get-HotFix` no enumera todos los mecanismos de actualización:
el inventario no equivale a afirmar que un CVE esté corregido. Para ello hay
que contrastar el build y las KB con los avisos de Microsoft u OEM.

El inventario lee además `Get-SmbServerConfiguration`, el ajuste efectivo de NLA
para RDP (priorizando la política de grupo), perfiles activos del firewall,
estado y antigüedad de firmas de Defender, UAC y protección BitLocker del volumen
del sistema. ScopeScan crea hallazgos de **comprobación positiva** cuando observa
una configuración insegura. Los controles ligados a servicios, como SMB y RDP,
solo aplican cuando el puerto correspondiente está abierto. Al repetir el
inventario, estos hallazgos y el riesgo agregado se actualizan. Una lectura
fallida o un valor ausente quedan como «sin dato» y no generan hallazgo.

También revisa los perfiles activos de Firewall de Windows, la protección en
tiempo real y antigüedad de firmas de Microsoft Defender, UAC y la protección
BitLocker del volumen del sistema. Solo se afirma un fallo cuando el proveedor
local devuelve un valor concluyente; un perfil de firewall inactivo no genera
hallazgo y la ausencia de datos de Defender no se interpreta como falta de antivirus.

## Inventario Linux autenticado

`scopescan inventory-linux ID --host HOST --user USUARIO` usa el cliente OpenSSH
del sistema en modo no interactivo. Solo admite claves, certificados o un agente
ya configurado; no pide ni guarda contraseñas. El host debe estar vivo y formar
parte del escaneo. Se puede indicar `--port` para un SSH no estándar.

Recoge `/etc/os-release`, kernel, hasta 5.000 paquetes de dpkg, rpm o apk y la
configuración efectiva que pueda leer de sshd, firewall, ASLR, SELinux/AppArmor
y el marcador de reinicio pendiente. Crea comprobaciones positivas para acceso
directo de root por SSH, autenticación por contraseña, ausencia observada de
reglas de firewall, ASLR deshabilitado y controles MAC deshabilitados. Un dato
que el usuario remoto no puede leer queda sin evaluar.

En Debian/Ubuntu se simula la actualización con APT y se seleccionan paquetes del
canal de seguridad. En RHEL y derivados se usa `dnf/yum updateinfo --security`.
Cuando el gestor no ofrece metadatos concluyentes, el control queda «sin datos».

## Controles autenticados

Cada inventario conserva controles con estado **cumple**, **falla**, **sin datos**
o **no aplica**, además de los hallazgos fallidos. Las referencias a CIS Controls
v8.1 y al ENS indican qué medida respalda la evidencia; no equivalen a una
certificación completa, que depende del alcance, la categoría y controles
organizativos que un escáner de host no puede observar.

El **riesgo agregado** (0–100) pondera por severidad y satura exponencialmente:
diez hallazgos medios no empatan con una crítica, y a partir de varias críticas
el número deja de decir nada nuevo.

## Decisiones de diseño

- **Se parsea el XML, no el texto.** La salida de texto de nmap cambia entre
  versiones y con la verbosidad; el DTD del XML es estable.
- **Los objetivos se validan antes de llegar a nmap.** Se ejecuta con una lista
  de argumentos y sin shell, pero un objetivo que empiece por `-` lo leería nmap
  como una opción suya: eso es inyección de argumentos, y se rechaza.
- **Hay un tope de 256 hosts por escaneo** salvo que se fuerce explícitamente,
  para que un `/8` mal tecleado no lance un barrido de 16 millones de direcciones.
- **El estado vive en SQLite, no en memoria.** Un escaneo dura minutos u horas y
  el panel tiene que poder consultarlo mientras corre. Si el proceso muere a
  mitad, al arrancar se cierran los escaneos que quedaron colgados.
- **El XML de un escaneo cancelado se aprovecha.** Lo escaneado hasta ese momento
  es información válida; el parser sabe recuperar un XML truncado.
- **El informe no depende del servidor.** Todo el CSS va en línea: se adjunta en
  un correo y se ve igual dentro de diez años.

## Límites de la herramienta

El escaneo nmap ve lo que puede observar desde la red. El inventario autenticado
añade datos locales Windows o Linux cuando se solicita. ScopeScan evalúa controles
técnicos concretos y el build acumulativo de Windows, pero no incorpora todavía
los miles de plugins de aplicaciones, firmware OEM y benchmarks auditables que
mantiene el feed comercial de Nessus. Tampoco sustituye una certificación CIS/ENS.
Un resultado limpio no demuestra que un sistema sea seguro.

La detección por versión de banner produce falsos positivos cuando la
distribución aplica parches sin cambiar el número de versión (lo habitual en
Debian, Ubuntu y RHEL): un OpenSSH 6.6.1p1 de Ubuntu puede tener los parches al
día. Por eso los hallazgos llevan la evidencia completa: hay que leerla antes de
actuar.

## Uso responsable

Escanear puertos de sistemas ajenos sin autorización es ilegal en España
(art. 197 bis del Código Penal) y en la mayoría de jurisdicciones. La herramienta
pide confirmación explícita de autorización antes de cada escaneo y deja
constancia de quién la dio en el informe. Úsala sobre equipos propios, laboratorios
o encargos con alcance firmado.

## Desarrollo

```bash
.venv\Scripts\python.exe -m pytest        # pruebas sin red ni nmap
.venv\Scripts\python.exe -m ruff check src tests
.venv\Scripts\scopescan.exe self-test       # sanity check local sin tocar la red
```

Las pruebas no lanzan nmap ni tocan la red: trabajan sobre un XML de ejemplo
realista (`tests/conftest.py`) y aíslan la base de datos en un directorio
temporal vía `SCOPESCAN_DATA`. `pytest` usa `src` como `pythonpath` y escribe sus
temporales en `.pytest_tmp/`, que esta ignorado por git para evitar problemas con
el directorio temporal del usuario en Windows.

La [verificación de la fase A](docs/phase-a-verification.md) registra la suite,
la instalación de rueda y el sdist comprobados localmente. El
[plan de implementación](docs/implementation-plan.md) conserva las fases pendientes.
La [consolidación](docs/consolidation.md) documenta la preservación del historial.

## Licencia, seguridad y datos

El código propio se distribuye bajo [MIT](LICENSE). Para comunicar una
vulnerabilidad, consulta [SECURITY.md](SECURITY.md). El
[contrato de datos y exportaciones](docs/data-and-exports.md) explica la evidencia
incluida, los hashes y el tratamiento de los archivos entregados.

## Estructura

```
src/scopescan/
  config.py        rutas, localización de nmap, detección de privilegios
  targets.py       validación y clasificación de objetivos
  profiles.py      perfiles de escaneo -> argumentos de nmap
  nmap_runner.py   subproceso, progreso en vivo, cancelación
  nmap_parser.py   XML de nmap -> modelo de datos
  models.py        Host, Port, Service, Finding, Severity
  rules.py         reglas propias sobre servicios y versiones
  analysis.py      NSE -> hallazgos con severidad y tipo de evidencia
  nvd.py           CPE -> CVE candidatas con caché
  threat_intel.py  CISA KEV y FIRST EPSS para priorizar candidatas
  exploitdb.py     CVE detectadas -> referencias Exploit-DB/SearchSploit
  msf_modules.py   catalogo Metasploit servicio/CVE -> scanner/check/exploit
  msf_runner.py    ejecucion de msfconsole con resource scripts y logs
  msf.py           verificacion y explotacion Metasploit con guardas
  attack_paths.py  vista consolidada host/puerto/CVE/PoC/MSF/ejecuciones
  msrc.py          build Windows -> CVE y KB pendientes en CVRF oficial
  windows_inventory.py  inventario Windows por WinRM o local
  linux_inventory.py  inventario Linux por OpenSSH o local
  authenticated_checks.py  controles sobre configuracion local observada
  compliance.py    resultados cumple/falla/sin datos y referencias
  db.py            SQLite
  service.py       orquestación de un escaneo completo
  jobs.py          cola en segundo plano
  report.py        informe HTML autocontenido
  export.py        JSON, CSV y bundle ZIP de entrega
  cli.py           scan | serve | list | report | export | enrich | exploitdb | msf | msf-catalog | msf-rc | inventory | patches | self-test
  web/             panel FastAPI + plantillas Jinja
```
