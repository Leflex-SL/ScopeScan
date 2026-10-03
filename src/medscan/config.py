"""Rutas, localizacion del binario de nmap y deteccion de privilegios."""

from __future__ import annotations

import os
import secrets
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Rutas habituales del instalador oficial de Nmap en Windows.
WINDOWS_NMAP_PATHS = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)

# Rutas habituales de Metasploit. En Windows el instalador deja un .bat que
# envuelve al ruby embebido; en Linux casi siempre esta en el PATH.
WINDOWS_MSF_PATHS = (
    r"C:\metasploit-framework\bin\msfconsole.bat",
    r"C:\metasploit-framework\bin\msfconsole",
)

# SearchSploit es el cliente local de Exploit-DB. En Kali suele estar en PATH;
# en Windows normalmente se apunta explicitamente con MEDSCAN_SEARCHSPLOIT.
WINDOWS_SEARCHSPLOIT_PATHS = (
    r"C:\exploitdb\searchsploit.bat",
    r"C:\exploitdb\searchsploit",
)

# Tope de hosts por escaneo sin --force: evita barridos accidentales de rangos enormes.
MAX_HOSTS_DEFAULT = 256

# Escaneos simultaneos. nmap ya paraleliza dentro de un escaneo; mas de 2 solo
# se estorban entre ellos y falsean los tiempos de respuesta.
MAX_CONCURRENT_SCANS = 2


def data_dir() -> Path:
    """Directorio de datos (BD, XML crudos, informes). Override: MEDSCAN_DATA."""
    raw = os.environ.get("MEDSCAN_DATA")
    path = Path(raw).expanduser() if raw else PROJECT_ROOT / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "medscan.sqlite3"


def raw_dir() -> Path:
    path = data_dir() / "raw"
    path.mkdir(parents=True, exist_ok=True)
    return path


class NmapNotFound(RuntimeError):
    """nmap no esta instalado o no se encuentra en el PATH."""

    INSTALL_HINT = (
        "nmap no encontrado.\n"
        "  Windows:  winget install -e --id Insecure.Nmap\n"
        "            (o el instalador oficial de https://nmap.org/download.html, con Npcap)\n"
        "  Linux:    sudo apt install nmap\n"
        "Si esta instalado en otra ruta, exporta MEDSCAN_NMAP con la ruta al ejecutable."
    )

    def __init__(self, msg: str = "") -> None:
        super().__init__(f"{msg}\n{self.INSTALL_HINT}" if msg else self.INSTALL_HINT)


def find_nmap() -> str:
    """Devuelve la ruta al ejecutable de nmap o lanza NmapNotFound."""
    override = os.environ.get("MEDSCAN_NMAP")
    if override:
        if Path(override).is_file():
            return override
        raise NmapNotFound(f"MEDSCAN_NMAP apunta a {override}, que no existe.")

    found = shutil.which("nmap")
    if found:
        return found

    for candidate in WINDOWS_NMAP_PATHS:
        if Path(candidate).is_file():
            return candidate

    raise NmapNotFound()


def nmap_available() -> bool:
    try:
        find_nmap()
    except NmapNotFound:
        return False
    return True


class MsfConsoleNotFound(RuntimeError):
    """msfconsole no esta instalado o no se encuentra en el PATH."""

    INSTALL_HINT = (
        "msfconsole no encontrado. La verificacion con Metasploit es opcional:\n"
        "  Windows:  instalador de https://windows.metasploit.com/ (deja msfconsole.bat)\n"
        "  Linux:    https://docs.metasploit.com/docs/using-metasploit/getting-started/"
        "nightly-installers.html\n"
        "            (o 'sudo apt install metasploit-framework' en Kali)\n"
        "Si esta en otra ruta, exporta MEDSCAN_MSFCONSOLE con la ruta al ejecutable."
    )

    def __init__(self, msg: str = "") -> None:
        super().__init__(f"{msg}\n{self.INSTALL_HINT}" if msg else self.INSTALL_HINT)


def find_msfconsole() -> str:
    """Devuelve la ruta a msfconsole o lanza MsfConsoleNotFound."""
    override = os.environ.get("MEDSCAN_MSFCONSOLE")
    if override:
        if Path(override).is_file():
            return override
        raise MsfConsoleNotFound(f"MEDSCAN_MSFCONSOLE apunta a {override}, que no existe.")

    for name in ("msfconsole", "msfconsole.bat"):
        found = shutil.which(name)
        if found:
            return found

    for candidate in WINDOWS_MSF_PATHS:
        if Path(candidate).is_file():
            return candidate

    raise MsfConsoleNotFound()


def msf_available() -> bool:
    try:
        find_msfconsole()
    except MsfConsoleNotFound:
        return False
    return True


def msf_exploit_enabled() -> bool:
    """True si se permite disparar exploits reales desde el panel web.

    La preparacion de `.rc` es el flujo normal. La ejecucion directa desde
    FastAPI queda detras de una bandera explicita para evitar habilitar una
    superficie ofensiva por accidente en una instalacion normal.
    """
    raw = os.environ.get("MEDSCAN_ENABLE_EXPLOIT", "")
    return raw.strip().lower() in {"1", "true", "yes", "y", "si", "s"}


def msf_lhost() -> str:
    """IP local para el payload reverse. Override: MEDSCAN_LHOST.

    Sin override se deduce abriendo un socket UDP hacia una IP externa (no envia
    nada): el SO elige la interfaz de salida y de ahi sale la IP local. Si falla,
    cae a 127.0.0.1, que solo sirve para objetivos en la propia maquina.
    """
    override = os.environ.get("MEDSCAN_LHOST")
    if override:
        return override
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # TEST-NET-1: no enruta a ningun sitio real
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def msf_lport() -> int:
    """Puerto de escucha del payload reverse. Override: MEDSCAN_LPORT."""
    raw = os.environ.get("MEDSCAN_LPORT")
    if raw and raw.isdigit() and 1 <= int(raw) <= 65535:
        return int(raw)
    return 4444


class SearchSploitNotFound(RuntimeError):
    """searchsploit no esta instalado o no se encuentra en el PATH."""

    INSTALL_HINT = (
        "searchsploit no encontrado. La correlacion con Exploit-DB es opcional:\n"
        "  Kali/Linux: instala el paquete exploitdb y actualiza con searchsploit -u\n"
        "  Windows:    instala/clona Exploit-DB y exporta MEDSCAN_SEARCHSPLOIT con la ruta "
        "al ejecutable."
    )

    def __init__(self, msg: str = "") -> None:
        super().__init__(f"{msg}\n{self.INSTALL_HINT}" if msg else self.INSTALL_HINT)


def find_searchsploit() -> str:
    """Devuelve la ruta a searchsploit o lanza SearchSploitNotFound."""
    override = os.environ.get("MEDSCAN_SEARCHSPLOIT")
    if override:
        if Path(override).is_file():
            return override
        raise SearchSploitNotFound(
            f"MEDSCAN_SEARCHSPLOIT apunta a {override}, que no existe."
        )

    for name in ("searchsploit", "searchsploit.bat"):
        found = shutil.which(name)
        if found:
            return found

    for candidate in WINDOWS_SEARCHSPLOIT_PATHS:
        if Path(candidate).is_file():
            return candidate

    raise SearchSploitNotFound()


def searchsploit_available() -> bool:
    try:
        find_searchsploit()
    except SearchSploitNotFound:
        return False
    return True


def panel_auth_credentials() -> tuple[str, str] | None:
    """Credenciales Basic opcionales para exponer el panel fuera de loopback.

    Sin credenciales configuradas, el panel sigue aceptando solo clientes locales.
    Esto evita que `medscan serve --host 0.0.0.0` abra el panel por accidente.
    """
    user = os.environ.get("MEDSCAN_PANEL_USER", "").strip()
    password = os.environ.get("MEDSCAN_PANEL_PASSWORD", "")
    if user and password:
        return user, password
    return None


def panel_auth_enabled() -> bool:
    return panel_auth_credentials() is not None


def panel_auth_matches(user: str, password: str) -> bool:
    configured = panel_auth_credentials()
    if configured is None:
        return False
    expected_user, expected_password = configured
    return secrets.compare_digest(user, expected_user) and secrets.compare_digest(
        password, expected_password
    )


def is_privileged() -> bool:
    """True si el proceso puede abrir sockets raw (SYN scan, -O)."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001 - detectar privilegios nunca debe tumbar el arranque
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


@dataclass(frozen=True)
class Environment:
    """Foto del entorno, para `medscan doctor` y para avisos en el panel."""

    nmap_path: str | None
    nmap_version: str | None
    privileged: bool
    data_dir: str
    msf_path: str | None = None
    msf_exploit_enabled: bool = False
    searchsploit_path: str | None = None
    panel_auth_enabled: bool = False

    @property
    def ready(self) -> bool:
        return self.nmap_path is not None

    @property
    def msf_ready(self) -> bool:
        return self.msf_path is not None

    @property
    def searchsploit_ready(self) -> bool:
        return self.searchsploit_path is not None


def probe_environment() -> Environment:
    import subprocess

    path: str | None
    version: str | None = None
    try:
        path = find_nmap()
    except NmapNotFound:
        path = None

    if path:
        try:
            out = subprocess.run(
                [path, "--version"], capture_output=True, text=True, timeout=15, check=False
            )
            first = (out.stdout or "").splitlines()
            version = first[0].strip() if first else None
        except Exception:  # noqa: BLE001 - sondear la version es opcional; sin ella se sigue
            version = None

    try:
        msf_path: str | None = find_msfconsole()
    except MsfConsoleNotFound:
        msf_path = None

    try:
        searchsploit_path: str | None = find_searchsploit()
    except SearchSploitNotFound:
        searchsploit_path = None

    return Environment(
        nmap_path=path,
        nmap_version=version,
        privileged=is_privileged(),
        data_dir=str(data_dir()),
        msf_path=msf_path,
        msf_exploit_enabled=msf_exploit_enabled(),
        searchsploit_path=searchsploit_path,
        panel_auth_enabled=panel_auth_enabled(),
    )
