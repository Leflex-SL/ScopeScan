"""Rutas, localizacion del binario de nmap y deteccion de privilegios."""

from __future__ import annotations

import os
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

    @property
    def ready(self) -> bool:
        return self.nmap_path is not None


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

    return Environment(
        nmap_path=path,
        nmap_version=version,
        privileged=is_privileged(),
        data_dir=str(data_dir()),
    )
