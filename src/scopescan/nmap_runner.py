"""Ejecucion de nmap como subproceso, con progreso en vivo y cancelacion.

nmap se lanza con una lista de argumentos y sin shell: los objetivos ya vienen
validados de targets.py, pero pasar por el shell anadiria una via de inyeccion
que no aporta nada.

El progreso sale de --stats-every: nmap escribe en stdout lineas de estado que
se parsean para alimentar la barra del panel. Es la unica forma de saber por
donde va un escaneo de 65535 puertos que dura media hora.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import find_nmap
from .process_runner import run_process

# "SYN Stealth Scan Timing: About 24.53% done; ETC: 20:15 (0:01:32 remaining)"
PROGRESS_RE = re.compile(r"^(?P<task>.+?)\s+Timing:\s+About\s+(?P<pct>[\d.]+)%\s+done")
# "Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan"
STATS_RE = re.compile(r"^Stats:\s+(?P<elapsed>[\d:]+)\s+elapsed;.*?undergoing\s+(?P<task>.+)$")
ETC_RE = re.compile(r"\((?P<remaining>[\d:]+)\s+remaining\)")

ProgressCallback = Callable[[float, str], None]


class NmapError(RuntimeError):
    """nmap termino con error."""


@dataclass
class NmapExecution:
    argv: list[str]
    xml_path: Path
    returncode: int
    stdout: str
    stderr: str
    cancelled: bool = False
    timed_out: bool = False
    output_truncated: bool = False

    @property
    def command(self) -> str:
        return " ".join(self.argv)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not (self.cancelled or self.timed_out)


def build_argv(
    *,
    targets: list[str],
    profile_args: list[str],
    xml_path: Path,
    nmap_path: str | None = None,
    stats_every: str = "5s",
) -> list[str]:
    # ScopeScan executes concrete pinned addresses. Nmap defaults to IPv4;
    # an IPv6 scope needs -6 and mixed families cannot share a command.
    try:
        families = {ipaddress.ip_address(target).version for target in targets}
    except ValueError:
        families = set()  # Compatibility for callers that validate target syntax separately.
    if len(families) > 1:
        raise ValueError("Nmap requiere separar los objetivos IPv4 e IPv6")
    binary = nmap_path or find_nmap()
    return [
        binary,
        *profile_args,
        *(["-6"] if families == {6} else []),
        "-n",
        "--stats-every",
        stats_every,
        "-v",
        "-oX",
        str(xml_path),
        *targets,
    ]


def run(
    argv: list[str],
    *,
    progress: ProgressCallback | None = None,
    cancel: threading.Event | None = None,
    timeout: float | None = None,
) -> NmapExecution:
    """Lanza nmap y devuelve el resultado cuando termina.

    `cancel` permite pararlo desde el panel: se comprueba periodicamente aunque el proceso no escriba.
    Al matar nmap el XML queda a medias, y el parser sabe recuperar lo escrito
    hasta ese punto.
    """
    xml_path = Path(argv[argv.index("-oX") + 1])

    def on_line(line: str) -> None:
        if progress is None:
            return
        match = PROGRESS_RE.match(line)
        if match:
            task = match.group("task").strip()
            etc = ETC_RE.search(line)
            if etc:
                task = f"{task} ({etc.group('remaining')} restantes)"
            progress(float(match.group("pct")), task)
        else:
            stats = STATS_RE.match(line)
            if stats:
                progress(-1.0, stats.group("task").strip())

    result = run_process(argv, cancel=cancel, timeout=timeout, on_line=on_line)
    return NmapExecution(argv, xml_path, result.returncode, result.stdout, result.stderr,
                         result.cancelled, result.timed_out, result.output_truncated)

def explain_failure(execution: NmapExecution) -> str:
    """Traduce el fallo de nmap a algo accionable."""
    if execution.timed_out:
        return "Tiempo maximo de ejecucion agotado; resultados parciales conservados."
    err = execution.stderr.lower()
    if "requires root privileges" in err or "operation not permitted" in err:
        return (
            "nmap necesita privilegios para esta tecnica. Ejecuta el panel como "
            "administrador o usa un perfil sin SYN scan ni deteccion de SO."
        )
    if "npcap" in err or "winpcap" in err or "dnet: failed to open device" in err:
        return (
            "Falta Npcap o la interfaz no esta accesible. Reinstala Nmap para Windows "
            "marcando Npcap, o ejecuta el panel como administrador."
        )
    if "failed to resolve" in err:
        return "No se pudo resolver alguno de los objetivos indicados."
    if "no route to host" in err or "network is unreachable" in err:
        return "No hay ruta hasta el objetivo desde esta maquina."
    return execution.stderr or f"nmap termino con codigo {execution.returncode}"
