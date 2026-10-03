"""Ejecucion de nmap como subproceso, con progreso en vivo y cancelacion.

nmap se lanza con una lista de argumentos y sin shell: los objetivos ya vienen
validados de targets.py, pero pasar por el shell anadiria una via de inyeccion
que no aporta nada.

El progreso sale de --stats-every: nmap escribe en stdout lineas de estado que
se parsean para alimentar la barra del panel. Es la unica forma de saber por
donde va un escaneo de 65535 puertos que dura media hora.
"""

from __future__ import annotations

import re
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import find_nmap

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

    @property
    def command(self) -> str:
        return " ".join(self.argv)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.cancelled


def build_argv(
    *,
    targets: list[str],
    profile_args: list[str],
    xml_path: Path,
    nmap_path: str | None = None,
    stats_every: str = "5s",
) -> list[str]:
    binary = nmap_path or find_nmap()
    return [
        binary,
        *profile_args,
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

    `cancel` permite pararlo desde el panel: se comprueba entre lineas de salida.
    Al matar nmap el XML queda a medias, y el parser sabe recuperar lo escrito
    hasta ese punto.
    """
    xml_path = Path(argv[argv.index("-oX") + 1])
    stdout_lines: list[str] = []
    last_task = ""
    cancelled = False

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    # stderr se lee en un hilo aparte: si nmap llena ese pipe mientras nosotros
    # seguimos leyendo stdout, el proceso se bloquea esperando a que lo vaciemos.
    stderr_chunks: list[str] = []

    def drain_stderr() -> None:
        if proc.stderr is not None:
            stderr_chunks.extend(proc.stderr)

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    stderr_thread.start()

    timer: threading.Timer | None = None
    if timeout:
        timer = threading.Timer(timeout, proc.kill)
        timer.daemon = True
        timer.start()

    try:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if line:
                stdout_lines.append(line)

            if cancel is not None and cancel.is_set():
                cancelled = True
                _terminate(proc)
                break

            if progress is None:
                continue

            match = PROGRESS_RE.match(line)
            if match:
                last_task = match.group("task").strip()
                etc = ETC_RE.search(line)
                task = f"{last_task} ({etc.group('remaining')} restantes)" if etc else last_task
                progress(float(match.group("pct")), task)
                continue

            stats = STATS_RE.match(line)
            if stats:
                last_task = stats.group("task").strip()
                progress(-1.0, last_task)
    finally:
        if timer:
            timer.cancel()

    proc.wait()
    stderr_thread.join(timeout=5)
    stderr = "".join(stderr_chunks)

    return NmapExecution(
        argv=argv,
        xml_path=xml_path,
        returncode=proc.returncode,
        stdout="\n".join(stdout_lines),
        stderr=stderr.strip(),
        cancelled=cancelled,
    )


def _terminate(proc: subprocess.Popen) -> None:
    """Corta nmap dandole margen a cerrar antes de matarlo."""
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def explain_failure(execution: NmapExecution) -> str:
    """Traduce el fallo de nmap a algo accionable."""
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
