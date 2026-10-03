"""Ejecucion de msfconsole como subproceso con un resource script.

Mismo patron que nmap_runner: se lanza sin shell, se leen stdout/stderr en vivo
y se puede cancelar desde fuera con un threading.Event. msfconsole tarda en
arrancar (carga todos los modulos), asi que el timeout por defecto es generoso.

msfconsole se invoca con:
  -q  silencioso (sin banner)
  -n  sin base de datos (no exige PostgreSQL para un `check`/`run` puntual)
  -r  resource script con los comandos
  -o  fichero de log (ademas de stdout, por si acaso)
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .config import find_msfconsole
from .process_runner import run_process

# Un `check`/`run` puntual no deberia tardar tanto, pero el arranque de
# msfconsole se come facil 30-60s la primera vez.
DEFAULT_TIMEOUT = 600.0

ProgressCallback = Callable[[str], None]


class MsfError(RuntimeError):
    """msfconsole termino con error."""


@dataclass
class MsfExecution:
    argv: list[str]
    rc_path: Path
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

    @property
    def output(self) -> str:
        """Salida combinada: msfconsole escribe resultados tanto en stdout como,
        a veces, en stderr segun la version."""
        return self.stdout if not self.stderr else f"{self.stdout}\n{self.stderr}"


def build_argv(rc_path: Path, *, log_path: Path | None = None, msf_path: str | None = None) -> list[str]:
    binary = msf_path or find_msfconsole()
    argv = [binary, "-q", "-n", "-r", str(rc_path)]
    if log_path is not None:
        argv += ["-o", str(log_path)]
    return argv


def run(
    argv: list[str],
    *,
    progress: ProgressCallback | None = None,
    cancel: threading.Event | None = None,
    timeout: float | None = DEFAULT_TIMEOUT,
) -> MsfExecution:
    """Lanza msfconsole y devuelve el resultado cuando termina."""
    rc_path = Path(argv[argv.index("-r") + 1])
    def on_line(line: str) -> None:
        if progress is not None and line.startswith(("[*]", "[+]", "[-]", "[!]")):
            progress(line)

    result = run_process(argv, cancel=cancel, timeout=timeout, on_line=on_line)
    return MsfExecution(argv, rc_path, result.returncode, result.stdout, result.stderr,
                        result.cancelled, result.timed_out, result.output_truncated)


def explain_failure(execution: MsfExecution) -> str:
    """Traduce el fallo de msfconsole a algo accionable."""
    if execution.timed_out:
        return "Tiempo maximo de ejecucion agotado; resultados parciales conservados."
    err = (execution.stderr + execution.stdout).lower()
    if "could not connect to the database" in err or "postgresql" in err:
        return (
            "msfconsole no pudo conectar con PostgreSQL. scopescan lanza con -n (sin BD), "
            "asi que esto no deberia bloquear un check; revisa la version de Metasploit."
        )
    if "bundler" in err or "gem" in err and "not" in err:
        return "La instalacion de Metasploit tiene dependencias Ruby rotas. Reinstala el framework."
    if execution.cancelled:
        return "Cancelado por el usuario."
    return execution.stderr or f"msfconsole termino con codigo {execution.returncode}"
