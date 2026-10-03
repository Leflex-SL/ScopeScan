"""Validacion y clasificacion de objetivos.

Dos motivos para no pasar la cadena del usuario directamente a nmap:

1. Aunque lanzamos nmap con una lista de argumentos (sin shell), un objetivo que
   empiece por "-" lo leeria nmap como una opcion suya. Eso es inyeccion de
   argumentos, asi que se rechaza aqui.
2. Un escaneo es trafico contra una maquina de alguien. Conviene saber de antemano
   cuantos hosts abarca y si salen de la red privada, para pedir confirmacion.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .config import MAX_HOSTS_DEFAULT

# Hostname RFC 1123 (con guiones, sin empezar ni acabar en guion).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
)
# Forma con rangos por octeto tipo nmap: 10.0.0-255.1-254
_OCTET_RANGE_RE = re.compile(r"^(\d{1,3}(-\d{1,3})?)(\.(\d{1,3}(-\d{1,3})?)){3}$")


class InvalidTarget(ValueError):
    """El objetivo no es una IP, CIDR, rango u hostname valido."""


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str  # ip | cidr | range | hostname
    hosts: int  # hosts estimados (1 si no se puede saber, p.ej. hostname)
    private: bool  # True si esta seguro en RFC1918/loopback/link-local


@dataclass(frozen=True)
class TargetSet:
    targets: tuple[Target, ...]
    warnings: tuple[str, ...] = field(default=())

    @property
    def raw(self) -> str:
        return " ".join(t.raw for t in self.targets)

    @property
    def argv(self) -> list[str]:
        return [t.raw for t in self.targets]

    @property
    def hosts(self) -> int:
        return sum(t.hosts for t in self.targets)

    @property
    def all_private(self) -> bool:
        return all(t.private for t in self.targets)


def _is_private_net(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return bool(net.is_private or net.is_loopback or net.is_link_local)


def _parse_octet_range(raw: str) -> tuple[int, bool]:
    """Cuenta hosts de un objetivo con rangos por octeto y dice si es privado."""
    total = 1
    lows: list[int] = []
    for part in raw.split("."):
        if "-" in part:
            low_s, high_s = part.split("-", 1)
            low, high = int(low_s), int(high_s)
            if not (0 <= low <= high <= 255):
                raise InvalidTarget(f"Rango de octeto invalido en '{raw}'")
            total *= high - low + 1
        else:
            low = int(part)
            if not 0 <= low <= 255:
                raise InvalidTarget(f"Octeto fuera de rango en '{raw}'")
        lows.append(low)

    try:
        first = ipaddress.ip_address(".".join(str(v) for v in lows))
    except ValueError as exc:  # pragma: no cover - lows siempre son 4 octetos validos
        raise InvalidTarget(str(exc)) from exc
    return total, bool(first.is_private or first.is_loopback or first.is_link_local)


def parse_target(raw: str) -> Target:
    """Valida un unico objetivo y lo clasifica."""
    raw = raw.strip()
    if not raw:
        raise InvalidTarget("Objetivo vacio")
    if raw.startswith("-"):
        raise InvalidTarget(f"'{raw}' empieza por '-': nmap lo leeria como una opcion")
    if any(ch in raw for ch in ' \t;|&$`<>()"\'\n\r'):
        raise InvalidTarget(f"'{raw}' contiene caracteres no permitidos en un objetivo")

    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise InvalidTarget(f"'{raw}' no es una red valida: {exc}") from exc
        return Target(raw=raw, kind="cidr", hosts=net.num_addresses, private=_is_private_net(net))

    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        private = bool(addr.is_private or addr.is_loopback or addr.is_link_local)
        return Target(raw=raw, kind="ip", hosts=1, private=private)

    if _OCTET_RANGE_RE.match(raw):
        hosts, private = _parse_octet_range(raw)
        return Target(raw=raw, kind="range", hosts=hosts, private=private)

    if _HOSTNAME_RE.match(raw):
        # Un nombre resuelve a lo que resuelva: se trata como publico salvo prueba
        # en contrario, para que caiga del lado prudente del aviso.
        return Target(raw=raw, kind="hostname", hosts=1, private=raw in ("localhost", "localhost."))

    raise InvalidTarget(f"'{raw}' no es una IP, red CIDR, rango ni nombre de host valido")


def parse_targets(raw: str, *, max_hosts: int = MAX_HOSTS_DEFAULT, force: bool = False) -> TargetSet:
    """Valida una lista de objetivos separados por espacios o comas.

    Lanza InvalidTarget si el conjunto supera `max_hosts` y no se pasa force=True.
    """
    pieces = [p for p in re.split(r"[\s,]+", raw.strip()) if p]
    if not pieces:
        raise InvalidTarget("No se ha indicado ningun objetivo")

    targets = tuple(parse_target(p) for p in pieces)
    total = sum(t.hosts for t in targets)

    if total > max_hosts and not force:
        raise InvalidTarget(
            f"El objetivo abarca {total} hosts (limite {max_hosts}). "
            "Reduce el rango o confirma explicitamente que quieres escanearlo entero."
        )

    warnings: list[str] = []
    public = [t.raw for t in targets if not t.private]
    if public:
        warnings.append(
            "Objetivos fuera de rango privado: "
            + ", ".join(public)
            + ". Escanea solo sistemas propios o con autorizacion por escrito."
        )
    if total > 64:
        warnings.append(f"{total} hosts en cola: un escaneo completo puede tardar horas.")

    return TargetSet(targets=targets, warnings=tuple(warnings))
