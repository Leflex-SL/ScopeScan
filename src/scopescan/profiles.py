"""Perfiles de escaneo (el equivalente a las "policies" de Nessus).

Un perfil describe la intencion ("quiero todos los puertos con deteccion de
vulnerabilidades") y se traduce a argumentos de nmap en el momento de lanzarlo,
porque algunas tecnicas dependen de si el proceso tiene privilegios:

- Sin privilegios solo hay connect scan (-sT): nmap completa el handshake TCP,
  asi que es mas lento y deja registro en los logs del objetivo.
- Con privilegios se usa SYN scan (-sS) y se puede pedir deteccion de SO (-O).
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Selector NSE prudente: categoria vuln sin los scripts que tumban el servicio.
# 'not dos' y 'not exploit' son la diferencia entre comprobar y explotar.
NSE_VULN_SAFE = "(default or vuln) and safe and not broadcast and not dos"
NSE_VULN_FULL = "(default or vuln) and not broadcast and not dos and not exploit"
NSE_VULN_DEEP_TLS = f"({NSE_VULN_FULL}) or ssl-enum-ciphers"


@dataclass(frozen=True)
class Profile:
    key: str
    label: str
    description: str
    ports: str | None = None  # None = puertos por defecto de nmap
    version: bool = False
    os_detect: bool = False
    scripts: str | None = None
    timing: str = "-T4"
    discovery_only: bool = False
    intrusive: bool = False
    transport: str = "tcp"  # tcp | udp
    extra: tuple[str, ...] = field(default=())

    def nmap_args(self, *, privileged: bool) -> list[str]:
        """Argumentos de nmap para este perfil (sin objetivos ni -oX)."""
        args: list[str] = [self.timing]

        if self.discovery_only:
            args += ["-sn", "-PE", "-PS443,80,22", "-PA3389", "-PU161"]
            return args + list(self.extra)

        if self.transport == "udp":
            args.append("-sU")
        else:
            args.append("-sS" if privileged else "-sT")
        # Sin privilegios el ping ICMP no esta disponible; -Pn evita descartar
        # hosts que si responden en TCP pero no al ping.
        args.append("-Pn")

        if self.ports:
            args += self.ports.split()
        if self.version:
            args += ["-sV", "--version-intensity", "7"]
        if self.os_detect and privileged:
            args.append("-O")
        if self.scripts:
            args += ["--script", self.scripts]

        return args + list(self.extra)

    def warnings(self, *, privileged: bool) -> list[str]:
        out: list[str] = []
        if not privileged and self.transport == "udp":
            out.append(
                "El escaneo UDP (-sU) necesita una consola con privilegios de administrador."
            )
        elif not privileged and not self.discovery_only:
            out.append(
                "Sin privilegios de administrador: se usa connect scan (-sT), mas lento "
                "y mas visible en los logs del objetivo."
            )
        if self.os_detect and not privileged:
            out.append("La deteccion de sistema operativo (-O) necesita privilegios; se omite.")
        if self.intrusive:
            out.append(
                "Perfil intrusivo: algunos scripts NSE pueden afectar al servicio. "
                "No lo lances contra produccion sin ventana acordada."
            )
        return out


PROFILES: dict[str, Profile] = {
    "descubrimiento": Profile(
        key="descubrimiento",
        label="Descubrimiento de red",
        description=(
            "Solo averigua que hosts estan vivos, sin escanear puertos. "
            "Util para inventariar una subred antes de decidir a quien auditar."
        ),
        discovery_only=True,
    ),
    "rapido": Profile(
        key="rapido",
        label="Rapido (1000 puertos comunes)",
        description=(
            "Los 1000 puertos mas frecuentes con deteccion de servicio y version. "
            "Un par de minutos por host; sirve como primera foto."
        ),
        ports="--top-ports 1000",
        version=True,
    ),
    "completo": Profile(
        key="completo",
        label="Completo (65535 puertos)",
        description=(
            "Los 65535 puertos TCP con deteccion de servicio, version, sistema "
            "operativo y scripts por defecto. Sin NSE de vulnerabilidades."
        ),
        ports="-p-",
        version=True,
        os_detect=True,
        scripts="default and safe",
    ),
    "vulnerabilidades": Profile(
        key="vulnerabilidades",
        label="Vulnerabilidades (65535 puertos + NSE vuln)",
        description=(
            "El perfil de referencia: todos los puertos, version de cada servicio y "
            "scripts NSE de la categoria vuln marcados como safe. Excluye dos y "
            "exploit, asi que comprueba sin tumbar el servicio."
        ),
        ports="-p-",
        version=True,
        os_detect=True,
        scripts=NSE_VULN_SAFE,
    ),
    "vulnerabilidades-profundo": Profile(
        key="vulnerabilidades-profundo",
        label="Vulnerabilidades profundo (NSE vuln completo)",
        description=(
            "Como el anterior pero sin limitarse a los scripts safe. Detecta mas, "
            "y algunos scripts pueden dejar un servicio fragil inestable."
        ),
        ports="-p-",
        version=True,
        os_detect=True,
        scripts=NSE_VULN_DEEP_TLS,
        intrusive=True,
    ),
    "auditoria-tls": Profile(
        key="auditoria-tls",
        label="Auditoria TLS (cifrados y certificados)",
        description=(
            "Busca TLS en todos los puertos y enumera protocolos y cifrados. "
            "Es ruidoso porque abre muchas conexiones por servicio."
        ),
        ports="-p-",
        version=True,
        scripts="ssl-enum-ciphers or ssl-cert",
        intrusive=True,
    ),
    "udp-comun": Profile(
        key="udp-comun",
        label="UDP comun (200 puertos)",
        description=(
            "Los 200 puertos UDP mas frecuentes con deteccion de servicio y scripts "
            "seguros. Encuentra DNS, DHCP, SNMP, NTP, TFTP, VPN y servicios de descubrimiento. "
            "Necesita administrador y suele tardar mas que TCP."
        ),
        ports="--top-ports 200",
        version=True,
        os_detect=True,
        scripts="default and safe",
        timing="-T4",
        transport="udp",
    ),
    "udp-completo": Profile(
        key="udp-completo",
        label="UDP completo (65535 puertos, muy lento)",
        description=(
            "Todos los puertos UDP con deteccion de servicio. Puede tardar muchas horas "
            "por host porque la ausencia de respuesta no distingue abierto de filtrado. "
            "Usalo solo en una ventana de auditoria dedicada."
        ),
        ports="-p-",
        version=True,
        os_detect=True,
        timing="-T3",
        transport="udp",
        intrusive=True,
    ),
    "sigiloso": Profile(
        key="sigiloso",
        label="Sigiloso (lento, menos ruido)",
        description=(
            "Todos los puertos con temporizacion -T2 para no saturar la red ni "
            "disparar IDS por volumen. Tarda mucho mas."
        ),
        ports="-p-",
        version=True,
        timing="-T2",
    ),
}

DEFAULT_PROFILE = "vulnerabilidades"


def get_profile(key: str) -> Profile:
    try:
        return PROFILES[key]
    except KeyError:
        opciones = ", ".join(PROFILES)
        raise KeyError(f"Perfil '{key}' desconocido. Disponibles: {opciones}") from None
