"""Reglas propias sobre el servicio detectado.

Los scripts NSE cubren vulnerabilidades concretas y conocidas. Estas reglas
cubren lo otro: exposiciones y malas practicas que nmap ve pero no denuncia
(un telnet abierto no es un CVE, pero es un hallazgo). Es la parte que en
Nessus harian los plugins de tipo "service detection" y "generic exposure".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Assessment, Finding, Port, Service, Severity


@dataclass(frozen=True)
class ServiceRule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    ports: frozenset[int] = field(default=frozenset())
    services: frozenset[str] = field(default=frozenset())
    product_re: str | None = None
    protocols: frozenset[str] = field(default_factory=lambda: frozenset({"tcp"}))
    # Si el objetivo es publico, la exposicion pesa mas: sube un nivel.
    bump_if_public: bool = True

    def matches(self, port: Port) -> bool:
        if port.protocol not in self.protocols:
            return False
        svc = port.service
        # Un fingerprint activo fiable prevalece sobre el numero de puerto.
        if svc.method == "probed" and svc.confidence >= 7 and svc.name:
            by_name = svc.name.lower() in self.services
            by_product = bool(
                self.product_re and svc.product
                and re.search(self.product_re, svc.product, re.IGNORECASE)
            )
            return by_name or by_product
        if port.portid in self.ports:
            return True
        if svc.name and svc.name.lower() in self.services:
            return True
        if self.product_re and svc.product:
            return bool(re.search(self.product_re, svc.product, re.IGNORECASE))
        return False


SERVICE_RULES: tuple[ServiceRule, ...] = (
    ServiceRule(
        id="telnet-claro",
        title="Telnet expuesto (credenciales en claro)",
        severity=Severity.HIGH,
        description=(
            "Telnet transmite usuario, contrasena y toda la sesion sin cifrar. "
            "Cualquiera con acceso al camino de red puede leer las credenciales."
        ),
        remediation="Desactivar telnetd y sustituirlo por SSH. Cerrar el puerto 23 en el firewall.",
        ports=frozenset({23, 2323}),
        services=frozenset({"telnet"}),
    ),
    ServiceRule(
        id="ftp-claro",
        title="FTP accesible; comprobar TLS",
        severity=Severity.MEDIUM,
        description=(
            "FTP puede transmitir credenciales en claro si no exige TLS. Este escaneo "
            "no ha comprobado el modo de autenticacion ni el cifrado negociado."
        ),
        remediation=(
            "Migrar a SFTP o FTPS. Si el servicio debe seguir, desactivar el acceso anonimo."
        ),
        ports=frozenset({21}),
        services=frozenset({"ftp"}),
    ),
    ServiceRule(
        id="r-services",
        title="Servicios r* (rsh/rlogin/rexec) activos",
        severity=Severity.HIGH,
        description=(
            "Los servicios r* confian en la direccion de origen y envian todo en claro. "
            "Estan obsoletos desde hace decadas."
        ),
        remediation="Desinstalar rsh-server / rlogin y usar SSH con claves.",
        ports=frozenset({512, 513, 514}),
        services=frozenset({"exec", "login", "shell", "rsh", "rlogin"}),
    ),
    ServiceRule(
        id="smb-expuesto",
        title="SMB accesible",
        severity=Severity.MEDIUM,
        description=(
            "El servicio de ficheros de Windows esta accesible. SMB expuesto es la via "
            "de entrada mas explotada en redes internas (EternalBlue, relay NTLM, "
            "enumeracion de recursos)."
        ),
        remediation=(
            "Restringir 445/139 a la red de gestion, desactivar SMBv1, exigir firma SMB "
            "y no exponerlo nunca a Internet."
        ),
        ports=frozenset({139, 445}),
        services=frozenset({"microsoft-ds", "netbios-ssn", "smb"}),
    ),
    ServiceRule(
        id="rdp-expuesto",
        title="Escritorio remoto (RDP) accesible",
        severity=Severity.MEDIUM,
        description=(
            "RDP accesible es objetivo constante de fuerza bruta y de CVEs criticos "
            "(BlueKeep y sucesores)."
        ),
        remediation=(
            "Publicarlo solo tras VPN o gateway RD, exigir NLA, MFA y bloqueo por "
            "intentos fallidos."
        ),
        ports=frozenset({3389}),
        services=frozenset({"ms-wbt-server", "rdp"}),
    ),
    ServiceRule(
        id="vnc-expuesto",
        title="VNC accesible",
        severity=Severity.HIGH,
        description=(
            "VNC permite control remoto del escritorio. Su acceso por red debe "
            "limitarse; este escaneo no ha comprobado autenticacion ni cifrado."
        ),
        remediation="Tunelizar VNC por SSH o VPN y exigir autenticacion robusta.",
        ports=frozenset({5900, 5901, 5902, 5903}),
        services=frozenset({"vnc", "vnc-http"}),
    ),
    ServiceRule(
        id="x11-abierto",
        title="Servidor X11 accesible por red",
        severity=Severity.HIGH,
        description=(
            "X11 escucha en red. Si falta control de acceso, un tercero podria "
            "interactuar con la sesion; el puerto abierto no demuestra esa condicion."
        ),
        remediation="Arrancar X con -nolisten tcp y reenviar sesiones por SSH (-X).",
        ports=frozenset({6000, 6001}),
        services=frozenset({"x11"}),
    ),
    ServiceRule(
        id="db-nosql-expuesta",
        title="Servicio NoSQL/cache accesible",
        severity=Severity.HIGH,
        description=(
            "Se observa un servicio de datos accesible por red. Es necesario "
            "comprobar su autenticacion y permisos antes de afirmar acceso a datos."
        ),
        remediation=(
            "Escuchar solo en 127.0.0.1 o en la red interna, activar autenticacion y "
            "poner la instancia detras del firewall."
        ),
        ports=frozenset({6379, 27017, 27018, 11211, 9200, 9300}),
        services=frozenset({"redis", "mongodb", "memcached", "elasticsearch"}),
    ),
    ServiceRule(
        id="db-expuesta",
        title="Servidor de base de datos accesible",
        severity=Severity.MEDIUM,
        description=(
            "El puerto de la base de datos es alcanzable. Las bases de datos no deberian "
            "aceptar conexiones desde fuera de la capa de aplicacion."
        ),
        remediation=(
            "Limitar el acceso por firewall a los servidores de aplicacion y exigir TLS."
        ),
        ports=frozenset({1433, 1521, 3306, 5432, 5984}),
        services=frozenset({"mysql", "ms-sql-s", "postgresql", "oracle-tns", "couchdb"}),
    ),
    ServiceRule(
        id="snmp-expuesto",
        title="SNMP accesible",
        severity=Severity.MEDIUM,
        description=(
            "SNMP v1/v2c autentica con una community string en claro; con la community "
            "por defecto se puede enumerar interfaces, procesos, usuarios y topologia."
        ),
        remediation="Usar SNMPv3 con autenticacion y cifrado, o restringir por ACL.",
        ports=frozenset({161, 162}),
        services=frozenset({"snmp"}),
        protocols=frozenset({"udp"}),
    ),
    ServiceRule(
        id="tftp-expuesto",
        title="TFTP accesible",
        severity=Severity.MEDIUM,
        description=(
            "TFTP no tiene autenticacion; suele servir configuraciones de equipos de red."
        ),
        remediation="Desactivarlo o limitarlo a la VLAN de aprovisionamiento.",
        ports=frozenset({69}),
        services=frozenset({"tftp"}),
        protocols=frozenset({"udp"}),
    ),
    ServiceRule(
        id="dns-udp-expuesto",
        title="Servicio DNS accesible por UDP",
        severity=Severity.LOW,
        description=(
            "El servidor DNS responde por UDP. Si permite recursion a clientes no autorizados "
            "puede filtrar consultas internas y participar en ataques de amplificacion."
        ),
        remediation=(
            "Limitar la recursion a redes de confianza, aplicar response-rate limiting y "
            "restringir las transferencias de zona."
        ),
        ports=frozenset({53}),
        services=frozenset({"domain", "dns"}),
        protocols=frozenset({"udp"}),
    ),
    ServiceRule(
        id="ntp-udp-expuesto",
        title="Servicio NTP accesible por UDP",
        severity=Severity.LOW,
        description=(
            "NTP responde por UDP. Las configuraciones antiguas pueden exponer informacion "
            "del sistema o utilizarse para amplificacion de trafico."
        ),
        remediation="Restringir clientes, desactivar consultas legacy y mantener ntpd/chrony actualizado.",
        ports=frozenset({123}),
        services=frozenset({"ntp"}),
        protocols=frozenset({"udp"}),
    ),
    ServiceRule(
        id="ssdp-udp-expuesto",
        title="Descubrimiento SSDP/UPnP accesible",
        severity=Severity.MEDIUM,
        description=(
            "SSDP anuncia dispositivos y servicios por UDP. No debe ser alcanzable desde "
            "redes no confiables y ha sido abusado para reflexion y amplificacion."
        ),
        remediation="Desactivar UPnP si no es necesario y filtrar UDP/1900 entre segmentos.",
        ports=frozenset({1900}),
        services=frozenset({"upnp", "ssdp"}),
        protocols=frozenset({"udp"}),
    ),
    ServiceRule(
        id="cldap-udp-expuesto",
        title="CLDAP accesible por UDP",
        severity=Severity.MEDIUM,
        description=(
            "CLDAP puede revelar informacion del dominio y actuar como reflector UDP cuando "
            "queda accesible fuera de la red de directorio."
        ),
        remediation="Permitir UDP/389 solo entre clientes autorizados y controladores de dominio.",
        ports=frozenset({389}),
        services=frozenset({"cldap", "ldap"}),
        protocols=frozenset({"udp"}),
    ),
    ServiceRule(
        id="netbios-udp-expuesto",
        title="NetBIOS accesible por UDP",
        severity=Severity.MEDIUM,
        description=(
            "NetBIOS Name Service permite enumerar nombres y facilita ataques de suplantacion "
            "y captura de credenciales en redes Windows."
        ),
        remediation="Deshabilitar NetBIOS sobre TCP/IP cuando no sea necesario y filtrar UDP/137-138.",
        ports=frozenset({137, 138}),
        services=frozenset({"netbios-ns", "netbios-dgm"}),
        protocols=frozenset({"udp"}),
    ),
    ServiceRule(
        id="http-sin-tls",
        title="HTTP sin cifrar",
        severity=Severity.LOW,
        description=(
            "Se detecta HTTP sin TLS. Si se transmiten credenciales o cookies por "
            "esta conexion, podrian quedar expuestas en la red."
        ),
        remediation="Comprobar el uso del servicio y exigir TLS si transporta datos sensibles.",
        ports=frozenset({80, 8080, 8000, 8008}),
        services=frozenset({"http"}),
    ),
    ServiceRule(
        id="correo-sin-tls",
        title="Servicio de correo posiblemente sin TLS",
        severity=Severity.LOW,
        description=(
            "SMTP/POP3/IMAP en su puerto en claro. Si no fuerza STARTTLS, las "
            "credenciales del buzon viajan legibles."
        ),
        remediation="Exigir STARTTLS o usar los puertos implicitos 465/993/995.",
        ports=frozenset({25, 110, 143}),
        services=frozenset({"smtp", "pop3", "imap"}),
    ),
)


def _version_tuple(version: str) -> tuple[int, ...]:
    """Convierte 8.2p1 o 2.4.49 en una tupla comparable."""
    nums = re.findall(r"\d+", version)
    return tuple(int(n) for n in nums[:3]) or (0,)


@dataclass(frozen=True)
class VersionRule:
    id: str
    product_re: str
    below: tuple[int, ...]
    title: str
    severity: Severity
    description: str
    remediation: str

    def matches(self, service: Service) -> bool:
        if not service.version:
            return False
        haystack = f"{service.product} {service.version}"
        if not re.search(self.product_re, haystack, re.IGNORECASE):
            return False
        return _version_tuple(service.version) < self.below


# Estos umbrales solo crean candidatos: el banner puede no reflejar parches
# retroportados y una vulnerabilidad puede depender de la configuracion.
VERSION_RULES: tuple[VersionRule, ...] = (
    VersionRule(
        id="openssh-antiguo",
        product_re=r"OpenSSH",
        below=(7, 4),
        title="OpenSSH en version antigua",
        severity=Severity.MEDIUM,
        description=(
            "El banner indica una version antigua de OpenSSH. Hay que comprobar "
            "la version del paquete y los parches de la distribucion."
        ),
        remediation="Actualizar OpenSSH a una version soportada por la distribucion.",
    ),
    VersionRule(
        id="apache-antiguo",
        product_re=r"Apache httpd",
        below=(2, 4, 52),
        title="Apache httpd desactualizado",
        severity=Severity.MEDIUM,
        description=(
            "El banner indica una version antigua de Apache httpd. Solo algunas "
            "revisiones y configuraciones presentan fallos concretos; verificar parches."
        ),
        remediation=(
            "Actualizar a la ultima 2.4.x y revisar las directivas Require de los Directory."
        ),
    ),
    VersionRule(
        id="nginx-antiguo",
        product_re=r"nginx",
        below=(1, 20),
        title="nginx desactualizado",
        severity=Severity.LOW,
        description="El banner indica una version antigua; verificar soporte y parches del proveedor.",
        remediation="Actualizar a una rama estable con soporte.",
    ),
    VersionRule(
        id="samba-antiguo",
        product_re=r"Samba smbd",
        below=(4, 6, 4),
        title="Samba desactualizado",
        severity=Severity.HIGH,
        description=(
            "El banner es anterior a 4.6.4. Comprobar el parche del proveedor y "
            "si existe un recurso escribible antes de evaluar CVE-2017-7494."
        ),
        remediation="Actualizar Samba y desactivar SMBv1.",
    ),
)


def bump(severity: Severity) -> Severity:
    """Sube un nivel de severidad, sin pasar de critica."""
    return Severity(min(int(severity) + 1, int(Severity.CRITICAL)))


def evaluate_port(host_address: str, port: Port, *, target_is_private: bool) -> list[Finding]:
    """Aplica las reglas propias a un puerto abierto."""
    findings: list[Finding] = []
    if not port.is_open:
        return findings

    svc = port.service
    matched_exposure = False

    # El puerto 16992 es una pista de AMT; ni el firmware vulnerable ni el
    # aprovisionamiento quedan demostrados por el banner de nmap.
    is_amt = (
        port.portid in (16992, 16993)
        and "active management technology" in svc.product.lower()
    )
    if is_amt:
        findings.append(Finding(
            title="Servicio asociado a Intel AMT accesible",
            severity=Severity.MEDIUM if target_is_private else Severity.HIGH,
            source="rule:amt-expuesto", host=host_address, port=port.portid,
            protocol=port.protocol, service=svc.display,
            description=("Servicio Intel AMT detectado por red. Verificar si la gestion "
                         "remota esta aprovisionada, la version real del firmware y su necesidad."),
            evidence=f"{port.portid}/{port.protocol} abierto - {svc.display}",
            remediation="Limitar el acceso a la red de gestion y comprobar firmware con el OEM.",
        ))

    for rule in SERVICE_RULES:
        if is_amt and rule.id == "http-sin-tls":
            continue
        if rule.id in ("http-sin-tls", "ftp-claro") and svc.tunnel in ("ssl", "tls"):
            continue
        if not rule.matches(port):
            continue
        # La regla generica de base de datos no debe duplicar a la de NoSQL sin auth.
        if rule.id == "db-expuesta" and matched_exposure:
            continue
        severity = rule.severity
        extra = ""
        if rule.bump_if_public and not target_is_private:
            severity = bump(severity)
            extra = " El objetivo esta fuera de rango privado, lo que agrava la exposicion."
        probed = svc.method == "probed" and svc.confidence >= 7
        inference = (
            "El tipo de servicio se infiere del puerto; nmap no obtuvo un fingerprint fiable. "
            if not probed else ""
        )
        findings.append(
            Finding(
                title=rule.title if probed else f"{rule.title} (servicio inferido)",
                severity=severity,
                source=f"rule:{rule.id}",
                host=host_address,
                port=port.portid,
                protocol=port.protocol,
                service=svc.display,
                description=inference + rule.description + extra,
                evidence=(f"{port.portid}/{port.protocol} abierto - {svc.display}; "
                          f"deteccion nmap: {svc.method or 'desconocida'}, "
                          f"confianza {svc.confidence}"),
                remediation=rule.remediation,
            )
        )
        matched_exposure = True

    for vrule in VERSION_RULES:
        if vrule.matches(svc):
            findings.append(
                Finding(
                    title=f"{vrule.title}: {svc.product} {svc.version}",
                    severity=vrule.severity,
                    source=f"rule:{vrule.id}",
                    host=host_address,
                    port=port.portid,
                    protocol=port.protocol,
                    service=svc.display,
                    description=vrule.description,
                    evidence=f"Version detectada por nmap: {svc.product} {svc.version}",
                    remediation=vrule.remediation,
                    assessment=Assessment.CANDIDATE,
                )
            )

    return findings
