"""Hallazgos basados en ajustes leidos dentro del equipo Windows."""

from __future__ import annotations

from .models import Assessment, Finding, Severity


def windows_findings(
    host: str, inventory: dict, open_tcp_ports: set[int]
) -> list[Finding]:
    """Solo afirma controles con un valor booleano observado y servicio accesible."""
    findings: list[Finding] = []
    smb = inventory.get("smb_server")
    if isinstance(smb, dict) and 445 in open_tcp_ports:
        if smb.get("smb1_enabled") is True:
            findings.append(Finding(
                title="SMBv1 habilitado en servidor Windows",
                severity=Severity.HIGH,
                source="auth:windows:smb1", host=host, port=445,
                service="SMB", assessment=Assessment.CONFIRMED, confirmed=True,
                description=("La configuracion local confirma que el servidor SMB acepta "
                             "SMBv1 y el puerto 445 es accesible desde el escaner."),
                evidence="Get-SmbServerConfiguration.EnableSMB1Protocol = True",
                remediation="Deshabilitar SMBv1 tras comprobar las dependencias heredadas.",
            ))
        if smb.get("signing_required") is False:
            findings.append(Finding(
                title="Firma SMB no obligatoria",
                severity=Severity.MEDIUM,
                source="auth:windows:smb-signing", host=host, port=445,
                service="SMB", assessment=Assessment.CONFIRMED, confirmed=True,
                description=("La configuracion local confirma que el servidor no exige "
                             "firma SMB en las conexiones entrantes."),
                evidence="Get-SmbServerConfiguration.RequireSecuritySignature = False",
                remediation="Exigir firma SMB si los clientes compatibles lo permiten.",
            ))

    rdp = inventory.get("rdp")
    if isinstance(rdp, dict) and 3389 in open_tcp_ports and rdp.get("nla_required") is False:
        findings.append(Finding(
            title="RDP accesible sin exigir NLA",
            severity=Severity.HIGH,
            source="auth:windows:rdp-nla", host=host, port=3389,
            service="RDP", assessment=Assessment.CONFIRMED, confirmed=True,
            description=("La configuracion local no exige autenticacion a nivel de red "
                         "antes de establecer la sesion RDP."),
            evidence=("UserAuthentication efectivo = 0; origen: "
                      f"{rdp.get('nla_source') or 'desconocido'}"),
            remediation="Exigir Network Level Authentication para RDP.",
        ))

    for profile in inventory.get("firewall_profiles") or []:
        if isinstance(profile, dict) and profile.get("active") is True \
                and profile.get("enabled") is False:
            name = str(profile.get("name") or "desconocido")
            findings.append(Finding(
                title=f"Firewall de Windows deshabilitado en el perfil activo {name}",
                severity=Severity.HIGH,
                source=f"auth:windows:firewall:{name.lower()}", host=host,
                protocol="host", assessment=Assessment.CONFIRMED, confirmed=True,
                description=("La politica efectiva de Firewall de Windows esta deshabilitada "
                             "para un perfil de red actualmente activo."),
                evidence=f"Get-NetFirewallProfile {name}: Enabled=False, Active=True",
                remediation="Habilitar el Firewall de Windows en el perfil activo.",
            ))

    defender = inventory.get("defender")
    if isinstance(defender, dict) and defender.get("antivirus_enabled") is True:
        if defender.get("realtime_enabled") is False:
            findings.append(Finding(
                title="Proteccion en tiempo real de Microsoft Defender deshabilitada",
                severity=Severity.HIGH,
                source="auth:windows:defender-realtime", host=host,
                protocol="host", assessment=Assessment.CONFIRMED, confirmed=True,
                description=("Microsoft Defender figura como antivirus activo, pero su "
                             "proteccion en tiempo real esta deshabilitada."),
                evidence="Get-MpComputerStatus.RealTimeProtectionEnabled = False",
                remediation="Habilitar la proteccion en tiempo real y revisar la politica aplicada.",
            ))
        signature_age = defender.get("signature_age_days")
        if isinstance(signature_age, int) and signature_age > 7:
            findings.append(Finding(
                title="Firmas de Microsoft Defender desactualizadas",
                severity=Severity.MEDIUM,
                source="auth:windows:defender-signatures", host=host,
                protocol="host", assessment=Assessment.CONFIRMED, confirmed=True,
                description="Las firmas antivirus observadas tienen mas de siete dias.",
                evidence=f"AntivirusSignatureAge = {signature_age} dias",
                remediation="Actualizar las firmas y comprobar el canal de actualizaciones.",
            ))

    if inventory.get("uac_enabled") is False:
        findings.append(Finding(
            title="Control de cuentas de usuario (UAC) deshabilitado",
            severity=Severity.HIGH,
            source="auth:windows:uac", host=host,
            protocol="host", assessment=Assessment.CONFIRMED, confirmed=True,
            description="El valor local EnableLUA confirma que UAC esta deshabilitado.",
            evidence="HKLM Policies\\System\\EnableLUA = 0",
            remediation="Habilitar UAC y reiniciar el equipo dentro de una ventana de mantenimiento.",
        ))

    bitlocker = inventory.get("bitlocker")
    if isinstance(bitlocker, dict) and bitlocker.get("protection_status") == "Off":
        findings.append(Finding(
            title="Volumen del sistema sin proteccion BitLocker",
            severity=Severity.MEDIUM,
            source="auth:windows:bitlocker", host=host,
            protocol="host", assessment=Assessment.CONFIRMED, confirmed=True,
            description="BitLocker informa que la proteccion del volumen del sistema esta desactivada.",
            evidence=(f"{bitlocker.get('mount_point', '')}: ProtectionStatus=Off; "
                      f"VolumeStatus={bitlocker.get('volume_status', '')}"),
            remediation="Habilitar BitLocker y custodiar la clave de recuperacion.",
        ))
    if inventory.get("secure_boot_enabled") is False:
        findings.append(Finding(
            title="Secure Boot deshabilitado",
            severity=Severity.MEDIUM,
            source="auth:windows:secure-boot", host=host,
            protocol="host", assessment=Assessment.CONFIRMED, confirmed=True,
            description="El firmware UEFI informa que Secure Boot esta deshabilitado.",
            evidence="Confirm-SecureBootUEFI = False",
            remediation="Habilitar Secure Boot en UEFI tras comprobar compatibilidad y BitLocker.",
        ))
    guest = inventory.get("guest_account")
    if isinstance(guest, dict) and guest.get("enabled") is True:
        findings.append(Finding(
            title="Cuenta Guest local habilitada",
            severity=Severity.HIGH,
            source="auth:windows:guest", host=host,
            protocol="host", assessment=Assessment.CONFIRMED, confirmed=True,
            description="La cuenta local con RID 501 esta habilitada.",
            evidence=f"Cuenta {guest.get('name') or 'Guest'} (SID *-501): Enabled=True",
            remediation="Deshabilitar la cuenta Guest local y revisar los inicios de sesion asociados.",
        ))
    if inventory.get("llmnr_enabled") is True:
        findings.append(Finding(
            title="LLMNR habilitado en Windows",
            severity=Severity.MEDIUM,
            source="auth:windows:llmnr", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description=("La resolucion multicast LLMNR esta habilitada y puede facilitar "
                         "suplantacion de nombres y captura de autenticacion NTLM."),
            evidence=f"LLMNR enabled; origen: {inventory.get('llmnr_source') or 'desconocido'}",
            remediation="Habilitar la politica 'Turn off multicast name resolution'.",
        ))
    winrm = inventory.get("winrm")
    if isinstance(winrm, dict) and 5985 in open_tcp_ports:
        if winrm.get("allow_unencrypted") is True:
            findings.append(Finding(
                title="WinRM permite trafico sin cifrar",
                severity=Severity.HIGH,
                source="auth:windows:winrm-unencrypted", host=host, port=5985,
                service="WinRM", assessment=Assessment.CONFIRMED, confirmed=True,
                description="WinRM por HTTP esta accesible y acepta mensajes sin cifrado.",
                evidence="WSMan Service.AllowUnencrypted = True; 5985/tcp abierto",
                remediation="Deshabilitar AllowUnencrypted y configurar un listener HTTPS.",
            ))
        if winrm.get("basic_auth") is True:
            findings.append(Finding(
                title="WinRM Basic habilitado sobre endpoint HTTP accesible",
                severity=Severity.HIGH,
                source="auth:windows:winrm-basic", host=host, port=5985,
                service="WinRM", assessment=Assessment.CONFIRMED, confirmed=True,
                description="La autenticacion Basic esta habilitada y el listener HTTP es accesible.",
                evidence="WSMan Service.Auth.Basic = True; 5985/tcp abierto",
                remediation="Deshabilitar Basic o limitarlo a WinRM HTTPS con controles compensatorios.",
            ))
    remote_registry = inventory.get("remote_registry")
    if isinstance(remote_registry, dict) and remote_registry.get("running") is True:
        findings.append(Finding(
            title="Servicio Remote Registry en ejecucion",
            severity=Severity.MEDIUM,
            source="auth:windows:remote-registry", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description="El servicio Remote Registry esta iniciado y amplia la superficie administrativa.",
            evidence="Get-Service RemoteRegistry: Status=Running",
            remediation="Detener y deshabilitar Remote Registry si no existe una necesidad operativa.",
        ))
    return findings


def collected_ssh_port(inventory: dict) -> int | None:
    """Legacy inventories without explicit collection endpoint establish no SSH binding."""
    value = inventory.get("ssh_port")
    return value if type(value) is int and 1 <= value <= 65535 else None


def linux_findings(host: str, inventory: dict, open_tcp_ports: set[int]) -> list[Finding]:
    """Convierte valores efectivos observados en hallazgos Linux confirmados."""
    findings: list[Finding] = []
    sshd = inventory.get("sshd")
    ssh_port = collected_ssh_port(inventory)
    if isinstance(sshd, dict) and ssh_port is not None and ssh_port in open_tcp_ports:
        if sshd.get("permit_root_login") == "yes":
            findings.append(Finding(
                title="SSH permite acceso directo de root",
                severity=Severity.HIGH,
                source="auth:linux:ssh-root", host=host, port=ssh_port,
                service="SSH", assessment=Assessment.CONFIRMED, confirmed=True,
                description="La configuracion efectiva de sshd permite iniciar sesion como root.",
                evidence="sshd -T: permitrootlogin yes",
                remediation="Configurar PermitRootLogin no y usar una cuenta nominal con sudo.",
            ))
        if sshd.get("password_authentication") == "yes":
            findings.append(Finding(
                title="SSH permite autenticacion por contrasena",
                severity=Severity.MEDIUM,
                source="auth:linux:ssh-password", host=host, port=ssh_port,
                service="SSH", assessment=Assessment.CONFIRMED, confirmed=True,
                description="La configuracion efectiva de sshd acepta contrasenas en el servicio expuesto.",
                evidence="sshd -T: passwordauthentication yes",
                remediation="Migrar a claves o certificados y deshabilitar PasswordAuthentication.",
            ))
        if sshd.get("permit_empty_passwords") == "yes":
            findings.append(Finding(
                title="SSH permite cuentas con contrasena vacia",
                severity=Severity.CRITICAL,
                source="auth:linux:ssh-empty-passwords", host=host, port=ssh_port,
                service="SSH", assessment=Assessment.CONFIRMED, confirmed=True,
                description="La configuracion efectiva de sshd permite autenticar cuentas sin contrasena.",
                evidence="sshd -T: permitemptypasswords yes",
                remediation="Configurar PermitEmptyPasswords no y bloquear cuentas sin credencial.",
            ))
        try:
            max_auth_tries = int(sshd.get("max_auth_tries") or 0)
        except ValueError:
            max_auth_tries = 0
        if max_auth_tries > 6:
            findings.append(Finding(
                title="SSH permite demasiados intentos por conexion",
                severity=Severity.LOW,
                source="auth:linux:ssh-max-auth-tries", host=host, port=ssh_port,
                service="SSH", assessment=Assessment.CONFIRMED, confirmed=True,
                description="MaxAuthTries supera seis intentos por conexion SSH.",
                evidence=f"sshd -T: maxauthtries {max_auth_tries}",
                remediation="Reducir MaxAuthTries a 6 o menos y aplicar proteccion ante fuerza bruta.",
            ))

    firewall = inventory.get("firewall")
    if isinstance(firewall, dict) and firewall.get("observed") is True \
            and firewall.get("active") is False:
        findings.append(Finding(
            title="Sin reglas activas de firewall local en Linux",
            severity=Severity.MEDIUM,
            source="auth:linux:firewall", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description="Los gestores de firewall observados no muestran una politica local activa.",
            evidence=firewall.get("detail") or "Firewall local inactivo",
            remediation="Aplicar una politica de minimo acceso con nftables, firewalld o ufw.",
        ))

    if inventory.get("aslr") == 0:
        findings.append(Finding(
            title="ASLR deshabilitado en Linux",
            severity=Severity.HIGH,
            source="auth:linux:aslr", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description="El kernel informa que la aleatorizacion del espacio de direcciones esta desactivada.",
            evidence="kernel.randomize_va_space = 0",
            remediation="Establecer kernel.randomize_va_space=2 y persistirlo con sysctl.",
        ))

    if inventory.get("os_id") in {"rhel", "centos", "rocky", "almalinux", "fedora"} \
            and inventory.get("selinux") == "disabled":
        findings.append(Finding(
            title="SELinux deshabilitado",
            severity=Severity.MEDIUM,
            source="auth:linux:selinux", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description="SELinux esta deshabilitado en una distribucion que lo integra de forma nativa.",
            evidence="getenforce = Disabled",
            remediation="Activar SELinux en modo enforcing tras resolver las denegaciones necesarias.",
        ))

    if inventory.get("apparmor") in {"n", "no", "disabled"}:
        findings.append(Finding(
            title="AppArmor cargado pero deshabilitado",
            severity=Severity.MEDIUM,
            source="auth:linux:apparmor", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description="El modulo AppArmor esta presente y su parametro indica que esta deshabilitado.",
            evidence=f"/sys/module/apparmor/parameters/enabled = {inventory['apparmor']}",
            remediation="Habilitar AppArmor y aplicar perfiles a los servicios expuestos.",
        ))

    if inventory.get("reboot_required") is True:
        findings.append(Finding(
            title="Reinicio pendiente tras actualizaciones Linux",
            severity=Severity.LOW,
            source="auth:linux:reboot", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description="El sistema mantiene el marcador de reinicio requerido.",
            evidence="/var/run/reboot-required existe",
            remediation="Programar un reinicio y volver a comprobar el kernel activo.",
        ))
    security_updates = inventory.get("security_updates") or []
    if inventory.get("security_updates_checked") is True and security_updates:
        names = ", ".join(str(item.get("name") or "?") for item in security_updates[:20])
        findings.append(Finding(
            title="Actualizaciones de seguridad Linux pendientes",
            severity=Severity.HIGH,
            source="auth:linux:security-updates", host=host, protocol="host",
            assessment=Assessment.CONFIRMED, confirmed=True,
            description=("El gestor de paquetes, con los metadatos locales actuales, "
                         "ofrece actualizaciones procedentes del canal de seguridad."),
            evidence=f"{len(security_updates)} paquetes: {names}",
            remediation="Actualizar desde los repositorios oficiales y reiniciar si procede.",
        ))
    return findings
