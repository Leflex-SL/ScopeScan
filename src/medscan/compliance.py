"""Resultados trazables de controles autenticados.

No declara conformidad global con CIS ni ENS: conserva el resultado tecnico de
cada comprobacion y las referencias a las que aporta evidencia.
"""

from __future__ import annotations

from typing import Any

VALID_STATUSES = {"pass", "fail", "unknown", "not_applicable"}


def _control(
    control_id: str, title: str, status: str, evidence: str,
    references: list[str] | None = None,
) -> dict[str, Any]:
    if status not in VALID_STATUSES:
        raise ValueError(f"Estado de control invalido: {status}")
    return {
        "control_id": control_id,
        "title": title,
        "status": status,
        "evidence": evidence,
        "references": references or [],
    }


def _boolean(
    control_id: str, title: str, value: bool | None, *, good: bool,
    observed: str, references: list[str] | None = None,
) -> dict[str, Any]:
    status = "unknown" if value is None else "pass" if value is good else "fail"
    evidence = "Sin dato concluyente" if value is None else f"{observed} = {value}"
    return _control(control_id, title, status, evidence, references)


def windows_controls(inventory: dict, open_tcp_ports: set[int]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    smb = inventory.get("smb_server")
    if 445 not in open_tcp_ports:
        controls.extend([
            _control("WIN-SMB1", "SMBv1 deshabilitado", "not_applicable", "Puerto 445 cerrado"),
            _control("WIN-SMB-SIGN", "Firma SMB obligatoria", "not_applicable", "Puerto 445 cerrado"),
        ])
    else:
        controls.append(_boolean(
            "WIN-SMB1", "SMBv1 deshabilitado",
            smb.get("smb1_enabled") if isinstance(smb, dict) else None,
            good=False, observed="EnableSMB1Protocol",
        ))
        controls.append(_boolean(
            "WIN-SMB-SIGN", "Firma SMB obligatoria",
            smb.get("signing_required") if isinstance(smb, dict) else None,
            good=True, observed="RequireSecuritySignature",
        ))

    rdp = inventory.get("rdp")
    if 3389 not in open_tcp_ports:
        controls.append(_control(
            "WIN-RDP-NLA", "RDP exige NLA", "not_applicable", "Puerto 3389 cerrado"
        ))
    else:
        controls.append(_boolean(
            "WIN-RDP-NLA", "RDP exige NLA",
            rdp.get("nla_required") if isinstance(rdp, dict) else None,
            good=True, observed="UserAuthentication efectivo",
        ))

    profiles = [item for item in inventory.get("firewall_profiles") or []
                if isinstance(item, dict) and item.get("active") is True]
    if not profiles:
        controls.append(_control(
            "WIN-FIREWALL", "Firewall habilitado en perfiles activos", "unknown",
            inventory.get("firewall_note") or "No se identifico ningun perfil activo",
            ["CIS Controls v8.1 4.4"],
        ))
    else:
        enabled = all(item.get("enabled") is True for item in profiles)
        detail = ", ".join(
            f"{item.get('name', '?')}={'on' if item.get('enabled') is True else 'off'}"
            for item in profiles
        )
        controls.append(_control(
            "WIN-FIREWALL", "Firewall habilitado en perfiles activos",
            "pass" if enabled else "fail", detail, ["CIS Controls v8.1 4.4"],
        ))

    defender = inventory.get("defender")
    controls.append(_boolean(
        "WIN-ANTIMALWARE", "Proteccion antimalware en tiempo real",
        defender.get("realtime_enabled") if isinstance(defender, dict)
        and defender.get("antivirus_enabled") is True else None,
        good=True, observed="RealTimeProtectionEnabled",
        references=["CIS Controls v8.1 10.1"],
    ))
    age = defender.get("signature_age_days") if isinstance(defender, dict) \
        and defender.get("antivirus_enabled") is True else None
    controls.append(_control(
        "WIN-AV-SIGNATURES", "Firmas antimalware con antiguedad maxima de 7 dias",
        "unknown" if not isinstance(age, int) else "pass" if age <= 7 else "fail",
        "Sin dato concluyente" if not isinstance(age, int) else f"AntivirusSignatureAge = {age} dias",
        ["CIS Controls v8.1 10.2", "ENS RD 311/2022 art. 21"],
    ))
    controls.append(_boolean(
        "WIN-UAC", "UAC habilitado", inventory.get("uac_enabled"),
        good=True, observed="EnableLUA",
    ))
    bitlocker = inventory.get("bitlocker")
    protection = bitlocker.get("protection_status") if isinstance(bitlocker, dict) else None
    controls.append(_control(
        "WIN-DISK-ENCRYPTION", "Proteccion de cifrado del volumen del sistema",
        "unknown" if protection is None else "pass" if protection == "On" else "fail",
        "Sin dato concluyente" if protection is None else f"ProtectionStatus = {protection}",
        ["CIS Controls v8.1 3.6", "ENS mp.eq.3.r1.1 cuando resulte aplicable"],
    ))
    controls.append(_boolean(
        "WIN-SECURE-BOOT", "Secure Boot habilitado", inventory.get("secure_boot_enabled"),
        good=True, observed="Confirm-SecureBootUEFI",
        references=["CIS Controls v8.1 10.5"],
    ))
    guest = inventory.get("guest_account")
    controls.append(_boolean(
        "WIN-GUEST", "Cuenta Guest local deshabilitada",
        guest.get("enabled") if isinstance(guest, dict) else None,
        good=False, observed="Cuenta local RID 501 Enabled",
    ))
    controls.append(_boolean(
        "WIN-LLMNR", "LLMNR deshabilitado", inventory.get("llmnr_enabled"),
        good=False, observed="LLMNR enabled",
    ))
    winrm = inventory.get("winrm")
    if 5985 in open_tcp_ports:
        controls.append(_boolean(
            "WIN-WINRM-UNENCRYPTED", "WinRM rechaza mensajes sin cifrar",
            winrm.get("allow_unencrypted") if isinstance(winrm, dict) else None,
            good=False, observed="WSMan AllowUnencrypted",
        ))
        controls.append(_boolean(
            "WIN-WINRM-BASIC", "WinRM HTTP no admite autenticacion Basic",
            winrm.get("basic_auth") if isinstance(winrm, dict) else None,
            good=False, observed="WSMan Auth.Basic",
        ))
    else:
        controls.extend([
            _control("WIN-WINRM-UNENCRYPTED", "WinRM rechaza mensajes sin cifrar",
                     "not_applicable", "Puerto 5985 cerrado"),
            _control("WIN-WINRM-BASIC", "WinRM HTTP no admite autenticacion Basic",
                     "not_applicable", "Puerto 5985 cerrado"),
        ])
    remote_registry = inventory.get("remote_registry")
    controls.append(_boolean(
        "WIN-REMOTE-REGISTRY", "Remote Registry detenido",
        remote_registry.get("running") if isinstance(remote_registry, dict) else None,
        good=False, observed="RemoteRegistry Running",
    ))
    return controls


def linux_controls(inventory: dict, open_tcp_ports: set[int]) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    ssh_port = inventory.get("ssh_port", 22)
    sshd = inventory.get("sshd")
    if ssh_port not in open_tcp_ports:
        controls.extend([
            _control("LINUX-SSH-ROOT", "SSH no permite acceso directo de root",
                     "not_applicable", f"Puerto {ssh_port} cerrado"),
            _control("LINUX-SSH-PASSWORD", "SSH no acepta contrasenas",
                     "not_applicable", f"Puerto {ssh_port} cerrado"),
        ])
    else:
        root = sshd.get("permit_root_login") if isinstance(sshd, dict) else None
        password = sshd.get("password_authentication") if isinstance(sshd, dict) else None
        controls.append(_control(
            "LINUX-SSH-ROOT", "SSH no permite acceso directo de root",
            "unknown" if root is None else "pass" if root != "yes" else "fail",
            "Sin dato concluyente" if root is None else f"permitrootlogin = {root}",
        ))
        controls.append(_control(
            "LINUX-SSH-PASSWORD", "SSH no acepta contrasenas",
            "unknown" if password is None else "pass" if password != "yes" else "fail",
            "Sin dato concluyente" if password is None else f"passwordauthentication = {password}",
        ))
        empty = sshd.get("permit_empty_passwords") if isinstance(sshd, dict) else None
        controls.append(_control(
            "LINUX-SSH-EMPTY", "SSH rechaza contrasenas vacias",
            "unknown" if empty is None else "pass" if empty != "yes" else "fail",
            "Sin dato concluyente" if empty is None else f"permitemptypasswords = {empty}",
        ))
        max_tries = sshd.get("max_auth_tries") if isinstance(sshd, dict) else None
        try:
            parsed_tries = int(max_tries) if max_tries is not None else None
        except ValueError:
            parsed_tries = None
        controls.append(_control(
            "LINUX-SSH-MAXAUTH", "SSH limita intentos por conexion a 6",
            "unknown" if parsed_tries is None else "pass" if parsed_tries <= 6 else "fail",
            "Sin dato concluyente" if parsed_tries is None else f"maxauthtries = {parsed_tries}",
        ))

    firewall = inventory.get("firewall")
    observed = isinstance(firewall, dict) and firewall.get("observed") is True
    active = firewall.get("active") if observed else None
    controls.append(_boolean(
        "LINUX-FIREWALL", "Firewall local activo", active,
        good=True, observed="Politica local observada",
        references=["CIS Controls v8.1 4.4"],
    ))
    aslr = inventory.get("aslr")
    controls.append(_control(
        "LINUX-ASLR", "ASLR completo habilitado",
        "unknown" if aslr is None else "pass" if aslr == 2 else "fail",
        "Sin dato concluyente" if aslr is None else f"kernel.randomize_va_space = {aslr}",
        ["CIS Controls v8.1 10.5"],
    ))
    os_id = inventory.get("os_id")
    if os_id in {"rhel", "centos", "rocky", "almalinux", "fedora"}:
        selinux = inventory.get("selinux")
        controls.append(_control(
            "LINUX-MAC", "Control de acceso obligatorio activo",
            "unknown" if selinux is None else "pass" if selinux == "enforcing" else "fail",
            "Sin dato concluyente" if selinux is None else f"SELinux = {selinux}",
        ))
    elif os_id in {"ubuntu", "debian", "opensuse", "sles"}:
        apparmor = inventory.get("apparmor")
        controls.append(_control(
            "LINUX-MAC", "Control de acceso obligatorio activo",
            "unknown" if apparmor is None else "pass" if apparmor in {"y", "yes"} else "fail",
            "Sin dato concluyente" if apparmor is None else f"AppArmor = {apparmor}",
        ))
    controls.append(_control(
        "LINUX-REBOOT", "Sin reinicio pendiente tras actualizaciones",
        "fail" if inventory.get("reboot_required") is True else "pass",
        f"reboot_required = {bool(inventory.get('reboot_required'))}",
        ["ENS RD 311/2022 art. 21"],
    ))
    checked = inventory.get("security_updates_checked") is True
    updates = inventory.get("security_updates") or []
    controls.append(_control(
        "LINUX-SECURITY-UPDATES", "Sin actualizaciones de seguridad pendientes",
        "unknown" if not checked else "pass" if not updates else "fail",
        "El gestor no ofrece metadatos de seguridad concluyentes" if not checked
        else f"Actualizaciones de seguridad pendientes: {len(updates)}",
        ["ENS RD 311/2022 art. 21"],
    ))
    return controls
