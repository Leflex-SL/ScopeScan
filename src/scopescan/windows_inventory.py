"""Inventario de Windows por PowerShell Remoting con la identidad del proceso.

No acepta contraseñas ni las guarda. El destino debe pertenecer a un escaneo
autorizado y WinRM debe estar configurado por el administrador del equipo.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import shutil
import subprocess
import sys

from . import db
from .authenticated_checks import windows_findings
from .compliance import windows_controls

SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$collect = {
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    $bios = $null
    try { $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop } catch { }
    $windows = $null
    try {
        $windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    } catch { }
    $updates = @()
    $updateError = $null
    try {
        $updates = @(Get-HotFix | ForEach-Object {
            [pscustomobject]@{ kb = $_.HotFixID; installed_on = [string]$_.InstalledOn }
        })
    } catch { $updateError = $_.Exception.Message }
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $software = @($paths | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -and $_.DisplayVersion } | ForEach-Object {
            [pscustomobject]@{
                name = [string]$_.DisplayName
                version = [string]$_.DisplayVersion
                publisher = [string]$_.Publisher
            }
        } | Sort-Object name, version -Unique | Select-Object -First 2000)
    $meFirmware = $null
    $meError = $null
    try {
        $me = Get-CimInstance -Namespace 'root\Intel_ME' -ClassName ME_System -ErrorAction Stop
        if ($me) { $meFirmware = [string]$me.FWVersion }
    } catch { $meError = 'Proveedor Intel ME WMI no disponible o sin datos' }
    $smbServer = $null
    $smbNote = $null
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        $smb1 = $null
        $signing = $null
        if ($null -ne $smb.EnableSMB1Protocol) { $smb1 = [bool]$smb.EnableSMB1Protocol }
        if ($null -ne $smb.RequireSecuritySignature) { $signing = [bool]$smb.RequireSecuritySignature }
        $smbServer = [pscustomobject]@{
            smb1_enabled = $smb1
            signing_required = $signing
        }
    } catch { $smbNote = 'Configuracion SMB no disponible' }
    $rdp = $null
    $rdpNote = $null
    try {
        $rdpTcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction Stop
        $rdpPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
        $nla = $null
        $nlaSource = $null
        if ($null -ne $rdpPolicy -and $null -ne $rdpPolicy.UserAuthentication) {
            $nla = [bool]($rdpPolicy.UserAuthentication -eq 1)
            $nlaSource = 'policy'
        } elseif ($null -ne $rdpTcp.UserAuthentication) {
            $nla = [bool]($rdpTcp.UserAuthentication -eq 1)
            $nlaSource = 'RDP-Tcp'
        }
        $rdp = [pscustomobject]@{ nla_required = $nla; nla_source = $nlaSource }
    } catch { $rdpNote = 'Configuracion RDP no disponible' }
    $firewallProfiles = @()
    $firewallNote = $null
    try {
        $categories = @(Get-NetConnectionProfile -ErrorAction Stop |
            ForEach-Object { [string]$_.NetworkCategory } | Sort-Object -Unique)
        $firewallProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                $profileName = [string]$_.Name
                $active = $categories -contains $profileName
                if ($profileName -eq 'Domain' -and $categories -contains 'DomainAuthenticated') {
                    $active = $true
                }
                [pscustomobject]@{
                    name = $profileName
                    enabled = [bool]$_.Enabled
                    active = [bool]$active
                    default_inbound_action = [string]$_.DefaultInboundAction
                }
            })
    } catch { $firewallNote = 'Configuracion de Firewall no disponible' }
    $defender = $null
    $defenderNote = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defender = [pscustomobject]@{
            antivirus_enabled = [bool]$mp.AntivirusEnabled
            am_service_enabled = [bool]$mp.AMServiceEnabled
            realtime_enabled = [bool]$mp.RealTimeProtectionEnabled
            signatures_outdated = [bool]$mp.DefenderSignaturesOutOfDate
            signature_age_days = [int64]$mp.AntivirusSignatureAge
            signature_version = [string]$mp.AntivirusSignatureVersion
        }
    } catch { $defenderNote = 'Estado de Microsoft Defender no disponible' }
    $uac = $null
    try {
        $uacConfig = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        if ($null -ne $uacConfig.EnableLUA) { $uac = [bool]($uacConfig.EnableLUA -eq 1) }
    } catch { }
    $bitlocker = $null
    $bitlockerNote = $null
    try {
        $osVolume = Get-BitLockerVolume -ErrorAction Stop |
            Where-Object { [string]$_.VolumeType -eq 'OperatingSystem' } | Select-Object -First 1
        if ($osVolume) {
            $bitlocker = [pscustomobject]@{
                mount_point = [string]$osVolume.MountPoint
                protection_status = [string]$osVolume.ProtectionStatus
                volume_status = [string]$osVolume.VolumeStatus
                encryption_method = [string]$osVolume.EncryptionMethod
            }
        }
    } catch { $bitlockerNote = 'Estado de BitLocker no disponible' }
    $secureBoot = $null
    $secureBootNote = $null
    try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    catch { $secureBootNote = 'Secure Boot no disponible o firmware no UEFI' }
    $guest = $null
    $guestNote = $null
    try {
        $guestAccount = Get-LocalUser -ErrorAction Stop |
            Where-Object { [string]$_.SID -like '*-501' } | Select-Object -First 1
        if ($guestAccount) {
            $guest = [pscustomobject]@{
                name = [string]$guestAccount.Name
                enabled = [bool]$guestAccount.Enabled
            }
        }
    } catch { $guestNote = 'Estado de la cuenta Guest no disponible' }
    $llmnr = $null
    $llmnrSource = $null
    try {
        $dnsPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
        if ($null -ne $dnsPolicy -and $null -ne $dnsPolicy.EnableMulticast) {
            $llmnr = [bool]($dnsPolicy.EnableMulticast -ne 0)
            $llmnrSource = 'policy'
        } else {
            $llmnr = $true
            $llmnrSource = 'Windows default (policy absent)'
        }
    } catch { }
    $winrm = $null
    $winrmNote = $null
    try {
        $allowUnencrypted = Get-Item 'WSMan:\localhost\Service\AllowUnencrypted' -ErrorAction Stop
        $basicAuth = Get-Item 'WSMan:\localhost\Service\Auth\Basic' -ErrorAction Stop
        $winrm = [pscustomobject]@{
            allow_unencrypted = [bool]($allowUnencrypted.Value -eq $true)
            basic_auth = [bool]($basicAuth.Value -eq $true)
        }
    } catch { $winrmNote = 'Configuracion WinRM no disponible' }
    $remoteRegistry = $null
    try {
        $remoteRegistryService = Get-Service -Name RemoteRegistry -ErrorAction Stop
        $remoteRegistry = [pscustomobject]@{
            running = [bool]($remoteRegistryService.Status -eq 'Running')
            status = [string]$remoteRegistryService.Status
        }
    } catch { }
    $fallbackVersion = [Environment]::OSVersion.Version
    [pscustomobject]@{
        platform = 'windows'
        computer = [string]$env:COMPUTERNAME
        os_name = if ($os) { [string]$os.Caption } elseif ($windows) { [string]$windows.ProductName } else { 'Windows' }
        os_version = if ($os) { [string]$os.Version } else { [string]$fallbackVersion }
        os_build = if ($os) { [string]$os.BuildNumber } elseif ($windows) { [string]$windows.CurrentBuildNumber } else { [string]$fallbackVersion.Build }
        display_version = if ($windows) { [string]$windows.DisplayVersion } else { $null }
        installation_type = if ($windows) { [string]$windows.InstallationType } else { $null }
        ubr = if ($windows) { $windows.UBR } else { $null }
        os_architecture = if ($os) { [string]$os.OSArchitecture } else { [string]$env:PROCESSOR_ARCHITECTURE }
        bios_version = if ($bios) { [string]$bios.SMBIOSBIOSVersion } else { $null }
        bios_manufacturer = if ($bios) { [string]$bios.Manufacturer } else { $null }
        intel_me_firmware = $meFirmware
        intel_me_note = $meError
        smb_server = $smbServer
        smb_note = $smbNote
        rdp = $rdp
        rdp_note = $rdpNote
        firewall_profiles = $firewallProfiles
        firewall_note = $firewallNote
        defender = $defender
        defender_note = $defenderNote
        uac_enabled = $uac
        bitlocker = $bitlocker
        bitlocker_note = $bitlockerNote
        secure_boot_enabled = $secureBoot
        secure_boot_note = $secureBootNote
        guest_account = $guest
        guest_note = $guestNote
        llmnr_enabled = $llmnr
        llmnr_source = $llmnrSource
        winrm = $winrm
        winrm_note = $winrmNote
        remote_registry = $remoteRegistry
        updates = $updates
        updates_note = $updateError
        software = $software
    }
}
try {
    if ($env:SCOPESCAN_LOCAL -eq '1') {
        $result = & $collect
    } else {
        $result = Invoke-Command -ComputerName $env:SCOPESCAN_TARGET -ScriptBlock $collect -ErrorAction Stop
    }
    $result | ConvertTo-Json -Depth 5 -Compress
} catch {
    [Console]::Error.WriteLine('SCOPESCAN_ERROR: ' + $_.Exception.Message)
    exit 1
}
"""


class InventoryError(RuntimeError):
    """No se pudo obtener el inventario autenticado."""


def collect(host: str, *, local: bool = False) -> dict:
    if sys.platform != "win32":
        raise InventoryError("El inventario Windows requiere ejecutar ScopeScan en Windows")
    powershell = shutil.which("powershell.exe")
    if not powershell:
        raise InventoryError("No se encontro Windows PowerShell")
    command = base64.b64encode(SCRIPT.encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env["SCOPESCAN_TARGET"] = host
    env["SCOPESCAN_LOCAL"] = "1" if local else "0"
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120, check=False, env=env,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError(f"No se pudo ejecutar PowerShell: {exc}") from exc
    if result.returncode:
        stderr = result.stderr or ""
        detail = stderr.split("SCOPESCAN_ERROR: ", 1)[-1].splitlines()[0][:300] if (
            "SCOPESCAN_ERROR: " in stderr
        ) else "Comprueba permisos WMI y la configuracion de WinRM"
        raise InventoryError(f"Fallo el inventario de {host}: {detail}")
    try:
        data = json.loads(result.stdout)
    except ValueError as exc:
        raise InventoryError("PowerShell no devolvio un inventario JSON valido") from exc
    if not isinstance(data, dict) or not data.get("os_build"):
        raise InventoryError("Inventario Windows incompleto")
    for key in ("updates", "software", "firewall_profiles"):
        value = data.get(key)
        data[key] = [] if value is None else value if isinstance(value, list) else [value]
    return data


def inventory_scan(scan_id: int, *, host: str | None = None, local: bool = False) -> int:
    """Consulta solo hosts presentes en un escaneo ya autorizado."""
    if db.get_scan(scan_id) is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    hosts = [row["address"] for row in db.get_hosts(scan_id) if row["state"] == "up"]
    if host and host not in hosts:
        raise ValueError("El host no pertenece a este escaneo")
    targets = [host] if host else hosts
    if local and len(targets) != 1:
        raise ValueError("El modo local requiere seleccionar exactamente un host")
    if local and not ipaddress.ip_address(targets[0]).is_loopback:
        raise ValueError("El modo local solo puede asociarse a un host loopback")
    for target in targets:
        data = collect(target, local=local)
        open_tcp_ports = {
            port["portid"] for found_host, ports in db.hosts_with_ports(scan_id)
            if found_host["address"] == target
            for port in ports if port["protocol"] == "tcp"
        }
        findings = windows_findings(target, data, open_tcp_ports)
        controls = windows_controls(data, open_tcp_ports)
        db.save_host_inventory(
            scan_id, target, data, "powershell-local" if local else "winrm",
            findings=findings, controls=controls,
        )
    return len(targets)
