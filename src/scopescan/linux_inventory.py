"""Inventario autenticado Linux mediante el cliente OpenSSH del sistema.

Usa claves o agente ya configurados y fuerza BatchMode: no solicita ni guarda
contrasenas. El destino siempre debe pertenecer a un escaneo previo.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import sys

from . import db
from .authenticated_checks import linux_findings
from .compliance import linux_controls

SSH_USER = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

SCRIPT = r"""
set -u
emit() {
    key="$1"
    value="$2"
    printf '%s\t' "$key"
    printf '%s' "$value" | base64 | tr -d '\r\n'
    printf '\n'
}
emit HOSTNAME "$(hostname 2>/dev/null || true)"
emit KERNEL "$(uname -r 2>/dev/null || true)"
os_release="$(cat /etc/os-release 2>/dev/null || true)"
emit OS_RELEASE "$os_release"

manager=''
packages=''
packages_checked='no'
if command -v dpkg-query >/dev/null 2>&1; then
    manager='dpkg'
    packages="$(dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null)" && packages_checked='yes'
elif command -v rpm >/dev/null 2>&1; then
    manager='rpm'
    packages="$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null)" && packages_checked='yes'
elif command -v apk >/dev/null 2>&1; then
    manager='apk'
    # Installed APK metadata keeps the full version (including -rN) separate.
    if [ -r /lib/apk/db/installed ]; then
        packages="$(awk 'BEGIN { RS=""; FS="\n" } { n=""; v=""; for (i=1;i<=NF;i++) { if ($i ~ /^P:/) n=substr($i,3); if ($i ~ /^V:/) v=substr($i,3) } if(n!="" && v!="") printf "%s\t%s\n",n,v }' /lib/apk/db/installed)" && packages_checked='yes'
    else
        packages="$(apk info -v 2>/dev/null)" && packages_checked='yes'
    fi
fi
package_total="$(printf '%s\n' "$packages" | awk 'NF { n++ } END { print n+0 }')"
packages="$(printf '%s\n' "$packages" | sed -n '1,5000p')"
emit PACKAGE_MANAGER "$manager"
emit PACKAGES_CHECKED "$packages_checked"
emit PACKAGE_TOTAL "$package_total"
emit PACKAGES "$packages"

security_updates=''
security_updates_checked='no'
if [ "$manager" = 'dpkg' ] && command -v apt-get >/dev/null 2>&1; then
    simulated="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null)" && {
        security_updates_checked='yes'
        security_updates="$(printf '%s\n' "$simulated" | grep '^Inst ' | grep -i 'security' || true)"
    }
elif [ "$manager" = 'rpm' ] && command -v dnf >/dev/null 2>&1; then
    security_updates="$(dnf -q updateinfo list --security --available 2>/dev/null)" && security_updates_checked='yes'
elif [ "$manager" = 'rpm' ] && command -v yum >/dev/null 2>&1; then
    security_updates="$(yum -q updateinfo list security available 2>/dev/null)" && security_updates_checked='yes'
fi
emit SECURITY_UPDATES_CHECKED "$security_updates_checked"
emit SECURITY_UPDATES "$security_updates"

sshd_effective=''
if command -v sshd >/dev/null 2>&1; then
    sshd_effective="$(sshd -T 2>/dev/null || true)"
fi
emit SSHD_EFFECTIVE "$sshd_effective"

firewall_observed='no'
firewall_active='no'
firewall_detail=''
if command -v ufw >/dev/null 2>&1; then
    ufw_state="$(ufw status 2>/dev/null | sed -n '1p' || true)"
    case "$ufw_state" in
        'Status: active'*) firewall_observed='yes'; firewall_active='yes' ;;
        'Status: inactive'*) firewall_observed='yes' ;;
    esac
    firewall_detail="ufw: ${ufw_state:-sin permiso}"
fi
if command -v firewall-cmd >/dev/null 2>&1; then
    firewalld_state="$(firewall-cmd --state 2>/dev/null || true)"
    if [ -n "$firewalld_state" ]; then firewall_observed='yes'; fi
    if [ "$firewalld_state" = 'running' ]; then firewall_active='yes'; fi
    firewall_detail="$firewall_detail; firewalld: ${firewalld_state:-sin permiso}"
fi
if command -v nft >/dev/null 2>&1; then
    nft_rules="$(nft list ruleset 2>/dev/null)" && {
        firewall_observed='yes'
        nft_count="$(printf '%s\n' "$nft_rules" | grep -cE '^[[:space:]]*(chain|table)[[:space:]]' || true)"
        if [ "$nft_count" -gt 0 ]; then firewall_active='yes'; fi
        firewall_detail="$firewall_detail; nftables: $nft_count tablas/cadenas"
    }
fi
emit FIREWALL_OBSERVED "$firewall_observed"
emit FIREWALL_ACTIVE "$firewall_active"
emit FIREWALL_DETAIL "$firewall_detail"

emit ASLR "$(sysctl -n kernel.randomize_va_space 2>/dev/null || true)"
if command -v getenforce >/dev/null 2>&1; then
    emit SELINUX "$(getenforce 2>/dev/null || true)"
else
    emit SELINUX ''
fi
if [ -r /sys/module/apparmor/parameters/enabled ]; then
    emit APPARMOR "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true)"
else
    emit APPARMOR ''
fi
"""

# A missing Debian-family marker is meaningful only when its notifier exists.
# RPM/Alpine need their own vendor checks; absence of this path proves nothing.
REBOOT_CHECK = r"""
os_id=''
while IFS= read -r os_line; do
    case "$os_line" in ID=*) os_id="${os_line#ID=}" ;; esac
done <<OS_RELEASE_DATA
$os_release
OS_RELEASE_DATA
os_id="${os_id#\"}"
os_id="${os_id%\"}"
os_id="${os_id#\'}"
os_id="${os_id%\'}"
reboot_required=''
case "$os_id" in
    ubuntu|debian)
        if [ -e /var/run/reboot-required ]; then
            reboot_required='yes'
        elif [ -x /usr/share/update-notifier/notify-reboot-required ]; then
            reboot_required='no'
        fi
        ;;
esac
emit REBOOT_REQUIRED "$reboot_required"
"""
SCRIPT += REBOOT_CHECK


class InventoryError(RuntimeError):
    """No se pudo obtener el inventario Linux."""


def _decode_records(output: str) -> dict[str, str]:
    records: dict[str, str] = {}
    for line in output.splitlines():
        if "\t" not in line:
            continue
        key, encoded = line.split("\t", 1)
        if not re.fullmatch(r"[A-Z_]+", key):
            continue
        try:
            records[key] = base64.b64decode(encoded, validate=True).decode("utf-8", "replace")
        except (ValueError, UnicodeError):
            raise InventoryError(f"Registro de inventario Linux invalido: {key}") from None
    return records


def _os_release(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in raw.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z0-9_]+", key):
            continue
        try:
            parsed = shlex.split(value, posix=True)
            result[key.lower()] = parsed[0] if parsed else ""
        except ValueError:
            result[key.lower()] = value.strip("'\"")
    return result


def _packages(raw: str, manager: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in raw.splitlines()[:5000]:
        if manager in {"dpkg", "rpm", "apk"} and "\t" in line:
            name, version = line.split("\t", 1)
        elif manager == "apk" and "-" in line:
            # APK versions start with a number and may include suffixes and
            # revision; a package name itself may contain hyphens/digits.
            match = re.fullmatch(r"(.+)-([0-9][A-Za-z0-9._+~]*-r[0-9]+)", line)
            if not match:
                continue
            name, version = match.groups()
        else:
            continue
        if name and version:
            rows.append({"name": name[:300], "version": version[:300]})
    return rows


def _sshd_setting(raw: str, name: str) -> str | None:
    prefix = name.lower() + " "
    for line in raw.splitlines():
        if line.lower().startswith(prefix):
            return line[len(prefix):].strip().lower() or None
    return None


def _security_updates(raw: str, manager: str) -> list[dict[str, str]]:
    updates: list[dict[str, str]] = []
    for line in raw.splitlines()[:2000]:
        line = line.strip()
        if not line:
            continue
        if manager == "dpkg":
            match = re.match(r"Inst\s+(\S+)\s+(?:\[([^\]]+)\]\s+)?\((\S+)", line)
            if match:
                updates.append({"name": match.group(1), "installed": match.group(2) or "",
                                "candidate": match.group(3), "advisory": "security repository"})
        elif manager == "rpm" and not line.lower().startswith(("last metadata", "update id")):
            parts = line.split()
            if len(parts) >= 3 and any(token.lower().startswith(("rhsa-", "elsa-", "al"))
                                       for token in parts):
                updates.append({"name": parts[-1], "installed": "", "candidate": "",
                                "advisory": parts[0]})
    return updates


def parse_inventory(output: str, *, ssh_port: int = 22) -> dict:
    records = _decode_records(output)
    os_data = _os_release(records.get("OS_RELEASE", ""))
    kernel = records.get("KERNEL", "").strip()
    if not kernel or not os_data.get("id"):
        raise InventoryError("Inventario Linux incompleto: faltan kernel o /etc/os-release")
    manager = records.get("PACKAGE_MANAGER", "").strip()
    sshd = records.get("SSHD_EFFECTIVE", "")
    observed = records.get("FIREWALL_OBSERVED") == "yes"
    packages = _packages(records.get("PACKAGES", ""), manager)
    raw_count = len(records.get("PACKAGES", "").splitlines())
    total_raw = records.get("PACKAGE_TOTAL", "")
    package_total = int(total_raw) if total_raw.isdigit() else None
    package_checked = records.get("PACKAGES_CHECKED")
    packages_unparsed = max(min(raw_count, 5000) - len(packages), 0)
    packages_truncated = (package_total is not None and package_total > min(raw_count, 5000)) or (
        raw_count > 5000
    )
    return {
        "platform": "linux",
        "computer": records.get("HOSTNAME", "").strip(),
        "os_name": os_data.get("pretty_name") or os_data.get("name") or os_data["id"],
        "os_id": os_data["id"].lower(),
        "os_version": os_data.get("version_id", ""),
        "kernel": kernel,
        "package_manager": manager,
        "packages": packages,
        "package_total": package_total,
        "packages_checked": package_checked == "yes" if package_checked else None,
        "packages_truncated": packages_truncated,
        "packages_unparsed": packages_unparsed,
        "packages_complete": (
            package_checked == "yes" and not packages_truncated and not packages_unparsed
            if package_checked and package_total is not None else None
        ),
        "security_updates_checked": records.get("SECURITY_UPDATES_CHECKED") == "yes",
        "security_updates": _security_updates(records.get("SECURITY_UPDATES", ""), manager),
        "ssh_port": ssh_port,
        "sshd": {
            "permit_root_login": _sshd_setting(sshd, "permitrootlogin"),
            "password_authentication": _sshd_setting(sshd, "passwordauthentication"),
            "permit_empty_passwords": _sshd_setting(sshd, "permitemptypasswords"),
            "max_auth_tries": _sshd_setting(sshd, "maxauthtries"),
        } if sshd else None,
        "firewall": {
            "observed": observed,
            "active": records.get("FIREWALL_ACTIVE") == "yes" if observed else None,
            "detail": records.get("FIREWALL_DETAIL", "").strip(),
        },
        "aslr": int(records["ASLR"]) if records.get("ASLR") in {"0", "1", "2"} else None,
        "selinux": records.get("SELINUX", "").strip().lower() or None,
        "apparmor": records.get("APPARMOR", "").strip().lower() or None,
        "reboot_required": (
            records["REBOOT_REQUIRED"] == "yes"
            if records.get("REBOOT_REQUIRED") in {"yes", "no"} else None
        ),
    }


def collect(
    host: str, *, user: str | None = None, port: int = 22, local: bool = False,
) -> dict:
    if not 1 <= port <= 65535:
        raise InventoryError("El puerto SSH debe estar entre 1 y 65535")
    if user and not SSH_USER.fullmatch(user):
        raise InventoryError("Nombre de usuario SSH invalido")
    if local:
        if os.name == "nt":
            raise InventoryError("El inventario Linux local requiere ejecutar ScopeScan en Linux")
        argv = ["sh", "-s"]
    else:
        ssh = shutil.which("ssh")
        if not ssh:
            raise InventoryError("No se encontro el cliente OpenSSH (ssh)")
        argv = [
            ssh, "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", "ConnectTimeout=12", "-p", str(port),
        ]
        if user:
            argv.extend(["-l", user])
        argv.extend([host, "sh", "-s"])
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    try:
        result = subprocess.run(
            argv, input=SCRIPT.encode("utf-8"), capture_output=True,
            timeout=180, check=False, **kwargs,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError(f"No se pudo ejecutar el inventario Linux: {exc}") from exc
    if result.returncode:
        stderr = result.stderr.decode("utf-8", "replace") if isinstance(result.stderr, bytes) \
            else result.stderr
        detail = (stderr or "fallo de autenticacion SSH").splitlines()[0][:300]
        raise InventoryError(f"Fallo el inventario de {host}: {detail}")
    stdout = result.stdout.decode("utf-8", "replace") if isinstance(result.stdout, bytes) \
        else result.stdout
    return parse_inventory(stdout, ssh_port=port)


def inventory_scan(
    scan_id: int, *, host: str | None = None, user: str | None = None,
    port: int = 22, local: bool = False,
) -> int:
    """Consulta por SSH solo hosts vivos pertenecientes al escaneo autorizado."""
    if db.get_scan(scan_id) is None:
        raise ValueError(f"No existe el escaneo {scan_id}")
    hosts = [row["address"] for row in db.get_hosts(scan_id) if row["state"] == "up"]
    if host and host not in hosts:
        raise ValueError("El host no pertenece a este escaneo")
    targets = [host] if host else hosts
    if local and len(targets) != 1:
        raise ValueError("El modo local requiere seleccionar exactamente un host")
    if local:
        try:
            is_loopback = ipaddress.ip_address(targets[0]).is_loopback
        except ValueError:
            is_loopback = targets[0].lower() == "localhost"
        if not is_loopback:
            raise ValueError("El modo local solo puede asociarse a un host loopback")
    ports_by_host = {
        found_host["address"]: {
            item["portid"] for item in ports if item["protocol"] == "tcp"
        }
        for found_host, ports in db.hosts_with_ports(scan_id)
    }
    for target in targets:
        data = collect(target, user=user, port=port, local=local)
        findings = linux_findings(target, data, ports_by_host.get(target, set()))
        controls = linux_controls(data, ports_by_host.get(target, set()))
        db.save_host_inventory(
            scan_id, target, data, "shell-local" if local else "openssh",
            findings=findings, controls=controls,
        )
    return len(targets)
