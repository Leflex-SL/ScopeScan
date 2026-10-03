"""Interpretacion de los scripts NSE y generacion de hallazgos.

nmap dice "el script X devolvio este texto". Esta capa decide si ese texto es un
hallazgo, con que severidad y que hay que hacer al respecto, que es el trabajo
que hace un plugin de Nessus.

El criterio para asignar severidad, en orden de preferencia:

1. Lo que declare el propio script (Risk factor, CVSS, State: VULNERABLE).
2. Una tabla de severidades conocidas por id de script, para los que no declaran.
3. Heuristica de ultimo recurso sobre el texto.

Si nada de eso da senal, no se crea hallazgo: la salida del script queda guardada
y visible bajo el puerto, pero no ensucia la lista de hallazgos.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from .models import Assessment, Finding, Host, NmapRun, ScriptResult, Severity
from .rules import evaluate_port

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
STATE_RE = re.compile(r"State:\s*(NOT VULNERABLE|LIKELY VULNERABLE|VULNERABLE[^\n|]*)", re.IGNORECASE)
RISK_RE = re.compile(r"Risk\s*factor:\s*([A-Za-z]+)", re.IGNORECASE)
CVSS_RE = re.compile(r"CVSS(?:v[23])?(?:\s*Base)?\s*[Ss]core:?\s*([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
CVSS_SHORT_RE = re.compile(r"CVSSv[23]?:\s*([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
# Filas del script vulners: <tab>CVE-2021-3618<tab>7.4<tab>https://vulners.com/...
VULNERS_ROW_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+([0-9]+\.[0-9]+)\s+http", re.IGNORECASE)
LEAST_STRENGTH_RE = re.compile(r"least strength:\s*([A-F])", re.IGNORECASE)
OLD_TLS_RE = re.compile(r"^\s*(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1):", re.IGNORECASE | re.MULTILINE)

RISK_MAP = {
    "critical": Severity.CRITICAL,
    "critico": Severity.CRITICAL,
    "high": Severity.HIGH,
    "alto": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

# Scripts cuya gravedad es conocida y que no siempre declaran Risk factor.
SCRIPT_SEVERITY: dict[str, Severity] = {
    "ssl-heartbleed": Severity.CRITICAL,
    "ssl-ccs-injection": Severity.HIGH,
    "ssl-poodle": Severity.HIGH,
    "sslv2": Severity.HIGH,
    "sslv2-drown": Severity.HIGH,
    "ssl-dh-params": Severity.MEDIUM,
    "smb-vuln-ms17-010": Severity.CRITICAL,
    "smb-vuln-ms08-067": Severity.CRITICAL,
    "smb-vuln-ms06-025": Severity.HIGH,
    "smb-vuln-cve-2017-7494": Severity.CRITICAL,
    "smb-double-pulsar-backdoor": Severity.CRITICAL,
    "smb-vuln-conficker": Severity.CRITICAL,
    "rdp-vuln-ms12-020": Severity.HIGH,
    "ftp-vsftpd-backdoor": Severity.CRITICAL,
    "ftp-proftpd-backdoor": Severity.CRITICAL,
    "irc-unrealircd-backdoor": Severity.CRITICAL,
    "ftp-anon": Severity.HIGH,
    "mysql-empty-password": Severity.CRITICAL,
    "vnc-info": Severity.LOW,
    "http-slowloris-check": Severity.MEDIUM,
    "http-csrf": Severity.MEDIUM,
    "http-dombased-xss": Severity.HIGH,
    "http-stored-xss": Severity.HIGH,
    "http-sql-injection": Severity.CRITICAL,
    "http-shellshock": Severity.CRITICAL,
    "http-passwd": Severity.HIGH,
    "http-git": Severity.MEDIUM,
    "http-config-backup": Severity.HIGH,
    "http-internal-ip-disclosure": Severity.LOW,
    "smb-security-mode": Severity.LOW,
    "smb2-security-mode": Severity.LOW,
    "clamav-exec": Severity.CRITICAL,
    "distcc-cve2004-2687": Severity.CRITICAL,
    "rmi-vuln-classloader": Severity.CRITICAL,
}

# Scripts puramente descriptivos: su salida se guarda, pero no genera hallazgo.
DESCRIPTIVE_SCRIPTS = frozenset(
    {
        "ssh-hostkey",
        "ssl-cert",
        "http-title",
        "http-server-header",
        "http-favicon",
        "http-methods",
        "smb-os-discovery",
        "smb-protocols",
        "nbstat",
        "banner",
        "fingerprint-strings",
        "rpcinfo",
        "dns-nsid",
        "ssl-date",
    }
)

REMEDIATION_HINTS: dict[str, str] = {
    "smb-vuln-ms17-010": (
        "Aplicar el boletin MS17-010, desactivar SMBv1 y aislar el host hasta "
        "comprobar que no esta ya comprometido."
    ),
    "ssl-heartbleed": (
        "Actualizar OpenSSL, reemitir el certificado y rotar toda credencial que "
        "haya podido viajar por ese servicio."
    ),
    "ssl-poodle": "Desactivar SSLv3 y dejar solo TLS 1.2 y 1.3.",
    "sslv2": "Desactivar SSLv2 y SSLv3 en la configuracion del servicio.",
    "ftp-anon": "Desactivar el acceso anonimo del servidor FTP.",
    "mysql-empty-password": "Asignar contrasena a todas las cuentas y revisar los privilegios.",
    "ssl-dh-params": "Usar parametros Diffie-Hellman de 2048 bits o mas y curvas modernas.",
    "ssl-enum-ciphers": "Desactivar SSLv2/SSLv3/TLS 1.0/1.1 y retirar cifrados con grado C o peor.",
}

DEFAULT_REMEDIATION = (
    "Revisar la referencia del script NSE y aplicar el parche o el cambio de "
    "configuracion del fabricante para el CVE indicado."
)


def _extract_cvss(text: str) -> float | None:
    """Mayor puntuacion CVSS que aparezca en la salida del script."""
    scores: list[float] = []
    for regex in (CVSS_RE, CVSS_SHORT_RE):
        for raw in regex.findall(text):
            try:
                scores.append(float(raw))
            except ValueError:
                continue
    for _cve, raw in VULNERS_ROW_RE.findall(text):
        try:
            scores.append(float(raw))
        except ValueError:
            continue
    valid = [s for s in scores if 0.0 <= s <= 10.0]
    return max(valid) if valid else None


def _extract_title(script: ScriptResult) -> str:
    """Titulo legible: la linea que sigue a 'VULNERABLE:' o el id del script."""
    lines = [ln.strip(" |\t") for ln in script.output.splitlines()]
    for i, line in enumerate(lines):
        if line.upper().rstrip(":") in ("VULNERABLE", "LIKELY VULNERABLE"):
            for candidate in lines[i + 1 :]:
                if candidate and not candidate.lower().startswith("state:"):
                    return candidate.rstrip(":")
            break
    title = script.elements.get("title")
    if title:
        return title
    return script.id


def _severity_for(script: ScriptResult) -> tuple[Severity, bool, float | None]:
    """Devuelve (severidad, confirmado, cvss) para un script NSE."""
    text = script.output or ""
    state_match = STATE_RE.search(text)
    state = state_match.group(1).upper() if state_match else ""

    if state.startswith("NOT VULNERABLE"):
        return Severity.INFO, False, None

    confirmed = state.startswith("VULNERABLE")
    likely = state.startswith("LIKELY")
    cvss = _extract_cvss(text)

    severity: Severity | None = None

    risk_match = RISK_RE.search(text)
    if risk_match:
        severity = RISK_MAP.get(risk_match.group(1).lower())

    if severity is None and cvss is not None:
        severity = Severity.from_cvss(cvss)

    if severity is None:
        severity = SCRIPT_SEVERITY.get(script.id)

    if severity is None and (confirmed or likely):
        # El script afirma vulnerabilidad pero no dice cuanto: media por defecto,
        # que es preferible a inventar una critica o a esconderlo.
        severity = Severity.MEDIUM

    if severity is None and script.id == "ssl-enum-ciphers":
        grade = LEAST_STRENGTH_RE.search(text)
        if grade:
            letter = grade.group(1).upper()
            if letter in ("E", "F"):
                severity = Severity.HIGH
            elif letter in ("C", "D"):
                severity = Severity.MEDIUM
            if severity is not None:
                confirmed = True
        if OLD_TLS_RE.search(text):
            severity = max(severity or Severity.INFO, Severity.MEDIUM)
            confirmed = True

    if severity is None:
        return Severity.INFO, confirmed, cvss

    # Un script que solo "podria" estar viendo algo no merece el nivel maximo.
    if likely and severity == Severity.CRITICAL:
        severity = Severity.HIGH

    return severity, confirmed, cvss


def _certificate_finding(
    script: ScriptResult, *, host: str, port: int | None,
    protocol: str, service: str,
) -> Finding | None:
    raw = script.elements.get("validity.notAfter", "")
    if not raw:
        match = re.search(r"Not valid after:\s*([^\n]+)", script.output, re.IGNORECASE)
        raw = match.group(1).strip() if match else ""
    if not raw:
        return None
    try:
        expires = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    remaining = expires - datetime.now(UTC)
    if remaining > timedelta(days=30):
        return None
    expired = remaining.total_seconds() < 0
    return Finding(
        title="Certificado TLS caducado" if expired else "Certificado TLS proximo a caducar",
        severity=Severity.HIGH if expired else Severity.MEDIUM,
        source="nse:ssl-cert", host=host, port=port, protocol=protocol, service=service,
        description=("La fecha de validez del certificado presentada por el servicio "
                     "ya ha vencido." if expired else
                     "El certificado presentado por el servicio caduca en menos de 30 dias."),
        evidence=f"ssl-cert validity.notAfter = {raw}",
        remediation="Renovar el certificado y desplegar la cadena completa antes de su vencimiento.",
        confirmed=True, assessment=Assessment.CONFIRMED,
    )


def finding_from_script(
    script: ScriptResult,
    *,
    host: str,
    port: int | None = None,
    protocol: str = "tcp",
    service: str = "",
) -> Finding | None:
    """Convierte un script NSE en hallazgo, o None si no aporta nada accionable."""
    if script.id == "ssl-cert":
        return _certificate_finding(
            script, host=host, port=port, protocol=protocol, service=service
        )
    if script.id in DESCRIPTIVE_SCRIPTS:
        return None
    if not script.output.strip():
        return None
    if "ERROR:" in script.output and len(script.output) < 200:
        return None

    severity, confirmed, cvss = _severity_for(script)
    if severity == Severity.INFO:
        return None

    cves = sorted({c.upper() for c in CVE_RE.findall(script.output)})

    return Finding(
        title=_extract_title(script),
        severity=severity,
        source=f"nse:{script.id}",
        host=host,
        port=port,
        protocol=protocol,
        service=service,
        description=(
            f"Detectado por el script NSE {script.id}. "
            + ("El script confirma el estado VULNERABLE." if confirmed else
               "El script senala indicios; conviene verificarlo a mano.")
        ),
        evidence=script.output.strip(),
        remediation=REMEDIATION_HINTS.get(script.id, DEFAULT_REMEDIATION),
        cvss=cvss,
        cve_ids=cves,
        confirmed=confirmed,
        assessment=(Assessment.CONFIRMED if confirmed else Assessment.CANDIDATE),
    )


def analyze_host(host: Host, *, target_is_private: bool) -> list[Finding]:
    findings: list[Finding] = []

    for script in host.hostscripts:
        finding = finding_from_script(script, host=host.address)
        if finding:
            findings.append(finding)

    for port in host.ports:
        if not port.is_open:
            continue
        for script in port.scripts:
            finding = finding_from_script(
                script,
                host=host.address,
                port=port.portid,
                protocol=port.protocol,
                service=port.service.display,
            )
            if finding:
                findings.append(finding)
        findings.extend(
            evaluate_port(host.address, port, target_is_private=target_is_private)
        )

    return findings


def analyze(run: NmapRun, *, target_is_private: bool = True) -> list[Finding]:
    """Todos los hallazgos de un escaneo, ordenados de mas grave a menos."""
    findings: list[Finding] = []
    for host in run.hosts:
        if host.is_up:
            findings.extend(analyze_host(host, target_is_private=target_is_private))

    deduped: dict[tuple, Finding] = {}
    for finding in findings:
        key = (finding.host, finding.port, finding.protocol, finding.title, finding.source)
        current = deduped.get(key)
        if current is None or finding.severity > current.severity:
            deduped[key] = finding

    return sorted(
        deduped.values(),
        key=lambda f: (-int(f.severity), f.host, f.port or 0, f.title),
    )


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Recuento por severidad, con las cinco claves siempre presentes."""
    counts = {sev.slug: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.slug] += 1
    return counts


def risk_score(findings: list[Finding]) -> int:
    """Puntuacion 0-100 de riesgo agregado del escaneo.

    Pondera por severidad y satura: diez hallazgos medios no deben empatar con
    una critica, y una vez que hay varias criticas el numero ya no dice mas.
    """
    return risk_score_evidence((f.severity, f.assessment) for f in findings)


def risk_score_evidence(items: Iterable[tuple[Severity, Assessment]]) -> int:
    """La misma escala para escaneos y nuevos controles autenticados."""
    weights = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 20,
        Severity.MEDIUM: 8,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }
    # Una coincidencia por banner/CPE no pesa igual que una comprobacion positiva.
    total = sum(
        weights[severity] * (0.35 if assessment == Assessment.CANDIDATE else 1)
        for severity, assessment in items
    )
    if total <= 0:
        return 0
    # Saturacion suave: 100 * (1 - e^(-total/60)).
    return round(100 * (1 - math.exp(-total / 60)))
