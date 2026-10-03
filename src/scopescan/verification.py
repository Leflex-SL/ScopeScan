"""Targeted plans select owned checks, never executable imported identifiers."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import db, nmap_runner
from .authenticated_checks import collected_ssh_port
from .config import NmapNotFound, is_privileged
from .models import Host, NmapRun, Port
from .rules import SERVICE_RULES, VERSION_RULES
from .scopes import pin_targets

RULES_VERSION = "scopescan-rules-" + hashlib.sha256(
    Path(__file__).with_name("rules.py").read_bytes()
    + Path(__file__).with_name("analysis.py").read_bytes()
    + Path(__file__).read_bytes()).hexdigest()[:20]
AUTH_VERSION = "authenticated-" + hashlib.sha256(
    Path(__file__).with_name("authenticated_checks.py").read_bytes()
    + Path(__file__).read_bytes()).hexdigest()[:20]

RULE_SOURCES = frozenset({f"rule:{r.id}" for r in (*SERVICE_RULES, *VERSION_RULES)}
                         | {"rule:amt-expuesto"})
# A deliberately closed execution list. Imported source IDs are evidence, not NSE selectors.
SAFE_NSE = frozenset({"ssl-cert", "ssl-heartbleed", "ssl-poodle",
                      "smb-vuln-ms17-010", "smb-protocols", "smb2-security-mode",
                      "http-security-headers", "ssh2-enum-algos"})


def configured_ssh_port() -> int:
    try:
        port = int(os.environ.get("SCOPESCAN_VERIFY_SSH_PORT", "22"))
    except ValueError as exc:
        raise ValueError("SCOPESCAN_VERIFY_SSH_PORT debe indicar un puerto SSH valido") from exc
    if not 1 <= port <= 65535:
        raise ValueError("SCOPESCAN_VERIFY_SSH_PORT debe estar entre 1 y 65535")
    return port


def validate_ssh_identity_endpoint(spec: dict) -> None:
    if spec.get("platform") == "linux" and spec.get("source", "").startswith("auth:linux:ssh-"):
        port = spec.get("port")
        if type(port) is not int or not 1 <= port <= 65535 or spec.get("protocol") != "tcp":
            raise ValueError("El control SSH no conserva un endpoint TCP concreto")
        if configured_ssh_port() != port:
            raise ValueError(f"La identidad SSH usa otro puerto; configura "
                             f"SCOPESCAN_VERIFY_SSH_PORT={port} para verificar este listener")


@dataclass
class VerificationPlan:
    requests: list[dict] = field(default_factory=list)
    previews: list[list[str]] = field(default_factory=list)
    missing_controls: list[dict] = field(default_factory=list)


def nmap_args_for_verification(spec: dict, *, privileged: bool) -> list[str]:
    protocol = spec.get("protocol")
    ports = spec.get("ports", [])
    scripts = spec.get("scripts", [])
    if (not isinstance(protocol, str) or protocol not in {"tcp", "udp"}
            or not isinstance(ports, list) or not ports or len(ports) > 65535):
        raise ValueError("Verificacion requiere protocolo TCP/UDP y puertos concretos")
    if any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError("Puerto de verificacion invalido")
    if not isinstance(scripts, list) or any(not isinstance(s, str) for s in scripts) \
            or not set(scripts) <= SAFE_NSE:
        raise ValueError("Script de verificacion fuera de la lista permitida")
    selected_rules = spec.get("rules", [])
    if not isinstance(selected_rules, list) or any(not isinstance(r, str) for r in selected_rules) \
            or not set(selected_rules) <= RULE_SOURCES:
        raise ValueError("Regla de verificacion desconocida")
    if protocol == "udp" and not privileged:
        raise ValueError("La verificacion UDP necesita privilegios de administrador")
    args = ["-T3", "-sU" if protocol == "udp" else ("-sS" if privileged else "-sT"),
            "-Pn", "-sV", "--version-intensity", "7", "-p", ",".join(map(str, sorted(set(ports))))]
    if scripts:
        args += ["--script", ",".join(sorted(set(scripts)))]
        if set(scripts) & {"ssl-heartbleed", "ssl-poodle", "smb-vuln-ms17-010"}:
            args += ["--script-args", "vulns.showall=1"]
    return args


def plan_verification(finding_ids: list[int | str], *, authorized_by: str = "",
                      identity_configured: bool = False, defer_identity: bool = False) -> VerificationPlan:
    if not authorized_by.strip():
        raise ValueError("La verificacion requiere un responsable de autorizacion")
    plan = VerificationPlan()
    groups: dict[tuple, dict] = {}
    for finding_id in finding_ids:
        row = db.get_current_finding(finding_id)
        if row is None:
            raise ValueError(f"No existe el hallazgo vigente {finding_id}")
        source = row["source"]
        reason = ""
        if source.startswith("auth:"):
            platform = source.split(":")[1]
            known = authenticated_coverage(platform, {}, set())["controls"]
            configured = defer_identity or os.environ.get(f"SCOPESCAN_VERIFY_{platform.upper()}_IDENTITY") == "1"
            if not configured:
                reason = "Requiere identidad autenticada configurada en el entorno del worker"
            elif source not in known and not source.startswith("auth:windows:firewall:"):
                reason = "Control autenticado desconocido; no se ejecuta contenido importado"
            else:
                spec = {"platform": platform, "source": source,
                        "port": row["port"], "protocol": row["protocol"]}
                try:
                    if not defer_identity:
                        validate_ssh_identity_endpoint(spec)
                except ValueError as exc:
                    plan.missing_controls.append({"finding_id": finding_id, "reason": str(exc)})
                    continue
                group = {"targets": pin_targets(row["host"]).target_set.raw,
                         "authorized_by": authorized_by, "namespace": row["namespace"],
                         "finding_ids": [finding_id], "authenticated": spec,
                         "identity_deferred": defer_identity}
                plan.requests.append(group)
                plan.previews.append([f"inventory:{platform}", group["targets"], source,
                                      "identity:worker-environment"])
                continue
        elif source not in RULE_SOURCES and not (source.startswith("nse:")
                                                  and source[4:] in SAFE_NSE):
            reason = "La fuente no tiene una comprobacion propia permitida"
        elif row["port"] is None or row["protocol"] not in {"tcp", "udp"}:
            reason = "No hay endpoint de red concreto para esta comprobacion"
        if reason:
            plan.missing_controls.append({"finding_id": finding_id, "reason": reason})
            continue
        pinned = pin_targets(row["host"]).target_set
        namespace = row["namespace"]
        key = (namespace, pinned.raw, row["protocol"])
        group = groups.setdefault(key, {"targets": pinned.raw, "authorized_by": authorized_by,
                                       "namespace": namespace, "finding_ids": [],
                                       "verification": {"protocol": row["protocol"],
                                                        "ports": [], "scripts": [], "rules": []}})
        group["finding_ids"].append(finding_id)
        group["verification"]["ports"].append(row["port"])
        if source in RULE_SOURCES:
            group["verification"]["rules"].append(source)
        else:
            group["verification"]["scripts"].append(source[4:])
    for group in groups.values():
        args = nmap_args_for_verification(group["verification"], privileged=is_privileged())
        try:
            preview = nmap_runner.build_argv(targets=group["targets"].split(), profile_args=args,
                                              xml_path=Path("<salida>.xml"))
        except NmapNotFound:
            preview = []
        plan.requests.append(group)
        plan.previews.append(preview)
    return plan


def queue_verification(plan: VerificationPlan) -> list[int]:
    from .service import ScanRequest, queue_scan
    ids = []
    for group in plan.requests:
        if group.get("authenticated"):
            ids.append(_queue_authenticated(group))
            continue
        # Revalidate owned selectors before persisting even if a caller mutated the plan.
        nmap_args_for_verification(group["verification"], privileged=is_privileged())
        pinned = pin_targets(group["targets"]).target_set
        scan_id = queue_scan(ScanRequest(targets=pinned.raw, profile="rapido",
                                         authorized_by=group["authorized_by"],
                                         name="Verificacion dirigida"))
        context = json.loads(db.get_scan(scan_id)["execution_context"])
        context.update({"namespace": group["namespace"],
                        "verification": group["verification"],
                        "verification_of": group["finding_ids"]})
        db.set_scan_context(scan_id, execution_context=context)
        ids.append(scan_id)
    return ids


def rerun_verification(row) -> int:
    """Rebuild owned checks from current finding IDs, retaining their namespace."""
    context = json.loads(row["execution_context"] or "{}")
    ids = context.get("verification_of")
    if (not isinstance(ids, list) or not ids or len(ids) > 10000
            or any(not isinstance(fid, str) or not fid for fid in ids)):
        raise ValueError("El plan repetido no conserva hallazgos vigentes validos; usa Verificar")
    try:
        plan = plan_verification(ids, authorized_by=row["authorized_by"])
    except ValueError as exc:
        raise ValueError(f"No se puede repetir el plan vigente: {exc}; usa Verificar") from exc
    if plan.missing_controls:
        reasons = "; ".join(item["reason"] for item in plan.missing_controls)
        raise ValueError(f"No se puede repetir la verificacion: {reasons}; usa Verificar")
    if len(plan.requests) != 1:
        raise ValueError("El plan vigente ya no corresponde a un unico trabajo; usa Verificar")
    group = plan.requests[0]
    current_targets = pin_targets(group["targets"]).target_set.argv
    if (context.get("namespace") != group["namespace"]
            or current_targets != context.get("pinned_targets")
            or current_targets != pin_targets(row["targets"]).target_set.argv):
        raise ValueError("Los objetivos o la identidad del hallazgo cambiaron; usa Verificar")
    for fid in ids:
        finding = db.get_current_finding(fid)
        if finding is None:
            raise ValueError("El hallazgo ya no esta vigente; usa Verificar")
        if finding.get("scope_id") is not None:
            from .scopes import get_scope
            scope = get_scope(finding["scope_id"])
            if (not set(current_targets) <= set(scope["pinned_targets"])
                    or row["authorized_by"] != scope["authorized_by"]):
                raise ValueError("El alcance o la autorizacion guardada cambiaron; usa Verificar")
    if group.get("authenticated"):
        if group["authenticated"] != context.get("authenticated"):
            raise ValueError("El control autenticado cambio desde el plan anterior; usa Verificar")
    else:
        old_spec = context.get("verification")
        if not isinstance(old_spec, dict):
            raise ValueError("El plan anterior no conserva comprobaciones propias; usa Verificar")
        nmap_args_for_verification(old_spec, privileged=is_privileged())
        fresh_spec = group["verification"]
        if (old_spec.get("protocol") != fresh_spec["protocol"]
                or any(sorted(set(old_spec.get(key, []))) != sorted(set(fresh_spec[key]))
                       for key in ("ports", "scripts", "rules"))):
            raise ValueError("Los endpoints o las reglas vigentes cambiaron; usa Verificar")
    return queue_verification(plan)[0]


def enrich_coverage(run: NmapRun) -> None:
    run.coverage["provenance"] = "local"
    run.coverage["rules_version"] = RULES_VERSION
    run.coverage["rules"] = sorted(RULE_SOURCES)
    run.coverage["scripts"] = sorted({s.id for h in run.hosts for p in h.ports for s in p.scripts})
    run.coverage["negative_evidence"] = []
    for host in run.hosts:
        if host.timed_out:
            continue
        for port in host.ports:
            for script in port.scripts:
                evidence = nse_negative_evidence(script)
                if evidence:
                    run.coverage["negative_evidence"].append({"host": host.address,
                        "port": port.portid, "protocol": port.protocol,
                        "source": f"nse:{script.id}", "evidence": evidence})
    for endpoint in run.coverage.get("endpoints", []):
        # An unversioned open banner cannot prove a version rule disappeared.
        host = next((h for h in run.hosts if h.address == endpoint["host"]), None)
        port = next((p for p in host.ports if p.portid == endpoint["port"]
                     and p.protocol == endpoint["protocol"]), None) if host else None
        service_rules = {f"rule:{r.id}" for r in SERVICE_RULES} | {"rule:amt-expuesto"}
        endpoint["rules"] = sorted(service_rules if port and port.is_open else RULE_SOURCES)
        if port and port.service.has_version:
            endpoint["rules"] = sorted(RULE_SOURCES)


def nse_negative_evidence(script) -> str:
    """Only explicit owned negative predicates can prove a prior NSE claim cleared."""
    output = script.output.strip()
    if not output or re.search(r"\b(ERROR|FAILED|TIMEOUT|INCOMPLETE)\b", output, re.IGNORECASE):
        return ""
    if script.id in {"ssl-heartbleed", "ssl-poodle", "smb-vuln-ms17-010"}:
        states = re.findall(r"^\s*State:\s*([^\n]+)", output, re.IGNORECASE | re.MULTILINE)
        if states and all(state.strip().upper() == "NOT VULNERABLE" for state in states):
            return "Owned vulnerability state explicitly NOT VULNERABLE"
    if script.id == "ssl-cert":
        dates = []
        for field, label in (("notBefore", "before"), ("notAfter", "after")):
            raw = script.elements.get(f"validity.{field}", "")
            if not raw:
                match = re.search(rf"Not valid {label}:\s*([^\n]+)", output, re.IGNORECASE)
                raw = match.group(1).strip() if match else ""
            try:
                date = datetime.fromisoformat(raw)
            except ValueError:
                return ""
            dates.append(date.replace(tzinfo=UTC) if date.tzinfo is None else date.astimezone(UTC))
        now = datetime.now(UTC)
        # ScopeScan's ssl-cert rule assesses expiry only. This says nothing about trust.
        if dates[0] <= now and dates[1] > now + timedelta(days=30):
            return f"Certificate expiry control passed: {dates[0].isoformat()} to {dates[1].isoformat()}"
    # Descriptive or partial outputs lack a negative predicate for an old finding.
    return ""


def authenticated_coverage(platform: str, data: dict, open_tcp_ports: set[int],
                           host: str = "", *, sources: list[str] | None = None) -> dict:
    """Explicit observed pass/fail predicates, with missing values kept unknown."""
    controls: dict[str, str] = {}
    evidence: dict[str, str] = {}
    control_endpoints: dict[str, dict] = {}
    def check(key, value, predicate, observed=True):
        controls[f"auth:{platform}:{key}"] = ("fail" if predicate(value) else "pass") \
            if observed and value is not None else "unknown"
        if controls[f"auth:{platform}:{key}"] != "unknown":
            evidence[f"auth:{platform}:{key}"] = (
                f"{platform} collected predicate {key}; observed="
                + json.dumps(value, ensure_ascii=True, sort_keys=True)[:4000])
    if platform == "linux":
        sshd = data.get("sshd") or {}
        ssh_port = collected_ssh_port(data)
        ssh_bound = ssh_port is not None and ssh_port in open_tcp_ports
        for key, field in (("ssh-root", "permit_root_login"),
                           ("ssh-password", "password_authentication"),
                           ("ssh-empty-passwords", "permit_empty_passwords")):
            value = sshd.get(field)
            check(key, value, lambda v: v == "yes",
                  ssh_bound and value in {"yes", "no", "prohibit-password", "forced-commands-only"})
        value = sshd.get("max_auth_tries")
        try:
            tries = int(value) if value is not None else None
        except (ValueError, TypeError):
            tries = None
        check("ssh-max-auth-tries", tries, lambda v: v > 6, ssh_bound)
        for source, status in controls.items():
            if source.startswith("auth:linux:ssh-") and status != "unknown":
                control_endpoints[source] = {"host": host, "port": ssh_port, "protocol": "tcp"}
                evidence[source] += f"; collected endpoint={host}:{ssh_port}/tcp"
        firewall = data.get("firewall") or {}
        check("firewall", firewall.get("active"), lambda v: v is False,
              firewall.get("observed") is True and type(firewall.get("active")) is bool)
        check("aslr", data.get("aslr"), lambda v: v == 0,
              type(data.get("aslr")) is int and data.get("aslr") in {0, 1, 2})
        check("selinux", data.get("selinux"), lambda v: v == "disabled",
              data.get("os_id") in {"rhel", "centos", "rocky", "almalinux", "fedora"}
              and data.get("selinux") in {"disabled", "permissive", "enforcing"})
        check("apparmor", data.get("apparmor"), lambda v: v in {"n", "no", "disabled"},
              data.get("apparmor") in {"n", "no", "disabled", "y", "yes", "enabled"})
        check("reboot", data.get("reboot_required"), lambda v: v is True,
              type(data.get("reboot_required")) is bool)
        check("security-updates", data.get("security_updates"), bool,
              data.get("security_updates_checked") is True)
    elif platform == "windows":
        for key, section, field, bad, port in (
            ("smb1", "smb_server", "smb1_enabled", True, 445),
            ("smb-signing", "smb_server", "signing_required", False, 445),
            ("rdp-nla", "rdp", "nla_required", False, 3389),
            ("winrm-unencrypted", "winrm", "allow_unencrypted", True, 5985),
            ("winrm-basic", "winrm", "basic_auth", True, 5985),
            ("guest", "guest_account", "enabled", True, None),
            ("remote-registry", "remote_registry", "running", True, None)):
            value = (data.get(section) or {}).get(field)
            check(key, value, lambda v, bad=bad: v is bad,
                  type(value) is bool and (port is None or port in open_tcp_ports))
        for key, field, bad in (("uac", "uac_enabled", False),
                                ("secure-boot", "secure_boot_enabled", False),
                                ("llmnr", "llmnr_enabled", True)):
            value = data.get(field)
            check(key, value, lambda v, bad=bad: v is bad, type(value) is bool)
        bitlocker = (data.get("bitlocker") or {}).get("protection_status")
        check("bitlocker", bitlocker, lambda v: v == "Off", bitlocker in {"Off", "On"})
        defender = data.get("defender") or {}
        check("defender-realtime", defender.get("realtime_enabled"), lambda v: v is False,
              defender.get("antivirus_enabled") is True and type(defender.get("realtime_enabled")) is bool)
        age = defender.get("signature_age_days")
        check("defender-signatures", age, lambda v: v > 7,
              defender.get("antivirus_enabled") is True and type(age) is int and age >= 0)
        for profile in data.get("firewall_profiles") or []:
            if profile.get("active") is True:
                value = profile.get("enabled")
                check("firewall:" + str(profile.get("name") or "desconocido").lower(),
                      value, lambda v: v is False, type(value) is bool)
    if sources is not None:
        controls = {source: controls.get(source, "unknown") for source in sources}
        evidence = {source: evidence[source] for source in sources if source in evidence}
        control_endpoints = {source: control_endpoints[source] for source in sources
                             if source in control_endpoints}
    return {"engine": "authenticated", "engine_version": "inventory-v1",
            "rules_version": AUTH_VERSION, "status": "complete", "hosts": [host] if host else [],
            "rules": list(controls), "controls": controls, "control_evidence": evidence,
            "control_endpoints": control_endpoints,
            "protocols": {"tcp": sorted(open_tcp_ports)}, "provenance": "local"}


def _queue_authenticated(group: dict) -> int:
    spec = group["authenticated"]
    platform = spec.get("platform")
    if platform not in {"linux", "windows"} or not spec["source"].startswith(f"auth:{platform}:"):
        raise ValueError("Control autenticado desconocido")
    # Identity and SSH listener configuration are checked in the executing worker.
    if not group.get("identity_deferred"):
        if os.environ.get(f"SCOPESCAN_VERIFY_{platform.upper()}_IDENTITY") != "1":
            raise ValueError("La identidad autenticada no esta configurada en el worker")
        validate_ssh_identity_endpoint(spec)
    pinned = pin_targets(group["targets"]).target_set
    scan_id = db.create_scan(name="Verificacion de control autenticado", targets=pinned.raw,
                             profile="authenticated", target_private=pinned.all_private,
                             authorized_by=group["authorized_by"], reserve_job=True,
                             execution_context={"namespace": group["namespace"],
                        "pinned_targets": pinned.argv, "authenticated": spec,
                        "verification_of": group["finding_ids"]})
    return scan_id


def execute_authenticated(scan_id: int, context: dict, *, cancel=None) -> None:
    from . import analysis, authenticated_checks, compliance, linux_inventory, windows_inventory
    spec = context["authenticated"]
    platform = spec["platform"]
    host = pin_targets(" ".join(context["pinned_targets"])).target_set.argv[0]
    if os.environ.get(f"SCOPESCAN_VERIFY_{platform.upper()}_IDENTITY") != "1":
        raise ValueError("La identidad autenticada ya no esta configurada")
    validate_ssh_identity_endpoint(spec)
    if cancel is not None and cancel.is_set():
        db.set_status(scan_id, "cancelled", error="Cancelado antes de recopilar")
        return
    db.set_status(scan_id, "running")
    db.set_progress(scan_id, 0, "Recopilando control autenticado")
    if platform == "linux":
        data = linux_inventory.collect(host, user=os.environ.get("SCOPESCAN_VERIFY_SSH_USER"),
                                       port=configured_ssh_port(), **({"cancel":cancel} if cancel is not None else {}))
    else:
        data = windows_inventory.collect(host, **({"cancel":cancel} if cancel is not None else {}))
    if cancel is not None and cancel.is_set():
        db.set_status(scan_id, "cancelled", error="Cancelado durante la recopilacion")
        return
    # Host controls need no synthetic endpoint. Port controls need a fresh connection
    # observation; SSH collection itself establishes its actual SSH endpoint only.
    ssh_port = collected_ssh_port(data) if platform == "linux" else None
    if spec["source"].startswith("auth:linux:ssh-") and ssh_port != spec["port"]:
        raise ValueError("El inventario no demuestra recopilacion del listener SSH afectado; "
                         "comprueba la identidad y vuelve a verificar")
    ports = {ssh_port} if ssh_port is not None else set()
    if spec.get("port") and spec["port"] not in ports:
        import socket
        try:
            with socket.create_connection((host, spec["port"]), timeout=5):
                ports.add(spec["port"])
        except OSError:
            pass  # Missing reachability is unknown, never pass.
    coverage = authenticated_coverage(platform, data, ports, host, sources=[spec["source"]])
    findings_fn = getattr(authenticated_checks, f"{platform}_findings")
    findings = [f for f in findings_fn(host, data, ports) if f.source == spec["source"]]
    run = NmapRun(hosts=[Host(address=host, state="up", ports=[Port(portid=p, state="open")
                          for p in ports])], hosts_up=1, hosts_total=1,
                  coverage=coverage, exit_status="success")
    db.set_scan_context(scan_id, execution_context={"coverage": coverage,
                        "observed_at": datetime.now(UTC).isoformat(),
                        "provenance": {"engine": "authenticated", "imported": False}})
    db.save_results(scan_id, run, findings, analysis.risk_score(findings))
    db.save_host_inventory(scan_id, host, data, "openssh" if platform == "linux" else "winrm",
                            controls=getattr(compliance, f"{platform}_controls")(data, ports))
    if cancel is not None and cancel.is_set():
        db.set_status(scan_id, "cancelled", error="Cancelado durante la recopilacion")
    else:
        db.set_progress(scan_id, 100, "Control evaluado")
        db.set_status(scan_id, "done")
