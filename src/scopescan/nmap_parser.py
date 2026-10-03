"""Parseo de la salida XML de nmap (-oX) al modelo de datos.

Se parsea el XML y no la salida de texto porque el texto cambia entre versiones
y con el nivel de verbosidad, mientras que el DTD del XML es estable.
"""

from __future__ import annotations

import ipaddress
import math
import re
from io import StringIO
from pathlib import Path
from xml.etree import ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .models import Host, NmapRun, OSMatch, Port, ScriptResult, Service


class NmapParseError(RuntimeError):
    """El XML no se pudo leer o no es una salida de nmap."""


MAX_XML_BYTES = 32 * 1024 * 1024
MAX_XML_ELEMENTS = 250000


def parse_port_spec(value: str) -> list[int]:
    ports: set[int] = set()
    for part in value.split(","):
        if not part:
            continue
        low, _, high = part.partition("-")
        try:
            first, last = int(low), int(high or low)
        except ValueError as exc:
            raise NmapParseError("scaninfo.services invalido") from exc
        if not 0 <= first <= last <= 65535:
            raise NmapParseError("scaninfo.services fuera de rango")
        ports.update(range(first, last + 1))
    return sorted(ports)


def _script_elements(node: ET.Element) -> dict[str, str]:
    """Aplana los <elem key="..."> de un script, incluidos los de tablas de primer nivel."""
    out: dict[str, str] = {}
    for elem in node.findall("elem"):
        key = elem.get("key")
        if key:
            out[key] = (elem.text or "").strip()
    for table in node.findall("table"):
        prefix = table.get("key", "")
        for elem in table.findall("elem"):
            key = elem.get("key")
            if key:
                out[f"{prefix}.{key}" if prefix else key] = (elem.text or "").strip()
    return out


def _parse_script(node: ET.Element) -> ScriptResult:
    identifier = node.get("id", "desconocido")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", identifier):
        raise NmapParseError("Identificador de script Nmap invalido")
    return ScriptResult(
        id=identifier,
        output=(node.get("output") or "").strip(),
        elements=_script_elements(node),
    )


def _parse_service(node: ET.Element | None) -> Service:
    if node is None:
        return Service()
    try:
        conf = int(node.get("conf", "0"))
    except ValueError:
        conf = 0
    return Service(
        name=node.get("name", ""),
        product=node.get("product", ""),
        version=node.get("version", ""),
        extrainfo=node.get("extrainfo", ""),
        ostype=node.get("ostype", ""),
        tunnel=node.get("tunnel", ""),
        method=node.get("method", ""),
        confidence=conf,
        cpes=[(c.text or "").strip() for c in node.findall("cpe") if (c.text or "").strip()],
    )


def _parse_port(node: ET.Element) -> Port | None:
    try:
        portid = int(node.get("portid", ""))
    except ValueError:
        return None
    if not 0 <= portid <= 65535 or node.get("protocol", "tcp") not in {"tcp", "udp", "sctp", "ip"}:
        raise NmapParseError("Puerto/protocolo de Nmap invalido")
    state_node = node.find("state")
    if state_node is not None and state_node.get("state", "unknown") not in {
        "open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered", "unknown"
    }:
        raise NmapParseError("Estado de puerto Nmap invalido")
    return Port(
        portid=portid,
        protocol=node.get("protocol", "tcp"),
        state=state_node.get("state", "unknown") if state_node is not None else "unknown",
        reason=state_node.get("reason", "") if state_node is not None else "",
        service=_parse_service(node.find("service")),
        scripts=[_parse_script(s) for s in node.findall("script")],
    )


def _parse_host(node: ET.Element) -> Host:
    host = Host(address="", timed_out=node.get("timedout") == "true")

    for addr in node.findall("address"):
        kind = addr.get("addrtype", "")
        value = addr.get("addr", "")
        if kind in ("ipv4", "ipv6") and not host.address:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise NmapParseError("IP de host Nmap invalida") from exc
            if address.version != (4 if kind == "ipv4" else 6):
                raise NmapParseError("La IP no coincide con addrtype")
            host.address = str(address)
            host.addrtype = kind
        elif kind == "mac":
            host.mac = value
            host.vendor = addr.get("vendor", "")

    status = node.find("status")
    if status is not None:
        host.state = status.get("state", "unknown")
        if host.state not in {"up", "down", "unknown", "skipped"}:
            raise NmapParseError("Estado de host Nmap invalido")

    for hn in node.findall("hostnames/hostname"):
        name = hn.get("name")
        if name and (len(name) > 253 or any(ord(ch) < 32 for ch in name)):
            raise NmapParseError("Nombre de host Nmap invalido")
        if name and name not in host.hostnames:
            host.hostnames.append(name)

    ports_node = node.find("ports")
    if ports_node is not None:
        for extra in ports_node.findall("extraports"):
            try:
                host.extraports[extra.get("state", "?")] = int(extra.get("count", "0"))
            except ValueError:
                pass
        for port_node in ports_node.findall("port"):
            port = _parse_port(port_node)
            if port is not None:
                host.ports.append(port)
        host.ports.sort(key=lambda p: (p.protocol, p.portid))

    host.hostscripts = [_parse_script(s) for s in node.findall("hostscript/script")]

    for match in node.findall("os/osmatch"):
        try:
            accuracy = int(match.get("accuracy", "0"))
        except ValueError:
            accuracy = 0
        host.osmatches.append(OSMatch(name=match.get("name", ""), accuracy=accuracy))

    return host


def parse_string(xml: str) -> NmapRun:
    if len(xml.encode("utf-8")) > MAX_XML_BYTES:
        raise NmapParseError("XML supera el limite de 32 MiB")
    try:
        parser = SafeET.iterparse(StringIO(xml), events=("start", "end"),
                                  forbid_entities=True, forbid_external=True)
        count = depth = 0
        for event, _node in parser:
            if event == "start":
                count += 1
                depth += 1
                if count > MAX_XML_ELEMENTS or depth > 100:
                    raise NmapParseError("XML supera el limite de elementos o profundidad")
            else:
                depth -= 1
        root = parser.root
    except (ET.ParseError, DefusedXmlException) as exc:
        raise NmapParseError(f"XML de nmap ilegible: {exc}") from exc
    return parse_element(root)


def parse_file(path: str | Path) -> NmapRun:
    path = Path(path)
    if not path.is_file():
        raise NmapParseError(f"No existe el XML {path}")
    if path.stat().st_size > MAX_XML_BYTES:
        raise NmapParseError("XML supera el limite de 32 MiB")
    with path.open("rb") as stream:
        xml = stream.read(MAX_XML_BYTES + 1)
    if len(xml) > MAX_XML_BYTES:
        raise NmapParseError("XML supera el limite de 32 MiB")
    try:
        return parse_string(xml.decode("utf-8"))
    except UnicodeError as exc:
        raise NmapParseError("XML debe ser UTF-8") from exc
    except NmapParseError as exc:
        if not isinstance(exc.__cause__, ET.ParseError):
            raise
        # nmap interrumpido a media escritura deja un XML truncado; se intenta
        # recuperar cerrando la etiqueta raiz antes de rendirse.
        recovered = _recover_truncated(xml.decode("utf-8", errors="replace"))
        if recovered is None:
            raise NmapParseError(f"XML de nmap ilegible ({path}): {exc}") from exc
        return parse_string(recovered)


def _recover_truncated(xml: str) -> str | None:
    if "<nmaprun" not in xml:
        return None
    # Corta por el ultimo </host> completo y cierra la raiz.
    cut = xml.rfind("</host>")
    if cut == -1:
        cut = xml.find(">", xml.find("<nmaprun"))
        if cut == -1:
            return None
        return xml[: cut + 1] + "</nmaprun>"
    return xml[: cut + len("</host>")] + "</nmaprun>"


def parse_element(root: ET.Element) -> NmapRun:
    if root.tag != "nmaprun":
        raise NmapParseError(f"La raiz del XML es <{root.tag}>, se esperaba <nmaprun>")

    run = NmapRun(
        args=root.get("args", ""),
        scanner_version=root.get("version", ""),
    )
    try:
        run.start = int(root.get("start", "0"))
    except ValueError:
        run.start = 0

    finished = root.find("runstats/finished")
    if finished is not None:
        try:
            run.elapsed = float(finished.get("elapsed", "0"))
        except ValueError:
            run.elapsed = 0.0
        if not math.isfinite(run.elapsed) or run.elapsed < 0:
            raise NmapParseError("Duracion de Nmap invalida")
        run.exit_status = finished.get("exit", "")
        run.summary = finished.get("summary", "")

    hosts_node = root.find("runstats/hosts")
    if hosts_node is not None:
        try:
            run.hosts_up = int(hosts_node.get("up", "0"))
            run.hosts_total = int(hosts_node.get("total", "0"))
        except ValueError:
            pass

    run.hosts = [_parse_host(h) for h in root.findall("host")]
    if not run.hosts_total:
        run.hosts_total = len(run.hosts)
        run.hosts_up = sum(1 for h in run.hosts if h.is_up)

    protocols: dict[str, list[int]] = {}
    scan_types: dict[str, str] = {}
    for info in root.findall("scaninfo"):
        protocol = info.get("protocol", "")
        if protocol not in {"tcp", "udp", "sctp", "ip"}:
            raise NmapParseError("Protocolo scaninfo desconocido")
        ports = parse_port_spec(info.get("services", ""))
        try:
            count = int(info.get("numservices", "0"))
        except ValueError as exc:
            raise NmapParseError("numservices invalido") from exc
        if count != len(ports):
            raise NmapParseError("numservices no coincide con services")
        protocols[protocol] = sorted(set(protocols.get(protocol, [])) | set(ports))
        scan_types[protocol] = info.get("type", "")
    complete = (run.exit_status == "success" and bool(protocols)
                and not any(h.timed_out for h in run.hosts))
    run.coverage = {"status": "complete" if complete else "partial", "engine": "nmap",
                    "engine_version": run.scanner_version, "protocols": protocols,
                    "scan_types": scan_types, "hosts": [h.address for h in run.hosts
                                                         if not h.timed_out and h.is_up],
                    "timed_out_hosts": [h.address for h in run.hosts if h.timed_out],
                    "endpoints": [{"host": h.address, "port": p.portid,
                                   "protocol": p.protocol, "state": p.state,
                                   "scripts": [s.id for s in p.scripts]}
                                  for h in run.hosts if not h.timed_out for p in h.ports]}
    run.provenance = {"engine": "nmap", "engine_version": run.scanner_version,
                      "source_timestamp": run.start,
                      "finished_exit": run.exit_status,
                      "finished_time": finished.get("time", "") if finished is not None else ""}

    return run
