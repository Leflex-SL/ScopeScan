"""Parseo de la salida XML de nmap (-oX) al modelo de datos.

Se parsea el XML y no la salida de texto porque el texto cambia entre versiones
y con el nivel de verbosidad, mientras que el DTD del XML es estable.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from .models import Host, NmapRun, OSMatch, Port, ScriptResult, Service


class NmapParseError(RuntimeError):
    """El XML no se pudo leer o no es una salida de nmap."""


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
    return ScriptResult(
        id=node.get("id", "desconocido"),
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
    state_node = node.find("state")
    return Port(
        portid=portid,
        protocol=node.get("protocol", "tcp"),
        state=state_node.get("state", "unknown") if state_node is not None else "unknown",
        reason=state_node.get("reason", "") if state_node is not None else "",
        service=_parse_service(node.find("service")),
        scripts=[_parse_script(s) for s in node.findall("script")],
    )


def _parse_host(node: ET.Element) -> Host:
    host = Host(address="")

    for addr in node.findall("address"):
        kind = addr.get("addrtype", "")
        value = addr.get("addr", "")
        if kind in ("ipv4", "ipv6") and not host.address:
            host.address = value
            host.addrtype = kind
        elif kind == "mac":
            host.mac = value
            host.vendor = addr.get("vendor", "")

    status = node.find("status")
    if status is not None:
        host.state = status.get("state", "unknown")

    for hn in node.findall("hostnames/hostname"):
        name = hn.get("name")
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
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise NmapParseError(f"XML de nmap ilegible: {exc}") from exc
    return parse_element(root)


def parse_file(path: str | Path) -> NmapRun:
    path = Path(path)
    if not path.is_file():
        raise NmapParseError(f"No existe el XML {path}")
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        # nmap interrumpido a media escritura deja un XML truncado; se intenta
        # recuperar cerrando la etiqueta raiz antes de rendirse.
        recovered = _recover_truncated(path.read_text(encoding="utf-8", errors="replace"))
        if recovered is None:
            raise NmapParseError(f"XML de nmap ilegible ({path}): {exc}") from exc
        return parse_string(recovered)
    return parse_element(tree.getroot())


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

    return run
