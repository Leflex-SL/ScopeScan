"""Bounded CycloneDX 1.6 / SPDX 2.3 interchange without remote resolution."""
from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from collections import deque
from datetime import UTC, datetime, timedelta

from .engine_store import sanitize

MAX_BYTES = 8_000_000
MAX_ITEMS = 20_000
EXPORT_METADATA_PREFIX = "Imported evidence; producer metadata and relationships: "


def timestamp(value: str | None) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError("Evidence timestamp must be text")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Evidence timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("Evidence timestamp needs timezone and must not be in the future")
    return parsed.astimezone(UTC).isoformat()


def bounded_json(payload: bytes) -> dict:
    if not isinstance(payload, bytes) or len(payload) > MAX_BYTES:
        raise ValueError("Evidence exceeds 8 MB")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(payload, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON number")))
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON evidence") from exc
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 64 or count > 300_000:
            raise ValueError("Evidence exceeds depth/node budget")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("Nonfinite JSON number")
    if not isinstance(value, dict):
        raise ValueError("Evidence must be a JSON object")  # noqa: TRY004 - invalid external evidence
    return value


def text(value, *, required=False, maximum=4096) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ValueError("Invalid or oversized evidence text")
    return value


def objects(value, label="collection") -> list:
    if not isinstance(value, list) or len(value) > MAX_ITEMS or any(not isinstance(x, dict) for x in value):
        raise ValueError(f"Invalid bounded {label}")
    return value


def component_identity(resource_id: str, component: dict) -> str:
    purl = component["purl"]
    if purl:
        path, marker, qualifiers = purl.partition("?")
        path, fragment_marker, fragment = path.partition("#")
        # Keep ecosystem/name, arch/distro qualifiers and subpath, separate observed version.
        if "@" in path:
            path = path.rsplit("@", 1)[0]
        key = path + (marker + qualifiers if marker else "") + (fragment_marker + fragment if fragment_marker else "")
    else:
        key = [component["type"], component["name"], component.get("identity_qualifiers", "")]
    return hashlib.sha256(json.dumps([resource_id, key], ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


def parse(payload: bytes) -> dict:
    original = bounded_json(payload)
    safe, redactions = sanitize(payload, "application/json")
    document = bounded_json(safe)
    components = []
    dependencies = []
    if document.get("bomFormat") == "CycloneDX" and document.get("specVersion") == "1.6":
        kind = "cyclonedx"
        metadata = document.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Invalid CycloneDX metadata")
        observed = timestamp(metadata.get("timestamp"))
        for prop in objects(metadata.get("properties", []), "metadata properties"):
            if prop.get("name") == "scopescan:source-metadata":
                source_metadata = bounded_json(text(prop.get("value"), required=True, maximum=MAX_BYTES).encode())
                observed = timestamp(source_metadata.get("observed_at"))
        if "version" in document and (type(document["version"]) is not int or document["version"] < 1):
            raise ValueError("CycloneDX version must be a positive integer")
        pending = deque(objects(document.get("components", []), "components"))
        while pending:
            item = pending.popleft()
            if len(components) >= MAX_ITEMS:
                raise ValueError("Too many software components")
            name = text(item.get("name"), required=True)
            ref = text(item.get("bom-ref")) or "generated:" + str(len(components))
            component_type = text(item.get("type"), required=True)
            if component_type not in {"application", "framework", "library", "container", "platform", "operating-system", "device", "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset"}:
                raise ValueError("Unsupported CycloneDX component type")
            purl = text(item.get("purl"))
            if purl and not purl.startswith("pkg:"):
                raise ValueError("Invalid component package URL")
            components.append({"ref": ref, "name": name, "version": text(item.get("version")),
                               "purl": purl, "type": component_type, "source": item,
                               "identity_qualifiers": text(item.get("group")), "hashes": item.get("hashes", []),
                               "properties": item.get("properties", [])})
            pending.extend(objects(item.get("components", []), "nested components"))
        for item in objects(document.get("dependencies", []), "dependencies"):
            ref = text(item.get("ref"), required=True)
            targets = item.get("dependsOn", [])
            if not isinstance(targets, list) or len(targets) > MAX_ITEMS:
                raise ValueError("Invalid dependency list")
            dependencies.extend({"source": ref, "target": text(target, required=True), "type": "DEPENDS_ON"} for target in targets)
        producers = metadata.get("tools", {})
        namespace = text(document.get("serialNumber"))
    elif document.get("spdxVersion") == "SPDX-2.3":
        kind = "spdx"
        if document.get("dataLicense") != "CC0-1.0" or document.get("SPDXID") != "SPDXRef-DOCUMENT":
            raise ValueError("SPDX document requires CC0-1.0 and SPDXRef-DOCUMENT")
        namespace = text(document.get("documentNamespace"), required=True)
        text(document.get("name"), required=True)
        metadata = document.get("creationInfo")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("creators"), list) or not metadata["creators"]:
            raise ValueError("SPDX creationInfo requires creators")
        observed = timestamp(text(metadata.get("created"), required=True))
        comment = document.get("comment", "")
        if isinstance(comment, str) and comment.startswith(EXPORT_METADATA_PREFIX):
            source_metadata = bounded_json(comment[len(EXPORT_METADATA_PREFIX):].encode())
            observed = timestamp(source_metadata.get("observed_at"))
        producers = metadata["creators"]
        for item in objects(document.get("packages", []), "packages"):
            ref = text(item.get("SPDXID"), required=True)
            if not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", ref):
                raise ValueError("Invalid SPDX package identifier")
            purls = [text(x.get("referenceLocator"), required=True) for x in objects(item.get("externalRefs", []), "external refs") if x.get("referenceType") == "purl"]
            if any(not x.startswith("pkg:") for x in purls):
                raise ValueError("Invalid SPDX package URL")
            text(item.get("downloadLocation"), required=True)
            components.append({"ref": ref, "name": text(item.get("name"), required=True),
                               "version": text(item.get("versionInfo")), "purl": purls[0] if purls else "",
                               "type": "library", "source": item, "hashes": item.get("checksums", []),
                               "identity_qualifiers": text(item.get("supplier"))})
        for item in objects(document.get("relationships", []), "relationships"):
            dependencies.append({"source": text(item.get("spdxElementId"), required=True),
                                 "target": text(item.get("relatedSpdxElement"), required=True),
                                 "type": text(item.get("relationshipType"), required=True)})
    else:
        raise ValueError("Supported formats: CycloneDX JSON 1.6 and SPDX JSON 2.3")
    refs = [item["ref"] for item in components]
    if len(set(refs)) != len(refs) or len(dependencies) > MAX_ITEMS:
        raise ValueError("Duplicate component references or too many relationships")
    return {"format": kind, "format_version": "1.6" if kind == "cyclonedx" else "2.3",
            "observed_at": observed, "components": components, "dependencies": dependencies,
            "producers": producers, "document_namespace": namespace, "document": document,
            "raw": safe, "received_sha256": hashlib.sha256(payload).hexdigest(),
            "raw_sha256": hashlib.sha256(safe).hexdigest(), "redactions": redactions,
            "coverage": "components_supplied", "original_format": original.get("bomFormat", original.get("spdxVersion"))}


def export(normalized: dict, kind: str) -> bytes:
    if kind not in {"cyclonedx", "spdx"}:
        raise ValueError("Choose cyclonedx or spdx")
    # Deterministic cross-format IDs retain exact original IDs in properties/comments.
    namespace = str(uuid.uuid5(uuid.NAMESPACE_URL, normalized["received_sha256"]))
    created = datetime.now(UTC).isoformat()
    items = normalized["components"]
    ids = {item["ref"]: f"SPDXRef-component-{index}" for index, item in enumerate(items)}
    if kind == "spdx":
        packages = []
        for item in items:
            entry = {"SPDXID": ids[item["ref"]], "name": item["name"], "downloadLocation": "NOASSERTION",
                     "filesAnalyzed": False, "comment": "ScopeScan source component: " + item["ref"],
                     "sourceInfo": json.dumps(item["source"], ensure_ascii=True, separators=(",", ":"))}
            if item["version"]:
                entry["versionInfo"] = item["version"]
            if item["purl"]:
                entry["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": item["purl"]}]
            packages.append(entry)
        relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": item["SPDXID"], "relationshipType": "DESCRIBES"} for item in packages]
        relationships.extend({"spdxElementId": ids[rel["source"]], "relatedSpdxElement": ids[rel["target"]], "relationshipType": "DEPENDS_ON"} for rel in normalized["dependencies"] if rel["source"] in ids and rel["target"] in ids and rel["type"] == "DEPENDS_ON")
        document = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                    "name": "ScopeScan software inventory", "documentNamespace": "https://scopescan.local/spdx/" + namespace,
                    "creationInfo": {"created": created.replace("+00:00", "Z"), "creators": ["Tool: ScopeScan"]},
                    "packages": packages, "relationships": relationships,
                    "comment": EXPORT_METADATA_PREFIX + json.dumps({"observed_at": normalized["observed_at"], "producers": normalized["producers"], "namespace": normalized["document_namespace"], "relationships": normalized["dependencies"], "original_document": normalized["document"]}, ensure_ascii=True)}
    else:
        components = []
        for item in items:
            entry = {"type": item["type"], "bom-ref": item["ref"], "name": item["name"],
                     "properties": [{"name": "scopescan:original-component", "value": json.dumps(item["source"], ensure_ascii=True)}]}
            if item["version"]:
                entry["version"] = item["version"]
            if item["purl"]:
                entry["purl"] = item["purl"]
            components.append(entry)
        grouped = {}
        for rel in normalized["dependencies"]:
            if rel["type"] == "DEPENDS_ON":
                grouped.setdefault(rel["source"], []).append(rel["target"])
        document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + namespace,
                    "version": 1, "metadata": {"timestamp": created.replace("+00:00", "Z"),
                    "properties": [{"name": "scopescan:source-metadata", "value": json.dumps({"observed_at": normalized["observed_at"], "producers": normalized["producers"], "namespace": normalized["document_namespace"], "relationships": normalized["dependencies"], "original_document": normalized["document"]}, ensure_ascii=True)}]},
                    "components": components, "dependencies": [{"ref": ref, "dependsOn": sorted(set(targets))} for ref, targets in grouped.items()]}
    encoded = json.dumps(document, ensure_ascii=True, indent=2).encode()
    if len(encoded) > MAX_BYTES:
        raise ValueError("Export with preserved original metadata exceeds 8 MB; use the sanitized raw evidence")
    return encoded
