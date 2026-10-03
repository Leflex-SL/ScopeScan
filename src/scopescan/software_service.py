"""Evidence interchange and durable worker-only software operations."""
from __future__ import annotations

import hashlib
import json
import math

from . import sbom, software_store
from .engine_store import redact_text


def import_evidence(kind: str, payload: bytes, *, namespace: str, resource_kind: str, resource_name: str) -> int:
    software_store.identity(namespace, resource_kind, resource_name)
    if kind == "sbom":
        value = sbom.parse(payload)
    elif kind == "scap":
        from .scap_import import parse
        value = parse(payload)
    elif kind == "grype":
        from .grype_adapter import parse
        value = parse(payload)
    else:
        raise ValueError("Choose sbom, scap or grype evidence")
    return software_store.persist(value, namespace=namespace, resource_kind=resource_kind,
                                  resource_name=resource_name, kind=kind,
                                  provenance={"producer": "external-import", "format": value["format"], "format_version": value["format_version"]})


def preview(kind: str, payload: dict, *, authorized_by: str) -> dict:
    sbom.text(authorized_by, required=True, maximum=256)
    if redact_text(authorized_by) != authorized_by:
        raise ValueError("Authorization actor must not contain credentials")
    if kind not in {"software.syft", "software.grype"}:
        raise ValueError("Unsupported software operation")
    value = {"namespace": payload.get("namespace", ""), "resource_kind": payload.get("resource_kind", "software"),
             "resource_name": payload.get("resource_name", ""), "authorized_by": authorized_by,
             "timeout": payload.get("timeout", 120)}
    software_store.identity(value["namespace"], value["resource_kind"], value["resource_name"])
    if isinstance(value["timeout"], bool) or not isinstance(value["timeout"], (int, float)) or not math.isfinite(value["timeout"]) or not 0 < value["timeout"] <= 3600:
        raise ValueError("Timeout must be finite and between 0 and 3600 seconds")
    if kind == "software.syft":
        source = sbom.text(payload.get("source"), required=True)
        if ":" not in source or redact_text(source) != source or any(ord(char) < 32 for char in source):
            raise ValueError("Use an explicit source without credentials")
        scheme, location = source.split(":", 1)
        from .syft_adapter import LOCAL_SCHEMES, registry_reference
        if scheme not in LOCAL_SCHEMES | {"registry"} or not location or location.startswith("-"):
            raise ValueError("Unsupported explicit Syft source")
        allow = payload.get("allow_registry", False)
        if type(allow) is not bool or scheme == "registry" and not allow:
            raise ValueError("Registry cataloguing requires explicit network authorization")
        if scheme == "registry" and not registry_reference(location):
            raise ValueError("Registry source must be an OCI image reference without credentials")
        value.update(source=source, allow_registry=allow)
    else:
        document_id = payload.get("document_id")
        if type(document_id) is not int or document_id < 1:
            raise ValueError("Choose an existing SBOM document")
        row = software_store.get(document_id)
        if row is None or row["kind"] != "sbom":
            raise ValueError("SBOM document not found")
        if (row["namespace"], row["resource_kind"], row["name"]) != (value["namespace"], value["resource_kind"], value["resource_name"]):
            raise ValueError("Grype resource must match its supplied SBOM")
        value.update(document_id=document_id, sbom_received_sha256=row["received_sha256"])
    fingerprint = hashlib.sha256(json.dumps([kind, value], sort_keys=True).encode()).hexdigest()
    return {"kind": kind, "payload": value, "fingerprint": fingerprint,
            "execution": "separate-worker", "coverage": "components_supplied", "confirmed": False}


def enqueue(kind: str, payload: dict, *, authorized_by: str) -> int:
    from .durable_jobs import enqueue as queue
    plan = preview(kind, payload, authorized_by=authorized_by)
    return queue(kind, plan["payload"], retry_safe=True, max_attempts=2)


def execute_job(kind: str, payload: dict, cancel) -> dict:
    # Revalidate durable, user-controlled JSON at the worker trust boundary.
    reviewed = preview(kind, payload, authorized_by=payload.get("authorized_by", ""))["payload"]
    if cancel.is_set():
        raise ValueError("Software operation cancelled")
    if kind == "software.syft":
        from .syft_adapter import SyftAdapter
        value = SyftAdapter().execute(reviewed["source"], allow_registry=reviewed["allow_registry"], timeout=reviewed["timeout"], cancel=cancel)
        document_kind = "sbom"
    else:
        from .grype_adapter import GrypeAdapter
        row = software_store.get(reviewed["document_id"], raw=True)
        if row is None or row["received_sha256"] != payload.get("sbom_received_sha256"):
            raise ValueError("Reviewed SBOM evidence changed or disappeared")
        value = GrypeAdapter().execute(row["raw"], timeout=reviewed["timeout"], cancel=cancel)
        document_kind = "grype"
    if cancel.is_set():
        raise ValueError("Software operation cancelled before persistence")
    document_id = software_store.persist(value, namespace=reviewed["namespace"], resource_kind=reviewed["resource_kind"],
                                         resource_name=reviewed["resource_name"], kind=document_kind,
                                         provenance={"producer": kind, "engine_version": value["engine_version"],
                                                     "authorized_by": reviewed["authorized_by"], "database": value.get("database")})
    evidence_status = value.get("status", "complete")
    return {"document_id": document_id, "status": "done" if evidence_status == "complete" else evidence_status,
            "evidence_status": evidence_status, "error": "; ".join(value.get("errors", []))[:4096]}


def register_jobs():
    from .worker import register_handler
    for kind in ("software.syft", "software.grype"):
        def handler(payload, context, kind=kind):
            context.check_cancelled()
            return execute_job(kind, payload, context.cancel)
        register_handler(kind, handler)


def export_document(document_id: int, kind: str) -> bytes:
    row = software_store.get(document_id)
    if row is None or row["kind"] != "sbom":
        raise ValueError("SBOM document not found")
    return sbom.export(row["normalized"], kind)
