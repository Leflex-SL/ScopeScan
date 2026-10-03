"""Private boundary helpers for optional external-process adapters."""
from __future__ import annotations

import json
import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .engine_contracts import EnginePlan, EngineResult, Observation, Provenance
from .models import Assessment, Finding, Severity


def stamp() -> str:
    return datetime.now(UTC).isoformat()


def isolated_environment(root: Path) -> dict[str, str]:
    # No proxy, engine variables, cloud credentials, config or parent PATH inheritance.
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}}
    for name in ("home", "config", "templates", "appdata", "localappdata", "tmp"):
        (root / name).mkdir(exist_ok=True)
    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
               APPDATA=str(root / "appdata"), LOCALAPPDATA=str(root / "localappdata"),
               XDG_CONFIG_HOME=str(root / "config"), NUCLEI_CONFIG_DIR=str(root / "config"),
               NUCLEI_TEMPLATES_DIR=str(root / "templates"), TMP=str(root / "tmp"),
               TEMP=str(root / "tmp"), TMPDIR=str(root / "tmp"))
    return env


def command_for(name: str, command: tuple[str, ...] | None) -> tuple[str, ...]:
    if command is not None:
        if not isinstance(command, tuple) or not command or any(not isinstance(x, str) or not x for x in command):
            raise ValueError("Trusted engine command must be a nonempty tuple")
        executable = shutil.which(command[0])
        if executable is None:
            raise FileNotFoundError(f"Engine executable unavailable: {name}")
        return (str(Path(executable).resolve()), *command[1:])
    executable = shutil.which(name)
    if executable is None:
        raise FileNotFoundError(f"Install optional {name} at its supported version and add its executable to PATH")
    return (str(Path(executable).resolve()),)


def checked_plan(adapter, plan: EnginePlan) -> None:
    expected = adapter.plan(plan.scope, timeout=plan.timeout)
    if (plan.engine, plan.endpoints, plan.rules, plan.options) != (
            expected.engine, expected.endpoints, expected.rules, expected.options):
        raise ValueError("Engine plan differs from the reviewed scope/rules policy")
    if len(plan.endpoints) * len(plan.rules) > 10000:
        raise ValueError("Engine plan exceeds 10000 bounded observations")


_SECRETS = re.compile(r"(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key):[^\r\n]*")


def redact_text(value: str) -> str:
    value = _SECRETS.sub(r"\1: [redacted]", value)
    return re.sub(r"(?i)(\b(?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*)[^\s&;,]+",
                  r"\1[redacted]", value)


def sanitized(value) -> bytes:
    def clean(item):
        if isinstance(item, dict):
            return {str(k): ("[redacted]" if re.search(r"(?i)password|secret|token|api[-_]?key|authorization|cookie|credential", str(k)) else clean(v))
                    for k, v in item.items()}
        if isinstance(item, list):
            return [clean(x) for x in item]
        if isinstance(item, str):
            return redact_text(item)
        return item
    return json.dumps(clean(value), ensure_ascii=True, separators=(",", ":")).encode()


def observation(endpoint, rule: str, vulnerable: bool | None, evidence: str,
                title: str, severity: Severity = Severity.MEDIUM,
                *, engine: str, exposure: bool = False) -> Observation:
    finding = None
    evidence = redact_text(evidence)
    outcome = "unknown" if vulnerable is None else "positive" if vulnerable else "negative"
    if vulnerable is True:
        finding = Finding(title, severity, f"{engine}:{rule}", endpoint.host,
                          port=endpoint.port, protocol=endpoint.protocol, service=endpoint.service,
                          evidence=evidence, description=title,
                          remediation="Review the observed configuration and verify the exact endpoint again.",
                          confirmed=not exposure,
                          assessment=Assessment.EXPOSURE if exposure else Assessment.CONFIRMED,
                          rule_id=rule)
    return Observation(endpoint, rule, outcome, evidence, stamp(), finding)


def result(engine: str, provenance: Provenance, observations: list[Observation], raw,
           errors: list[str], started: str, *, cancelled: bool = False,
           failed: bool = False, maximum: int = 2_000_000) -> EngineResult:
    encoded = sanitized(raw)
    if len(encoded) > maximum:
        encoded = b""
        errors.append("Sanitized raw evidence exceeds the job budget; normalized observations retained")
    status = ("cancelled" if cancelled else "failed" if failed else "partial"
              if errors or any(o.outcome == "unknown" for o in observations) else "complete")
    return EngineResult(engine, status, provenance, tuple(observations), encoded,
                        tuple(errors), started, stamp())
