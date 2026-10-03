# Saved scopes, targeted verification and evidence imports

Saved scopes contain validated targets, exclusions, an owned profile key, authorization,
and the concrete IP addresses resolved at creation/update. Preview, queue and worker use
those same IPs. Editing a scope resolves it again but does not rewrite existing jobs.
IPv4 and IPv6 require separate scopes; IPv6 execution includes Nmap `-6`. CIDR ranges
include every address, matching Nmap, and exclusions are applied before execution.
The default host limit is configurable per request with a hard ceiling of 65,536.

Network verification plans select affected ports and an explicit owned rule/NSE allowlist.
An imported script identifier never becomes an NSE expression. Successful execution alone
does not prove a fix: actual port, script output, service-version evidence, engine and rule
coverage must match. A timeout, skipped check, unversioned banner or missing control stays
not assessed. Rule versions are implementation hashes, so changed checks cannot silently
close old findings.
Repeating a verification rebuilds its plan from the current finding IDs and retains
their namespace. It checks the original endpoint, owned selectors and current saved
scope authorization before queuing. A changed or missing scope, stale plan or unavailable
authenticated identity requires selecting the current finding and using Verify again.
An authenticated repeat uses the currently configured worker identity rather than
treating the inventory profile as a Nmap profile.
Repeating an ordinary ad hoc scan retains the original scan namespace and pinned IPs,
so repeated observations update the same current assets and findings.
Vulnerability negatives require an explicit recognized `State: NOT VULNERABLE`;
the owned plan enables `vulns.showall=1` so successful negative output is visible.
`ssl-cert` closes only the expiry control when both validity dates are complete
and expiry exceeds 30 days. It does not assert chain or hostname trust. See the
[official ssl-cert output](https://nmap.org/nsedoc/scripts/ssl-cert.html) and
[Heartbleed script documentation](https://nmap.org/nsedoc/scripts/ssl-heartbleed.html).

Authenticated verification uses the existing static inventory collectors. Configure
`SCOPESCAN_VERIFY_LINUX_IDENTITY=1` only when OpenSSH keys/agent and host trust are ready;
optional `SCOPESCAN_VERIFY_SSH_USER` and `SCOPESCAN_VERIFY_SSH_PORT` select the identity
and endpoint. Configure `SCOPESCAN_VERIFY_WINDOWS_IDENTITY=1` when the worker process
identity has authorized WinRM access. Passwords and private keys are never stored in jobs.
The worker collects observed control predicates; absent or inaccessible settings remain
unknown. A configured identity flag cannot manufacture a successful collection.
For SSH daemon controls, the configured identity port must match the affected listener
at planning, queueing and execution. Inventories retain the actual collection port;
positive and negative control evidence belongs only to that TCP endpoint. An inventory
from port 2222 cannot resolve a finding on port 22. Legacy data without explicit collection
port yields unknown SSH coverage and controls. Host controls can still be collected through
any configured SSH port, since their predicates are independent of the SSH listener.
Collectors currently bound collection to 180 seconds for SSH and 120 for WinRM;
cancellation during collection takes effect when that call returns, preserves partial
evidence and prevents negative reconciliation. D05/D07 must move these collectors to
the shared cancellable process runner before claiming immediate worker cancellation.

Nmap XML imports follow the [official Nmap DTD](https://nmap.org/book/nmap-dtd.html):
`scaninfo` determines ports/protocols, `host timedout` excludes incomplete host coverage,
and only `finished exit="success"` establishes a completed source run. Imported `args`
are evidence only and never executed. XML entities/external resolution are prohibited;
the harmless normal `DOCTYPE nmaprun SYSTEM "nmap.dtd"` declaration is supported.
Files are bounded to 32 MiB, 250,000 elements and depth 100. A truncated local process
XML may be recovered as partial evidence; malformed import documents are rejected.

Each imported document gets a uniquely named managed raw copy and SHA-256 hash, source
timestamp, engine/version and external provenance. Identical uploads cannot overwrite
earlier evidence. Findings are external unverified claims, including imported positive
NSE verdicts. Imported records cannot grant Metasploit actions or replay an external
command. Recheck through an authorized local scope to collect local evidence.
An explicit namespace groups imports for chronological comparison; isolated namespaces
are the default. Older observations do not replace newer current state.
Source dates more than five minutes ahead of the worker UTC clock are rejected before
creating a scan or raw copy. This tolerance accommodates small clock skew while keeping
future claims from freezing current state; correct the source clock/date before retrying.

## Versioned external JSON contract

ScopeScan owns `scopescan.external.v1`; vendor formats must first be translated to this
contract rather than guessed. Required top-level fields are `schema`, `engine`,
`engine_version`, `observed_at` (ISO-8601 with timezone), `coverage` and `hosts`.
`rules_version` and `findings` are optional. Lists and the aggregate number of endpoints
are capped at 10,000 records.

```json
{
  "schema": "scopescan.external.v1",
  "engine": "example-scanner",
  "engine_version": "1.0",
  "rules_version": "policy-1",
  "observed_at": "2026-10-03T10:00:00Z",
  "coverage": {"status": "complete", "protocols": {"tcp": [23]}, "rules": ["telnet"]},
  "hosts": [{"address": "192.168.1.10", "state": "up", "ports": [
    {"port": 23, "protocol": "tcp", "state": "open", "service": {"name": "telnet"}}
  ]}],
  "findings": [{"host": "192.168.1.10", "port": 23, "protocol": "tcp",
    "rule_id": "telnet", "title": "Cleartext service", "severity": "medium",
    "evidence": "23/tcp reachable", "remediation": "Restrict or replace the service"}]
}
```

Coverage status is `complete`, `partial` or `unknown`; protocols map to port lists or
bounded `1-65535` range strings. Coverage rule identifiers refer to the exact evaluated
rules. Hosts must be literal IPs. Services preserve name/product/version/extrainfo/tunnel;
findings preserve rule ID, endpoint, evidence, remediation, CVSS and CVE IDs. Sources are
namespaced `external:<engine>:<rule_id>`. Imported filesystem paths, job IDs, arbitrary
arguments, scripts, modules and claimed confirmation do not become executable state.
Structural values are checked before normalization: enum fields and IPs require text,
ports require integers excluding booleans, CVSS requires finite numeric values, and
external `observed_at` requires ISO-8601 text with timezone. Invalid input produces an
actionable import error before any scan or raw evidence is created.
