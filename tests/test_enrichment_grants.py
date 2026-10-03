"""Active enrichments must retain and revalidate their exact target authorization."""
import json
from types import SimpleNamespace

import pytest

from scopescan import (
    db,
    durable_jobs,
    jobs,
    linux_inventory,
    msf,
    scopes,
    windows_inventory,
    worker,
)
from scopescan.models import Host, NmapRun, Port, Service

HOST = "192.0.2.10"


def baseline(*, host=HOST, scoped=True):
    scope_id = scopes.create_scope(name="grant",targets=host,profile="rapido",authorized_by="operator") if scoped else None
    scan_id = db.create_scan(name="historical",targets=host,profile="rapido",authorized_by="operator",
        scope_id=scope_id,execution_context={"pinned_targets":[host]})
    db.save_results(scan_id,NmapRun(exit_status="success",hosts_up=1,hosts_total=1,
        hosts=[Host(host,state="up",ports=[Port(22,state="open",service=Service("ssh"))])]),[],0)
    db.set_status(scan_id,"done")
    return scan_id,scope_id


def change(scope_id, field):
    if field == "delete":
        db.delete_scope(scope_id)
        return
    with db.connect() as conn:
        row = conn.execute("SELECT specification FROM saved_scopes WHERE id=?",(scope_id,)).fetchone()
        value = json.loads(row[0])
        if field == "authorization":
            value["authorized_by"] = ""
        elif field == "exclusions":
            value.update(exclusions=HOST,pinned_targets=[])
        elif field == "profile":
            value["profile"] = "descubrimiento"
        elif field == "limits":
            value["max_hosts"] += 1
        elif field == "resolution":
            value["resolutions"] = {"changed.example":[HOST]}
        conn.execute("UPDATE saved_scopes SET specification=? WHERE id=?",(json.dumps(value),scope_id))


@pytest.mark.parametrize("kind",["linux","windows","metasploit","metasploit-exploit"])
@pytest.mark.parametrize("mutation",["authorization","exclusions","delete","profile","limits","resolution"])
def test_scope_changes_stop_active_enrichment_before_collector_or_runner(monkeypatch,kind,mutation):
    scan_id,scope_id = baseline()
    module = SimpleNamespace(path="auxiliary/scanner/ssh/ssh_version",action="scanner")
    monkeypatch.setattr(msf,"plan_scan",lambda sid:[(HOST,22,"ssh",module)])
    monkeypatch.setattr(msf,"_validated_exploit_context",lambda *args,**kwargs:(db.get_scan(scan_id),module,22))
    def forbidden(*args,**kwargs):
        pytest.fail("Revoked or changed active grant reached a collector/runner")
    monkeypatch.setattr(linux_inventory,"collect",forbidden)
    monkeypatch.setattr(windows_inventory,"collect",forbidden)
    monkeypatch.setattr(msf,"verify_scan",forbidden)
    monkeypatch.setattr(msf,"exploit_target",forbidden)
    options = {"host":HOST} if kind in {"linux","windows"} else {}
    if kind == "metasploit-exploit":
        options = {"host":HOST,"port":22,"module_path":module.path}
    job_id = jobs.enqueue_enrichment(scan_id,kind,options)
    payload = json.loads(durable_jobs.get(job_id)["payload"])
    assert payload["grant"]["scope_snapshot"]["authorized_by"] == "operator"
    assert payload["grant"]["targets"] == [HOST]
    change(scope_id,mutation)
    result = worker.run_once(job_id=job_id)
    assert result["status"] == "failed"
    assert "scope" in result["error"].lower()
    assert db.get_enrichment_statuses(scan_id)[kind]["status"] == "failed"


def test_revoked_grant_at_enqueue_rolls_back_status_and_job():
    scan_id,scope_id = baseline()
    change(scope_id,"authorization")
    with pytest.raises(ValueError,match="authorization revoked"):
        jobs.enqueue_enrichment(scan_id,"linux",{"host":HOST})
    assert durable_jobs.list_jobs() == [] and db.get_enrichment_statuses(scan_id) == {}


def test_endpoint_addition_after_enqueue_cannot_broaden_inventory(monkeypatch):
    scan_id,_ = baseline(scoped=False)
    job_id = jobs.enqueue_enrichment(scan_id,"linux",{})
    with db.connect() as conn:
        conn.execute("INSERT INTO hosts(scan_id,address,state) VALUES (?,?,'up')",(scan_id,"192.0.2.11"))
    monkeypatch.setattr(linux_inventory,"collect",lambda *args,**kwargs:pytest.fail("Endpoint selection expanded"))
    result = worker.run_once(job_id=job_id)
    assert result["status"] == "failed"
    assert "original ad-hoc scan grant" in result["error"]


def test_missing_grant_fails_before_ssh(monkeypatch):
    scan_id,_ = baseline()
    job_id = durable_jobs.enqueue("enrichment",{"scan_id":scan_id,"kind":"linux","options":{"host":HOST}},scan_id=scan_id)
    monkeypatch.setattr(linux_inventory,"collect",lambda *args,**kwargs:pytest.fail("Missing grant reached SSH"))
    row = worker.run_once(job_id=job_id)
    assert row["status"] == "failed" and "grant missing" in row["error"]


def test_valid_scope_grant_inventory_executes_exact_listener(monkeypatch):
    scan_id,_ = baseline()
    called = []
    def collect(host,**options):
        called.append((host,options["port"]))
        return {"platform":"linux","ssh_port":options["port"],"sshd":{}}
    monkeypatch.setattr(linux_inventory,"collect",collect)
    job_id = jobs.enqueue_enrichment(scan_id,"linux",{"host":HOST,"port":2222})
    assert worker.run_once(job_id=job_id)["status"] == "done"
    assert called == [(HOST,2222)]


@pytest.mark.parametrize("kind",["nvd","msrc","exploitdb"])
def test_feed_and_offline_enrichments_can_use_historical_scope_after_deletion(monkeypatch,kind):
    from scopescan import exploitdb, msrc, nvd
    scan_id,scope_id = baseline()
    called = []
    def evaluate(sid,**options):
        called.append(sid)
        return 0
    module = {"nvd":nvd,"msrc":msrc,"exploitdb":exploitdb}[kind]
    monkeypatch.setattr(module,"assess_scan" if kind=="msrc" else "enrich_scan",evaluate)
    job_id = jobs.enqueue_enrichment(scan_id,kind,{})
    assert "grant" not in json.loads(durable_jobs.get(job_id)["payload"])
    db.delete_scope(scope_id)
    assert worker.run_once(job_id=job_id)["status"] == "done"
    assert called == [scan_id]


def test_explicit_local_loopback_inventory_can_use_historical_scope(monkeypatch):
    scan_id,scope_id = baseline(host="127.0.0.1")
    called = []
    def collect(host,**options):
        assert options["local"]
        called.append(host)
        return {"platform":"windows","os_build":"19045","ubr":1}
    monkeypatch.setattr(windows_inventory,"collect",collect)
    job_id = jobs.enqueue_enrichment(scan_id,"windows",{"host":"127.0.0.1","local":True})
    db.delete_scope(scope_id)
    assert worker.run_once(job_id=job_id)["status"] == "done"
    assert called == ["127.0.0.1"]


def test_revoke_between_hosts_stops_next_collector(monkeypatch):
    scan_id,scope_id = baseline()
    second = "192.0.2.11"
    scopes.update_scope(scope_id,name="grant",targets=f"{HOST} {second}",profile="rapido",authorized_by="operator")
    with db.connect() as conn:
        conn.execute("INSERT INTO hosts(scan_id,address,state) VALUES (?,?,'up')",(scan_id,second))
    called = []
    def collect(host,**options):
        called.append(host)
        change(scope_id,"authorization")
        return {"platform":"linux","ssh_port":options["port"],"sshd":{}}
    monkeypatch.setattr(linux_inventory,"collect",collect)
    job_id = jobs.enqueue_enrichment(scan_id,"linux",{})
    row = worker.run_once(job_id=job_id)
    assert row["status"] == "failed" and called == [HOST]
