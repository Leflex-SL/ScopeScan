import json
import re
from dataclasses import asdict

import pytest
from fastapi.testclient import TestClient

from scopescan import cli, db, engine_service, engine_store, scopes, service
from scopescan.engine_contracts import EnginePlan, EngineResult, Observation, Provenance
from scopescan.models import Finding, Host, NmapRun, Port, Service, Severity
from scopescan.web import app as web


class FixtureEngine:
    name='nuclei'
    def available(self):
        return True,'Fixture only; no network process'
    def plan(self,scope,timeout=120):
        return EnginePlan(self.name,scope,scope.endpoints,('headers',),timeout)
    def execute(self,plan,cancel=None):
        endpoint=plan.endpoints[0]
        finding=Finding('<script>unsafe</script>',Severity.LOW,'engine:nuclei:headers',endpoint.host,endpoint.port,rule_id='headers',evidence='observed header')
        observation=Observation(endpoint,'headers','positive','Observed response','2026-01-01T00:00:00Z',finding)
        return EngineResult('nuclei','complete',Provenance('nuclei','3.11.1','fixture'),(observation,),raw=b'{"response":"public"}')


@pytest.fixture
def fixture_engine(monkeypatch):
    monkeypatch.setattr(engine_service,'adapter',lambda name:FixtureEngine())


def saved_scope():
    return scopes.create_scope(name='Fixture',targets='192.0.2.1',authorized_by='operator')


def test_real_registry_builds_both_adapters_and_plans_without_execution():
    from scopescan.nuclei import NucleiAdapter
    from scopescan.sslyze_adapter import SSLyzeAdapter
    assert isinstance(engine_service.adapter('nuclei'),NucleiAdapter)
    assert isinstance(engine_service.adapter('sslyze'),SSLyzeAdapter)
    scope=saved_scope()
    plan=engine_service.preview('sslyze',scope,ports=(443,),service='https')
    assert plan.engine=='sslyze' and plan.endpoints[0].port==443
    assert engine_service.preview('nuclei',scope,ports=(80,),service='http').engine=='nuclei'


def test_cli_preview_run_result_raw(fixture_engine,capsys):
    scope=saved_scope()
    assert cli.main(['engine','preview','nuclei',str(scope),'--ports','80','--service','http'])==0
    preview=json.loads(capsys.readouterr().out)
    assert preview['plan']['scope']['authorized_by']=='operator'
    assert cli.main(['engine','run','nuclei',str(scope),'--ports','80','--service','http'])==2
    capsys.readouterr()
    assert cli.main(['engine','run','nuclei',str(scope),'--ports','80','--service','http','--yes'])==0
    scan=json.loads(capsys.readouterr().out)['scan_id']
    assert cli.main(['engine','results','--scan-id',str(scan)])==0
    result_id=json.loads(capsys.readouterr().out)['items'][0]['id']
    assert cli.main(['engine','raw',str(result_id)])==0
    assert json.loads(capsys.readouterr().out)['raw']
    with pytest.raises(ValueError,match='revis'):
        service.rerun(scan)


def test_preview_queue_csrf_one_use_and_evidence_html(fixture_engine,monkeypatch):
    submitted=[]
    monkeypatch.setattr(web.QUEUE,'submit',lambda scan_id:submitted.append(scan_id))
    monkeypatch.setattr(web.QUEUE,'shutdown',lambda **kwargs:None)
    scope=saved_scope()
    with TestClient(web.app,base_url='http://localhost',client=('127.0.0.1',51000)) as client:
        assert client.get('/engines').status_code==200
        assert client.post('/engines/preview',data={'engine':'nuclei','scope_id':scope,'ports':'80','service':'http'}).status_code==403
        client.headers['X-CSRF-Token']=client.cookies['scopescan_csrf']
        preview=client.post('/engines/preview',data={'engine':'nuclei','scope_id':scope,'ports':'80','service':'http'})
        assert preview.status_code==200,preview.text
        token=re.search(r'name="preview_token" value="([^"]+)"',preview.text)[1]
        response=client.post('/engines/run',data={'preview_token':token},follow_redirects=False)
        assert response.status_code==303
        assert len(submitted)==1
        assert client.post('/engines/run',data={'preview_token':token}).status_code==400
        service.execute(submitted[0])
        items,_=engine_store.list_results()
        detail=client.get(f"/engines/results/{items[0]['id']}")
        assert detail.status_code==200 and '3.11.1' in detail.text
        assert '<script>unsafe</script>' not in detail.text
        assert client.get(f"/api/engines/results/{items[0]['id']}/raw").json()['raw']
        assert client.get('/api/engines/results').json()['total']==1


def test_changed_scope_rejects_preview_and_worker(fixture_engine):
    from scopescan.web.engines import save_preview, take_preview
    scope=saved_scope()
    plan=engine_service.preview('nuclei',scope,ports=(80,),service='http')
    token=save_preview(plan)
    scopes.update_scope(scope,name='Fixture',targets='192.0.2.2',authorized_by='operator')
    with pytest.raises(ValueError,match='changed'):
        take_preview(token)
    with pytest.raises(ValueError,match='changed'):
        engine_service.execute(plan)
    assert not db.list_scans()


def test_service_at_position_101_is_in_plan(fixture_engine):
    scope=saved_scope()
    scan=db.create_scan(name='Many ports',targets='192.0.2.1',profile='tcp',scope_id=scope)
    run=NmapRun(hosts=[Host('192.0.2.1',state='up',ports=[Port(port,state='open',service=Service('http')) for port in range(1,102)])],exit_status='success')
    db.set_status(scan,'running')
    db.save_results(scan,run,[],0)
    db.set_status(scan,'done')
    plan=engine_service.preview('nuclei',scope)
    assert len(plan.endpoints)==101
    assert plan.endpoints[-1].port==101
    assert engine_service.decode_plan(json.loads(json.dumps(asdict(plan))))==plan


def test_tls_tunnel_and_explicit_service_are_preserved(fixture_engine):
    scope=saved_scope()
    scan=db.create_scan(name='TLS',targets='192.0.2.1',profile='tcp',scope_id=scope)
    run=NmapRun(hosts=[Host('192.0.2.1',state='up',ports=[Port(443,state='open',service=Service('http',tunnel='ssl'))])],exit_status='success')
    db.set_status(scan,'running')
    db.save_results(scan,run,[],0)
    db.set_status(scan,'done')
    assert engine_service.scope_from_saved(scope).endpoints[0].service=='https'
    assert engine_service.scope_from_saved(scope,ports=(8443,),service='https').endpoints[0].service=='https'
    with pytest.raises(ValueError):
        engine_service.scope_from_saved(scope,service='http')


def test_asset_at_position_101_is_in_execution_scope(fixture_engine):
    hosts=[f'192.0.2.{index}' for index in range(1,102)]
    scope=scopes.create_scope(name='Many hosts',targets=' '.join(hosts),authorized_by='operator')
    scan=db.create_scan(name='Many hosts',targets=' '.join(hosts),profile='tcp',scope_id=scope)
    run=NmapRun(hosts=[Host(address,state='up',ports=[Port(80,state='open',service=Service('http'))]) for address in hosts],exit_status='success')
    db.set_status(scan,'running')
    db.save_results(scan,run,[],0)
    db.set_status(scan,'done')
    plan=engine_service.preview('nuclei',scope)
    assert len(plan.endpoints)==101
    assert {endpoint.host for endpoint in plan.endpoints}==set(hosts)


def test_cli_vuls_import_retains_original_source_hash(tmp_path,capsys):
    import hashlib

    from test_vuls_linux_adapters import report
    data=report()
    scope=scopes.create_scope(name='ImportedLinux',targets='192.0.2.4',authorized_by='operator')
    payload=json.dumps(data).encode()
    path=tmp_path/'vuls.json'
    path.write_bytes(payload)
    assert cli.main(['engine','import','vuls',str(path),'--scope-id',str(scope),'--host','192.0.2.4'])==0
    scan=json.loads(capsys.readouterr().out)['scan_id']
    items,_=engine_store.list_results(scan_id=scan)
    evidence=engine_store.get_result(items[0]['id'],include_raw=True)
    assert evidence['provenance']['imported']
    assert json.loads(evidence['raw'])['source_sha256']==hashlib.sha256(payload).hexdigest()
    assert 'DO_NOT_PERSIST' not in json.dumps(evidence)
    finding=db.get_findings(scan)[0]
    assert finding['assessment']=='candidate' and not finding['confirmed']
    with pytest.raises(ValueError):
        engine_service.import_evidence('vuls',payload,scope_id=scope,host='192.0.2.5')


def test_linux_advisories_import_uses_original_db_inventory_date():
    from test_precision_feeds import feed
    scope=scopes.create_scope(name='ImportedLinux',targets='192.0.2.4',authorized_by='operator')
    scan=db.create_scan(name='Inventory',targets='192.0.2.4',profile='tcp')
    inventory={'platform':'linux','os_id':'debian','os_version':'12','package_manager':'dpkg','packages':[{'name':'openssl','version':'3.0.11-1+deb12u1','repository':'bookworm-security','repository_class':'distribution'}]}
    with db.connect() as conn:
        conn.execute('INSERT INTO host_inventory(scan_id,host,source,collected_at,data) VALUES(?,?,?,?,?)',(scan,'192.0.2.4','ssh','2025-01-01T00:00:00+00:00',json.dumps(inventory)))
    imported=engine_service.import_evidence('linux-advisories',json.dumps(feed()).encode(),scope_id=scope,host='192.0.2.4',inventory_scan_id=scan)
    items,_=engine_store.list_results(scan_id=imported)
    evidence=engine_store.get_result(items[0]['id'])
    assert evidence['normalized'][0]['observed_at']=='2025-01-01T00:00:00+00:00'
    assert db.get_scan(imported)['observed_at'].startswith('2025-01-01')
