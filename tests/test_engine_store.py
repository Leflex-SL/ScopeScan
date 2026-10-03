import json
from dataclasses import replace

import pytest

from scopescan import db
from scopescan.engine_contracts import (
    Endpoint,
    EnginePlan,
    EngineResult,
    Observation,
    Provenance,
    ScanScope,
)
from scopescan.engine_store import get_result, list_results, persist
from scopescan.models import Finding, Severity


def plan():
    endpoint=Endpoint('192.0.2.1',443)
    return EnginePlan('tls',ScanScope('scope:fixture','operator',(endpoint,)),(endpoint,),('certificate',))


def result(p, outcome='positive', status='complete', imported=False, version='v1'):
    finding=Finding('Bad certificate',Severity.HIGH,'engine:tls:certificate','192.0.2.1',443,rule_id='certificate') if outcome=='positive' else None
    observations=() if outcome=='empty' else (Observation(p.endpoints[0],'certificate',outcome,'hostname mismatches' if finding else 'hostname matches','2026-01-01T00:00:00Z',finding),)
    return EngineResult('tls',status,Provenance('tls','6.3.1',version,imported=imported),observations,raw=b'{"certificate":"public", "config":{"password":"hidden"},"authorization":"hidden"}')


def test_versions_raw_redaction_export_and_deletion():
    from scopescan import export
    p=plan()
    scan=persist(p,result(p))
    items,total=list_results(scan_id=scan)
    assert total==1
    evidence=get_result(items[0]['id'],include_raw=True)
    assert evidence['provenance']['engine_version']=='6.3.1'
    assert 'hidden' not in evidence['raw']
    assert evidence['raw_sha256']!=evidence['received_sha256']
    assert export.scan_payload(scan)['engine_results'][0]['plan_hash']==p.fingerprint
    db.delete_scan(scan)
    assert list_results(scan_id=scan)[1]==0


@pytest.mark.parametrize('outcome,status,imported,version', [('empty','complete',False,'v1'),('negative','failed',False,'v1'),('negative','partial',False,'v1'),('negative','cancelled',False,'v1'),('negative','complete',True,'v1'),('negative','complete',False,'v2')])
def test_uncovered_or_untrusted_absence_never_resolves(outcome,status,imported,version):
    p=plan()
    persist(p,result(p))
    persist(p,result(p,outcome,status,imported,version))
    findings,_=db.list_current_findings()
    assert len(findings)==1
    assert findings[0]['lifecycle']!='resolved'


def test_explicit_exact_negative_resolves():
    p=plan()
    persist(p,result(p))
    persist(p,result(p,'negative'))
    findings,_=db.list_current_findings()
    assert findings[0]['lifecycle']=='resolved'


def test_offscope_observation_is_rejected_before_db():
    p=plan()
    malicious=replace(result(p),observations=(Observation(Endpoint('192.0.2.2',443),'certificate','negative','good','2026-01-01T00:00:00Z'),))
    with pytest.raises(ValueError):
        persist(p,malicious)
    assert not db.list_scans()


def test_host_assessment_grant_does_not_create_ssh_port():
    endpoint=Endpoint('192.0.2.1',None,'host')
    scope=ScanScope('host-test','operator',(endpoint,))
    assert scope.contains(endpoint.host,None,'host')
    assert not scope.contains(endpoint.host,22,'tcp')
    p=EnginePlan('packages',scope,(endpoint,),('CVE-test',))
    finding=Finding('Package candidate',Severity.HIGH,'engine:packages:CVE-test',endpoint.host,protocol='host',rule_id='CVE-test')
    scan=persist(p,EngineResult('packages','complete',Provenance('packages','1','1'),(Observation(endpoint,'CVE-test','positive','version less than fix','2026-01-01T00:00:00Z',finding),)))
    assert not db.get_ports(scan)
    assert json.loads(db.get_scan(scan)['coverage'])['protocols']=={'host':[None]}


def test_normalized_overflow_rejected_before_any_database_write():
    p=plan()
    output=result(p)
    output.observations[0].finding.evidence='x'*8_000_001
    with pytest.raises(ValueError):
        persist(p,output)
    assert not db.list_scans()


def test_mutated_finding_scope_rejected():
    p=plan()
    output=result(p)
    output.observations[0].finding.host='192.0.2.99'
    with pytest.raises(ValueError):
        persist(p,output)
    assert not db.list_scans()


def test_secrets_removed_from_normalized_findings_and_errors():
    p=plan()
    output=result(p)
    output.observations[0].finding.evidence='Authorization: Bearer hidden\npassword=hidden'
    output=replace(output,errors=('token=hidden',))
    scan=persist(p,output)
    finding=db.get_findings(scan)[0]
    assert 'hidden' not in finding['evidence']
    item=list_results(scan_id=scan)[0][0]
    assert 'hidden' not in json.dumps(get_result(item['id'],include_raw=True))


def test_old_import_preserves_newer_import_observation_timestamp():
    p=plan()
    output=result(p,imported=True)
    newer=replace(output,observations=(replace(output.observations[0],observed_at='2026-06-01T00:00:00Z'),))
    persist(p,newer)
    older=replace(output,observations=(replace(output.observations[0],observed_at='2020-01-01T00:00:00Z'),))
    persist(p,older)
    findings,_=db.list_current_findings()
    assert findings[0]['last_seen'].startswith('2026-06-01')


def test_unknown_engine_preserves_closed_network_state():
    from scopescan.models import Host, NmapRun, Port, Service
    p=plan()
    scan=db.create_scan(name='Nmap',targets='192.0.2.1',profile='tcp',execution_context={'namespace':p.scope.namespace})
    run=NmapRun(hosts=[Host('192.0.2.1',state='up',ports=[Port(443,state='closed',service=Service('https',version='original'))])],exit_status='success',start=1767225600)
    db.set_status(scan,'running')
    db.save_results(scan,run,[],0)
    db.set_status(scan,'done')
    persist(p,result(p,'unknown'))
    assets,_=db.list_assets()
    asset=db.get_asset(assets[0]['id'])
    assert asset['current_state']['ports'][0]['state']=='closed'
    assert asset['current_state']['ports'][0]['version']=='original'


def test_changed_trust_store_never_resolves_incompatible_baseline():
    p=plan()
    output=result(p)
    output=replace(output,provenance=replace(output.provenance,feeds=(('Mozilla','2026.01'),)))
    persist(p,output)
    negative=result(p,'negative')
    negative=replace(negative,provenance=replace(negative.provenance,feeds=(('Mozilla','2026.02'),)))
    persist(p,negative)
    findings,_=db.list_current_findings()
    assert findings[0]['lifecycle']!='resolved'


@pytest.mark.parametrize('outcome', ['unknown','negative'])
def test_store_revalidates_non_positive_finding_before_database_writes(outcome):
    p=plan()
    output=result(p,status='partial')
    # Defensive persistence validation also rejects deserialized/tampered contracts.
    object.__setattr__(output.observations[0],'outcome',outcome)
    with pytest.raises(ValueError,match='Only positive'):
        persist(p,output)
    assert not db.list_scans()
    assert db.list_current_findings()[1]==0


@pytest.mark.parametrize('url,expected',[
    ('https://fixture-user:PRIVATE-SENTINEL@repo.example.test/packages','https://repo.example.test/packages'),
    ('ftp://fixture%2Duser:PRIVATE%2DSENTINEL@[2001:db8::1]:2121/packages','ftp://[2001:db8::1]:2121/packages'),
    ('custom+repo://user:PRIVATE-SENTINEL%40repo.example.test/packages','custom+repo://repo.example.test/packages'),
    ('//user:PRIVATE-SENTINEL@repo.example.test/path','//repo.example.test/path')])
def test_uri_userinfo_is_redacted_preserving_host_port_and_path(url,expected):
    from scopescan.engine_store import redact_text
    assert redact_text(url)==expected


def test_vuls_repository_credentials_never_survive_any_persisted_evidence_or_exports():
    import hashlib

    from test_vuls_linux_adapters import report, scope

    from scopescan import export, vuls_import
    document=report()
    document['packages']['openssl']['repository']='https://fixture-user:PRIVATE-SENTINEL@repo.example.test/packages'
    payload=json.dumps(document).encode()
    adapter=vuls_import.VulsImportAdapter(payload,host='192.0.2.4')
    p=adapter.plan(scope())
    adapter_result=adapter.execute(p)
    assert b'PRIVATE-SENTINEL' not in adapter_result.raw
    assert 'PRIVATE-SENTINEL' not in adapter_result.observations[0].evidence
    scan=persist(p,adapter_result)
    row=db.get_findings(scan)[0]
    assert 'PRIVATE-SENTINEL' not in row['evidence']
    items,_=list_results(scan_id=scan)
    evidence=get_result(items[0]['id'],include_raw=True)
    assert 'PRIVATE-SENTINEL' not in json.dumps(evidence)
    assert json.loads(evidence['raw'])['source_sha256']==hashlib.sha256(payload).hexdigest()
    assert evidence['redactions'] or json.loads(evidence['raw'])['redaction_manifest']
    assert 'https://repo.example.test/packages' in evidence['raw']
    assert 'PRIVATE-SENTINEL' not in export.render_json(scan)
    assert 'PRIVATE-SENTINEL' not in export.render_findings_csv(scan)


def test_unknown_only_engine_result_does_not_count_host_up():
    p=plan()
    scan=persist(p,result(p,'unknown',status='partial'))
    assert db.get_scan(scan)['hosts_up']==0
    assert db.get_scan(scan)['hosts_total']==1
    assert db.get_hosts(scan)[0]['state']=='unknown'


def virtual_plan(hostnames=('a.example.test','b.example.test'),service='https'):
    endpoints=tuple(Endpoint('192.0.2.1',443,service=service,hostname=name) for name in hostnames)
    return EnginePlan('tls',ScanScope('virtual-hosts','operator',endpoints,resolutions=tuple((name,('192.0.2.1',)) for name in hostnames)),endpoints,('certificate',))


def virtual_result(p,outcomes):
    observations=[]
    for endpoint,outcome in zip(p.endpoints,outcomes,strict=True):
        finding=Finding('Hostname failure',Severity.HIGH,'engine:tls:certificate',endpoint.host,endpoint.port,rule_id='certificate',component='original-plugin-component') if outcome=='positive' else None
        observations.append(Observation(endpoint,'certificate',outcome,'actual certificate matches requested identity' if outcome=='negative' else 'actual certificate hostname mismatch','2026-01-01T00:00:00Z',finding))
    return EngineResult('tls','complete',Provenance('tls','6.3.1','v1'),tuple(observations))


def test_virtual_hosts_coexist_and_negative_resolves_only_exact_hostname():
    p=virtual_plan()
    persist(p,virtual_result(p,('positive','positive')))
    findings,total=db.list_current_findings()
    assert total==2
    assert all(finding['component'].startswith('original-plugin-component::endpoint-v1:') for finding in findings)
    components={item['endpoint']['hostname']:item['finding']['component'] for item in get_result(list_results()[0][0]['id'])['normalized']}
    b_plan=virtual_plan(('b.example.test',))
    persist(b_plan,virtual_result(b_plan,('negative',)))
    findings,_=db.list_current_findings()
    lifecycle={finding['component']:finding['lifecycle'] for finding in findings}
    assert lifecycle[components['b.example.test']]=='resolved'
    assert lifecycle[components['a.example.test']]!='resolved'
    a_plan=virtual_plan(('a.example.test',))
    persist(a_plan,virtual_result(a_plan,('negative',)))
    assert all(finding['lifecycle']=='resolved' for finding in db.list_current_findings()[0])


def test_service_change_never_resolves_incompatible_endpoint_condition():
    p=virtual_plan(('a.example.test',),service='https')
    persist(p,virtual_result(p,('positive',)))
    other=virtual_plan(('a.example.test',),service='http')
    persist(other,virtual_result(other,('negative',)))
    assert db.list_current_findings()[0][0]['lifecycle']!='resolved'


def test_metadata_userinfo_redacted_and_grant_credentials_rejected():
    p=plan()
    output=result(p)
    output=replace(output,provenance=replace(output.provenance,feeds=(('https://user:PRIVATE-SENTINEL@feed.test/data','1'),)))
    scan=persist(p,output)
    items,_=list_results(scan_id=scan)
    evidence=get_result(items[0]['id'],include_raw=True)
    assert 'PRIVATE-SENTINEL' not in json.dumps(evidence)
    assert 'Credential-bearing provenance text redacted' in evidence['redactions']
    bad_plan=replace(p,options=(('source','https://user:PRIVATE-SENTINEL@feed.test/data'),))
    before=len(db.list_scans())
    with pytest.raises(ValueError,match='grants cannot contain URI credentials'):
        persist(bad_plan,result(bad_plan))
    assert len(db.list_scans())==before
