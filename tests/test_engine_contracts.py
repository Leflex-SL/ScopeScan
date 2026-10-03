import pytest

from scopescan.engine_contracts import (
    Endpoint,
    EnginePlan,
    EngineResult,
    Observation,
    Provenance,
    ScanScope,
)
from scopescan.models import Finding, Severity


def test_hostname_is_operator_pinned():
    e = Endpoint('192.0.2.1', 443, hostname='example.test')
    with pytest.raises(ValueError):
        ScanScope('scope:1', 'operator', (e,))
    scope = ScanScope('scope:1', 'operator', (e,), resolutions=(('example.test', ('192.0.2.1',)),))
    assert scope.contains('192.0.2.1', 443)
    assert not scope.contains('192.0.2.2', 443)
    for name in ('a..b', '-host.test', 'host-.test', 'a'*64+'.test', 'a/test'):
        with pytest.raises(ValueError):
            Endpoint('192.0.2.1',443,hostname=name)


@pytest.mark.parametrize('timeout', [True, float('nan'), float('inf'), -1, 3601])
def test_bounds(timeout):
    endpoint = Endpoint('192.0.2.1',443)
    scope = ScanScope('test','operator',(endpoint,))
    with pytest.raises(ValueError):
        EnginePlan('tls',scope,(endpoint,),('certificate',),timeout=timeout)


def test_scope_plan_is_immutable_and_exact():
    endpoint = Endpoint('192.0.2.1',443)
    scope = ScanScope('test','operator',(endpoint,))
    with pytest.raises(ValueError):
        EnginePlan('tls',scope,(Endpoint('192.0.2.2',443),),('certificate',))
    with pytest.raises(ValueError):
        EnginePlan('tls',scope,(endpoint,),('certificate',),options=(('key',[]),))
    assert EnginePlan('tls',scope,(endpoint,),('certificate',)).fingerprint


def test_exact_observation_rule_endpoint_and_timestamp():
    endpoint = Endpoint('192.0.2.1',443)
    finding = Finding('Bad certificate',Severity.HIGH,'engine:tls:certificate','192.0.2.1',443,rule_id='certificate')
    positive = Observation(endpoint,'certificate','positive','bad hostname','2026-01-01T00:00:00Z',finding)
    result = EngineResult('tls','complete',Provenance('tls','6.3.1','v1'),(positive,))
    assert result.observations[0].finding is finding
    with pytest.raises(ValueError):
        Observation(endpoint,'certificate','negative','','2026-01-01T00:00:00Z')
    with pytest.raises(ValueError):
        Observation(endpoint,'other','positive','bad','2026-01-01T00:00:00Z',finding)
    with pytest.raises(ValueError):
        Observation(endpoint,'certificate','negative','good','2100-01-01T00:00:00Z')


@pytest.mark.parametrize('outcome', ['unknown','negative'])
def test_non_positive_observation_cannot_carry_a_finding(outcome):
    endpoint = Endpoint('192.0.2.1',443)
    finding = Finding('Claim',Severity.HIGH,'engine:tls:certificate',endpoint.host,endpoint.port,rule_id='certificate')
    with pytest.raises(ValueError,match='Only positive'):
        Observation(endpoint,'certificate',outcome,'timeout or pass','2026-01-01T00:00:00Z',finding)
