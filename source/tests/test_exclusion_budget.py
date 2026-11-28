"""Exclusion checks are bounded and do not repeat established ASN evidence."""
import subprocess,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'routing/scripts'))
from exclusion_policy import ExclusionPolicy,lookup_addresses
from update_routing import cached_dns_compatible
policy=ExclusionPolicy({45102},['47.245.128.0/18'])
verified={'ok.example':{'results':[{'asn':'AS1'}]},'denied.example':{'results':[{'asn':'AS45102'}]}}
with patch('exclusion_policy.lookup_addresses',side_effect=AssertionError('Redundant resolver call')):
    assert policy.excluded_domains(set(verified),set(),verified,deadline=0)=={'denied.example'}
    assert not policy.unchecked_domains
print('PASS existing ASN evidence avoids resolver calls and preserves denied domains')
clock=[0];calls=[]
def resolve(host):
    calls.append(host);clock[0]=2
    return {'47.245.183.75'}
with patch('exclusion_policy.time.monotonic',side_effect=lambda:clock[0]),patch('exclusion_policy.lookup_addresses',side_effect=resolve):
    blocked=policy.excluded_domains({f'h{i:06}.example' for i in range(504000)},set(),{},deadline=1)
assert len(calls)==24 and len(blocked)==24 and len(policy.unchecked_domains)==504000-24
print('PASS 504000-name exclusion queue schedules only one cohort before deadline, no unbounded executor shutdown')
with patch('exclusion_policy.subprocess.run',side_effect=subprocess.TimeoutExpired('resolver',2)) as run:
    assert lookup_addresses('timeout.example')==set()
    assert run.call_args.kwargs['timeout']==2
print('PASS system resolver is isolated in a process with enforceable two-second timeout')

assert cached_dns_compatible({'complete':False,'results':[],'errors':[{'check_host':'n'}]},policy,False)
assert cached_dns_compatible({'results':[{'asn':'AS1','ips':['11.0.0.1']}]},policy,False)
assert not cached_dns_compatible({'results':[{'asn':'AS1','ips':['47.245.183.75']}]},policy,False)
assert cached_dns_compatible({'results':[],'excluded_ips':['47.245.183.75']},policy,False)
assert not cached_dns_compatible({'results':[],'excluded_ips':['11.0.0.1']},policy,False)
print('PASS changed BGP export reuses unaffected DNS rows but refreshes changed exclusion membership')
