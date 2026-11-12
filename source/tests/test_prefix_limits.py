"""Observed-IP-only ASN narrowing, ownership, masks and workflow refresh regression."""
import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'routing/scripts'))
from prefix_limits import PrefixLimits, read_limits, merge_observations
from update_routing import global_rules, incremental_update, write_json

snapshot = {24940: ['62.238.0.0/17', '88.99.0.0/16', '178.104.0.0/15', '188.40.0.0/16']}
policy = PrefixLimits({24940: 24}, snapshot)
records = {
    'luxcdn.com': {'AS24940': ['62.238.15.232', '178.104.21.52']},
    's.luxcdn.com': {'AS24940': ['62.238.15.232', '178.104.21.52']},
    'api.sypexgeo.net': {'AS24940': ['88.99.125.123']},
    '2ip.io': {'AS24940': ['188.40.167.81']},
    '2ip.ru': {'AS24940': ['188.40.167.82']},
}
domains = {'rules': [{'ruleTag': host, 'domain': ['domain:' + host]} for host in records]}
raw = {'rules': [{'ruleTag': 'luxcdn.com', 'ip': ['62.238.0.0/17', '178.104.0.0/15']},
                 {'ruleTag': 'api.sypexgeo.net', 'ip': ['88.99.0.0/16']},
                 {'ruleTag': '2ip.io', 'ip': ['188.40.0.0/16']},
                 {'ruleTag': '2ip.ru', 'ip': ['188.40.0.0/16']}]}
narrowed = policy.filter_rules(raw, domains, records)
narrowed['ipv4_prefix_limits'] = policy.signature()
result = global_rules(narrowed)
assert {p for r in result['rules'] for p in r['ip']} == {
    '62.238.15.0/24', '88.99.125.0/24', '178.104.21.0/24', '188.40.167.0/24'}
assert sum(len(r['ip']) for r in result['rules']) == 4
for host, origins in records.items():
    for value in origins['AS24940']:
        assert any(ipaddress.ip_address(value) in ipaddress.ip_network(p) for r in result['rules'] for p in r['ip'])
assert policy.filter_rules({'rules': [{'ruleTag': 'unknown.example', 'ip': ['188.40.0.0/16']}]}, domains, records)['rules'] == []
assert policy.unobserved[-1]['ruleTag'] == 'unknown.example'
# Already narrow/manual prefixes and IPv6 survive; foreign ASN evidence cannot seed a Hetzner /24.
assert policy.filter_rules({'rules': [{'ruleTag': 'manual', 'ip': ['188.40.167.128/25', '2001:db8::/32', '192.0.2.0/24']}]}, domains, records)['rules'][0]['ip'] == ['188.40.167.128/25', '192.0.2.0/24', '2001:db8::/32']
assert policy.filter_rules(raw, domains, {host: {'AS999': values['AS24940']} for host, values in records.items()})['rules'] == []
adjacent = {'rules': [{'ruleTag': 'x', 'ip': ['188.40.166.0/24', '188.40.167.0/24']}], 'ipv4_prefix_limits': policy.signature()}
assert global_rules(adjacent)['rules'] == adjacent['rules']
# Complete refresh replaces stale observations; partial observations retain old evidence.
assert merge_observations(records, {'2ip.io': {'complete': True, 'results': []}})['2ip.io'] == {}
assert merge_observations(records, {'2ip.io': {'complete': False, 'results': []}})['2ip.io']['AS24940'] == {'188.40.167.81'}

with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    limits = tmp / 'limits.txt'; limits.write_text('AS24940 /24\nAS213230 /24 # cloud\n')
    assert read_limits(limits) == {24940: 24, 213230: 24}
    for bad in ['AS24940 /0', 'AS24940 /33', 'ASoops /24', 'AS24940 /24\nAS24940 /24']:
        limits.write_text(bad)
        try: read_limits(limits)
        except ValueError: pass
        else: raise AssertionError(bad)
    limits.write_text('AS24940 /24\n')
    previous = tmp / 'provenance.json'; previous.write_text(json.dumps(records))
    args = argparse.Namespace(scanner=root / 'SubnetResolve.sh', verbose=False, allow_partial=True,
                              domains_output=tmp / 'domains.json', sources_output=tmp / 'sources.json',
                              output=tmp / 'IP.json', evidence=tmp / 'evidence',
                              prefix_limits=limits, prefix_limit_policy=PrefixLimits({24940: 24}, snapshot),
                              previous_provenance=previous, manual_ips=tmp / 'ip.txt')
    args.manual_ips.write_text('188.40.0.0/16\n')
    write_json(args.sources_output, {'rules': [{'ruleTag': '2ip.io', 'ip': ['188.40.0.0/16']}]})
    write_json(args.domains_output, {'rules': [{'ruleTag': '2ip.io', 'domain': ['domain:2ip.io']}]})
    with patch('update_routing.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps({
        'pages': [{'site': '2ip.io', 'domains': [], 'errors': []}]}))):
        incremental_update(args, [('2ip.io', '2ip.io')], set(), lambda *_: ([], [], ''))
    assert json.loads(args.output.read_text())['rules'] == [{'ruleTag': '2ip.io', 'ip': ['188.40.167.0/24']}]
    assert '188.40.0.0/16' not in args.manual_ips.read_text()
    # A future broad WHOIS response must not restore the /16.
    args.full_refresh = True
    args.evidence = tmp / 'refresh'
    response = {'domain': '2ip.io', 'complete': True, 'results': [
        {'asn': 'AS24940', 'prefix': '188.40.0.0/16', 'ips': ['188.40.169.81']}]}
    with patch('update_routing.subprocess.run', side_effect=[
        subprocess.CompletedProcess([], 0, json.dumps({'pages': [{'site': '2ip.io', 'domains': [], 'errors': []}]})),
        subprocess.CompletedProcess([], 0, json.dumps(response)),
    ]):
        incremental_update(args, [('2ip.io', '2ip.io')], set(), lambda *_: ([], [], ''))
    assert json.loads(args.output.read_text())['rules'] == [{'ruleTag': '2ip.io', 'ip': ['188.40.169.0/24']}]
print('PASS ASN narrowing: four requested /24s, dedup, no ASN enumeration, mask preservation, missing DNS, cached incremental and full refresh')
