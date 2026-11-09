"""Cloudflare-origin filtering for direct routing, including historical rules."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'routing'))
from cloudflare import CloudflarePolicy, cloudflare_origins
from update_routing import incremental_update, write_json

with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    registry = tmp / 'asns.csv'
    registry.write_text('asn,name\nAS13335,"Cloudflare, Inc."\nAS209242,Cloudflare BYOIP Customers\n'
                        'AS139242,"Cloudflare Sydney, LLC"\nAS1,Independent Networks\n')
    origins = cloudflare_origins(registry)
    assert origins == {13335, 209242, 139242}
    policy = CloudflarePolicy(origins, ['192.0.2.128/25', '2001:db8:1::/48'])
    args = argparse.Namespace(scanner=root / 'SubnetResolve.sh', verbose=False, allow_partial=False,
                              domains_output=tmp / 'domains.json', sources_output=tmp / 'sources.json',
                              output=tmp / 'IP.json', evidence=tmp / 'evidence')
    write_json(args.domains_output, {'rules': [
        {'ruleTag': 'example.com', 'domain': ['domain:cdn.example.com', 'domain:example.com',
                                             'domain:history.example.com']}
    ]})
    write_json(args.sources_output, {'rules': [
        {'ruleTag': 'AS13335', 'ip': ['203.0.113.0/24']},
        {'ruleTag': 'legacy', 'ip': ['192.0.2.0/24', '2001:db8::/47']},
    ]})
    discovery = {'pages': [
        {'site': 'example.com', 'domains': ['fresh.example.com', 'openai.com', 'auth.openai.com', 'whois.example.com'], 'errors': []}
    ]}
    rows = {'domains': [
        {'domain': 'auth.openai.com', 'complete': False, 'results': []},
        {'domain': 'fresh.example.com', 'complete': True, 'results': [
            {'prefix': '198.51.100.0/24', 'asn': 'AS1', 'ips': ['198.51.100.1']},
            {'prefix': '192.0.2.128/25', 'asn': 'AS209242', 'ips': ['192.0.2.129']},
        ]},
        {'domain': 'whois.example.com', 'complete': False, 'results': [],
         'errors': [{'ip': '192.0.2.130'}]},
        {'domain': 'openai.com', 'complete': True, 'results': [
            {'prefix': '198.51.100.0/24', 'asn': 'AS1', 'ips': ['198.51.100.1']},
        ]},
    ]}
    entries = [('example.com', 'example.com')]
    with patch('cloudflare.lookup_addresses', side_effect=lambda host: {
        'history.example.com': {'2001:db8:1::8'},
    }.get(host, set())), patch('update_routing.subprocess.run', side_effect=[
        subprocess.CompletedProcess([], 0, json.dumps(discovery)),
        subprocess.CompletedProcess([], 3, json.dumps(rows)),
    ]):
        incremental_update(args, entries, {'AS13335'}, lambda *_: ([], [], ''), policy)
    domains = json.loads(args.domains_output.read_text())
    assert domains['rules'][0]['domain'] == ['domain:cdn.example.com', 'full:example.com', 'full:openai.com'], domains
    sources = json.loads(args.sources_output.read_text())
    assert sources['excluded_cloudflare_domains'] == [
        'auth.openai.com', 'fresh.example.com', 'history.example.com', 'whois.example.com',
    ]
    assert sources['pending_dns'] == []
    assert {r['ruleTag']:r['ip'] for r in sources['rules']} == {
        'example.com': ['198.51.100.0/24'], 'legacy': ['192.0.2.0/25', '2001:db8::/48'],
    }
    with patch('cloudflare.lookup_addresses', return_value=set()), patch(
        'update_routing.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(discovery))
    ) as run:
        incremental_update(args, entries, set(), lambda *_: ([], [], ''), policy)
        assert run.call_count == 1
    assert json.loads(args.domains_output.read_text()) == domains

print('PASS Cloudflare IPv4/IPv6 subtraction, exclusion on mixed origins, exact ancestors and persistent DNS exclusion')
