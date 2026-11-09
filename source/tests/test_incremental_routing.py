"""Incremental workflow DNS selection and publication."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'routing'))
from update_routing import incremental_update, write_json

with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    args = argparse.Namespace(scanner=root / 'SubnetResolve.sh', verbose=False, allow_partial=True,
                              domains_output=tmp / 'domains.json', sources_output=tmp / 'sources.json',
                              output=tmp / 'IP.json', evidence=tmp / 'evidence')
    write_json(args.domains_output, {'rules': [
        {'ruleTag': 'old.example', 'domain': ['domain:old.example']}
    ]})
    write_json(args.sources_output, {'rules': [
        {'ruleTag': 'old.example', 'ip': ['192.0.2.0/24']}
    ]})
    discovery = {
        'pages': [
            {'site': 'old.example', 'domains': ['old.example', 'child.old.example'], 'errors': []},
            {'site': 'service.example', 'domains': [], 'errors': ['Ошибка HTTPS']},
            {'site': 'pending.example', 'domains': ['cdn.pending.example'], 'errors': []},
        ],
        'complete': False,
    }
    good = {'complete': True, 'results': [{'prefix': '198.51.100.0/24'}]}
    dns = {'domains': [
        dict(good, domain='child.old.example'),
        dict(good, domain='cdn.pending.example'),
        dict(good, domain='service.example'),
        {'domain': 'pending.example', 'complete': False, 'results': [{'prefix': '203.0.113.0/24'}]},
    ]}
    entries = [(host, host) for host in ('old.example', 'service.example', 'pending.example')]
    with patch('update_routing.subprocess.run', side_effect=[
        subprocess.CompletedProcess([], 0, json.dumps(discovery)),
        subprocess.CompletedProcess([], 3, json.dumps(dns)),
    ]) as run:
        incremental_update(args, entries, set(), lambda *_: ([], [], ''))
        browser_call, dns_call = [call.args[0] for call in run.call_args_list]
    subprocess.run(['bash', '-n', '-c', browser_call[2]], check=True)
    assert 'cat "$batch/discovery.json"' in browser_call[2]
    assert dns_call[dns_call.index('--') + 1:] == ['cdn.pending.example', 'child.old.example', 'pending.example', 'service.example']
    assert json.loads(args.domains_output.read_text()) == {'rules': [
        {'ruleTag': 'old.example', 'domain': ['domain:child.old.example', 'domain:old.example']},
        {'ruleTag': 'pending.example', 'domain': ['domain:cdn.pending.example']},
        {'ruleTag': 'service.example', 'domain': ['domain:service.example']},
    ]}
    result = json.loads(args.output.read_text())
    assert {prefix for rule in result['rules'] for prefix in rule['ip']} == {
        '192.0.2.0/24', '198.51.100.0/24',
    }
    report = json.loads((args.evidence / 'completeness.json').read_text())
    assert report['domains_without_complete_dns_bgp'] == ['pending.example']
    assert report['dns_skipped_existing'] == 1 and report['dns_requested'] == 4
    discovery.update(pages=[], complete=True)
    with patch('update_routing.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(discovery))) as run:
        incremental_update(args, [('old.example', 'old.example')], set(), lambda *_: ([], [], ''))
        assert run.call_count == 1
    assert json.loads(args.output.read_text()) == result

print('PASS incremental routing keeps old rules, skips exact names, resolves service hosts and retries unresolved names')
