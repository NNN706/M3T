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
    baseline = {p: p.read_bytes() for p in (args.domains_output, args.sources_output)}

    def checkout():
        args.output.unlink(missing_ok=True)
        for path, content in baseline.items():
            path.write_bytes(content)

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
        {'ruleTag': 'pending.example', 'domain': ['domain:cdn.pending.example', 'domain:pending.example']},
        {'ruleTag': 'service.example', 'domain': ['domain:service.example']},
    ]}
    result = json.loads(args.output.read_text())
    assert {prefix for rule in result['rules'] for prefix in rule['ip']} == {
        '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
    }
    report = json.loads((args.evidence / 'completeness.json').read_text())
    assert report['domains_without_complete_dns_bgp'] == ['pending.example']
    assert report['dns_skipped_existing'] == 1 and report['dns_requested'] == 4
    assert json.loads(args.sources_output.read_text())['pending_dns'] == ['pending.example']
    args.resume = args.evidence
    args.evidence = tmp / 'resumed'
    checkout()
    with patch('update_routing.subprocess.run', return_value=subprocess.CompletedProcess(
        [], 0, json.dumps(dict(good, domain='pending.example'))
    )) as run:
        incremental_update(args, entries, set(), lambda *_: ([], [], ''))
        assert run.call_count == 1 and run.call_args.args[0][-1] == 'pending.example'
    prepared_output = args.output.read_bytes()
    assert json.loads((args.evidence / 'dns-checkpoint.json').read_text()).keys() == {
        'cdn.pending.example', 'child.old.example', 'service.example', 'pending.example',
    }

    resumed = args.evidence
    args.evidence = tmp / 'extended'
    checkout()
    extra = {'site': 'extra.example', 'domains': ['extra.example'], 'errors': []}
    with patch('update_routing.subprocess.run', side_effect=[
        subprocess.CompletedProcess([], 0, json.dumps({'pages': [extra], 'complete': True})),
        subprocess.CompletedProcess([], 0, json.dumps({'domains': [
            dict(good, domain='extra.example'), dict(good, domain='pending.example'),
        ]})),
    ]) as run:
        incremental_update(args, entries + [('extra.example', 'extra.example')], {'AS12345'},
                           lambda *_: ([], [], ''))
        browser_call, dns_call = [call.args[0] for call in run.call_args_list]
        assert browser_call[browser_call.index('--') + 1:] == ['extra.example']
        assert dns_call[dns_call.index('--') + 1:] == ['extra.example', 'pending.example']

    args.evidence = resumed
    args.resume = args.evidence
    args.evidence = tmp / 'ready'
    checkout()
    with patch('update_routing.subprocess.run') as run:
        incremental_update(args, entries, set(), lambda *_: (_ for _ in ()).throw(AssertionError('ASN stage repeated')))
        run.assert_not_called()
    assert args.output.read_bytes() == prepared_output
    try:
        incremental_update(args, entries, set(), lambda *_: ([], [], ''))
    except RuntimeError as error:
        assert 'Контрольная точка несовместима' in str(error)
    else:
        raise AssertionError('Changed routing baseline was accepted')
    args.resume = None
    result = json.loads(args.output.read_text())

    # The unfinished hostname remains eligible even after it appears in domains.json.
    checkout()
    write_json(args.domains_output, {'rules': [
        {'ruleTag': 'old.example', 'domain': ['domain:old.example']},
        {'ruleTag': 'pending.example', 'domain': ['domain:pending.example']},
    ]})
    write_json(args.sources_output, {'rules': [
        {'ruleTag': 'old.example', 'ip': ['192.0.2.0/24']},
    ], 'pending_dns': ['pending.example']})
    with patch('update_routing.subprocess.run', side_effect=[
        subprocess.CompletedProcess([], 0, json.dumps({'pages': [], 'complete': True})),
        subprocess.CompletedProcess([], 1, ''),
    ]) as run:
        incremental_update(args, [('pending.example', 'pending.example'), ('dns-s', 'dns-s')],
                           set(), lambda *_: ([], [], ''))
        assert run.call_args.args[0][-1] == 'pending.example'
        assert 'dns-s' not in run.call_args.args[0]
    assert json.loads(args.sources_output.read_text())['pending_dns'] == ['pending.example']
    result = json.loads(args.output.read_text())

    discovery.update(pages=[], complete=True)
    with patch('update_routing.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(discovery))) as run:
        incremental_update(args, [('old.example', 'old.example')], set(), lambda *_: ([], [], ''))
        assert run.call_count == 1
    assert json.loads(args.output.read_text()) == result

print('PASS incremental routing keeps old rules, skips exact names, resolves service hosts and retries unresolved names')
