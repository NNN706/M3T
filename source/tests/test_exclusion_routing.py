"""Filter CDN IPs before WHOIS and keep CDN domains out of direct rules."""
import argparse
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'routing'))
from exclusion_policy import ExclusionPolicy, read_excluded_asns
from update_routing import incremental_update, write_json

with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    configured = tmp / 'exclude'
    configured.write_text('# CDN and Microsoft\nAS13335\nAS209242\nAS54113\nASN08075 # Microsoft\nAS8075\n')
    origins = read_excluded_asns(configured)
    assert origins == {13335, 209242, 54113, 8075}
    configured.write_text('AS8075\nMicrosoft\n')
    try:
        read_excluded_asns(configured)
    except ValueError as error:
        assert 'exclude:2' in str(error), error
    else:
        raise AssertionError('Invalid ASN was accepted')
    policy = ExclusionPolicy(origins, ['192.0.2.128/25', '203.0.113.0/24', '2001:db8:1::/48'])
    scanner = root / 'SubnetResolve.sh'
    index = tmp / 'index.json'
    write_json(index, policy.ipv4_index())

    module = ast.parse(Path(__file__).with_name('test_pipeline.py').read_text())
    mock = next(ast.literal_eval(node.value) for node in module.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'MOCK' for target in node.targets))
    mock = mock.replace("  if mode=='result'", """  if host=='cloud.example':print(json.dumps({'n':[{'A':['192.0.2.128','192.0.2.255']}]}));sys.exit(0)
  if host=='mixed.example':print(json.dumps({'n':[{'A':['192.0.2.127','192.0.2.128','198.51.100.1','203.0.113.1']}]}));sys.exit(0)
  if mode=='result'""")
    mock = mock.replace("  if mode=='bgp' and ip", """  if mode=='incomplete' and ip=='198.51.100.1':continue
  if mode=='bgp' and ip""")
    mock = mock.replace("print('13335 | '+ip", "print('1 | '+ip")
    bin_dir = tmp / 'bin'
    bin_dir.mkdir()
    for tool in ('curl', 'nc'):
        path = bin_dir / tool
        path.write_text(mock)
        path.chmod(0o755)
    trace = tmp / 'trace'

    def scan(*args, policy_enabled=True, mode='ok'):
        trace.write_text('')
        env = {**os.environ, 'PATH': str(bin_dir) + ':' + os.environ['PATH'],
               'CASE': mode, 'TRACE': str(trace), 'XDG_CACHE_HOME': str(tmp / 'cache')}
        if policy_enabled:
            env['SUBNET_EXCLUDED_IPV4_INDEX'] = str(index)
        else:
            env.pop('SUBNET_EXCLUDED_IPV4_INDEX', None)
        proc = subprocess.run(['bash', str(scanner), '-sv', *args], env=env,
                              capture_output=True, text=True, timeout=25)
        return proc, [json.loads(line) for line in trace.read_text().splitlines()]

    proc, events = scan('cloud.example')
    only = json.loads(proc.stdout)
    assert proc.returncode == 0 and only['complete'] and not only['results'], proc.stderr
    assert only['excluded_ips'] == ['192.0.2.128', '192.0.2.255']
    assert not any(phase.startswith('bgp') or phase == 'bulk' for phase, _ in events), events

    proc, events = scan('cloud.example', 'mixed.example')
    assert proc.returncode == 0, proc.stderr
    rows = json.loads(proc.stdout)
    mixed = rows['domains'][1]
    assert mixed['excluded_ips'] == ['192.0.2.128', '203.0.113.1'] and mixed['complete'], mixed
    assert [ip for phase, ip in events if phase == 'bulk'] == [['192.0.2.127', '198.51.100.1']], events
    assert ['bgp-health', ['1.1.1.1']] not in events
    assert next(i for i, event in enumerate(events) if event[0] == 'bgp-health') > max(
        i for i, event in enumerate(events) if event[0] == 'result')

    proc, _ = scan('mixed.example', mode='incomplete')
    assert proc.returncode == 3 and json.loads(proc.stdout)['excluded_ips'] == ['192.0.2.128', '203.0.113.1'], proc.stderr
    checkpoint, = (tmp / 'cache' / 'SubnetResolve').glob('bgp-resume.*')
    proc, events = scan('--resume-bgp', str(checkpoint), policy_enabled=False)
    assert proc.returncode == 0, proc.stderr
    assert [ips for phase, ips in events if phase == 'bulk'] == [['198.51.100.1']], events

    args = argparse.Namespace(scanner=scanner, verbose=False, allow_partial=False,
                              domains_output=tmp / 'domains.json', sources_output=tmp / 'sources.json',
                              output=tmp / 'IP.json', evidence=tmp / 'evidence')
    write_json(args.sources_output, {'rules': [
        {'ruleTag': 'AS13335', 'ip': ['203.0.113.0/24']},
        {'ruleTag': 'legacy', 'ip': ['192.0.2.0/24', '2001:db8::/47']},
    ]})
    write_json(args.domains_output, {'rules': [
        {'ruleTag': 'other.example', 'domain': ['domain:ipv6.other.example', 'domain:other.example']},
    ]})
    baseline = {path: path.read_bytes() for path in (args.sources_output, args.domains_output)}
    discovery = {'pages': [
        {'site': 'cloud.example', 'domains': ['mixed.example'], 'errors': []}
    ]}
    entries = [('cloud.example', 'cloud.example')]
    with patch('update_routing.subprocess.run', side_effect=[
        subprocess.CompletedProcess([], 0, json.dumps(discovery)),
        subprocess.CompletedProcess([], 0, json.dumps(rows)),
    ]) as run, patch('exclusion_policy.lookup_addresses', side_effect=lambda host: (
        {'2001:db8:1::12'} if host == 'ipv6.other.example' else set()
    )):
        incremental_update(args, entries, {'AS13335', 'AS54113', 'AS8075'}, lambda *_: ([], [], ''), policy)
        assert 'SUBNET_EXCLUDED_IPV4_INDEX' in run.call_args.kwargs['env']
    domains = json.loads(args.domains_output.read_text())
    assert domains == {'rules': [{'ruleTag': 'other.example', 'domain': ['full:other.example']}]}, domains
    sources = json.loads(args.sources_output.read_text())
    assert sources['pending_dns'] == []
    assert sources['excluded_asns'] == sorted(policy.asns)
    assert sources['excluded_domains'] == ['cloud.example', 'ipv6.other.example', 'mixed.example']
    assert {r['ruleTag']:r['ip'] for r in sources['rules']} == {
        'cloud.example': ['192.0.2.0/25', '198.51.100.0/24'],
        'legacy': ['192.0.2.0/25', '2001:db8::/48'],
    }
    stats = json.loads((args.evidence / 'completeness.json').read_text())
    assert stats['complete'] and stats['excluded_ipv4_skipped_before_whois'] == 3, stats

    published = {path: path.read_bytes() for path in (*baseline, args.output)}
    args.resume = args.evidence
    args.evidence = tmp / 'replayed'
    for path, content in baseline.items():
        path.write_bytes(content)
    args.output.unlink()

    def unexpected_collect(*_):
        raise AssertionError('Repeated ASN collection')

    explicit = {'AS13335', 'AS54113', 'AS8075'}
    with patch('update_routing.subprocess.run') as run, patch('exclusion_policy.lookup_addresses') as dns:
        incremental_update(args, entries, explicit, unexpected_collect, policy)
        run.assert_not_called()
        dns.assert_not_called()
    assert all(path.read_bytes() == payload for path, payload in published.items())
    evidence_file = 'scanner-output-1.json'
    assert (args.evidence / evidence_file).read_bytes() == (args.resume / evidence_file).read_bytes()

    # IPv4 is unchanged, but IPv6 changed. The prepared rules must be rebuilt.
    for path, content in baseline.items():
        path.write_bytes(content)
    args.output.unlink()
    args.evidence = tmp / 'changed-policy'
    changed = ExclusionPolicy(origins, ['192.0.2.128/25', '203.0.113.0/24', '2001:db8::/47'])
    with patch('update_routing.subprocess.run') as run, patch('exclusion_policy.lookup_addresses', return_value=set()):
        incremental_update(args, entries, explicit, lambda *_: ([], [], ''), changed)
        run.assert_not_called()
    assert all(':' not in prefix for rule in json.loads(args.output.read_text())['rules'] for prefix in rule['ip'])
    for path, payload in published.items():
        path.write_bytes(payload)
    args.resume = None
    args.evidence = tmp / 'incremental'

    with patch('exclusion_policy.lookup_addresses', return_value=set()), patch(
        'update_routing.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(discovery))
    ) as run:
        incremental_update(args, entries, set(), lambda *_: ([], [], ''), policy)
        assert run.call_count == 1, run.call_args_list
    assert json.loads(args.domains_output.read_text()) == domains

print('PASS Cloudflare/Fastly early IPv4 filtering, mixed IPs, domain exclusions, resume and IPv6 subtraction')
