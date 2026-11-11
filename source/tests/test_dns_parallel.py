"""Test the real Bash entry point with a controlled Check-Host API and WHOIS."""
import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
module = ast.parse(Path(__file__).with_name('test_pipeline.py').read_text())
mock = next(ast.literal_eval(node.value) for node in module.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'MOCK' for target in node.targets))
mock = mock.replace('import sys,os,json,pathlib,urllib.parse', 'import sys,os,json,pathlib,urllib.parse,time')
mock = mock.replace('def check(host):', '''def pause_until(predicate):
 deadline=time.monotonic()+8
 while not predicate():
  if time.monotonic()>=deadline: raise RuntimeError('test synchronization timed out')
  time.sleep(.025)
def events():
 return [json.loads(line) for line in trace.read_text().splitlines()]
def check(host):''')
mock = mock.replace("  if phase=='health':", """  if phase=='dns' and host=='rate.example' and mode!='poll429':
   count=events().count(['dns',host])
   if count==1 or mode=='exhaust':
    delay=2 if mode=='cooldown' else 0
    headers=pathlib.Path(args[args.index('-D')+1])
    headers.write_bytes(f'HTTP/2 429\\r\\nRetry-After: {delay}\\r\\n\\r\\n'.encode())
    log('rejected',time.time());sys.exit(22)
  if phase=='dns' and host=='peer.example':
   cooldown=pathlib.Path(args[args.index('-D')+1]).parent.parent/'check-host-cooldown'
   pause_until(lambda:any(cooldown.glob('*.until')))
   log('peer-ready',time.time())
  if phase=='health':""")
mock = mock.replace("  if mode=='result' and", """  if mode=='parallel':
   pause_until(lambda:sum(phase=='dns' for phase,_ in events())>=15)
   if host=='h00.example':
    pause_until(lambda:['dns','h15.example'] in events())
  if mode=='poll429' and events().count(['result',host])==1:
   pathlib.Path(args[args.index('-D')+1]).write_bytes(b'HTTP/2 429\\r\\n\\r\\n')
   log('rejected',time.time());sys.exit(22)
  log('result-time',[host,time.time()])
  if mode=='result' and""")

with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    for name in ('curl', 'nc'):
        path = tmp / name
        path.write_text(mock)
        path.chmod(0o755)
    trace = tmp / 'trace'

    def run(mode, hosts, **overrides):
        trace.write_text('')
        env = {**os.environ, 'PATH': str(tmp) + ':' + os.environ['PATH'],
               'CASE': mode, 'TRACE': str(trace), 'XDG_CACHE_HOME': str(tmp / 'cache')}
        env.pop('SUBNET_DNS_CONCURRENCY', None)
        env.update(overrides)
        proc = subprocess.run(['bash', str(root / 'SubnetResolve.sh'), '-sv', *hosts], env=env,
                              capture_output=True, text=True, timeout=35)
        return proc, [json.loads(line) for line in trace.read_text().splitlines()]

    hosts = [f'h{i:02}.example' for i in range(17)]
    proc, events = run('parallel', hosts)
    assert proc.returncode == 0, proc.stderr
    assert [row['domain'] for row in json.loads(proc.stdout)['domains']] == hosts
    active = set()
    peak = 0
    for phase, value in events:
        if phase == 'dns':
            active.add(value)
            peak = max(peak, len(active))
        if phase == 'result-time':
            active.remove(value[0])
    assert peak == 15 and not active, events
    assert events.index(['dns', 'h15.example']) < next(i for i, (phase, value) in enumerate(events)
                                                       if phase == 'result-time' and value[0] == hosts[0])
    assert [payload for phase, payload in events if phase == 'bulk'] == [['2.2.2.2']], events

    proc, events = run('cooldown', ['rate.example', 'peer.example'])
    assert proc.returncode == 0 and events.count(['dns', 'rate.example']) == 2, (proc.stderr, events)
    rejected = next(value for phase, value in events if phase == 'rejected')
    peer_result = next(value[1] for phase, value in events if phase == 'result-time' and value[0] == 'peer.example')
    assert peer_result - rejected >= 2, events

    proc, events = run('poll429', ['rate.example'])
    assert proc.returncode == 0 and events.count(['dns', 'rate.example']) == 1, proc.stderr
    assert events.count(['result', 'rate.example']) == 2, events
    rejected = next(value for phase, value in events if phase == 'rejected')
    finished = next(value[1] for phase, value in events if phase == 'result-time')
    assert finished - rejected >= 5, events

    proc, events = run('exhaust', ['rate.example', 'h00.example'], SUBNET_DNS_CONCURRENCY='1')
    assert proc.returncode == 3 and events.count(['dns', 'rate.example']) == 4, (proc.stderr, events)
    assert 'исчерпаны 3 повтора' in proc.stderr
    assert json.loads(proc.stdout)['domains'][1]['complete'] is True

    proc, events = run('ok', ['h00.example'], SUBNET_DNS_CONCURRENCY='16')
    assert proc.returncode == 1 and not events, proc.stderr

print('PASS DNS worker limit, slot refill, shared Retry-After, bounded retries and WHOIS deduplication')
