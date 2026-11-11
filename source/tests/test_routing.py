"""Routing contract, exact CIDR aggregation, scanner failures and atomic output."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent
source = root.parent / 'SubnetResolve.sh'
if not source.exists():
    source = root / 'SubnetResolve.sh'
generator = root.parent / 'routing/scripts' / 'update_routing.py'
if not generator.exists():
    generator = root / 'update_routing.py'
spec = importlib.util.spec_from_file_location('routing', generator)
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)
result = routing.compact_rules({'rules': [
    {'ruleTag': 'a.example', 'ip': ['192.0.2.0/25', '192.0.2.128/25', '192.0.2.0/25']},
    {'ruleTag': 'b.example', 'ip': ['192.0.2.0/25', '198.51.100.0/24', '198.51.102.0/24']}
]}, ['a.example', 'b.example'])
assert result['rules'][0]['ip'] == ['192.0.2.0/24']
assert result['rules'][1]['ip'] == ['192.0.2.0/25', '198.51.100.0/24', '198.51.102.0/24']
for bad in ('192.0.2.1/24', '::/0', 'invalid'):
    try:
        routing.compact_rules({'rules': [{'ruleTag':'a', 'ip':[bad]}]}, ['a'])
    except ValueError:
        pass
    else:
        raise AssertionError(bad)
mock = next(ast.literal_eval(n.value) for n in ast.parse((root/'test_pipeline.py').read_text()).body
            if isinstance(n, ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MOCK' for t in n.targets))
with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    binary = tmp/'bin'; binary.mkdir()
    for name in ('curl','nc','node'):
        path=binary/name;path.write_text(mock);path.chmod(0o755)
    trace=tmp/'trace'; trace.write_text('')
    env={**os.environ,'PATH':str(binary)+':'+os.environ['PATH'],'CASE':'empty','TRACE':str(trace),'XDG_CACHE_HOME':str(tmp/'cache')}
    for verbose in (False, True):
        scan=subprocess.run(['bash',str(source),'-rules','-s',*(['-v'] if verbose else []),'good.example','bad.example'],env=env,text=True,capture_output=True,timeout=30)
        assert scan.returncode==3,scan.stderr
        assert ('No A records' in scan.stderr)==verbose,scan.stderr
        assert ('Узел сообщил об ошибке DNS' in scan.stderr)==verbose,scan.stderr
        assert json.loads(scan.stdout)['rules']==[{'ruleTag':'bad.example','domain':['domain:bad.example'],'ip':[]},{'ruleTag':'good.example','domain':['domain:good.example'],'ip':['2.2.2.0/24']}]
    env['CASE']='ok'
    scan=subprocess.run(['bash',str(source),'-parse','-rules','-s','good.example','good2.example'],env=env,text=True,capture_output=True,timeout=30)
    assert scan.returncode==0,scan.stderr
    assert [r['ruleTag'] for r in json.loads(scan.stdout)['rules']]==['good.example','good2.example']
    sites=tmp/'sites.txt';sites.write_text('# services\na.example\nhttps://a.example/path\nb.example\n')
    assert routing.services(sites)==[('a.example','a.example'),('b.example','b.example')]
    fake=tmp/'fake.sh';fake.write_text('exit 3\n')
    out=tmp/'IP.txt';out.write_text('existing\n')
    failed=subprocess.run(['python3',str(generator),'--sites',str(sites),'--scanner',str(fake),'--output',str(out)],capture_output=True,text=True)
    assert failed.returncode and out.read_text()=='existing\n'
    fatal=subprocess.run(['python3',str(generator),'--allow-partial','--sites',str(sites),'--scanner',str(fake),'--output',str(out)],capture_output=True,text=True)
    assert fatal.returncode and out.read_text()=='existing\n'
    fake.write_text('printf \'%s\\n\' \'{"rules":[{"ruleTag":"a.example","ip":["192.0.2.0/25"]},{"ruleTag":"b.example","ip":[]}]}\'\nexit 3\n')
    out.write_text(json.dumps({'rules':[{'ruleTag':'a.example','ip':['192.0.2.128/25']},{'ruleTag':'b.example','ip':['198.51.100.0/24']}]}))
    partial=subprocess.run(['python3',str(generator),'--allow-partial','--evidence',str(tmp/'evidence'),'--sites',str(sites),'--scanner',str(fake),'--output',str(out)],capture_output=True,text=True)
    assert partial.returncode==0,partial.stderr
    assert json.loads(out.read_text())=={'rules':[{'ruleTag':'a.example','ip':['192.0.2.0/24']},{'ruleTag':'b.example','ip':['198.51.100.0/24']}]}
    assert json.loads((tmp/'evidence/completeness.json').read_text())['complete'] is False
print('PASS rule tags, service isolation, exact CIDR union, quiet no-A, parse rules, input dedup and failed scan preserves IP.txt')
