"""Verbose progress emits state changes, not repeated polling snapshots."""
import ast, json, os, pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parent
script = root.parent / 'SubnetResolve.sh'
source = script.read_text()
helper = source.split('\nprogress() {', 1)[1].split('\ncleanup() {', 1)[0]
unit = 'verbose=1; started=0; stage_name=DNS\nprogress() {' + helper + '\nprogress same\nprogress same\nstage_name=BGP\nprogress same\nprogress changed\nprogress changed\n'
result = subprocess.run(['bash', '-c', unit], text=True, capture_output=True, check=True)
assert len(result.stderr.splitlines()) == 3, result.stderr
mock = next(ast.literal_eval(n.value) for n in ast.parse((root/'test_pipeline.py').read_text()).body
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MOCK' for t in n.targets))
mock = mock.replace("'nodes':{'n':['xx','Country','City','9.9.9.9','AS9']}",
                    "'nodes':{'n':['xx','Country','City','9.9.9.9','AS9'],'m':['xx','Country','City','9.9.9.8','AS9']}")
old = "else:print(json.dumps({'n':[{'A':['3.3.3.3' if host.startswith('bad') else '2.2.2.2']}]}))"
new = """else:
   replies={'n':[{'A':['2.2.2.2']}]}
   if trace.read_text().count('"result"')>=3:replies['m']=[{'A':['2.2.2.2']}]
   print(json.dumps(replies))"""
assert old in mock
mock = mock.replace(old,new)
with tempfile.TemporaryDirectory() as directory:
    tmp=pathlib.Path(directory); binary=tmp/'bin';binary.mkdir()
    for name in ('curl','nc'):
        path=binary/name;path.write_text(mock);path.chmod(0o755)
    trace=tmp/'trace';trace.write_text('')
    env={**os.environ,'PATH':str(binary)+':'+os.environ['PATH'],'CASE':'ok','TRACE':str(trace)}
    result=subprocess.run(['bash',str(script),'-4sv','good.example'],text=True,capture_output=True,env=env,timeout=30)
    assert result.returncode==0,result.stderr
    assert result.stderr.count('ответили 1/2 узлов; уникальных A-адресов: 1')==1,result.stderr
    assert result.stderr.count('ответили 2/2 узлов; уникальных A-адресов: 1')==1,result.stderr
    assert 'опрос ' not in result.stderr,result.stderr
    assert 'TLS 1.2' in result.stderr,result.stderr
    assert json.loads(result.stdout)=={'ip':['2.2.2.0/24']}
assert 'wait_left % 5' not in source
print('PASS verbose state changes, repeated DNS snapshot suppressed, stage changes retained, JSON stable')
