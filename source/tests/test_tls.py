"""Test production HTTP helpers with controlled failures; --live probes real API."""
import argparse,json,os,pathlib,subprocess,tempfile,time
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');p.add_argument('--live',action='store_true');args=p.parse_args()
s=args.script.read_text();helpers=s[s.index('fetch_http() {'):s.index('\nbgp_exchange()')]
setup='''set -euo pipefail
batch=$1; stage=probe; stage_name=DNS; verbose=1; http_pid=''
progress(){ printf '%s\\n' "$*" >&2; }
finish_progress(){ :; }
die(){ printf '%s\\n' "$*" >&2; exit 1; }
'''
mock=r'''#!/usr/bin/env python3
import os,sys,json,pathlib
p=pathlib.Path(os.environ['TLS_TRACE']);a=sys.argv[1:]
with p.open('a') as f:f.write(json.dumps(a)+'\n')
n=len(p.read_text().splitlines());code=int(os.environ['TLS_FAILURE'])
assert '--insecure' not in a and '-k' not in a
assert a[a.index('--max-time')+1]=='1.5' and a[a.index('--connect-timeout')+1]=='1.5'
if n==1 or os.environ.get('TLS_ALWAYS')=='1':
 if code==-1:print('bad json');sys.exit(0)
 if code:sys.exit(code)
print('{"ok":1,"request_id":"abc","nodes":{"n":[]},"permanent_link":"https://check-host.net/check-report/abc"}')
'''
with tempfile.TemporaryDirectory() as directory:
 root=pathlib.Path(directory)
 if args.live:
  start=time.monotonic();r=subprocess.run(['bash','-c',setup+helpers+'\ncheck_service\ncat "$batch/service-check.json"','probe',str(root)],capture_output=True,text=True,timeout=10)
  if os.environ.get('TEST_ARTIFACTS'):
   d=pathlib.Path(os.environ['TEST_ARTIFACTS']);d.mkdir(parents=True,exist_ok=True);(d/'live-check-host.json').write_text(r.stdout);(d/'live-check-host.log').write_text(r.stderr)
  print(r.stderr,end='');assert r.returncode==0,r.stderr
  assert json.loads(r.stdout)['ok']==1
  print('PASS live Check-Host API: ok=1, elapsed',round(time.monotonic()-start,3),'seconds')
 else:
  bin=root/'bin';bin.mkdir();f=bin/'curl';f.write_text(mock);f.chmod(0o755)
  for expected in ('check','object','site'):
   for code in (0,28,35,60,22,-1,6,7):
    trace=root/'trace';trace.write_text('')
    env={**os.environ,'PATH':str(bin)+':'+os.environ['PATH'],'TLS_TRACE':str(trace),'TLS_FAILURE':str(code)}
    # Two consecutive requests in the same shell prove TLS choice is not sticky.
    run='\nfetch_http '+expected+' https://check-host.net/check-dns > "$batch/one"\nfetch_http '+expected+' https://check-host.net/check-dns > "$batch/two"\ncat "$batch/two"\n'
    r=subprocess.run(['bash','-c',setup+helpers+run,'test',str(root)],env=env,capture_output=True,text=True,timeout=10)
    assert r.returncode==0,r.stderr;json.loads(r.stdout)
    calls=[json.loads(x) for x in trace.read_text().splitlines()]
    retries=code!=0 and not(expected=='site' and code==-1)
    assert len(calls)==(3 if retries else 2),(expected,code,calls)
    modes=['tls12' if '--tlsv1.2' in a else 'default' for a in calls]
    wanted=['default']*len(calls) if expected=='site' else ['tls12']+(['default' if code in (28,35,60) else 'tls12'] if retries else [])+['tls12']
    assert modes==wanted,(expected,code,modes,wanted)
    for a in calls:
     if '--tlsv1.2' in a:assert a[a.index('--tls-max')+1]=='1.2'
    if retries:assert 'Причина повторной попытки:' in r.stderr
    print('PASS TLS',expected,'failure',code,'modes',','.join(modes),flush=True)
  for code in (28,35,60,22,-1):
   trace.write_text('');env.update(TLS_ALWAYS='1',TLS_FAILURE=str(code))
   r=subprocess.run(['bash','-c',setup+helpers+'\nfetch_http check https://check-host.net/check-dns','test',str(root)],env=env,capture_output=True,text=True,timeout=10)
   assert r.returncode==1 and not r.stdout and len(trace.read_text().splitlines())==2
  print('PASS both attempts fail: timeout, TLS, certificate, HTTP, JSON')
