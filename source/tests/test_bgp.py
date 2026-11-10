"""BGP WHOIS recovery/partial-response tests; --live is a bounded diagnostic."""
import argparse,ast,json,os,pathlib,signal,subprocess,tempfile,time
p=argparse.ArgumentParser();p.add_argument('--script',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]/'SubnetResolve.sh');p.add_argument('--live',action='store_true');args=p.parse_args();script=args.script.resolve();source=script.read_text()
helpers=source[source.index('bgp_state() {'):source.index('\n# Optional browser')]
setup='''set -euo pipefail
batch=$1; started=$SECONDS; stage_name=BGP; stage=probe; verbose=1; ncpid=''
progress(){ printf '%s\\n' "$*" >&2; }
finish_progress(){ :; }
cleanup(){ if [ -n "$ncpid" ]; then kill "$ncpid" 2>/dev/null || :; wait "$ncpid" 2>/dev/null || :; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
'''
mock=r'''#!/usr/bin/env python3
import sys,os,json,pathlib,time
if os.environ['MODE']=='blocked':time.sleep(60)
ips=[]
for line in sys.stdin:
 line=line.strip()
 if line=='end':break
 if line not in ('begin','verbose'):ips.append(line)
trace=pathlib.Path(os.environ['TRACE'])
with trace.open('a') as f:f.write(json.dumps(ips)+'\n')
n=len(trace.read_text().splitlines());mode=os.environ['MODE']
def row(ip):print('13335 | '+ip+' | '+ip.rsplit('.',1)[0]+'.0/24 | US | ARIN | 2020-01-01 | Test',flush=True)
if mode in ('recover','long','forever','partial') and (mode=='forever' or n <= (8 if mode=='long' else 2)):
 if mode=='partial' and n==1:row(ips[0]);print('13335 | '+ips[-1]+' | ',end='',flush=True)
 time.sleep(60)
elif mode=='refused' and n<=2:print('connection refused',file=sys.stderr);sys.exit(1)
else:
 for ip in ips:
  if mode=='missing' and ip==ips[-1]:continue
  if mode=='na':print('NA | '+ip+' | NA | | | | Not announced',flush=True)
  elif mode=='prefix':print('13335 | '+ip+' | 9.9.9.0/24 | US | ARIN | | Test',flush=True)
  elif mode=='asn':print('oops | '+ip+' | '+ip.rsplit('.',1)[0]+'.0/24 | US | ARIN | | Test',flush=True)
  else:row(ip)
'''
with tempfile.TemporaryDirectory(prefix='subnet-bgp-') as directory:
 root=pathlib.Path(directory);bin=root/'bin';bin.mkdir();trace=root/'trace';sleeps=root/'sleeps';evidence=[]
 ips=root/'ips';ips.write_text('2.2.2.2\n3.3.3.3\n')
 code=setup+helpers+'\nrc=0\nbgp_exchange "$batch/ips" "$batch/result" || rc=$?\ncat "$batch/bgp-state.json"\nexit "$rc"\n'
 if args.live:
  ips.write_text('1.1.1.1\n8.8.8.8\n23.48.248.198\n')
  proc=subprocess.Popen(['bash','-c',code,'live',str(root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  try:out,err=proc.communicate(timeout=15)
  except subprocess.TimeoutExpired:
   os.killpg(proc.pid,signal.SIGTERM);out,err=proc.communicate(timeout=3)
  print(err,end='');print('LIVE BGP.tools:', 'prefix/ASN received' if proc.returncode==0 else 'not confirmed within diagnostic limit (see log)')
  if out:print(out)
  if os.environ.get('TEST_ARTIFACTS'):
   dest=pathlib.Path(os.environ['TEST_ARTIFACTS']);dest.mkdir(parents=True,exist_ok=True);(dest/'live-bgp.json').write_text(out);(dest/'live-bgp.log').write_text(err)
 else:
  f=bin/'nc';f.write_text(mock);f.chmod(0o755)
  f=bin/'sleep';f.write_text('#!/bin/bash\nif [ "$1" = 0.1 ]; then exec /bin/sleep 0.03; fi\nprintf "%s\\n" "$1" >> "$SLEEPS"\n');f.chmod(0o755)
  clock=root/'clock.sh'
  clock.write_text(r'''sleep() {
    if [ "$1" = 0.1 ]; then
      SECONDS=$((SECONDS + 1))
      /bin/sleep 0.03
    else
      printf '%s\n' "$1" >> "$SLEEPS"
      # Keep the scanner in backoff until the test sends SIGINT. An
      # instantaneous mock sleep races the next WHOIS cycle instead.
      if [[ "$MODE" == blocked || "$MODE" == forever ]]; then /bin/sleep 60; fi
    fi
  }
  ''')
  for mode in ('ok','recover','partial','long','refused','missing','na','prefix','asn','forever'):
   trace.write_text('');sleeps.write_text('');env={**os.environ,'PATH':str(bin)+':'+os.environ['PATH'],'TRACE':str(trace),'SLEEPS':str(sleeps),'MODE':mode,'BASH_ENV':str(clock)}
   proc=subprocess.Popen(['bash','-c',code,'test',str(root)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
   if mode=='forever':
    # Wait for evidence that backoff has started, then interrupt the whole group.
    deadline=time.monotonic()+5
    while time.monotonic()<deadline and not sleeps.read_text():time.sleep(0.02)
    os.killpg(proc.pid,signal.SIGINT);out,err=proc.communicate(timeout=3)
    assert proc.returncode in (130,-signal.SIGINT),(proc.returncode,err)
    print('PASS BGP persistent timeout: Ctrl+C stops',flush=True);continue
   out,err=proc.communicate(timeout=20);state=json.loads(out);calls=[json.loads(x) for x in trace.read_text().splitlines()]
   success=mode in ('ok','recover','partial','long','refused')
   assert proc.returncode==(0 if success else 1),(mode,err,out)
   if success:assert {r['ip'] for r in state['routes']}=={'2.2.2.2','3.3.3.3'},(mode,state)
   if mode in ('recover','partial','long','refused'):assert 'ждём 5 с' in err and 'снова отвечает' in err,(mode,err)
   if mode=='partial':assert calls[0]==['2.2.2.2','3.3.3.3'] and all(c==['3.3.3.3'] for c in calls[1:]),calls
   if mode=='long':assert sleeps.read_text().splitlines().count('1')==65
   if mode=='missing':assert calls==[['2.2.2.2','3.3.3.3'],['3.3.3.3']] and len(state['routes'])==1 and 'нет записи' in state['errors'][0]['message'],(calls,state)
   if mode in ('na','prefix','asn'):assert len(calls)==1 and len(state['errors'])==2 and not state['routes'],(mode,calls,state)
   if mode=='na':assert 'не указал анонсируемую' in state['errors'][0]['message']
   if mode=='prefix':assert 'не содержащую' in state['errors'][0]['message']
   if mode=='asn':assert 'без корректного ASN' in state['errors'][0]['message']
   evidence.append({'mode':mode,'calls':calls,'state':state,'stderr':err});print('PASS BGP',mode,flush=True)
  # A stalled receiver with a large input must not block timeouts or cleanup.
  ips.write_text('2.2.2.2\n'*20000);sleeps.write_text('');env['MODE']='blocked'
  proc=subprocess.Popen(['bash','-c',code,'test',str(root)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  deadline=time.monotonic()+6
  while time.monotonic()<deadline and not sleeps.read_text():time.sleep(0.02)
  started_wait=bool(sleeps.read_text());os.killpg(proc.pid,signal.SIGINT);out,err=proc.communicate(timeout=3)
  assert started_wait and proc.returncode in (130,-signal.SIGINT),(proc.returncode,err)
  print('PASS BGP large input: bounded batches and cleanup remain responsive',flush=True)
  if os.environ.get('TEST_ARTIFACTS'):
   dest=pathlib.Path(os.environ['TEST_ARTIFACTS']);dest.mkdir(parents=True,exist_ok=True);(dest/'bgp-tests.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2))
